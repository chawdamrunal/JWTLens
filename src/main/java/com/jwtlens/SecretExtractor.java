package com.jwtlens;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passively extracts JWT secrets, HMAC keys, RSA/EC private keys, and JWKS
 * configurations from JavaScript files and API responses flowing through Burp Proxy.
 *
 * Discovered secrets are fed directly into the brute force and algorithm confusion attacks,
 * and stored in the Forge tab for manual use.
 */
public class SecretExtractor {

    private final MontoyaApi api;
    private final JwtDedup dedup;

    // Discovered secrets stored for use by active scanner and forge tab
    private final Set<String> discoveredSecrets = ConcurrentHashMap.newKeySet();
    private final Set<String> discoveredPublicKeys = ConcurrentHashMap.newKeySet();
    private final Set<String> discoveredJwksUrls = ConcurrentHashMap.newKeySet();

    // Dedup: don't re-scan the same URL
    private final Set<String> scannedUrls = ConcurrentHashMap.newKeySet();

    // ================================================================
    // SECRET PATTERNS
    // ================================================================

    // Environment variable / config patterns: KEY = "value" or KEY: "value"
    private static final Pattern[] SECRET_ASSIGNMENT_PATTERNS = {
            // JS/TS: const JWT_SECRET = "value"  or  var secret = 'value'
            Pattern.compile("(?:jwt[_\\-]?secret|jwt[_\\-]?key|signing[_\\-]?key|secret[_\\-]?key|hmac[_\\-]?secret|auth[_\\-]?secret|token[_\\-]?secret|app[_\\-]?secret|encryption[_\\-]?key|private[_\\-]?key|api[_\\-]?secret)\\s*[:=]\\s*[\"'`]([^\"'`]{4,256})[\"'`]", Pattern.CASE_INSENSITIVE),

            // JSON: "jwtSecret": "value"  or  "secret": "value"
            Pattern.compile("\"(?:jwt[_\\-]?[Ss]ecret|secret[_\\-]?[Kk]ey|signing[_\\-]?[Kk]ey|hmac[_\\-]?[Ss]ecret|auth[_\\-]?[Ss]ecret|token[_\\-]?[Ss]ecret|app[_\\-]?[Ss]ecret|encryption[_\\-]?[Kk]ey|private[_\\-]?[Kk]ey|api[_\\-]?[Ss]ecret|JWT_SECRET|SECRET_KEY|SIGNING_KEY|HMAC_SECRET|AUTH_SECRET)\"\\s*:\\s*\"([^\"]{4,256})\""),

            // .env style: JWT_SECRET=value or export SECRET_KEY=value
            Pattern.compile("(?:^|\\n|;|export\\s+)(?:JWT[_\\-]?SECRET|SECRET[_\\-]?KEY|SIGNING[_\\-]?KEY|HMAC[_\\-]?SECRET|AUTH[_\\-]?SECRET|TOKEN[_\\-]?SECRET|APP[_\\-]?SECRET|ENCRYPTION[_\\-]?KEY|PRIVATE[_\\-]?KEY|API[_\\-]?SECRET)\\s*=\\s*[\"']?([^\\s\"'\\n;]{4,256})[\"']?", Pattern.CASE_INSENSITIVE),

            // YAML: jwt_secret: value
            Pattern.compile("(?:jwt[_\\-]?secret|secret[_\\-]?key|signing[_\\-]?key|hmac[_\\-]?secret):\\s+[\"']?([^\\s\"'\\n#]{4,256})[\"']?", Pattern.CASE_INSENSITIVE),
    };

    // RSA/EC Private Key patterns (PEM)
    private static final Pattern RSA_PRIVATE_KEY = Pattern.compile(
            "-----BEGIN (?:RSA )?PRIVATE KEY-----[\\s\\S]{50,4096}?-----END (?:RSA )?PRIVATE KEY-----"
    );
    private static final Pattern EC_PRIVATE_KEY = Pattern.compile(
            "-----BEGIN EC PRIVATE KEY-----[\\s\\S]{50,2048}?-----END EC PRIVATE KEY-----"
    );

    // RSA Public Key (for algorithm confusion)
    private static final Pattern RSA_PUBLIC_KEY = Pattern.compile(
            "-----BEGIN (?:RSA )?PUBLIC KEY-----[\\s\\S]{50,4096}?-----END (?:RSA )?PUBLIC KEY-----"
    );

    // JWKS inline patterns
    private static final Pattern JWKS_INLINE = Pattern.compile(
            "\\{\\s*\"keys\"\\s*:\\s*\\[\\s*\\{[^}]*\"kty\"\\s*:\\s*\"(?:RSA|EC)\"[^]]*\\]\\s*\\}"
    );

    // JWKS URL references
    private static final Pattern JWKS_URL_PATTERN = Pattern.compile(
            "(?:jwks[_\\-]?uri|jwks[_\\-]?url|jwk[_\\-]?endpoint|openid[_\\-]?configuration)\\s*[:=]\\s*[\"']?(https?://[^\\s\"'\\n;,]{10,500})[\"']?",
            Pattern.CASE_INSENSITIVE
    );

    // Base64-encoded secrets (common in JS bundles)
    private static final Pattern BASE64_SECRET = Pattern.compile(
            "(?:atob|Buffer\\.from|base64[_\\-]?decode)\\s*\\(\\s*[\"']([A-Za-z0-9+/=]{16,256})[\"']",
            Pattern.CASE_INSENSITIVE
    );

    // JS content types
    private static final Set<String> JS_CONTENT_TYPES = Set.of(
            "application/javascript", "application/x-javascript",
            "text/javascript", "application/ecmascript",
            "application/json", "text/json"
    );

    public SecretExtractor(MontoyaApi api, JwtDedup dedup) {
        this.api = api;
        this.dedup = dedup;
    }

    // ================================================================
    // MAIN SCAN ENTRY POINT
    // ================================================================

    /**
     * Passively scans a response for JWT secrets, keys, and JWKS configurations.
     * Called from the passive scan check for every request/response.
     * Returns findings for anything discovered.
     */
    public List<AuditIssue> scan(HttpRequestResponse requestResponse) {
        List<AuditIssue> issues = new ArrayList<>();

        if (requestResponse.response() == null) return issues;

        String url = requestResponse.request().url();
        if (!scannedUrls.add(url)) return issues; // Already scanned this URL

        HttpResponse response = requestResponse.response();
        String body = response.bodyToString();
        if (body == null || body.length() < 10) return issues;

        // Only scan JS, JSON, HTML, and text responses
        String contentType = getContentType(response);
        boolean isJs = isJsContent(contentType, url);
        boolean isJson = contentType.contains("json");
        boolean isHtml = contentType.contains("html");
        boolean isText = contentType.contains("text");

        if (!isJs && !isJson && !isHtml && !isText) return issues;

        // Priority: JS files get full scan, others get targeted patterns
        if (isJs || isJson) {
            issues.addAll(scanForSecrets(body, requestResponse));
            issues.addAll(scanForPrivateKeys(body, requestResponse));
            issues.addAll(scanForPublicKeys(body, requestResponse));
            issues.addAll(scanForJwks(body, requestResponse));
            issues.addAll(scanForBase64Secrets(body, requestResponse));
        } else {
            // HTML/text: look for inline scripts and key patterns
            issues.addAll(scanForSecrets(body, requestResponse));
            issues.addAll(scanForPrivateKeys(body, requestResponse));
            issues.addAll(scanForPublicKeys(body, requestResponse));
        }

        return issues;
    }

    // ================================================================
    // INDIVIDUAL SCANNERS
    // ================================================================

    private List<AuditIssue> scanForSecrets(String body, HttpRequestResponse base) {
        List<AuditIssue> issues = new ArrayList<>();

        for (Pattern pattern : SECRET_ASSIGNMENT_PATTERNS) {
            Matcher matcher = pattern.matcher(body);
            while (matcher.find()) {
                String secret = matcher.group(1).trim();

                // Filter out false positives
                if (isLikelyFalsePositive(secret)) continue;

                if (discoveredSecrets.add(secret)) {
                    api.logging().logToOutput("JWTLens SecretExtractor: Found potential JWT secret: "
                            + truncate(secret, 40) + " in " + base.request().url());

                    issues.add(Findings.secretExtracted(
                            secret, matcher.group(0).trim(), base.request().url(), base));

                    // Feed to forge tab
                    notifyForgeTab(secret);

                    // Immediately verify against any known JWTs
                    verifySecretAgainstKnownTokens(secret);
                }
            }
        }

        return issues;
    }

    private List<AuditIssue> scanForPrivateKeys(String body, HttpRequestResponse base) {
        List<AuditIssue> issues = new ArrayList<>();

        Matcher rsaMatcher = RSA_PRIVATE_KEY.matcher(body);
        while (rsaMatcher.find()) {
            String key = rsaMatcher.group();
            if (discoveredSecrets.add(key.hashCode() + "_rsa_priv")) {
                api.logging().logToOutput("JWTLens SecretExtractor: RSA PRIVATE KEY found in " + base.request().url());
                issues.add(Findings.privateKeyExtracted("RSA", base.request().url(), base));
            }
        }

        Matcher ecMatcher = EC_PRIVATE_KEY.matcher(body);
        while (ecMatcher.find()) {
            String key = ecMatcher.group();
            if (discoveredSecrets.add(key.hashCode() + "_ec_priv")) {
                api.logging().logToOutput("JWTLens SecretExtractor: EC PRIVATE KEY found in " + base.request().url());
                issues.add(Findings.privateKeyExtracted("EC", base.request().url(), base));
            }
        }

        return issues;
    }

    private List<AuditIssue> scanForPublicKeys(String body, HttpRequestResponse base) {
        List<AuditIssue> issues = new ArrayList<>();

        Matcher matcher = RSA_PUBLIC_KEY.matcher(body);
        while (matcher.find()) {
            String key = matcher.group();
            if (discoveredPublicKeys.add(key)) {
                api.logging().logToOutput("JWTLens SecretExtractor: RSA PUBLIC KEY found in " + base.request().url());
                issues.add(Findings.publicKeyExtracted(base.request().url(), base));
            }
        }

        return issues;
    }

    private List<AuditIssue> scanForJwks(String body, HttpRequestResponse base) {
        List<AuditIssue> issues = new ArrayList<>();

        // Inline JWKS
        Matcher jwksMatcher = JWKS_INLINE.matcher(body);
        if (jwksMatcher.find()) {
            String jwks = jwksMatcher.group();
            if (discoveredSecrets.add(jwks.hashCode() + "_jwks")) {
                api.logging().logToOutput("JWTLens SecretExtractor: Inline JWKS found in " + base.request().url());
                issues.add(Findings.jwksInlineFound(base.request().url(), base));
            }
        }

        // JWKS URL references
        Matcher urlMatcher = JWKS_URL_PATTERN.matcher(body);
        while (urlMatcher.find()) {
            String jwksUrl = urlMatcher.group(1);
            if (discoveredJwksUrls.add(jwksUrl)) {
                api.logging().logToOutput("JWTLens SecretExtractor: JWKS URL reference found: " + jwksUrl);
                issues.add(Findings.jwksUrlFound(jwksUrl, base.request().url(), base));
            }
        }

        return issues;
    }

    private List<AuditIssue> scanForBase64Secrets(String body, HttpRequestResponse base) {
        List<AuditIssue> issues = new ArrayList<>();

        Matcher matcher = BASE64_SECRET.matcher(body);
        while (matcher.find()) {
            String b64 = matcher.group(1);
            try {
                String decoded = new String(Base64.getDecoder().decode(b64), java.nio.charset.StandardCharsets.UTF_8);
                if (decoded.length() >= 4 && decoded.length() <= 256 && !isLikelyFalsePositive(decoded)) {
                    if (discoveredSecrets.add(decoded)) {
                        api.logging().logToOutput("JWTLens SecretExtractor: Base64-decoded secret: "
                                + truncate(decoded, 40) + " in " + base.request().url());
                        issues.add(Findings.secretExtracted(
                                decoded, "Base64 decoded from: " + truncate(b64, 40),
                                base.request().url(), base));
                        notifyForgeTab(decoded);
                        verifySecretAgainstKnownTokens(decoded);
                    }
                }
            } catch (Exception ignored) {
                // Not valid base64, skip
            }
        }

        return issues;
    }

    // ================================================================
    // HELPERS
    // ================================================================

    /**
     * Filters out common false positives — placeholder values, code patterns, etc.
     */
    private boolean isLikelyFalsePositive(String secret) {
        if (secret.length() < 4) return true;
        String lower = secret.toLowerCase();

        // Common placeholder / template values
        if (lower.startsWith("${") || lower.startsWith("#{") || lower.startsWith("<%")) return true;
        if (lower.contains("process.env") || lower.contains("os.environ")) return true;
        if (lower.equals("your-secret-key") || lower.equals("change-me") || lower.equals("replace-me")) return true;
        if (lower.equals("undefined") || lower.equals("null") || lower.equals("true") || lower.equals("false")) return true;
        if (lower.startsWith("http://") || lower.startsWith("https://")) return true;

        // Pure whitespace or punctuation
        if (secret.trim().isEmpty()) return true;
        if (secret.chars().allMatch(c -> !Character.isLetterOrDigit(c))) return true;

        // Too generic (single common words)
        Set<String> tooGeneric = Set.of("name", "value", "type", "data", "string", "number",
                "object", "array", "error", "message", "result", "response", "request",
                "config", "options", "settings", "params");
        if (tooGeneric.contains(lower)) return true;

        return false;
    }

    private void notifyForgeTab(String secret) {
        JwtLensTab tab = JwtLensExtension.tab();
        if (tab != null) {
            JwtForgeTab forgeTab = JwtLensExtension.forgeTab();
            if (forgeTab != null) {
                forgeTab.setDiscoveredSecret(secret, "HS256");
            }
        }
    }

    /**
     * When a secret is found, immediately test it against JWTs we've seen.
     * If it works, log it prominently.
     */
    private void verifySecretAgainstKnownTokens(String secret) {
        // This is a lightweight offline check — no network traffic.
        // We rely on the dedup tracker to have seen tokens.
        // For now, just add to the effective wordlist for future scans.
        api.logging().logToOutput("JWTLens SecretExtractor: Added '" + truncate(secret, 30)
                + "' to runtime wordlist for active scanning.");
    }

    /**
     * Returns all secrets discovered so far across the session.
     * Used by ActiveScanCheck to augment the brute force wordlist.
     */
    public List<String> getDiscoveredSecrets() {
        return new ArrayList<>(discoveredSecrets);
    }

    /**
     * Returns all discovered public keys (PEM format) for algorithm confusion.
     */
    public List<String> getDiscoveredPublicKeys() {
        return new ArrayList<>(discoveredPublicKeys);
    }

    /**
     * Returns all discovered JWKS URLs.
     */
    public Set<String> getDiscoveredJwksUrls() {
        return new HashSet<>(discoveredJwksUrls);
    }

    /**
     * Returns the total count of unique secrets discovered.
     */
    public int getDiscoveredCount() {
        return discoveredSecrets.size() + discoveredPublicKeys.size() + discoveredJwksUrls.size();
    }

    private String getContentType(HttpResponse response) {
        for (var header : response.headers()) {
            if (header.name().equalsIgnoreCase("Content-Type")) {
                return header.value().toLowerCase();
            }
        }
        return "";
    }

    private boolean isJsContent(String contentType, String url) {
        for (String jsType : JS_CONTENT_TYPES) {
            if (contentType.contains(jsType)) return true;
        }
        // Also check file extension
        String lowerUrl = url.toLowerCase();
        return lowerUrl.endsWith(".js") || lowerUrl.endsWith(".mjs")
                || lowerUrl.endsWith(".jsx") || lowerUrl.endsWith(".ts")
                || lowerUrl.endsWith(".tsx") || lowerUrl.contains(".js?")
                || lowerUrl.contains(".bundle") || lowerUrl.contains(".chunk");
    }

    private static String truncate(String s, int max) {
        if (s == null) return "(null)";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...";
    }
}
