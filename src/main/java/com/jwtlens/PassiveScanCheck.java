package com.jwtlens;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Performs all passive JWT security checks.
 * Analyzes requests and responses without sending any additional traffic.
 * Runs P01 through P23 from the JWTLens checklist.
 */
public class PassiveScanCheck {

    private static final Pattern SENSITIVE_EMAIL = Pattern.compile("[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}");
    private static final Pattern SENSITIVE_PHONE = Pattern.compile("\\+?\\d[\\d\\-\\s]{8,}\\d");
    private static final Pattern SENSITIVE_SSN = Pattern.compile("\\d{3}[\\-\\s]?\\d{2}[\\-\\s]?\\d{4}");
    private static final Pattern SENSITIVE_CC = Pattern.compile("\\d{4}[\\-\\s]?\\d{4}[\\-\\s]?\\d{4}[\\-\\s]?\\d{4}");

    private static final Set<String> SENSITIVE_KEYS = Set.of(
            "password", "passwd", "pass", "pwd", "secret", "token", "api_key",
            "apikey", "api-key", "private_key", "privatekey", "ssn",
            "social_security", "credit_card", "creditcard", "card_number",
            "cvv", "pin", "bank_account", "routing_number"
    );

    private static final long LONG_LIFETIME_THRESHOLD_SECONDS = 86400; // 24 hours

    private final MontoyaApi api;
    private final JwtDedup dedup;

    public PassiveScanCheck(MontoyaApi api, JwtDedup dedup) {
        this.api = api;
        this.dedup = dedup;
    }

    /**
     * Run all passive checks on a request/response pair.
     * Returns list of findings.
     */
    public List<AuditIssue> check(HttpRequestResponse requestResponse) {
        List<AuditIssue> issues = new ArrayList<>();

        String host = requestResponse.request().httpService().host();
        String requestStr = requestResponse.request().toString();

        // Extract JWTs from request
        List<JwtToken> requestTokens = JwtToken.extractFromString(requestStr);

        // Extract JWTs from response (if present)
        List<JwtToken> responseTokens = new ArrayList<>();
        if (requestResponse.response() != null) {
            responseTokens = JwtToken.extractFromString(requestResponse.response().toString());
        }

        // Deduplicated set of tokens to check
        Set<String> checkedSignatures = new HashSet<>();

        // Check request tokens
        for (JwtToken jwt : requestTokens) {
            if (dedup.isDuplicatePassive(host, jwt)) continue;
            if (!checkedSignatures.add(jwt.getSignature())) continue;

            // P01: JWT Detected
            issues.add(Findings.p01_jwtDetected(jwt, requestResponse));

            // Run all passive checks on this token
            issues.addAll(runTokenChecks(jwt, requestResponse));
        }

        // Check for JWTs in URL query parameters (P02)
        issues.addAll(checkJwtInUrl(requestResponse, requestTokens));

        // Check cookie flags (P04, P05, P06)
        if (requestResponse.response() != null) {
            issues.addAll(checkCookieFlags(requestResponse));
        }

        // Check response tokens (P14)
        if (requestResponse.response() != null) {
            for (JwtToken jwt : responseTokens) {
                if (dedup.isDuplicatePassive(host, jwt)) continue;
                if (!checkedSignatures.add(jwt.getSignature())) continue;
                issues.add(Findings.p14_jwtInResponseBody(jwt, requestResponse));
                issues.addAll(runTokenChecks(jwt, requestResponse));
            }
        }

        return issues;
    }

    /**
     * Runs all token-level passive checks on a single JWT.
     */
    private List<AuditIssue> runTokenChecks(JwtToken jwt, HttpRequestResponse base) {
        List<AuditIssue> issues = new ArrayList<>();

        // P07: Missing expiry
        if (!jwt.hasExpiry()) {
            issues.add(Findings.p07_missingExpiry(jwt, base));
        }

        // P08: Excessive lifetime
        jwt.getLifetimeSeconds().ifPresent(lifetime -> {
            if (lifetime > LONG_LIFETIME_THRESHOLD_SECONDS) {
                long hours = lifetime / 3600;
                issues.add(Findings.p08_longLifetime(jwt, hours, base));
            }
        });

        // P09: Sensitive data in payload
        String sensitiveFields = checkSensitivePayload(jwt);
        if (!sensitiveFields.isEmpty()) {
            issues.add(Findings.p09_sensitiveData(jwt, sensitiveFields, base));
        }

        // P10: Expired token in use
        if (jwt.isExpired()) {
            issues.add(Findings.p10_expiredInUse(jwt, base));
        }

        // P11: Missing issuer
        if (!jwt.hasClaim("iss")) {
            issues.add(Findings.p11_missingIssuer(jwt, base));
        }

        // P12: Missing audience
        if (!jwt.hasClaim("aud")) {
            issues.add(Findings.p12_missingAudience(jwt, base));
        }

        // P13: Symmetric algorithm info
        if (jwt.hasSymmetricAlg()) {
            issues.add(Findings.p13_symmetricAlg(jwt, base));
        }

        // P15: kid present
        if (jwt.hasHeader("kid")) {
            issues.add(Findings.p15_kidPresent(jwt, base));
        }

        // P16: jku present
        if (jwt.hasHeader("jku")) {
            issues.add(Findings.p16_jkuPresent(jwt, base));
        }

        // P17: x5u present
        if (jwt.hasHeader("x5u")) {
            issues.add(Findings.p17_x5uPresent(jwt, base));
        }

        // P18: x5c present
        if (jwt.hasHeader("x5c")) {
            issues.add(Findings.p18_x5cPresent(jwt, base));
        }

        // P19: jwk present
        if (jwt.hasHeader("jwk")) {
            issues.add(Findings.p19_jwkPresent(jwt, base));
        }

        // P20: Nested JWT
        for (Map.Entry<String, Object> entry : jwt.getPayload().entrySet()) {
            if (entry.getValue() instanceof String strVal) {
                if (JwtToken.JWT_PATTERN.matcher(strVal).find()) {
                    issues.add(Findings.p20_nestedJwt(jwt, entry.getKey(), base));
                    break;
                }
            }
        }

        // P22: Missing nbf
        if (!jwt.hasClaim("nbf")) {
            issues.add(Findings.p22_missingNbf(jwt, base));
        }

        // P23: Missing jti
        if (!jwt.hasClaim("jti")) {
            issues.add(Findings.p23_missingJti(jwt, base));
        }

        return issues;
    }

    /**
     * P02: Check if JWT appears in URL query parameters.
     */
    private List<AuditIssue> checkJwtInUrl(HttpRequestResponse base, List<JwtToken> requestTokens) {
        List<AuditIssue> issues = new ArrayList<>();
        String url = base.request().url();

        // Check query string
        String query = "";
        int qIdx = url.indexOf('?');
        if (qIdx >= 0) {
            query = url.substring(qIdx + 1);
        }

        if (!query.isEmpty()) {
            for (JwtToken jwt : requestTokens) {
                if (query.contains(jwt.getEncodedHeader())) {
                    // Find the parameter name
                    String paramName = "unknown";
                    for (HttpParameter param : base.request().parameters()) {
                        if (param.type() == HttpParameterType.URL) {
                            if (JwtToken.JWT_PATTERN.matcher(param.value()).find()) {
                                paramName = param.name();
                                break;
                            }
                        }
                    }
                    issues.add(Findings.p02_jwtInUrl(jwt, paramName, base));
                    break;
                }
            }
        }

        // Check fragment (if visible in URL)
        int hashIdx = url.indexOf('#');
        if (hashIdx >= 0) {
            String fragment = url.substring(hashIdx + 1);
            for (JwtToken jwt : requestTokens) {
                if (fragment.contains(jwt.getEncodedHeader())) {
                    issues.add(Findings.p03_jwtInFragment(jwt, base));
                    break;
                }
            }
        }

        return issues;
    }

    /**
     * P04, P05, P06: Check Set-Cookie headers for JWT cookies missing security flags.
     * Only flags when we actually have the Set-Cookie header in the response.
     * Does not flag missing Secure flag on HTTPS connections (already secure transport).
     */
    private List<AuditIssue> checkCookieFlags(HttpRequestResponse base) {
        List<AuditIssue> issues = new ArrayList<>();
        HttpResponse response = base.response();
        if (response == null) return issues;

        boolean isHttps = base.request().httpService().secure();

        // Only check Set-Cookie headers from the response, not request cookies.
        // If we don't see Set-Cookie, we can't know the flags, so we don't guess.
        for (var header : response.headers()) {
            if (!header.name().equalsIgnoreCase("Set-Cookie")) continue;

            String setCookieValue = header.value();

            // Check if this cookie value contains a JWT
            int eqIdx = setCookieValue.indexOf('=');
            if (eqIdx <= 0) continue;

            String cookieName = setCookieValue.substring(0, eqIdx).trim();
            // Get the cookie value (up to first ; or end)
            String rest = setCookieValue.substring(eqIdx + 1);
            int semiIdx = rest.indexOf(';');
            String cookieValue = semiIdx >= 0 ? rest.substring(0, semiIdx).trim() : rest.trim();

            if (!JwtToken.JWT_PATTERN.matcher(cookieValue).find()) continue;

            // We have a Set-Cookie with a JWT. Now check the flags.
            String lowerHeader = setCookieValue.toLowerCase();

            // Only flag cookie security issues on HTTP (not HTTPS).
            // On HTTPS these flags still matter in theory, but flagging every
            // HTTPS domain produces noise. Report only when truly insecure transport.
            if (!isHttps) {
                if (!lowerHeader.contains("httponly")) {
                    issues.add(Findings.p04_cookieMissingHttpOnly(cookieName, base));
                }
                if (!lowerHeader.contains("secure")) {
                    issues.add(Findings.p05_cookieMissingSecure(cookieName, base));
                }
                if (!lowerHeader.contains("samesite")) {
                    issues.add(Findings.p06_cookieMissingSameSite(cookieName, base));
                }
            }
        }

        return issues;
    }

    /**
     * P09: Check JWT payload for sensitive data patterns.
     */
    private String checkSensitivePayload(JwtToken jwt) {
        List<String> found = new ArrayList<>();
        Map<String, Object> payload = jwt.getPayload();

        for (Map.Entry<String, Object> entry : payload.entrySet()) {
            String key = entry.getKey().toLowerCase();

            // Check key names
            if (SENSITIVE_KEYS.contains(key)) {
                found.add(entry.getKey() + " (sensitive key name)");
                continue;
            }

            // Check values
            if (entry.getValue() instanceof String strVal) {
                if (SENSITIVE_EMAIL.matcher(strVal).find() && !key.equals("email") && !key.equals("iss") && !key.equals("sub")) {
                    // Only flag email if it's not in expected fields
                    // Actually, email in JWT is itself a concern, so flag it
                    if (!key.equals("email")) {
                        found.add(entry.getKey() + " (contains email address)");
                    }
                }
                if (SENSITIVE_SSN.matcher(strVal).matches()) {
                    found.add(entry.getKey() + " (possible SSN pattern)");
                }
                if (SENSITIVE_CC.matcher(strVal).matches()) {
                    found.add(entry.getKey() + " (possible credit card number)");
                }
                if (SENSITIVE_PHONE.matcher(strVal).matches() && strVal.length() >= 10) {
                    found.add(entry.getKey() + " (possible phone number)");
                }
            }
        }

        return String.join(", ", found);
    }
}
