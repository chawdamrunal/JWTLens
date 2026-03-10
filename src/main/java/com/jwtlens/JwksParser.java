package com.jwtlens;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

/**
 * Parses JWKS (JSON Web Key Set) responses and extracts RSA public keys
 * for use in algorithm confusion attacks.
 *
 * This properly reconstructs RSAPublicKey objects from JWK n/e values,
 * which is required for the RS256→HS256 algorithm confusion attack to
 * work against real targets.
 */
public class JwksParser {

    private static final Gson GSON = new Gson();
    private static final Base64.Decoder B64_URL_DECODER = Base64.getUrlDecoder();
    private static final Base64.Decoder B64_STD_DECODER = Base64.getDecoder();

    /**
     * A parsed JWK key with its metadata.
     */
    public static class JwkKey {
        public final String kid;
        public final String kty;
        public final String alg;
        public final String use;
        public final RSAPublicKey publicKey;

        public JwkKey(String kid, String kty, String alg, String use, RSAPublicKey publicKey) {
            this.kid = kid;
            this.kty = kty;
            this.alg = alg;
            this.use = use;
            this.publicKey = publicKey;
        }

        @Override
        public String toString() {
            return "JwkKey{kid='" + kid + "', kty='" + kty + "', alg='" + alg
                    + "', bits=" + publicKey.getModulus().bitLength() + "}";
        }
    }

    /**
     * Parses a JWKS JSON string and extracts all RSA public keys.
     * Handles both direct JWKS {"keys":[...]} and OpenID Configuration
     * responses that contain a "jwks_uri" field.
     *
     * @param jwksJson the raw JSON response body
     * @return list of parsed RSA public keys, empty if none found
     */
    public static List<JwkKey> parseJwks(String jwksJson) {
        List<JwkKey> keys = new ArrayList<>();

        if (jwksJson == null || jwksJson.isBlank()) return keys;

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> root = GSON.fromJson(jwksJson,
                    new TypeToken<LinkedHashMap<String, Object>>(){}.getType());

            if (root == null) return keys;

            // Direct JWKS: {"keys": [...]}
            Object keysObj = root.get("keys");
            if (keysObj instanceof List<?> keysList) {
                for (Object keyObj : keysList) {
                    if (keyObj instanceof Map<?, ?> keyMap) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> jwk = (Map<String, Object>) keyMap;
                        JwkKey parsed = parseRsaJwk(jwk);
                        if (parsed != null) {
                            keys.add(parsed);
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Not valid JWKS JSON — fall through
        }

        return keys;
    }

    /**
     * Parses a single JWK map into an RSAPublicKey.
     * Returns null if the key is not RSA or cannot be parsed.
     */
    public static JwkKey parseRsaJwk(Map<String, Object> jwk) {
        try {
            String kty = getStr(jwk, "kty");
            if (!"RSA".equals(kty)) return null;

            String nB64 = getStr(jwk, "n");
            String eB64 = getStr(jwk, "e");
            if (nB64 == null || eB64 == null) return null;

            // Decode n and e from Base64url
            BigInteger modulus = base64UrlToBigInteger(nB64);
            BigInteger exponent = base64UrlToBigInteger(eB64);

            // Reconstruct the RSA public key
            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(spec);

            String kid = getStr(jwk, "kid");
            String alg = getStr(jwk, "alg");
            String use = getStr(jwk, "use");

            return new JwkKey(kid, kty, alg, use, pubKey);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extracts the "jwks_uri" from an OpenID Configuration response.
     * Returns null if not found.
     */
    public static String extractJwksUri(String openidConfigJson) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> config = GSON.fromJson(openidConfigJson,
                    new TypeToken<LinkedHashMap<String, Object>>(){}.getType());
            if (config != null && config.containsKey("jwks_uri")) {
                return String.valueOf(config.get("jwks_uri"));
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * Finds the best matching key for algorithm confusion.
     * Prefers: key matching the token's kid > key with "sig" use > first key.
     */
    public static JwkKey findBestKey(List<JwkKey> keys, String tokenKid) {
        if (keys.isEmpty()) return null;

        // First try: exact kid match
        if (tokenKid != null) {
            for (JwkKey key : keys) {
                if (tokenKid.equals(key.kid)) return key;
            }
        }

        // Second try: key with "sig" use
        for (JwkKey key : keys) {
            if ("sig".equals(key.use)) return key;
        }

        // Third try: key with RS256/RS384/RS512 alg
        for (JwkKey key : keys) {
            if (key.alg != null && key.alg.startsWith("RS")) return key;
        }

        // Fallback: first key
        return keys.get(0);
    }

    // ================================================================
    // HELPERS
    // ================================================================

    private static BigInteger base64UrlToBigInteger(String b64url) {
        // Handle both URL-safe and standard Base64
        byte[] bytes;
        try {
            bytes = B64_URL_DECODER.decode(padBase64(b64url));
        } catch (Exception e) {
            bytes = B64_STD_DECODER.decode(padBase64(b64url));
        }
        // Always positive (unsigned)
        return new BigInteger(1, bytes);
    }

    private static String padBase64(String input) {
        int padding = (4 - input.length() % 4) % 4;
        return input + "=".repeat(padding);
    }

    private static String getStr(Map<String, Object> map, String key) {
        Object val = map.get(key);
        return val instanceof String ? (String) val : null;
    }
}
