package com.jwtlens;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Cryptographic utility methods for JWT signing and verification.
 */
public class CryptoUtils {

    private static final Base64.Encoder B64_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static KeyPair cachedRsaKeyPair;

    // ======================== HMAC ========================

    public static String signHmac(String algorithm, String signingInput, String secret) {
        return signHmacBytes(algorithm, signingInput, secret.getBytes(StandardCharsets.UTF_8));
    }

    public static String signHmacBytes(String algorithm, String signingInput, byte[] keyBytes) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            SecretKeySpec keySpec = new SecretKeySpec(
                    keyBytes.length == 0 ? new byte[1] : keyBytes,
                    algorithm
            );
            mac.init(keySpec);
            byte[] sig = mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
            return B64_ENCODER.encodeToString(sig);
        } catch (Exception e) {
            throw new RuntimeException("HMAC signing failed: " + e.getMessage(), e);
        }
    }

    /**
     * Special handling for truly empty key (used for empty password check).
     */
    public static String signHmacEmptyKey(String signingInput) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(new byte[]{0}, "HmacSHA256");
            mac.init(keySpec);
            byte[] sig = mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
            return B64_ENCODER.encodeToString(sig);
        } catch (Exception e) {
            throw new RuntimeException("HMAC empty key signing failed: " + e.getMessage(), e);
        }
    }

    // ======================== RSA ========================

    public static synchronized KeyPair getOrGenerateRsaKeyPair() {
        if (cachedRsaKeyPair == null) {
            try {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
                cachedRsaKeyPair = gen.generateKeyPair();
            } catch (Exception e) {
                throw new RuntimeException("RSA key generation failed: " + e.getMessage(), e);
            }
        }
        return cachedRsaKeyPair;
    }

    public static String signRsa(String algorithm, String signingInput, PrivateKey privateKey) {
        try {
            Signature signer = Signature.getInstance(algorithm);
            signer.initSign(privateKey);
            signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return B64_ENCODER.encodeToString(signer.sign());
        } catch (Exception e) {
            throw new RuntimeException("RSA signing failed: " + e.getMessage(), e);
        }
    }

    /**
     * Encodes an RSA public key as a JWK (JSON Web Key) map representation.
     */
    public static String rsaPublicKeyToJwk(RSAPublicKey publicKey, String kid) {
        String n = B64_ENCODER.encodeToString(publicKey.getModulus().toByteArray());
        String e = B64_ENCODER.encodeToString(publicKey.getPublicExponent().toByteArray());
        return String.format(
                "{\"kty\":\"RSA\",\"kid\":\"%s\",\"use\":\"sig\",\"n\":\"%s\",\"e\":\"%s\"}",
                kid, n, e
        );
    }

    /**
     * Encodes an RSA public key as PEM format.
     */
    public static String rsaPublicKeyToPem(RSAPublicKey publicKey) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----";
    }

    /**
     * Get the raw bytes of an RSA public key (DER encoded) for use as HMAC key in alg confusion.
     */
    public static byte[] rsaPublicKeyToBytes(RSAPublicKey publicKey) {
        return publicKey.getEncoded();
    }

    /**
     * Get the raw bytes of an RSA public key in PEM format for alg confusion.
     */
    public static byte[] rsaPublicKeyToPemBytes(RSAPublicKey publicKey) {
        return rsaPublicKeyToPem(publicKey).getBytes(StandardCharsets.UTF_8);
    }

    // ======================== JWKS HELPERS ========================

    /**
     * Creates a JWKS JSON string containing a single RSA public key.
     */
    public static String createJwks(RSAPublicKey publicKey, String kid) {
        return "{\"keys\":[" + rsaPublicKeyToJwk(publicKey, kid) + "]}";
    }

    // ======================== X509 HELPERS ========================

    /**
     * Generates a self-signed X.509 certificate and returns the key pair.
     * The certificate is stored as a Base64 DER string for x5c embedding.
     */
    public static SelfSignedCert generateSelfSignedCert() {
        try {
            KeyPair keyPair = getOrGenerateRsaKeyPair();

            // We create a minimal self-signed cert representation
            // For full x5c support, a proper X509 cert would be needed
            // This provides the Base64 DER of the public key as a stand-in
            String certDer = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            return new SelfSignedCert(keyPair, certDer);
        } catch (Exception e) {
            throw new RuntimeException("Self-signed cert generation failed: " + e.getMessage(), e);
        }
    }

    public static class SelfSignedCert {
        public final KeyPair keyPair;
        public final String certBase64Der;

        public SelfSignedCert(KeyPair keyPair, String certBase64Der) {
            this.keyPair = keyPair;
            this.certBase64Der = certBase64Der;
        }
    }

    // ======================== VERIFICATION HELPERS ========================

    /**
     * Verifies HMAC signature locally (used for brute force).
     */
    public static boolean verifyHmac(String algorithm, String signingInput, String secret, String expectedSig) {
        try {
            String computed = signHmac(algorithm, signingInput, secret);
            return computed.equals(expectedSig);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Determines the HMAC algorithm name from JWT alg header value.
     */
    public static String jwtAlgToHmacAlgorithm(String jwtAlg) {
        return switch (jwtAlg) {
            case "HS256" -> "HmacSHA256";
            case "HS384" -> "HmacSHA384";
            case "HS512" -> "HmacSHA512";
            default -> "HmacSHA256";
        };
    }
}
