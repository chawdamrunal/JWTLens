package com.jwtlens;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.List;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.*;
import static burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.*;

/**
 * All JWTLens finding definitions with human tone descriptions.
 * Each method returns a Burp AuditIssue with proper severity, confidence, detail, and remediation.
 */
public class Findings {

    private static List<HttpRequestResponse> reqList(HttpRequestResponse base, HttpRequestResponse... checks) {
        if (checks.length == 0) return List.of(base);
        var list = new java.util.ArrayList<HttpRequestResponse>();
        list.add(base);
        list.addAll(List.of(checks));
        return list;
    }

    // ============================================================
    // PASSIVE FINDINGS
    // ============================================================

    public static AuditIssue p01_jwtDetected(JwtToken jwt, HttpRequestResponse base) {
        return auditIssue(
                "JWT Token Detected in HTTP Traffic",
                "<p>A JSON Web Token was identified in this HTTP request. The token is being transmitted between the client and server as part of the authentication or authorization flow.</p>"
                        + jwt.getSummary()
                        + "<p>Algorithm: <b>" + jwt.getAlg().orElse("unknown") + "</b></p>",
                "No immediate action is required. Review the additional findings from JWTLens to determine whether the JWT implementation follows security best practices.",
                base.request().url(),
                INFORMATION, CERTAIN, null, null, INFORMATION,
                reqList(base));
    }

    public static AuditIssue p02_jwtInUrl(JwtToken jwt, String paramName, HttpRequestResponse base) {
        return auditIssue(
                "JWT Token Exposed in URL Query Parameter",
                "<p>The application is transmitting a JWT token as part of the URL query string. This is a significant security concern because URLs are commonly logged by web servers, proxy servers, browser history, and analytics tools. The token was found in the parameter <b>" + paramName + "</b> of this request.</p>"
                        + "<p>An attacker who gains access to server logs, proxy logs, browser history, or Referer headers sent to third party domains can steal the JWT and impersonate the victim. Since JWTs are often long lived, a single leaked token can provide persistent unauthorized access to the user's account and data.</p>",
                "Transmit JWT tokens using the HTTP Authorization header (Bearer scheme) or within secure, HttpOnly cookies. Never include authentication tokens in URL query parameters or URL fragments. If URL based transmission is absolutely necessary for a specific use case, ensure the tokens are extremely short lived (under 60 seconds) and single use.",
                base.request().url(),
                MEDIUM, CERTAIN, null, null, MEDIUM,
                reqList(base));
    }

    public static AuditIssue p03_jwtInFragment(JwtToken jwt, HttpRequestResponse base) {
        return auditIssue(
                "JWT Token Exposed in URL Fragment",
                "<p>A JWT token was found in the URL fragment (the portion after the # symbol). While URL fragments are not sent to the server in HTTP requests, they are accessible to client side JavaScript, stored in browser history, and can be leaked through the Referer header in some browser implementations.</p>"
                        + "<p>Malicious JavaScript running on the page (through XSS or a compromised third party script) can read the URL fragment and exfiltrate the JWT token, allowing an attacker to hijack the user's session.</p>",
                "Avoid placing JWT tokens in URL fragments. Use the Authorization header or secure cookies for token transmission. If an OAuth or OpenID Connect implicit flow is producing this behavior, consider migrating to the authorization code flow with PKCE.",
                base.request().url(),
                MEDIUM, CERTAIN, null, null, MEDIUM,
                reqList(base));
    }

    public static AuditIssue p04_cookieMissingHttpOnly(String cookieName, HttpRequestResponse base) {
        return auditIssue(
                "JWT Cookie Missing HttpOnly Flag",
                "<p>The JWT token is stored in a cookie named <b>" + cookieName + "</b> that does not have the HttpOnly flag set. Without this flag, the cookie is accessible to JavaScript running in the browser through <code>document.cookie</code>. This means any cross site scripting (XSS) vulnerability on the application would allow an attacker to steal the JWT.</p>"
                        + "<p>If the application has any XSS vulnerability, an attacker can inject JavaScript that reads the JWT cookie and sends it to an attacker controlled server, fully impersonating the victim user.</p>",
                "Set the HttpOnly flag on all cookies that contain JWT tokens. This prevents JavaScript from accessing the cookie value, which significantly reduces the impact of XSS attacks.",
                base.request().url(),
                MEDIUM, CERTAIN, null, null, MEDIUM,
                reqList(base));
    }

    public static AuditIssue p05_cookieMissingSecure(String cookieName, HttpRequestResponse base) {
        return auditIssue(
                "JWT Cookie Missing Secure Flag",
                "<p>The JWT token is stored in a cookie named <b>" + cookieName + "</b> that does not have the Secure flag set. Without this flag, the browser will send the cookie over unencrypted HTTP connections, exposing the JWT to network level attackers.</p>"
                        + "<p>An attacker performing a man in the middle attack on any unencrypted connection (such as on public WiFi) can intercept the JWT cookie in plaintext and impersonate the victim.</p>",
                "Set the Secure flag on all cookies containing JWT tokens. This ensures the cookie is only transmitted over HTTPS connections and cannot be intercepted by network level attackers.",
                base.request().url(),
                MEDIUM, CERTAIN, null, null, MEDIUM,
                reqList(base));
    }

    public static AuditIssue p06_cookieMissingSameSite(String cookieName, HttpRequestResponse base) {
        return auditIssue(
                "JWT Cookie Missing SameSite Attribute",
                "<p>The JWT token is stored in a cookie named <b>" + cookieName + "</b> that does not have the SameSite attribute set. Without this attribute, the browser will include the cookie in cross site requests, which can be exploited through CSRF attacks.</p>",
                "Set the SameSite attribute to Strict or Lax on cookies containing JWT tokens.",
                base.request().url(),
                LOW, CERTAIN, null, null, LOW,
                reqList(base));
    }

    public static AuditIssue p07_missingExpiry(JwtToken jwt, HttpRequestResponse base) {
        return auditIssue(
                "JWT Token Missing Expiration Claim",
                "<p>The JWT token does not contain an <code>exp</code> (expiration) claim in its payload. This means the token is valid indefinitely and will never expire on its own. Once issued, this token can be used forever unless the server implements additional revocation mechanisms.</p>"
                        + "<p>If this token is ever compromised through any means (log files, browser history, XSS, man in the middle, or a data breach), the attacker has permanent access to the victim's account.</p>"
                        + jwt.getSummary(),
                "Always include an <code>exp</code> claim in JWT tokens. For access tokens, a short expiration of 15 to 30 minutes is recommended. For refresh tokens, a longer expiration of hours or days may be acceptable. Implement server side token revocation as an additional layer of defense.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base));
    }

    public static AuditIssue p08_longLifetime(JwtToken jwt, long lifetimeHours, HttpRequestResponse base) {
        return auditIssue(
                "JWT Token Has Excessive Lifetime",
                "<p>The JWT token has an expiration time that is more than <b>" + lifetimeHours + " hours</b> from the time it was issued. Long lived tokens increase the window of opportunity for an attacker if the token is compromised.</p>"
                        + "<p>A stolen token remains valid for an extended period, giving attackers a large window to exploit it.</p>"
                        + jwt.getSummary(),
                "Reduce the lifetime of JWT access tokens to 15 to 30 minutes. Use refresh tokens with a longer (but still bounded) lifetime to maintain user sessions.",
                base.request().url(),
                LOW, FIRM, null, null, LOW,
                reqList(base));
    }

    public static AuditIssue p09_sensitiveData(JwtToken jwt, String sensitiveFields, HttpRequestResponse base) {
        return auditIssue(
                "Sensitive Data Exposed in JWT Payload",
                "<p>The JWT payload contains data that appears to be sensitive. The following potentially sensitive fields were identified: <b>" + sensitiveFields + "</b>.</p>"
                        + "<p>JWT tokens are only Base64 encoded, not encrypted. Anyone who intercepts or accesses the token can trivially decode the payload and read all claims in plaintext. This may violate privacy regulations such as GDPR, HIPAA, or PCI DSS.</p>"
                        + jwt.getSummary(),
                "Keep JWT payloads minimal. Only include claims that are necessary for authorization decisions. Never include passwords, credit card numbers, social security numbers, or other highly sensitive data in JWT claims. If sensitive data must be transmitted, use JWE (JSON Web Encryption).",
                base.request().url(),
                MEDIUM, TENTATIVE, null, null, MEDIUM,
                reqList(base));
    }

    public static AuditIssue p10_expiredInUse(JwtToken jwt, HttpRequestResponse base) {
        return auditIssue(
                "Expired JWT Token Still in Use",
                "<p>The JWT token observed in this request has already expired. The <code>exp</code> claim indicates the token's validity period has passed. The server may or may not be validating the expiration. An active check will be performed separately to determine if the server actually accepts this expired token.</p>"
                        + jwt.getSummary(),
                "Ensure the server validates the <code>exp</code> claim on every request and rejects tokens that have expired.",
                base.request().url(),
                INFORMATION, CERTAIN, null, null, INFORMATION,
                reqList(base));
    }

    public static AuditIssue p11_missingIssuer(JwtToken jwt, HttpRequestResponse base) {
        return auditIssue(
                "JWT Token Missing Issuer (iss) Claim",
                "<p>The JWT token does not contain an <code>iss</code> (issuer) claim. Without it, the receiving service cannot verify that the token came from a trusted source, making it easier for an attacker to use tokens generated by unauthorized parties.</p>",
                "Include an <code>iss</code> claim in all JWT tokens that identifies the issuing authority. Validate the <code>iss</code> claim against a list of trusted issuers.",
                base.request().url(),
                LOW, CERTAIN, null, null, LOW,
                reqList(base));
    }

    public static AuditIssue p12_missingAudience(JwtToken jwt, HttpRequestResponse base) {
        return auditIssue(
                "JWT Token Missing Audience (aud) Claim",
                "<p>The JWT token does not contain an <code>aud</code> (audience) claim. Without it, a token issued for one service could potentially be replayed against a completely different service that uses the same signing key.</p>",
                "Include an <code>aud</code> claim in all JWT tokens. Each receiving service should validate that its own identifier is present in the <code>aud</code> claim.",
                base.request().url(),
                LOW, CERTAIN, null, null, LOW,
                reqList(base));
    }

    public static AuditIssue p13_symmetricAlg(JwtToken jwt, HttpRequestResponse base) {
        return auditIssue(
                "JWT Signed with Symmetric Algorithm",
                "<p>The JWT is signed using the symmetric algorithm <b>" + jwt.getAlg().orElse("unknown") + "</b>. Symmetric algorithms use the same secret key for both signing and verification, which increases the attack surface for key compromise.</p>"
                        + "<p>You can attempt to crack this token using: <pre>hashcat -a 0 -m 16500 " + jwt.encode() + " /path/to/wordlist.txt</pre></p>",
                "If using symmetric algorithms, ensure the secret key is at least 256 bits long and generated using a cryptographically secure random number generator. Consider migrating to asymmetric algorithms (RS256, ES256).",
                base.request().url(),
                INFORMATION, CERTAIN, null, null, INFORMATION,
                reqList(base));
    }

    public static AuditIssue p14_jwtInResponseBody(JwtToken jwt, HttpRequestResponse base) {
        return auditIssue(
                "JWT Token Leaked in HTTP Response Body",
                "<p>A JWT token was found in the HTTP response body of this endpoint. Response body JWTs can be cached by browsers, CDNs, or intermediary proxies, and may appear in application logs.</p>"
                        + "<p>If the response is cached by a CDN or shared proxy, other users could receive the cached response containing someone else's JWT, leading to account takeover.</p>",
                "Ensure responses containing JWT tokens include appropriate cache control headers: <code>Cache-Control: no-store, no-cache, must-revalidate</code>. Consider whether the token needs to be in the response body at all.",
                base.request().url(),
                MEDIUM, FIRM, null, null, MEDIUM,
                reqList(base));
    }

    public static AuditIssue p15_kidPresent(JwtToken jwt, HttpRequestResponse base) {
        return auditIssue(
                "JWT Uses Key ID (kid) Header Parameter",
                "<p>The JWT header contains a <code>kid</code> (Key ID) parameter with value <b>" + jwt.getKid().orElse("") + "</b>. While this is a legitimate JWT feature, the kid parameter is a common injection point if the server uses its value in file system operations, database queries, or command execution without proper validation.</p>",
                "Validate the kid parameter against a strict allowlist of known key identifiers. Never use the kid value directly in file system paths, SQL queries, or shell commands.",
                base.request().url(),
                INFORMATION, CERTAIN, null, null, INFORMATION,
                reqList(base));
    }

    public static AuditIssue p16_jkuPresent(JwtToken jwt, HttpRequestResponse base) {
        return auditIssue(
                "JWT Uses JKU (JSON Web Key Set URL) Header Parameter",
                "<p>The JWT header contains a <code>jku</code> parameter pointing to <b>" + jwt.getJku().orElse("") + "</b>. This parameter specifies a URL where the server should fetch the public key set used to verify the token's signature. If the server trusts and follows this URL without proper validation, an attacker can point it to a malicious key set.</p>",
                "Never blindly trust the jku header value. Maintain a strict allowlist of trusted JWKS URLs and reject any token whose jku does not match. Alternatively, ignore the jku header entirely and configure the verification key set statically.",
                base.request().url(),
                LOW, CERTAIN, null, null, LOW,
                reqList(base));
    }

    public static AuditIssue p17_x5uPresent(JwtToken jwt, HttpRequestResponse base) {
        return auditIssue(
                "JWT Uses X5U (X.509 Certificate URL) Header Parameter",
                "<p>The JWT header contains an <code>x5u</code> parameter pointing to <b>" + jwt.getX5u().orElse("") + "</b>. This is a server side request forgery (SSRF) and key injection vector if not properly validated.</p>",
                "Do not trust the x5u header from incoming tokens. Use statically configured certificates for signature verification.",
                base.request().url(),
                LOW, CERTAIN, null, null, LOW,
                reqList(base));
    }

    public static AuditIssue p18_x5cPresent(JwtToken jwt, HttpRequestResponse base) {
        return auditIssue(
                "JWT Uses X5C (X.509 Certificate Chain) Header Parameter",
                "<p>The JWT header contains an <code>x5c</code> parameter with an embedded X.509 certificate chain. If the server extracts the public key from this embedded certificate and uses it to verify the signature without validating the certificate chain against trusted roots, an attacker can embed a self signed certificate.</p>",
                "If x5c is supported, always validate the entire certificate chain against a trusted certificate authority. Consider ignoring the x5c header entirely.",
                base.request().url(),
                LOW, CERTAIN, null, null, LOW,
                reqList(base));
    }

    public static AuditIssue p19_jwkPresent(JwtToken jwt, HttpRequestResponse base) {
        return auditIssue(
                "JWT Uses Embedded JWK (JSON Web Key) Header Parameter",
                "<p>The JWT header contains an embedded <code>jwk</code> parameter with a public key. If the server uses this embedded key to verify the signature, an attacker can embed their own public key and sign the token with the corresponding private key.</p>",
                "Do not use the jwk value from the token header for signature verification. Use statically configured keys or fetch them from a trusted, pre configured JWKS endpoint.",
                base.request().url(),
                LOW, CERTAIN, null, null, LOW,
                reqList(base));
    }

    public static AuditIssue p20_nestedJwt(JwtToken jwt, String claimName, HttpRequestResponse base) {
        return auditIssue(
                "Nested JWT Token Detected",
                "<p>A nested JWT was detected inside the payload of the outer JWT token. The claim <b>" + claimName + "</b> contains what appears to be another JWT. Nested JWTs increase parsing complexity and can introduce vulnerabilities if the inner and outer tokens are not validated independently.</p>",
                "Avoid nesting JWT tokens unless absolutely necessary. If nested JWTs are required, ensure both the inner and outer tokens are independently validated.",
                base.request().url(),
                INFORMATION, FIRM, null, null, INFORMATION,
                reqList(base));
    }

    public static AuditIssue p22_missingNbf(JwtToken jwt, HttpRequestResponse base) {
        return auditIssue(
                "JWT Token Missing Not Before (nbf) Claim",
                "<p>The JWT token does not contain an <code>nbf</code> (not before) claim. Without it, a token is valid from the moment it is created, which may be undesirable in scenarios where tokens are pre generated for future use.</p>",
                "Consider including an <code>nbf</code> claim in JWT tokens, especially in environments where tokens may be pre generated or distributed before they should become active.",
                base.request().url(),
                INFORMATION, CERTAIN, null, null, INFORMATION,
                reqList(base));
    }

    public static AuditIssue p23_missingJti(JwtToken jwt, HttpRequestResponse base) {
        return auditIssue(
                "JWT Token Missing Unique Identifier (jti) Claim",
                "<p>The JWT token does not contain a <code>jti</code> (JWT ID) claim. The jti claim provides a unique identifier essential for implementing token revocation and replay protection. Without it, the server has no straightforward way to track individual tokens or prevent their reuse.</p>",
                "Include a <code>jti</code> claim with a cryptographically random unique value (such as a UUID v4) in every JWT to enable individual token revocation and replay detection.",
                base.request().url(),
                INFORMATION, CERTAIN, null, null, INFORMATION,
                reqList(base));
    }

    // ============================================================
    // ACTIVE FINDINGS
    // ============================================================

    public static AuditIssue a01_algNone(JwtToken forgedJwt, int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT Algorithm None Attack Successful",
                "<p>The server accepts JWT tokens that use the \"none\" algorithm with the value <b>" + forgedJwt.getAlg().orElse("none") + "</b>. The \"none\" algorithm means no signature is applied to the token, so anyone can create a valid token with arbitrary claims.</p>"
                        + "<p>The forged token was: <pre>" + forgedJwt.encode() + "</pre></p>"
                        + "<p>The server responded with HTTP <b>" + statusCode + "</b> which is similar to the response for the original valid token, indicating the forged token was accepted.</p>"
                        + "<p>This is a critical vulnerability. Any attacker can create a JWT token with any claims (any user ID, any role, admin privileges) by simply setting the algorithm to \"none\" and leaving the signature empty.</p>",
                "Configure the JWT validation library to explicitly reject the \"none\" algorithm. Do not rely on the <code>alg</code> header from the incoming token to determine the verification algorithm. Instead, define the expected algorithm in the server's configuration.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a02_invalidSignature(int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT Signature Verification Not Enforced",
                "<p>The server accepts JWT tokens with a completely invalid signature. JWTLens modified the signature portion of the original token by randomizing its characters, and the server still accepted the token and returned a valid response.</p>"
                        + "<p>Server response: HTTP <b>" + statusCode + "</b></p>"
                        + "<p>This is a critical vulnerability. Since the server does not verify signatures, an attacker can modify any claim in the JWT payload (user ID, role, permissions) and the server will accept it as valid.</p>",
                "Enable signature verification in the JWT processing library. Ensure the correct verification key is configured and that every incoming token's signature is validated before any claims are processed.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a03_signatureStripping(String originalAlg, int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT Accepted Without Signature",
                "<p>The server accepts a JWT token that has had its signature completely removed. JWTLens sent the token with an empty signature portion and the server accepted it with HTTP <b>" + statusCode + "</b>. The algorithm header was left unchanged as <b>" + originalAlg + "</b>.</p>"
                        + "<p>An attacker can take any valid JWT, remove the signature entirely, modify the payload claims as desired, and the server will accept it.</p>",
                "Ensure the JWT validation logic checks that a signature is present before attempting to verify it. Use a well tested JWT library that handles this case correctly by default.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a04_expiredAccepted(int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "Server Accepts Expired JWT Token",
                "<p>The server continues to accept a JWT token that has passed its expiration time. The server returned HTTP <b>" + statusCode + "</b> indicating the token was still treated as valid.</p>"
                        + "<p>If expired tokens are accepted, stolen tokens remain usable indefinitely even after they should have expired. This undermines the primary defense that short token lifetimes provide against token theft.</p>",
                "Configure the JWT validation library to enforce expiration checking. Ensure the server's system clock is synchronized using NTP. Allow a maximum clock skew tolerance of 30 to 60 seconds.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a05_emptySecret(int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT Accepted When Signed with Empty Secret",
                "<p>The server accepts a JWT token that was signed using HMAC-SHA256 with an empty string as the secret key. The server accepted it with HTTP <b>" + statusCode + "</b>.</p>"
                        + "<p>This means the server's signing key is literally an empty string, which is equivalent to having no secret at all. Any attacker can forge valid JWT tokens by signing them with an empty key.</p>",
                "Set a strong, randomly generated secret key that is at least 256 bits (32 bytes) long. Ensure the application fails to start if the JWT secret is empty or not configured.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a06_weakSecret(String crackedSecret, int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT Signed with Weak Secret Key (Cracked)",
                "<p>JWTLens successfully determined the JWT signing secret by testing it against a list of commonly used weak secrets. The secret key is: <b>" + crackedSecret + "</b></p>"
                        + "<p>The token was re-signed with this secret and the server accepted it with HTTP <b>" + statusCode + "</b>.</p>"
                        + "<p>Since the signing secret is known, any attacker who discovers it can forge arbitrary JWT tokens with any user identity, any role, and any permissions, completely bypassing authentication and authorization.</p>",
                "Immediately rotate the JWT signing secret to a new, cryptographically random value of at least 256 bits. Generate the secret using: <code>openssl rand -base64 32</code> and store it securely in a secrets management system (not in source code or configuration files).",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a07_algConfusion(String originalAlg, String publicKeySource, int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT Algorithm Confusion Attack Successful (RS256 to HS256)",
                "<p>The server is vulnerable to a JWT algorithm confusion attack. The original token used the asymmetric algorithm <b>" + originalAlg + "</b>, but JWTLens changed the algorithm to HS256 and signed the token using the server's RSA public key as the HMAC secret. The server accepted this forged token with HTTP <b>" + statusCode + "</b>.</p>"
                        + "<p>This attack works because the server uses the <code>alg</code> header from the token to determine the verification method. When it sees HS256, it uses its verification key (the RSA public key) as the HMAC secret. Since the RSA public key is public knowledge, the attacker knows the HMAC signing key.</p>"
                        + "<p>Public key source: <b>" + publicKeySource + "</b></p>",
                "Never trust the <code>alg</code> header from incoming JWT tokens. Configure the server to use a fixed, expected algorithm for verification. Use different key objects for RSA and HMAC verification so that an RSA public key object cannot accidentally be used as an HMAC secret.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a08_jwkInjection(int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT JWK Header Injection Attack Successful",
                "<p>The server accepts a JWT token with an injected <code>jwk</code> header parameter. JWTLens generated a new RSA key pair, embedded the public key in the JWT's jwk header, signed the token with the corresponding private key, and the server accepted it with HTTP <b>" + statusCode + "</b>.</p>"
                        + "<p>This means the server is extracting the verification key directly from the token's header rather than using a pre configured trusted key. An attacker can generate their own key pair and forge any token.</p>",
                "Do not extract verification keys from the JWT's jwk header. Use pre configured keys stored securely on the server or fetched from a trusted JWKS endpoint with URL allowlisting.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a09_jkuInjection(String injectedUrl, int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT JKU Header Injection Attack Successful",
                "<p>The server follows the <code>jku</code> header in the JWT to fetch verification keys, and it accepted a token whose jku pointed to an attacker controlled URL: <b>" + injectedUrl + "</b>.</p>"
                        + "<p>The server accepted the forged token with HTTP <b>" + statusCode + "</b>. An attacker can host a malicious JWKS anywhere, point the jku header to it, and the server will use the attacker's public key for verification.</p>",
                "Implement strict URL allowlisting for jku values. Only allow jku URLs that point to your own trusted JWKS endpoint(s). Consider ignoring the jku header entirely.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a10_jkuPingback(String collaboratorDetails, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT JKU Triggers Server Side Request (SSRF Pingback)",
                "<p>The server made an outbound HTTP request to the URL specified in the JWT's <code>jku</code> header. Even if the final token validation fails, the SSRF behavior itself is a vulnerability.</p>"
                        + "<p>Collaborator interaction: <b>" + collaboratorDetails + "</b></p>"
                        + "<p>An attacker can use this to probe internal network infrastructure, access cloud metadata endpoints (such as AWS IMDSv1 at 169.254.169.254), and potentially exfiltrate data through DNS.</p>",
                "Do not make outbound requests based on URLs from untrusted JWT headers. If jku support is required, validate the URL against a strict allowlist. Block requests to private IP ranges, localhost, and cloud metadata endpoints.",
                base.request().url(),
                MEDIUM, CERTAIN, null, null, MEDIUM,
                reqList(base, check));
    }

    public static AuditIssue a11_x5uInjection(String injectedUrl, int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT X5U Header Injection Attack Successful",
                "<p>The server follows the <code>x5u</code> header in the JWT to fetch a verification certificate, and it accepted a token whose x5u pointed to: <b>" + injectedUrl + "</b>. The server accepted it with HTTP <b>" + statusCode + "</b>.</p>"
                        + "<p>An attacker can create a self signed certificate, host it anywhere, and the server will use it to verify tokens.</p>",
                "Do not trust x5u URLs from incoming tokens. Statically configure trusted certificates on the server. If x5u must be supported, validate the URL against a strict allowlist and verify certificate chains.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a12_x5cInjection(int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT X5C Header Injection Attack Successful",
                "<p>The server accepts a JWT token with a self signed certificate embedded in the <code>x5c</code> header. JWTLens generated a self signed certificate, embedded it in the x5c header, signed the token with the corresponding private key, and the server accepted it with HTTP <b>" + statusCode + "</b>.</p>"
                        + "<p>This means the server extracts the public key from the embedded certificate without validating the certificate chain against trusted roots. An attacker can generate any certificate and forge valid tokens.</p>",
                "If x5c is supported, always validate the complete certificate chain against a trusted root certificate authority. Consider rejecting tokens with x5c headers entirely if your architecture does not require them.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a13_kidPathTraversal(String traversalPath, int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT KID Header Path Traversal Attack Successful",
                "<p>The server is vulnerable to path traversal through the JWT's <code>kid</code> header parameter. JWTLens set the kid to <b>" + traversalPath + "</b> and signed the token with a key derived from the expected file content. The server accepted it with HTTP <b>" + statusCode + "</b>.</p>"
                        + "<p>The server is using the kid parameter to construct a file system path for loading the verification key. By traversing to a known or predictable file, the attacker controls the verification key material.</p>",
                "Never use the kid value to construct file system paths. Validate kid against an allowlist of known key identifiers. Use the kid as a lookup key in a dictionary or database rather than a file path.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a14_kidSqlInjection(String sqlPayload, int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT KID Header SQL Injection Detected",
                "<p>The server appears to be vulnerable to SQL injection through the JWT's <code>kid</code> header parameter. JWTLens injected the SQL payload: <pre>" + sqlPayload + "</pre></p>"
                        + "<p>The server responded with HTTP <b>" + statusCode + "</b> indicating the injected token was accepted or triggered a SQL error.</p>"
                        + "<p>SQL injection in the kid parameter allows an attacker to manipulate the database query that retrieves the verification key. The attacker can use UNION SELECT to return a known key value, then sign the token with that known value. In more severe cases, the SQL injection can be used to extract sensitive data or modify records.</p>",
                "Use parameterized queries (prepared statements) when looking up keys by kid. Never concatenate the kid value directly into a SQL query string. Validate the kid against an allowlist before performing any database lookup.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a15_kidCommandInjection(String payload, String detectionMethod, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT KID Header Command Injection Detected",
                "<p>The server appears to be vulnerable to operating system command injection through the JWT's <code>kid</code> header parameter.</p>"
                        + "<p>Payload tested: <pre>" + payload + "</pre></p>"
                        + "<p>Detection method: <b>" + detectionMethod + "</b></p>"
                        + "<p>Command injection in the kid parameter gives the attacker the ability to execute arbitrary operating system commands on the server, allowing complete server compromise, data exfiltration, and persistent access.</p>",
                "Never pass the kid value to a shell command or system() call. Use the kid exclusively as a lookup key in an in memory map or database with parameterized queries. Validate against strict character allowlists (alphanumeric only).",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a16_kidLdapInjection(String payload, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT KID Header LDAP Injection Detected",
                "<p>The server appears to be vulnerable to LDAP injection through the JWT's <code>kid</code> header parameter. Payload tested: <b>" + payload + "</b></p>"
                        + "<p>LDAP injection allows the attacker to manipulate the LDAP query used to look up the verification key, potentially retrieving a different key or extracting directory information.</p>",
                "Sanitize the kid value by escaping LDAP special characters. Validate the kid against an allowlist and never use it directly in LDAP filter construction.",
                base.request().url(),
                HIGH, FIRM, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a17_nbfBypass(int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT Not Before (nbf) Claim Not Enforced",
                "<p>The server accepts JWT tokens with a <code>nbf</code> (not before) claim set to a time in the future. JWTLens modified the token's nbf claim to 24 hours in the future and the server accepted it with HTTP <b>" + statusCode + "</b>.</p>"
                        + "<p>The server does not enforce the nbf time constraint, meaning tokens intended for future use are accepted immediately.</p>",
                "Configure the JWT validation library to enforce the nbf claim. Allow a small clock skew tolerance (30 to 60 seconds) to account for time differences between servers.",
                base.request().url(),
                MEDIUM, CERTAIN, null, null, MEDIUM,
                reqList(base, check));
    }

    public static AuditIssue a18_claimTampering(String modifiedClaims, int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT Claim Tampering Allows Privilege Escalation",
                "<p>JWTLens successfully tampered with claims in the JWT payload to elevate privileges, and the server accepted the modified token. This check was performed in combination with a successful signature bypass.</p>"
                        + "<p>Modified claims: <b>" + modifiedClaims + "</b></p>"
                        + "<p>The server returned HTTP <b>" + statusCode + "</b> with a response indicating elevated access.</p>"
                        + "<p>An attacker can modify authorization claims to gain administrator or higher privilege access, bypassing all authentication and authorization controls.</p>",
                "Always validate the JWT signature before trusting any claims. Implement server side authorization checks that do not rely solely on JWT claims. Apply the principle of least privilege to all token claims.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a19_subEnumeration(String validIds, String invalidIds, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT Subject Claim Enumeration Possible",
                "<p>JWTLens modified the <code>sub</code> claim to different values and observed that the server returns different responses based on whether the subject exists, allowing enumeration of valid user identifiers.</p>"
                        + "<p>Identifiers that appear to be valid: <b>" + validIds + "</b></p>"
                        + "<p>Identifiers that appear to be invalid: <b>" + invalidIds + "</b></p>",
                "Return identical responses for valid and invalid subject claims when authorization fails. Implement rate limiting on JWT validation endpoints.",
                base.request().url(),
                MEDIUM, FIRM, null, null, MEDIUM,
                reqList(base, check));
    }

    public static AuditIssue a20_cve202221449(int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT Vulnerable to Psychic Signatures (CVE-2022-21449)",
                "<p>The server is vulnerable to CVE-2022-21449, known as \"Psychic Signatures.\" This is a vulnerability in Java's ECDSA signature verification (Java 15 through 18.0.1) where a signature consisting of zero values (r=0, s=0) is accepted as valid for any message with any public key.</p>"
                        + "<p>JWTLens sent a token with algorithm ES256 and a null signature, and the server accepted it with HTTP <b>" + statusCode + "</b>.</p>"
                        + "<p>An attacker can forge a valid ECDSA signature for any JWT token without knowing the private key, resulting in complete authentication bypass.</p>",
                "Update the Java runtime to version 18.0.2 or later. If immediate patching is not possible, switch to RSA based JWT signing as a temporary mitigation.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a22_crossAlgSigning(String originalAlg, String newAlg, String keyDesc, int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT Cross Algorithm Signing Accepted",
                "<p>The server accepts a JWT re-signed using a different HMAC algorithm. JWTLens changed the algorithm from <b>" + originalAlg + "</b> to <b>" + newAlg + "</b> and signed with <b>" + keyDesc + "</b>. The server accepted it with HTTP <b>" + statusCode + "</b>.</p>"
                        + "<p>The server does not enforce the expected signing algorithm and accepts tokens signed with alternative HMAC algorithms.</p>",
                "Configure the server to accept only the specific algorithm it expects. Do not allow the incoming token's alg header to dictate the verification algorithm.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a23_nullSignature(int statusCode, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT Accepted with Null Signature Bytes",
                "<p>The server accepts a JWT token where the signature consists of null bytes (all zeros). The server accepted it with HTTP <b>" + statusCode + "</b>.</p>"
                        + "<p>Null byte signatures may bypass signature verification in implementations that use string comparison functions which terminate at null bytes.</p>",
                "Ensure the JWT library uses constant time, full length byte comparison for signature verification. Update the JWT library to the latest version.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue a27_jwksDiscovered(String jwksUrl, String keysSummary, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWKS (JSON Web Key Set) Endpoint Discovered",
                "<p>JWTLens discovered a publicly accessible JWKS endpoint at <b>" + jwksUrl + "</b>.</p>"
                        + "<p>" + keysSummary + "</p>"
                        + "<p>While exposing public keys is normal for asymmetric JWT verification, this information enables algorithm confusion attacks if the server is vulnerable.</p>",
                "Ensure the server is not vulnerable to algorithm confusion attacks. Review the keys in the JWKS for adequate key sizes and remove old or compromised keys.",
                base.request().url(),
                INFORMATION, CERTAIN, null, null, INFORMATION,
                reqList(base, check));
    }

    // ============================================================
    // SECRET EXTRACTOR FINDINGS
    // ============================================================

    public static AuditIssue secretExtracted(String secret, String context, String sourceUrl, HttpRequestResponse base) {
        String masked = secret.length() > 8
                ? secret.substring(0, 4) + "****" + secret.substring(secret.length() - 4)
                : "****";
        return auditIssue(
                "JWT Signing Secret Extracted from Response",
                "<p>JWTLens discovered a potential JWT signing secret in a JavaScript file or API response.</p>"
                        + "<p>Secret value: <code>" + masked + "</code> (masked for safety)</p>"
                        + "<p>Found in context: <pre>" + context + "</pre></p>"
                        + "<p>Source: <b>" + sourceUrl + "</b></p>"
                        + "<p>If this is the actual signing secret, an attacker can forge arbitrary JWT tokens with any claims, completely bypassing authentication and authorization. "
                        + "The secret has been added to JWTLens's runtime wordlist and will be tested against JWT tokens found during active scanning.</p>",
                "Never expose JWT signing secrets in client-side code, JavaScript bundles, or API responses. "
                        + "Store secrets in environment variables or secure vaults (AWS Secrets Manager, HashiCorp Vault). "
                        + "Rotate the compromised secret immediately.",
                base.request().url(),
                HIGH, FIRM, null, null, HIGH,
                List.of(base));
    }

    public static AuditIssue privateKeyExtracted(String keyType, String sourceUrl, HttpRequestResponse base) {
        return auditIssue(
                keyType + " Private Key Exposed in HTTP Response",
                "<p>JWTLens discovered a <b>" + keyType + " private key</b> in a server response.</p>"
                        + "<p>Source: <b>" + sourceUrl + "</b></p>"
                        + "<p>If this is the JWT signing key, an attacker can forge tokens signed with the legitimate private key. "
                        + "Even if not used for JWT signing, exposing private keys enables impersonation, decryption of encrypted traffic, and man-in-the-middle attacks.</p>",
                "Never serve private keys in HTTP responses. Remove the key from the codebase and rotate it immediately. "
                        + "Store private keys in secure key management systems.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                List.of(base));
    }

    public static AuditIssue publicKeyExtracted(String sourceUrl, HttpRequestResponse base) {
        return auditIssue(
                "RSA Public Key Found in HTTP Response",
                "<p>JWTLens discovered an RSA public key in a server response at <b>" + sourceUrl + "</b>.</p>"
                        + "<p>While exposing public keys is not inherently a vulnerability, this key can be used for algorithm confusion attacks (RS256 to HS256). "
                        + "The key has been stored for use in JWTLens's algorithm confusion checks.</p>",
                "Ensure the server is not vulnerable to algorithm confusion attacks. "
                        + "Configure the JWT library to accept only the expected algorithm and reject tokens with a different alg header.",
                base.request().url(),
                LOW, CERTAIN, null, null, LOW,
                List.of(base));
    }

    public static AuditIssue jwksInlineFound(String sourceUrl, HttpRequestResponse base) {
        return auditIssue(
                "Inline JWKS (JSON Web Key Set) Found in Response",
                "<p>JWTLens found a JWKS structure embedded directly in a server response at <b>" + sourceUrl + "</b>.</p>"
                        + "<p>The JWKS contains public keys that can be used for algorithm confusion attacks. "
                        + "JWTLens has extracted the keys for use in active scanning.</p>",
                "Serve JWKS only from well-known endpoints with proper access controls. "
                        + "Ensure the server validates the alg header against a server-side allowlist.",
                base.request().url(),
                LOW, CERTAIN, null, null, LOW,
                List.of(base));
    }

    public static AuditIssue jwksUrlFound(String jwksUrl, String sourceUrl, HttpRequestResponse base) {
        return auditIssue(
                "JWKS URL Reference Discovered in Response",
                "<p>JWTLens found a reference to a JWKS endpoint in a server response.</p>"
                        + "<p>JWKS URL: <b>" + jwksUrl + "</b></p>"
                        + "<p>Found in: <b>" + sourceUrl + "</b></p>"
                        + "<p>This URL will be fetched during active scanning to extract public keys for algorithm confusion attacks.</p>",
                "Ensure the JWKS endpoint serves only public keys. "
                        + "Validate tokens against a server-side algorithm allowlist to prevent confusion attacks.",
                base.request().url(),
                INFORMATION, CERTAIN, null, null, INFORMATION,
                List.of(base));
    }

    public static AuditIssue a07_algConfusionReal(String originalAlg, String keySource, int keyBits, int statusCode,
                                                    HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT Algorithm Confusion Attack Successful (Real Server Key)",
                "<p>The server is vulnerable to a critical algorithm confusion attack. JWTLens extracted the server's actual RSA public key from <b>" + keySource + "</b> "
                        + "(" + keyBits + "-bit), switched the token's algorithm from <b>" + originalAlg + "</b> to <b>HS256</b>, "
                        + "and used the public key bytes as the HMAC secret. The server accepted the forged token with HTTP <b>" + statusCode + "</b>.</p>"
                        + "<p>This is a confirmed, exploitable vulnerability. The attacker can forge tokens for any user by:</p>"
                        + "<ol>"
                        + "<li>Downloading the server's public key (often at /.well-known/jwks.json)</li>"
                        + "<li>Using the public key as an HMAC-SHA256 secret</li>"
                        + "<li>Setting the JWT alg header to HS256</li>"
                        + "<li>Signing arbitrary claims with HMAC using the public key</li>"
                        + "</ol>",
                "Configure the JWT validation library to accept ONLY the expected algorithm. "
                        + "The server must check the alg header against a hardcoded allowlist and reject any token that specifies a different algorithm. "
                        + "Specifically, if RS256 is expected, HS256 must be explicitly rejected. "
                        + "Most JWT libraries have a configuration option like 'algorithms=[\"RS256\"]'.",
                base.request().url(),
                HIGH, CERTAIN, null, null, HIGH,
                reqList(base, check));
    }

    public static AuditIssue serverError(String checkName, HttpRequestResponse base, HttpRequestResponse check) {
        return auditIssue(
                "JWT Check Triggered Server Error: " + checkName,
                "<p>While performing the <b>" + checkName + "</b> check, the server responded with a 500 Internal Server Error. This indicates the server encountered an unexpected condition when processing the modified JWT. This error response may reveal information about the server's JWT processing logic or indicate a potential denial of service vector.</p>",
                "Investigate the server logs for the root cause of the error. Ensure the JWT parsing and validation logic handles malformed or unexpected tokens gracefully without crashing.",
                base.request().url(),
                LOW, CERTAIN, null, null, LOW,
                reqList(base, check));
    }
}
