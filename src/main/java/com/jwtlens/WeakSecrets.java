package com.jwtlens;

import java.util.List;

/**
 * Embedded list of commonly used JWT signing secrets for brute force testing.
 * Curated from jwt.secrets.list, common defaults, and real world leaks.
 */
public class WeakSecrets {

    public static final List<String> SECRETS = List.of(
            // jwt.io defaults
            "secret",
            "your-256-bit-secret",
            "your-384-bit-secret",
            "your-512-bit-secret",

            // Common passwords
            "password",
            "password1",
            "password123",
            "123456",
            "1234567890",
            "12345678",
            "123456789",
            "admin",
            "admin123",
            "administrator",
            "root",
            "toor",
            "test",
            "test123",
            "guest",
            "default",
            "changeme",
            "changeit",
            "letmein",
            "welcome",
            "monkey",
            "dragon",
            "master",
            "qwerty",
            "abc123",
            "iloveyou",
            "trustno1",
            "sunshine",
            "princess",
            "football",
            "shadow",
            "superman",
            "michael",
            "ninja",
            "mustang",

            // JWT specific
            "jwt_secret",
            "jwt-secret",
            "jwtsecret",
            "jwt_secret_key",
            "jwt-secret-key",
            "jwtSecretKey",
            "JWT_SECRET",
            "JWT_SECRET_KEY",
            "my-jwt-secret",
            "my_jwt_secret",
            "mysecretkey",
            "my-secret-key",
            "my_secret_key",
            "MySecretKey",
            "secretkey",
            "secret-key",
            "secret_key",
            "SecretKey",
            "SECRET_KEY",
            "secret123",
            "s3cr3t",
            "s3cret",
            "sup3rs3cr3t",
            "supersecret",
            "super-secret",
            "super_secret",

            // API/Token patterns
            "api_secret",
            "api-secret",
            "apisecret",
            "API_SECRET",
            "token_secret",
            "token-secret",
            "tokensecret",
            "TOKEN_SECRET",
            "auth_secret",
            "auth-secret",
            "authsecret",
            "AUTH_SECRET",
            "app_secret",
            "app-secret",
            "appsecret",
            "APP_SECRET",

            // Signing key patterns
            "signing-key",
            "signing_key",
            "signingkey",
            "SigningKey",
            "SIGNING_KEY",
            "encryption-key",
            "encryption_key",
            "encryptionkey",
            "private-key",
            "private_key",
            "privatekey",
            "hmac-secret",
            "hmac_secret",
            "hmacsecret",

            // Framework defaults
            "AllYourBase",
            "HS256-secret",
            "key",
            "Key",
            "KEY",
            "pass",
            "Pass",
            "PASS",
            "node_secret",
            "express_secret",
            "flask_secret",
            "django_secret",
            "rails_secret",
            "spring_secret",
            "laravel_secret",

            // Company/tech names (commonly used as secrets)
            "google",
            "facebook",
            "amazon",
            "microsoft",
            "apple",
            "github",
            "kubernetes",
            "docker",

            // UUID/Hash like
            "00000000-0000-0000-0000-000000000000",
            "aaaa",
            "AAAA",
            "aaaaaa",
            "aaaaaaaa",
            "bbbb",
            "xxxx",
            "1111",
            "0000",

            // Base64 common
            "c2VjcmV0",          // base64("secret")
            "cGFzc3dvcmQ",      // base64("password")
            "YWRtaW4",          // base64("admin")

            // Hex patterns
            "deadbeef",
            "cafebabe",
            "0123456789abcdef",

            // Long but common
            "thisisasecretkey",
            "this-is-a-secret",
            "this_is_a_secret",
            "ThisIsASecretKey",
            "mysupersecretkey",
            "my-super-secret-key",
            "a]V@Ird}Xo4S&amp;r:8",
            "gZH75aKtMN3Yj0iPS3Xc",

            // Development defaults
            "development",
            "dev_secret",
            "dev-secret",
            "staging",
            "production",
            "prod_secret",
            "localhost",
            "example",
            "sample",
            "demo",

            // Keyboard patterns
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
            "1q2w3e4r",
            "q1w2e3r4",

            // Single words
            "token",
            "access",
            "bearer",
            "auth",
            "login",
            "user",
            "hello",
            "world",
            "helloworld",
            "hello-world",
            "foobar",
            "foo",
            "bar",
            "baz",
            "temp",
            "tmp",
            "null",
            "undefined",
            "none",
            "true",
            "false",
            "yes",
            "no",
            "on",
            "off",

            // Numeric
            "111111",
            "000000",
            "654321",
            "666666",
            "121212",
            "112233",
            "123123",
            "159753",
            "987654321",

            // Phrases
            "iamadmin",
            "passw0rd",
            "p@ssw0rd",
            "P@ssw0rd",
            "P@ssword1",
            "Admin123!",
            "Welcome1",
            "Tr0ub4dor&3",

            // Specific to JWT tools/tutorials
            "shhhhh",
            "shhhh",
            "ssh-secret",
            "keyboard cat",
            "keyboard-cat",
            "keyboardcat"
    );
}
