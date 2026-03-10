package com.jwtlens;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Context menu entries for manual JWT scanning.
 * Right-click a request to trigger JWT checks.
 */
public class JwtContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final JwtDedup dedup;

    public JwtContextMenu(MontoyaApi api, JwtDedup dedup) {
        this.api = api;
        this.dedup = dedup;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // Only show menu if there are selected request/responses
        if (event.selectedRequestResponses().isEmpty() && event.messageEditorRequestResponse().isEmpty()) {
            return menuItems;
        }

        JMenu jwtMenu = new JMenu("JWTLens");

        // Passive scan option
        JMenuItem passiveItem = new JMenuItem("Run Passive Checks");
        passiveItem.addActionListener(e -> {
            new Thread(() -> runPassiveChecks(event)).start();
        });
        jwtMenu.add(passiveItem);

        // Active scan option
        JMenuItem activeItem = new JMenuItem("Run Full Active Scan");
        activeItem.addActionListener(e -> {
            new Thread(() -> runActiveChecks(event)).start();
        });
        jwtMenu.add(activeItem);

        // Brute force only
        JMenuItem bruteItem = new JMenuItem("Brute Force Secret Only");
        bruteItem.addActionListener(e -> {
            new Thread(() -> runBruteForce(event)).start();
        });
        jwtMenu.add(bruteItem);

        jwtMenu.addSeparator();

        // Send to JWT Forge tab
        JMenuItem forgeItem = new JMenuItem("Send to JWT Forge");
        forgeItem.addActionListener(e -> {
            new Thread(() -> sendToForge(event)).start();
        });
        jwtMenu.add(forgeItem);

        // Decode JWT (display)
        JMenuItem decodeItem = new JMenuItem("Decode JWT");
        decodeItem.addActionListener(e -> {
            new Thread(() -> decodeJwt(event)).start();
        });
        jwtMenu.add(decodeItem);

        // Clear dedup cache
        JMenuItem clearItem = new JMenuItem("Clear Dedup Cache (" + dedup.size() + " entries)");
        clearItem.addActionListener(e -> {
            dedup.clear();
            api.logging().logToOutput("JWTLens: Dedup cache cleared.");
        });
        jwtMenu.add(clearItem);

        menuItems.add(jwtMenu);
        return menuItems;
    }

    private List<HttpRequestResponse> getSelectedRequests(ContextMenuEvent event) {
        List<HttpRequestResponse> requests = new ArrayList<>(event.selectedRequestResponses());
        event.messageEditorRequestResponse().ifPresent(editor -> {
            requests.add(editor.requestResponse());
        });
        return requests;
    }

    /**
     * Extracts all JWTs from both request AND response of an HttpRequestResponse.
     * Returns a list of tokens with their source labeled for display.
     */
    private List<JwtTokenWithSource> extractAllJwts(HttpRequestResponse reqResp) {
        List<JwtTokenWithSource> results = new ArrayList<>();

        // Extract from request
        String requestStr = reqResp.request().toString();
        for (JwtToken jwt : JwtToken.extractFromString(requestStr)) {
            results.add(new JwtTokenWithSource(jwt, "Request"));
        }

        // Extract from response
        if (reqResp.response() != null) {
            String responseStr = reqResp.response().toString();
            for (JwtToken jwt : JwtToken.extractFromString(responseStr)) {
                // Avoid duplicates if same token appears in both request and response
                boolean alreadyFound = results.stream()
                        .anyMatch(existing -> existing.token.encode().equals(jwt.encode()));
                if (!alreadyFound) {
                    results.add(new JwtTokenWithSource(jwt, "Response"));
                }
            }
        }

        return results;
    }

    /**
     * Simple wrapper to track where a JWT was found.
     */
    private static class JwtTokenWithSource {
        final JwtToken token;
        final String source; // "Request" or "Response"

        JwtTokenWithSource(JwtToken token, String source) {
            this.token = token;
            this.source = source;
        }
    }

    private void runPassiveChecks(ContextMenuEvent event) {
        api.logging().logToOutput("JWTLens: Running passive checks...");
        PassiveScanCheck passive = new PassiveScanCheck(api, dedup);

        for (HttpRequestResponse reqResp : getSelectedRequests(event)) {
            List<AuditIssue> issues = passive.check(reqResp);
            for (AuditIssue issue : issues) {
                api.siteMap().add(issue);
            }
            api.logging().logToOutput("JWTLens: Found " + issues.size() + " passive findings.");
        }
    }

    private void runActiveChecks(ContextMenuEvent event) {
        api.logging().logToOutput("JWTLens: Running active scan...");
        ActiveScanCheck active = new ActiveScanCheck(api, dedup);
        JwtInsertionPointProvider ipp = new JwtInsertionPointProvider();

        for (HttpRequestResponse reqResp : getSelectedRequests(event)) {
            // First run passive
            PassiveScanCheck passive = new PassiveScanCheck(api, dedup);
            List<AuditIssue> passiveIssues = passive.check(reqResp);
            for (AuditIssue issue : passiveIssues) {
                api.siteMap().add(issue);
            }

            // Then run active with insertion points
            var insertionPoints = ipp.provideInsertionPoints(reqResp);
            for (var ip : insertionPoints) {
                List<AuditIssue> issues = active.check(reqResp, ip);
                for (AuditIssue issue : issues) {
                    api.siteMap().add(issue);
                }
                api.logging().logToOutput("JWTLens: Found " + issues.size() + " active findings.");
            }
        }
        api.logging().logToOutput("JWTLens: Active scan complete.");
    }

    private void runBruteForce(ContextMenuEvent event) {
        api.logging().logToOutput("JWTLens: Running brute force...");

        // Get the effective wordlist from the tab (built-in + custom if loaded)
        JwtLensTab tab = JwtLensExtension.tab();
        List<String> wordlist = new java.util.ArrayList<>((tab != null) ? tab.getEffectiveWordlist() : WeakSecrets.SECRETS);

        // Prepend secrets discovered by SecretExtractor (higher priority)
        SecretExtractor extractor = JwtLensExtension.secretExtractor();
        if (extractor != null && !extractor.getDiscoveredSecrets().isEmpty()) {
            List<String> augmented = new java.util.ArrayList<>(extractor.getDiscoveredSecrets());
            augmented.addAll(wordlist);
            wordlist = augmented;
        }

        // Find a JWT to brute force from request+response
        JwtToken jwt = null;
        String source = "";
        for (HttpRequestResponse reqResp : getSelectedRequests(event)) {
            List<JwtTokenWithSource> tokensWithSource = extractAllJwts(reqResp);

            if (tokensWithSource.isEmpty()) continue;

            // If multiple JWTs found, let user pick which one
            JwtTokenWithSource selected = tokensWithSource.get(0);
            if (tokensWithSource.size() > 1) {
                String[] choices = tokensWithSource.stream()
                        .map(t -> "[" + t.source + "] " + t.token.getAlg().orElse("?")
                                + " | sub:" + t.token.getClaimString("sub").orElse("?")
                                + " | " + truncateToken(t.token.encode(), 50))
                        .toArray(String[]::new);
                String pick = (String) JOptionPane.showInputDialog(null,
                        "Multiple JWTs found. Select one to brute force:",
                        "JWTLens - Select JWT",
                        JOptionPane.QUESTION_MESSAGE, null, choices, choices[0]);
                if (pick == null) return;
                int idx = java.util.Arrays.asList(choices).indexOf(pick);
                selected = tokensWithSource.get(idx);
            }

            jwt = selected.token;
            source = selected.source;
            break;
        }

        if (jwt == null) {
            JOptionPane.showMessageDialog(null,
                    "No JWT token found in the request or response.",
                    "JWTLens - Brute Force",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        api.logging().logToOutput("JWTLens: Brute forcing JWT from " + source);

        String signingInput = jwt.getSigningInput();
        String expectedSig = jwt.getSignature();
        String originalAlg = jwt.getAlg().orElse("unknown");

        if (expectedSig == null || expectedSig.isEmpty()) {
            api.logging().logToOutput("JWTLens: Token has no signature, skipping brute force.");
            JOptionPane.showMessageDialog(null,
                    "Token has no signature (alg=none?). Nothing to brute force.",
                    "JWTLens - Brute Force",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String[] hmacAlgs = {"HmacSHA256", "HmacSHA384", "HmacSHA512"};
        String[] algNames = {"HS256", "HS384", "HS512"};

        api.logging().logToOutput("JWTLens: Token algorithm: " + originalAlg + " (from " + source + ")");
        api.logging().logToOutput("JWTLens: Testing " + wordlist.size() + " secrets across HS256/HS384/HS512...");

        boolean found = false;
        for (int a = 0; a < hmacAlgs.length; a++) {
            for (String secret : wordlist) {
                if (CryptoUtils.verifyHmac(hmacAlgs[a], signingInput, secret, expectedSig)) {
                    api.logging().logToOutput("JWTLens: SECRET FOUND: " + secret + " (algorithm: " + algNames[a] + ")");

                    // Auto-fill the Forge tab with the discovered secret
                    JwtForgeTab forge = JwtLensExtension.forgeTab();
                    if (forge != null) {
                        forge.setDiscoveredSecret(secret, algNames[a]);
                        forge.loadTokenWithSecret(jwt.encode(), secret, algNames[a]);
                    }

                    JOptionPane.showMessageDialog(null,
                            "JWT Secret Cracked!\n\n"
                                    + "Source: " + source + "\n"
                                    + "Secret: " + secret + "\n"
                                    + "Algorithm: " + algNames[a] + "\n"
                                    + "Original alg header: " + originalAlg + "\n\n"
                                    + "Secret has been loaded into the JWT Forge tab.",
                            "JWTLens - Secret Found",
                            JOptionPane.WARNING_MESSAGE);
                    found = true;
                    break;
                }
            }
            if (found) break;
        }

        if (!found) {
            api.logging().logToOutput("JWTLens: No weak secret found.");
            JOptionPane.showMessageDialog(null,
                    "No weak secret found (" + wordlist.size() + " secrets tested across HS256/HS384/HS512).\n\n"
                            + "Try a larger wordlist:\n"
                            + "  hashcat -a 0 -m 16500 <jwt> /path/to/wordlist.txt\n\n"
                            + "Or upload a custom wordlist in the JWTLens tab.",
                    "JWTLens - Brute Force Complete",
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void sendToForge(ContextMenuEvent event) {
        for (HttpRequestResponse reqResp : getSelectedRequests(event)) {
            List<JwtTokenWithSource> tokensWithSource = extractAllJwts(reqResp);

            if (tokensWithSource.isEmpty()) continue;

            // If multiple JWTs, let user pick
            JwtTokenWithSource selected = tokensWithSource.get(0);
            if (tokensWithSource.size() > 1) {
                String[] choices = tokensWithSource.stream()
                        .map(t -> "[" + t.source + "] " + t.token.getAlg().orElse("?")
                                + " | sub:" + t.token.getClaimString("sub").orElse("?")
                                + " | " + truncateToken(t.token.encode(), 50))
                        .toArray(String[]::new);
                String pick = (String) JOptionPane.showInputDialog(null,
                        "Multiple JWTs found. Select one to send to Forge:",
                        "JWTLens - Select JWT",
                        JOptionPane.QUESTION_MESSAGE, null, choices, choices[0]);
                if (pick == null) return;
                int idx = java.util.Arrays.asList(choices).indexOf(pick);
                selected = tokensWithSource.get(idx);
            }

            JwtForgeTab forgeTab = JwtLensExtension.forgeTab();
            if (forgeTab != null) {
                forgeTab.loadToken(selected.token.encode());
                api.logging().logToOutput("JWTLens: JWT from " + selected.source + " sent to Forge tab.");
            }
            return;
        }

        JOptionPane.showMessageDialog(null,
                "No JWT token found in the request or response.",
                "JWTLens - Send to Forge",
                JOptionPane.WARNING_MESSAGE);
    }

    private void decodeJwt(ContextMenuEvent event) {
        for (HttpRequestResponse reqResp : getSelectedRequests(event)) {
            List<JwtTokenWithSource> tokensWithSource = extractAllJwts(reqResp);

            if (tokensWithSource.isEmpty()) {
                api.logging().logToOutput("JWTLens: No JWT found in request or response.");
                return;
            }

            for (JwtTokenWithSource tws : tokensWithSource) {
                JwtToken jwt = tws.token;
                StringBuilder sb = new StringBuilder();
                sb.append("=== JWT Decoded [").append(tws.source).append("] ===\n\n");
                sb.append("Algorithm: ").append(jwt.getAlg().orElse("none")).append("\n\n");
                sb.append("Header:\n").append(jwt.getDecodedHeaderJson()).append("\n\n");
                sb.append("Payload:\n").append(jwt.getDecodedPayloadJson()).append("\n\n");
                sb.append("Signature: ").append(jwt.getSignature()).append("\n\n");

                if (jwt.hasExpiry()) {
                    sb.append("Expires: ").append(jwt.getExp().orElse(0L)).append(jwt.isExpired() ? " (EXPIRED)" : " (valid)").append("\n");
                } else {
                    sb.append("Expires: NEVER (no exp claim)\n");
                }

                api.logging().logToOutput(sb.toString());
            }
            return;
        }
    }

    private static String truncateToken(String token, int max) {
        if (token == null) return "";
        if (token.length() <= max) return token;
        return token.substring(0, max) + "...";
    }
}
