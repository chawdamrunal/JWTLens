package com.jwtlens;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.*;

/**
 * JWTLens - Comprehensive JWT Security Scanner for Burp Suite
 *
 * Performs 23 passive checks and 33 active checks covering the complete
 * JWT attack surface: signature bypasses, algorithm attacks, header injection,
 * KID exploitation, claim manipulation, token lifecycle, cookie security,
 * token leakage, cryptographic weaknesses, CVEs, and token revocation.
 */
public class JwtLensExtension implements BurpExtension {

    private static MontoyaApi api;
    private static JwtDedup dedup;
    private static JwtLensTab tab;
    private static JwtForgeTab forgeTab;
    private static SecretExtractor secretExtractor;

    public static MontoyaApi api() { return api; }
    public static JwtDedup dedup() { return dedup; }
    public static JwtLensTab tab() { return tab; }
    public static JwtForgeTab forgeTab() { return forgeTab; }
    public static SecretExtractor secretExtractor() { return secretExtractor; }

    @Override
    public void initialize(MontoyaApi api) {
        JwtLensExtension.api = api;
        JwtLensExtension.dedup = new JwtDedup();
        JwtLensExtension.secretExtractor = new SecretExtractor(api, dedup);

        api.extension().setName("JWTLens");

        // Register the main tab in Burp's top-level tab bar
        tab = new JwtLensTab(api, dedup);
        api.userInterface().registerSuiteTab("JWTLens", tab);

        // Register the Forge tab
        forgeTab = new JwtForgeTab(api);
        api.userInterface().registerSuiteTab("JWT Forge", forgeTab);

        // Register scan check (passive + active)
        api.scanner().registerScanCheck(new JwtLensScanCheck());

        // Register insertion point provider
        api.scanner().registerInsertionPointProvider(new JwtInsertionPointProvider());

        // Register context menu
        api.userInterface().registerContextMenuItemsProvider(new JwtContextMenu(api, dedup));

        api.logging().logToOutput("=========================================");
        api.logging().logToOutput("  JWTLens v1.0.0 Loaded Successfully");
        api.logging().logToOutput("  JWT Security Scanner for Burp Suite");
        api.logging().logToOutput("  23 Passive + 33 Active = 56 Checks");
        api.logging().logToOutput("  + JWT Forge Tab + Secret Extractor");
        api.logging().logToOutput("=========================================");
        api.logging().logToOutput("");
        api.logging().logToOutput("  Tabs: JWTLens + JWT Forge (in top bar)");
        api.logging().logToOutput("  Right-click any request -> JWTLens");
        api.logging().logToOutput("  Or use Burp's Active/Passive scanner");
        api.logging().logToOutput("");
    }

    /**
     * Core scan check that integrates with Burp's scanner.
     * Findings go to both Burp's Issues tab AND the JWTLens tab.
     */
    private class JwtLensScanCheck implements ScanCheck {

        @Override
        public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
            if (tab != null && !tab.isActiveEnabled()) {
                return auditResult(List.of());
            }

            List<AuditIssue> issues = new ArrayList<>();

            try {
                ActiveScanCheck active = new ActiveScanCheck(api, dedup);
                issues.addAll(active.check(baseRequestResponse, auditInsertionPoint));

                // Also add to JWTLens tab
                for (AuditIssue issue : issues) {
                    addToTab(issue, baseRequestResponse);
                }
            } catch (Exception e) {
                api.logging().logToError("JWTLens active scan error: " + e.getMessage());
            }

            return auditResult(issues);
        }

        @Override
        public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
            if (tab != null && !tab.isPassiveEnabled()) {
                return auditResult(List.of());
            }

            List<AuditIssue> issues = new ArrayList<>();

            try {
                PassiveScanCheck passive = new PassiveScanCheck(api, dedup);
                issues.addAll(passive.check(baseRequestResponse));

                // Secret Extractor: scan JS/JSON/HTML responses for secrets and keys
                if (secretExtractor != null) {
                    List<AuditIssue> secretIssues = secretExtractor.scan(baseRequestResponse);
                    issues.addAll(secretIssues);
                }

                // Also add to JWTLens tab
                for (AuditIssue issue : issues) {
                    addToTab(issue, baseRequestResponse);
                }

                if (!issues.isEmpty()) {
                    tab.incrementJwtsScanned();
                }
            } catch (Exception e) {
                api.logging().logToError("JWTLens passive scan error: " + e.getMessage());
            }

            return auditResult(issues);
        }

        @Override
        public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
            if (newIssue.name().equals(existingIssue.name())) {
                if (newIssue.baseUrl().equals(existingIssue.baseUrl())) {
                    return KEEP_EXISTING;
                }
            }
            return KEEP_BOTH;
        }

        private void addToTab(AuditIssue issue, HttpRequestResponse reqResp) {
            if (tab == null) return;

            String host = reqResp.request().httpService().host();
            String url = reqResp.request().url();
            String severity = issue.severity().name().substring(0, 1).toUpperCase()
                    + issue.severity().name().substring(1).toLowerCase();
            String confidence = issue.confidence().name().substring(0, 1).toUpperCase()
                    + issue.confidence().name().substring(1).toLowerCase();

            // Extract decoded JWT from request for the decoded tab
            String decodedJwt = "";
            try {
                List<JwtToken> tokens = JwtToken.extractFromString(reqResp.request().toString());
                if (!tokens.isEmpty()) {
                    JwtToken jwt = tokens.get(0);
                    decodedJwt = "<h3>Header</h3><pre>" + escapeHtml(jwt.getDecodedHeaderJson())
                            + "</pre><h3>Payload</h3><pre>" + escapeHtml(jwt.getDecodedPayloadJson())
                            + "</pre><h3>Signature</h3><pre>" + jwt.getSignature() + "</pre>";
                }
            } catch (Exception ignored) {}

            tab.addFinding(
                    severity,
                    issue.name(),
                    host,
                    url,
                    confidence,
                    issue.detail(),
                    decodedJwt
            );
        }

        private String escapeHtml(String text) {
            return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        }
    }
}
