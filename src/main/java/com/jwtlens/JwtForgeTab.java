package com.jwtlens;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * JWT Forge Tab — a live JWT editor and forger built into Burp Suite.
 * Like jwt.io but with signing capability, secret auto-fill from brute force,
 * and one-click Send to Repeater.
 */
public class JwtForgeTab extends JPanel {

    private final burp.api.montoya.MontoyaApi api;

    // Input
    private final JTextArea rawTokenArea;
    private final JTextArea headerArea;
    private final JTextArea payloadArea;
    private final JLabel signatureLabel;

    // Signing controls
    private JComboBox<String> algCombo;
    private JTextArea secretKeyArea;
    private final JLabel statusLabel;

    // Output
    private final JTextArea forgedTokenArea;

    // State
    private boolean updatingFromRaw = false;
    private boolean updatingFromEdited = false;
    private String lastDiscoveredSecret = null;
    private String lastDiscoveredAlg = null;

    public JwtForgeTab(burp.api.montoya.MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout(0, 0));

        // ========== TOP: Title bar ==========
        JPanel titleBar = new JPanel(new BorderLayout());
        titleBar.setBorder(new EmptyBorder(8, 12, 8, 12));
        JLabel title = new JLabel("JWT Forge");
        title.setFont(new Font("SansSerif", Font.BOLD, 16));
        JLabel subtitle = new JLabel("  Decode, edit, re-sign, and send forged JWTs");
        subtitle.setFont(new Font("SansSerif", Font.PLAIN, 12));
        subtitle.setForeground(Color.GRAY);
        JPanel titleLeft = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        titleLeft.add(title);
        titleLeft.add(subtitle);
        titleBar.add(titleLeft, BorderLayout.WEST);

        statusLabel = new JLabel("");
        statusLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
        titleBar.add(statusLabel, BorderLayout.EAST);

        add(titleBar, BorderLayout.NORTH);

        // ========== CENTER: Main editor ==========
        JPanel centerPanel = new JPanel(new GridBagLayout());
        centerPanel.setBorder(new EmptyBorder(4, 12, 4, 12));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(4, 4, 4, 4);

        // Left side: Raw JWT input
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.4; gbc.weighty = 0.0;
        gbc.gridheight = 1;
        centerPanel.add(createLabel("Encoded JWT (paste token here)"), gbc);

        rawTokenArea = new JTextArea(6, 40);
        rawTokenArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        rawTokenArea.setLineWrap(true);
        rawTokenArea.setWrapStyleWord(false);
        rawTokenArea.setForeground(new Color(220, 50, 47));
        gbc.gridy = 1; gbc.weighty = 0.2;
        centerPanel.add(new JScrollPane(rawTokenArea), gbc);

        // Right side: Header
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 0.6; gbc.weighty = 0.0;
        centerPanel.add(createLabel("Header (editable JSON)"), gbc);

        headerArea = new JTextArea(5, 50);
        headerArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        headerArea.setForeground(new Color(211, 54, 130));
        gbc.gridy = 1; gbc.weighty = 0.15;
        centerPanel.add(new JScrollPane(headerArea), gbc);

        // Payload
        gbc.gridx = 1; gbc.gridy = 2; gbc.weighty = 0.0;
        centerPanel.add(createLabel("Payload (editable JSON)"), gbc);

        payloadArea = new JTextArea(10, 50);
        payloadArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        payloadArea.setForeground(new Color(42, 161, 152));
        gbc.gridy = 3; gbc.weighty = 0.35;
        centerPanel.add(new JScrollPane(payloadArea), gbc);

        // Signing panel (left side, below raw)
        gbc.gridx = 0; gbc.gridy = 2; gbc.weighty = 0.0;
        centerPanel.add(createLabel("Signing"), gbc);

        JPanel signingPanel = createSigningPanel();
        gbc.gridy = 3; gbc.weighty = 0.35;
        centerPanel.add(signingPanel, gbc);

        // Signature display
        gbc.gridx = 1; gbc.gridy = 4; gbc.weighty = 0.0;
        signatureLabel = new JLabel("Signature: (none)");
        signatureLabel.setFont(new Font("Monospaced", Font.PLAIN, 11));
        signatureLabel.setForeground(new Color(108, 113, 196));
        centerPanel.add(signatureLabel, gbc);

        // Forged token output
        gbc.gridx = 0; gbc.gridy = 4; gbc.weighty = 0.0; gbc.gridwidth = 1;
        centerPanel.add(createLabel("Forged Token Output"), gbc);

        gbc.gridx = 0; gbc.gridy = 5; gbc.weighty = 0.15; gbc.gridwidth = 2;
        forgedTokenArea = new JTextArea(3, 80);
        forgedTokenArea.setFont(new Font("Monospaced", Font.BOLD, 13));
        forgedTokenArea.setLineWrap(true);
        forgedTokenArea.setWrapStyleWord(false);
        forgedTokenArea.setEditable(false);
        forgedTokenArea.setBackground(new Color(245, 245, 245));
        forgedTokenArea.setForeground(new Color(0, 100, 0));
        centerPanel.add(new JScrollPane(forgedTokenArea), gbc);

        // Action buttons
        gbc.gridx = 0; gbc.gridy = 6; gbc.weighty = 0.0; gbc.gridwidth = 2;
        centerPanel.add(createButtonPanel(), gbc);

        add(centerPanel, BorderLayout.CENTER);

        // Wire up listeners
        setupListeners();

        // Algorithm combo
        algCombo.setSelectedItem("HS256");
    }

    private JLabel createLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("SansSerif", Font.BOLD, 12));
        return label;
    }

    private JPanel createSigningPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Sign Token",
                TitledBorder.LEFT, TitledBorder.TOP,
                new Font("SansSerif", Font.BOLD, 11)));

        // Algorithm selector
        JPanel algPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        algPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        algPanel.add(new JLabel("Algorithm:"));
        algCombo = new JComboBox<>(new String[]{
                "none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512"
        });
        algCombo.setFont(new Font("Monospaced", Font.BOLD, 12));
        algCombo.setPreferredSize(new Dimension(100, 26));
        algPanel.add(algCombo);

        JButton useDiscoveredBtn = new JButton("Use Discovered Secret");
        useDiscoveredBtn.setFont(new Font("SansSerif", Font.PLAIN, 10));
        useDiscoveredBtn.setToolTipText("Auto-fill with secret found during brute force scan");
        useDiscoveredBtn.addActionListener(e -> fillDiscoveredSecret());
        algPanel.add(useDiscoveredBtn);
        panel.add(algPanel);

        panel.add(Box.createVerticalStrut(4));

        // Secret/Key input
        JLabel keyLabel = new JLabel("Secret / Private Key:");
        keyLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        keyLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        panel.add(keyLabel);

        secretKeyArea = new JTextArea(6, 30);
        secretKeyArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        secretKeyArea.setLineWrap(true);
        secretKeyArea.setWrapStyleWord(false);
        JScrollPane keyScroll = new JScrollPane(secretKeyArea);
        keyScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(keyScroll);

        panel.add(Box.createVerticalStrut(4));

        JButton signBtn = new JButton("Sign Token");
        signBtn.setFont(new Font("SansSerif", Font.BOLD, 12));
        signBtn.setAlignmentX(Component.LEFT_ALIGNMENT);
        signBtn.setBackground(new Color(46, 204, 113));
        signBtn.addActionListener(e -> signToken());
        panel.add(signBtn);

        return panel;
    }

    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        JButton copyBtn = new JButton("Copy Forged Token");
        copyBtn.addActionListener(e -> {
            String token = forgedTokenArea.getText().trim();
            if (!token.isEmpty()) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(token), null);
                setStatus("Copied to clipboard", new Color(46, 204, 113));
            }
        });
        panel.add(copyBtn);

        JButton curlBtn = new JButton("Copy as cURL");
        curlBtn.addActionListener(e -> copyAsCurl());
        panel.add(curlBtn);

        JButton pythonBtn = new JButton("Copy as Python");
        pythonBtn.addActionListener(e -> copyAsPython());
        panel.add(pythonBtn);

        JButton clearBtn = new JButton("Clear All");
        clearBtn.addActionListener(e -> clearAll());
        panel.add(clearBtn);

        return panel;
    }

    // ================================================================
    // LISTENERS
    // ================================================================

    private void setupListeners() {
        // When raw token changes, decode into header/payload
        rawTokenArea.getDocument().addDocumentListener(new SimpleDocListener() {
            @Override
            public void onChange() {
                if (updatingFromEdited) return;
                updatingFromRaw = true;
                try {
                    decodeRawToken();
                } finally {
                    updatingFromRaw = false;
                }
            }
        });

        // When header/payload edits happen, rebuild the forged token
        DocumentListener editListener = new SimpleDocListener() {
            @Override
            public void onChange() {
                if (updatingFromRaw) return;
                updatingFromEdited = true;
                try {
                    rebuildForgedToken();
                } finally {
                    updatingFromEdited = false;
                }
            }
        };
        headerArea.getDocument().addDocumentListener(editListener);
        payloadArea.getDocument().addDocumentListener(editListener);

        algCombo.addActionListener(e -> {
            if (!updatingFromRaw) rebuildForgedToken();
        });
    }

    // ================================================================
    // CORE LOGIC
    // ================================================================

    private void decodeRawToken() {
        String raw = rawTokenArea.getText().trim();
        if (raw.isEmpty()) {
            headerArea.setText("");
            payloadArea.setText("");
            signatureLabel.setText("Signature: (none)");
            forgedTokenArea.setText("");
            setStatus("", Color.GRAY);
            return;
        }

        try {
            JwtToken jwt = new JwtToken(raw);
            headerArea.setText(prettyJson(jwt.getDecodedHeaderJson()));
            payloadArea.setText(prettyJson(jwt.getDecodedPayloadJson()));
            signatureLabel.setText("Signature: " + truncate(jwt.getSignature(), 60));

            // Set algorithm combo to match token
            jwt.getAlg().ifPresent(alg -> algCombo.setSelectedItem(alg));

            setStatus("Decoded successfully", new Color(46, 204, 113));
            rebuildForgedToken();
        } catch (Exception e) {
            setStatus("Invalid JWT: " + e.getMessage(), new Color(231, 76, 60));
        }
    }

    private void rebuildForgedToken() {
        String headerJson = headerArea.getText().trim();
        String payloadJson = payloadArea.getText().trim();
        if (headerJson.isEmpty() || payloadJson.isEmpty()) return;

        try {
            com.google.gson.Gson gson = new com.google.gson.GsonBuilder().disableHtmlEscaping().create();
            java.lang.reflect.Type mapType = new com.google.gson.reflect.TypeToken<LinkedHashMap<String, Object>>(){}.getType();

            LinkedHashMap<String, Object> header = gson.fromJson(headerJson, mapType);
            LinkedHashMap<String, Object> payload = gson.fromJson(payloadJson, mapType);

            // Override alg from combo
            String selectedAlg = (String) algCombo.getSelectedItem();
            header.put("alg", selectedAlg);

            // Build unsigned token
            java.util.Base64.Encoder b64 = java.util.Base64.getUrlEncoder().withoutPadding();
            String headerB64 = b64.encodeToString(gson.toJson(header).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String payloadB64 = b64.encodeToString(gson.toJson(payload).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String signingInput = headerB64 + "." + payloadB64;

            String signature = "";
            if ("none".equalsIgnoreCase(selectedAlg)) {
                signature = "";
            } else {
                // Keep original signature for display; user must click "Sign" to re-sign
                String raw = rawTokenArea.getText().trim();
                if (!raw.isEmpty()) {
                    String[] parts = raw.split("\\.", -1);
                    if (parts.length == 3) {
                        signature = parts[2];
                    }
                }
            }

            String token = signingInput + "." + signature;
            forgedTokenArea.setText(token);
            signatureLabel.setText("Signature: " + ("".equals(signature) ? "(empty)" : truncate(signature, 60)));
        } catch (Exception e) {
            // JSON parse error while editing, expected
        }
    }

    private void signToken() {
        String headerJson = headerArea.getText().trim();
        String payloadJson = payloadArea.getText().trim();
        String secret = secretKeyArea.getText();

        if (headerJson.isEmpty() || payloadJson.isEmpty()) {
            setStatus("Header and payload cannot be empty", new Color(231, 76, 60));
            return;
        }

        try {
            com.google.gson.Gson gson = new com.google.gson.GsonBuilder().disableHtmlEscaping().create();
            java.lang.reflect.Type mapType = new com.google.gson.reflect.TypeToken<LinkedHashMap<String, Object>>(){}.getType();

            LinkedHashMap<String, Object> header = gson.fromJson(headerJson, mapType);
            LinkedHashMap<String, Object> payload = gson.fromJson(payloadJson, mapType);

            String selectedAlg = (String) algCombo.getSelectedItem();
            header.put("alg", selectedAlg);

            java.util.Base64.Encoder b64 = java.util.Base64.getUrlEncoder().withoutPadding();
            String headerB64 = b64.encodeToString(gson.toJson(header).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String payloadB64 = b64.encodeToString(gson.toJson(payload).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String signingInput = headerB64 + "." + payloadB64;

            String signature;

            switch (selectedAlg) {
                case "none" -> signature = "";
                case "HS256" -> signature = CryptoUtils.signHmac("HmacSHA256", signingInput, secret);
                case "HS384" -> signature = CryptoUtils.signHmac("HmacSHA384", signingInput, secret);
                case "HS512" -> signature = CryptoUtils.signHmac("HmacSHA512", signingInput, secret);
                case "RS256", "RS384", "RS512" -> {
                    KeyPair kp = CryptoUtils.getOrGenerateRsaKeyPair();
                    String rsaAlg = switch (selectedAlg) {
                        case "RS256" -> "SHA256withRSA";
                        case "RS384" -> "SHA384withRSA";
                        case "RS512" -> "SHA512withRSA";
                        default -> "SHA256withRSA";
                    };
                    signature = CryptoUtils.signRsa(rsaAlg, signingInput, kp.getPrivate());
                }
                default -> {
                    setStatus("Unsupported algorithm: " + selectedAlg, new Color(231, 76, 60));
                    return;
                }
            }

            String token = signingInput + "." + signature;
            forgedTokenArea.setText(token);
            signatureLabel.setText("Signature: " + ("".equals(signature) ? "(empty - alg none)" : truncate(signature, 60)));

            // Update header area to reflect the alg
            headerArea.setText(prettyJson(gson.toJson(header)));

            setStatus("Signed with " + selectedAlg, new Color(46, 204, 113));
        } catch (Exception e) {
            setStatus("Signing failed: " + e.getMessage(), new Color(231, 76, 60));
        }
    }

    // ================================================================
    // PoC EXPORT
    // ================================================================

    private void copyAsCurl() {
        String token = forgedTokenArea.getText().trim();
        if (token.isEmpty()) {
            setStatus("No forged token to export", new Color(231, 76, 60));
            return;
        }
        String curl = "curl -H 'Authorization: Bearer " + token + "' <TARGET_URL>";
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(curl), null);
        setStatus("cURL copied to clipboard", new Color(46, 204, 113));
    }

    private void copyAsPython() {
        String token = forgedTokenArea.getText().trim();
        if (token.isEmpty()) {
            setStatus("No forged token to export", new Color(231, 76, 60));
            return;
        }
        String python = "import requests\n\n"
                + "token = \"" + token + "\"\n"
                + "headers = {\"Authorization\": f\"Bearer {token}\"}\n"
                + "r = requests.get(\"<TARGET_URL>\", headers=headers)\n"
                + "print(r.status_code, r.text[:500])";
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(python), null);
        setStatus("Python script copied to clipboard", new Color(46, 204, 113));
    }

    private void clearAll() {
        rawTokenArea.setText("");
        headerArea.setText("");
        payloadArea.setText("");
        secretKeyArea.setText("");
        forgedTokenArea.setText("");
        signatureLabel.setText("Signature: (none)");
        setStatus("Cleared", Color.GRAY);
    }

    // ================================================================
    // PUBLIC API
    // ================================================================

    /**
     * Called by brute force or active scan when a secret is discovered.
     * Auto-fills the forge tab for immediate use.
     */
    public void setDiscoveredSecret(String secret, String algorithm) {
        this.lastDiscoveredSecret = secret;
        this.lastDiscoveredAlg = algorithm;
        api.logging().logToOutput("JWTLens Forge: Secret discovered and stored — use 'Use Discovered Secret' button.");
    }

    /**
     * Loads a JWT into the forge tab from another component (e.g., findings table, context menu).
     */
    public void loadToken(String encodedJwt) {
        SwingUtilities.invokeLater(() -> rawTokenArea.setText(encodedJwt));
    }

    /**
     * Loads a JWT and pre-fills the secret for immediate re-signing.
     */
    public void loadTokenWithSecret(String encodedJwt, String secret, String algorithm) {
        SwingUtilities.invokeLater(() -> {
            rawTokenArea.setText(encodedJwt);
            secretKeyArea.setText(secret);
            if (algorithm != null) {
                algCombo.setSelectedItem(algorithm);
            }
        });
    }

    // ================================================================
    // HELPERS
    // ================================================================

    private void fillDiscoveredSecret() {
        if (lastDiscoveredSecret != null) {
            secretKeyArea.setText(lastDiscoveredSecret);
            if (lastDiscoveredAlg != null) {
                algCombo.setSelectedItem(lastDiscoveredAlg);
            }
            setStatus("Loaded discovered secret: " + truncate(lastDiscoveredSecret, 30), new Color(46, 204, 113));
        } else {
            setStatus("No secret discovered yet. Run brute force scan first.", new Color(243, 156, 18));
        }
    }

    private void setStatus(String message, Color color) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(message);
            statusLabel.setForeground(color);
        });
    }

    private String prettyJson(String json) {
        try {
            com.google.gson.Gson gson = new com.google.gson.GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
            Object obj = gson.fromJson(json, Object.class);
            return gson.toJson(obj);
        } catch (Exception e) {
            return json;
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) return "(null)";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...";
    }

    // Simple DocumentListener adapter
    private static abstract class SimpleDocListener implements DocumentListener {
        public abstract void onChange();
        @Override public void insertUpdate(DocumentEvent e) { onChange(); }
        @Override public void removeUpdate(DocumentEvent e) { onChange(); }
        @Override public void changedUpdate(DocumentEvent e) { onChange(); }
    }
}
