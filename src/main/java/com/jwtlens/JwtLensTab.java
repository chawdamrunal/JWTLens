package com.jwtlens;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.file.Files;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Main JWTLens tab that appears in Burp Suite's top-level tab bar.
 * Contains: Findings table, JWT decoder, config panel with wordlist upload.
 */
public class JwtLensTab extends JPanel {

    private final MontoyaApi api;
    private final JwtDedup dedup;

    // Findings table
    private final DefaultTableModel findingsModel;
    private final JTable findingsTable;

    // Detail panes
    private final JEditorPane detailPane;
    private final JEditorPane decodedPane;

    // Config
    private final JLabel wordlistStatusLabel;
    private final JCheckBox passiveEnabledCheck;
    private final JCheckBox activeEnabledCheck;
    private final JSpinner lifetimeThresholdSpinner;

    // Custom wordlist
    private List<String> customWordlist = new ArrayList<>();
    private boolean useCustomWordlist = false;

    // Stats
    private final JLabel statsLabel;
    private int totalFindings = 0;
    private int totalJwtsScanned = 0;

    public JwtLensTab(MontoyaApi api, JwtDedup dedup) {
        this.api = api;
        this.dedup = dedup;
        setLayout(new BorderLayout());

        // ========== TOP: Header ==========
        JPanel headerPanel = createHeaderPanel();
        add(headerPanel, BorderLayout.NORTH);

        // ========== CENTER: Split pane with findings table + detail ==========
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setResizeWeight(0.5);

        // Top: Findings table
        String[] columns = {"#", "Severity", "Issue Name", "Host", "URL", "Confidence", "Time"};
        findingsModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        findingsTable = new JTable(findingsModel);
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        findingsTable.setAutoCreateRowSorter(true);
        findingsTable.setRowHeight(24);
        findingsTable.setFont(new Font("SansSerif", Font.PLAIN, 12));
        findingsTable.getTableHeader().setFont(new Font("SansSerif", Font.BOLD, 12));

        // Column widths
        findingsTable.getColumnModel().getColumn(0).setPreferredWidth(40);   // #
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(70);   // Severity
        findingsTable.getColumnModel().getColumn(2).setPreferredWidth(300);  // Issue Name
        findingsTable.getColumnModel().getColumn(3).setPreferredWidth(150);  // Host
        findingsTable.getColumnModel().getColumn(4).setPreferredWidth(250);  // URL
        findingsTable.getColumnModel().getColumn(5).setPreferredWidth(80);   // Confidence
        findingsTable.getColumnModel().getColumn(6).setPreferredWidth(80);   // Time

        // Severity color renderer
        findingsTable.getColumnModel().getColumn(1).setCellRenderer(new SeverityCellRenderer());

        // Selection listener
        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedFinding();
            }
        });

        JScrollPane tableScroll = new JScrollPane(findingsTable);
        mainSplit.setTopComponent(tableScroll);

        // Bottom: Tabbed detail pane
        JTabbedPane detailTabs = new JTabbedPane();

        detailPane = new JEditorPane("text/html", "<html><body style='font-family:sans-serif;padding:10px;'><i>Select a finding to view details</i></body></html>");
        detailPane.setEditable(false);
        detailTabs.addTab("Advisory", new JScrollPane(detailPane));

        decodedPane = new JEditorPane("text/html", "<html><body style='font-family:sans-serif;padding:10px;'><i>Select a finding to view decoded JWT</i></body></html>");
        decodedPane.setEditable(false);
        detailTabs.addTab("Decoded JWT", new JScrollPane(decodedPane));

        mainSplit.setBottomComponent(detailTabs);

        // ========== RIGHT: Config sidebar ==========
        JPanel configPanel = createConfigPanel();

        JSplitPane outerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        outerSplit.setResizeWeight(0.78);
        outerSplit.setLeftComponent(mainSplit);
        outerSplit.setRightComponent(configPanel);

        add(outerSplit, BorderLayout.CENTER);

        // ========== BOTTOM: Stats ==========
        statsLabel = new JLabel("  JWTs scanned: 0  |  Findings: 0  |  Dedup entries: 0");
        statsLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        statsLabel.setBorder(new EmptyBorder(4, 8, 4, 8));
        add(statsLabel, BorderLayout.SOUTH);

        // Initialize config defaults
        wordlistStatusLabel = findWordlistLabel();
        passiveEnabledCheck = findPassiveCheck();
        activeEnabledCheck = findActiveCheck();
        lifetimeThresholdSpinner = findLifetimeSpinner();
    }

    // Workaround: these are set during createConfigPanel, but we need references
    private JLabel _wordlistLabel;
    private JCheckBox _passiveCheck;
    private JCheckBox _activeCheck;
    private JSpinner _lifetimeSpinner;

    private JLabel findWordlistLabel() { return _wordlistLabel; }
    private JCheckBox findPassiveCheck() { return _passiveCheck; }
    private JCheckBox findActiveCheck() { return _activeCheck; }
    private JSpinner findLifetimeSpinner() { return _lifetimeSpinner; }

    // ================================================================
    // HEADER
    // ================================================================
    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(8, 12, 8, 12));

        JLabel title = new JLabel("JWTLens");
        title.setFont(new Font("SansSerif", Font.BOLD, 18));

        JLabel subtitle = new JLabel("  JWT Security Scanner  |  23 Passive + 33 Active = 56 Checks");
        subtitle.setFont(new Font("SansSerif", Font.PLAIN, 12));
        subtitle.setForeground(Color.GRAY);

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        left.add(title);
        left.add(subtitle);

        JButton clearBtn = new JButton("Clear Findings");
        clearBtn.addActionListener(e -> clearFindings());

        JButton exportBtn = new JButton("Export CSV");
        exportBtn.addActionListener(e -> exportCsv());

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        right.add(clearBtn);
        right.add(exportBtn);

        panel.add(left, BorderLayout.WEST);
        panel.add(right, BorderLayout.EAST);

        return panel;
    }

    // ================================================================
    // CONFIG SIDEBAR
    // ================================================================
    private JPanel createConfigPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));
        panel.setPreferredSize(new Dimension(280, 600));

        // --- Scanner Settings ---
        JPanel scannerPanel = new JPanel();
        scannerPanel.setLayout(new BoxLayout(scannerPanel, BoxLayout.Y_AXIS));
        scannerPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Scanner Settings",
                TitledBorder.LEFT, TitledBorder.TOP,
                new Font("SansSerif", Font.BOLD, 12)));

        _passiveCheck = new JCheckBox("Enable Passive Scanning", true);
        _passiveCheck.setAlignmentX(Component.LEFT_ALIGNMENT);
        scannerPanel.add(_passiveCheck);
        scannerPanel.add(Box.createVerticalStrut(4));

        _activeCheck = new JCheckBox("Enable Active Scanning", true);
        _activeCheck.setAlignmentX(Component.LEFT_ALIGNMENT);
        scannerPanel.add(_activeCheck);
        scannerPanel.add(Box.createVerticalStrut(8));

        JPanel lifetimePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        lifetimePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        lifetimePanel.add(new JLabel("Long lifetime threshold (hours): "));
        _lifetimeSpinner = new JSpinner(new SpinnerNumberModel(24, 1, 8760, 1));
        _lifetimeSpinner.setPreferredSize(new Dimension(60, 24));
        lifetimePanel.add(_lifetimeSpinner);
        scannerPanel.add(lifetimePanel);

        panel.add(scannerPanel);
        panel.add(Box.createVerticalStrut(12));

        // --- Wordlist Settings ---
        JPanel wordlistPanel = new JPanel();
        wordlistPanel.setLayout(new BoxLayout(wordlistPanel, BoxLayout.Y_AXIS));
        wordlistPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Brute Force Wordlist",
                TitledBorder.LEFT, TitledBorder.TOP,
                new Font("SansSerif", Font.BOLD, 12)));

        JLabel builtinLabel = new JLabel("Built-in: " + WeakSecrets.SECRETS.size() + " secrets");
        builtinLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        wordlistPanel.add(builtinLabel);
        wordlistPanel.add(Box.createVerticalStrut(6));

        _wordlistLabel = new JLabel("Custom: Not loaded");
        _wordlistLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        _wordlistLabel.setForeground(Color.GRAY);
        wordlistPanel.add(_wordlistLabel);
        wordlistPanel.add(Box.createVerticalStrut(8));

        JButton uploadBtn = new JButton("Upload Custom Wordlist");
        uploadBtn.setAlignmentX(Component.LEFT_ALIGNMENT);
        uploadBtn.addActionListener(e -> uploadWordlist());
        wordlistPanel.add(uploadBtn);
        wordlistPanel.add(Box.createVerticalStrut(4));

        JButton clearWordlistBtn = new JButton("Reset to Built-in");
        clearWordlistBtn.setAlignmentX(Component.LEFT_ALIGNMENT);
        clearWordlistBtn.addActionListener(e -> clearCustomWordlist());
        wordlistPanel.add(clearWordlistBtn);
        wordlistPanel.add(Box.createVerticalStrut(4));

        JCheckBox appendCheck = new JCheckBox("Append to built-in list", true);
        appendCheck.setAlignmentX(Component.LEFT_ALIGNMENT);
        appendCheck.setToolTipText("If checked, custom wordlist is added to the built-in list. If unchecked, custom wordlist replaces it.");
        wordlistPanel.add(appendCheck);

        panel.add(wordlistPanel);
        panel.add(Box.createVerticalStrut(12));

        // --- Dedup Settings ---
        JPanel dedupPanel = new JPanel();
        dedupPanel.setLayout(new BoxLayout(dedupPanel, BoxLayout.Y_AXIS));
        dedupPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Deduplication",
                TitledBorder.LEFT, TitledBorder.TOP,
                new Font("SansSerif", Font.BOLD, 12)));

        JLabel dedupLine1 = new JLabel("Same JWT per host is scanned");
        dedupLine1.setAlignmentX(Component.LEFT_ALIGNMENT);
        dedupLine1.setFont(new Font("SansSerif", Font.PLAIN, 11));
        dedupPanel.add(dedupLine1);
        JLabel dedupLine2 = new JLabel("only once to avoid duplicates.");
        dedupLine2.setAlignmentX(Component.LEFT_ALIGNMENT);
        dedupLine2.setFont(new Font("SansSerif", Font.PLAIN, 11));
        dedupPanel.add(dedupLine2);
        dedupPanel.add(Box.createVerticalStrut(8));

        JButton clearDedupBtn = new JButton("Clear Dedup Cache");
        clearDedupBtn.setAlignmentX(Component.LEFT_ALIGNMENT);
        clearDedupBtn.addActionListener(e -> {
            dedup.clear();
            api.logging().logToOutput("JWTLens: Dedup cache cleared.");
            updateStats();
        });
        dedupPanel.add(clearDedupBtn);

        panel.add(dedupPanel);
        panel.add(Box.createVerticalStrut(12));

        // --- Quick Actions ---
        JPanel actionsPanel = new JPanel();
        actionsPanel.setLayout(new BoxLayout(actionsPanel, BoxLayout.Y_AXIS));
        actionsPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Quick Actions",
                TitledBorder.LEFT, TitledBorder.TOP,
                new Font("SansSerif", Font.BOLD, 12)));

        JLabel actionLine1 = new JLabel("Right-click any request in");
        actionLine1.setAlignmentX(Component.LEFT_ALIGNMENT);
        actionLine1.setFont(new Font("SansSerif", Font.PLAIN, 11));
        actionsPanel.add(actionLine1);
        JLabel actionLine2 = new JLabel("Proxy/Repeater for scan options.");
        actionLine2.setAlignmentX(Component.LEFT_ALIGNMENT);
        actionLine2.setFont(new Font("SansSerif", Font.PLAIN, 11));
        actionsPanel.add(actionLine2);

        panel.add(actionsPanel);

        // Glue to push everything to top
        panel.add(Box.createVerticalGlue());

        return panel;
    }

    // ================================================================
    // PUBLIC API (called by scanner checks)
    // ================================================================

    /**
     * Adds a finding to the tab's findings table.
     * Thread-safe: can be called from scanner threads.
     */
    public void addFinding(String severity, String issueName, String host, String url,
                           String confidence, String detail, String decodedJwt) {
        SwingUtilities.invokeLater(() -> {
            totalFindings++;
            String time = DateTimeFormatter.ofPattern("HH:mm:ss")
                    .withZone(ZoneId.systemDefault())
                    .format(Instant.now());

            findingsModel.addRow(new Object[]{
                    totalFindings,
                    severity,
                    issueName,
                    host,
                    url,
                    confidence,
                    time
            });

            // Store detail and decoded as client properties on the model
            // We use row index as key
            int row = findingsModel.getRowCount() - 1;
            findingsTable.putClientProperty("detail_" + row, detail);
            findingsTable.putClientProperty("decoded_" + row, decodedJwt);

            updateStats();
        });
    }

    public void incrementJwtsScanned() {
        totalJwtsScanned++;
        SwingUtilities.invokeLater(this::updateStats);
    }

    public boolean isPassiveEnabled() {
        return _passiveCheck == null || _passiveCheck.isSelected();
    }

    public boolean isActiveEnabled() {
        return _activeCheck == null || _activeCheck.isSelected();
    }

    public int getLifetimeThresholdHours() {
        if (_lifetimeSpinner == null) return 24;
        return (int) _lifetimeSpinner.getValue();
    }

    /**
     * Returns the effective wordlist (custom + built-in or custom only).
     */
    public List<String> getEffectiveWordlist() {
        if (!useCustomWordlist || customWordlist.isEmpty()) {
            return WeakSecrets.SECRETS;
        }
        // Check if append mode
        List<String> combined = new ArrayList<>(WeakSecrets.SECRETS);
        combined.addAll(customWordlist);
        return combined;
    }

    // ================================================================
    // INTERNAL METHODS
    // ================================================================

    private void showSelectedFinding() {
        int viewRow = findingsTable.getSelectedRow();
        if (viewRow < 0) return;

        int modelRow = findingsTable.convertRowIndexToModel(viewRow);
        String detail = (String) findingsTable.getClientProperty("detail_" + modelRow);
        String decoded = (String) findingsTable.getClientProperty("decoded_" + modelRow);
        String severity = (String) findingsModel.getValueAt(modelRow, 1);
        String issueName = (String) findingsModel.getValueAt(modelRow, 2);
        String url = (String) findingsModel.getValueAt(modelRow, 4);
        String confidence = (String) findingsModel.getValueAt(modelRow, 5);

        String severityColor = switch (severity) {
            case "High" -> "#e74c3c";
            case "Medium" -> "#f39c12";
            case "Low" -> "#3498db";
            default -> "#95a5a6";
        };

        String html = "<html><body style='font-family:sans-serif;padding:12px;'>"
                + "<h2 style='margin:0 0 8px 0;'>" + issueName + "</h2>"
                + "<table cellpadding='3'>"
                + "<tr><td><b>Severity:</b></td><td><span style='color:" + severityColor + ";font-weight:bold;'>" + severity + "</span></td></tr>"
                + "<tr><td><b>Confidence:</b></td><td>" + confidence + "</td></tr>"
                + "<tr><td><b>URL:</b></td><td>" + url + "</td></tr>"
                + "</table>"
                + "<hr style='margin:12px 0;'>"
                + "<h3>Issue Detail</h3>"
                + (detail != null ? detail : "<i>No details available</i>")
                + "</body></html>";

        detailPane.setText(html);
        detailPane.setCaretPosition(0);

        String decodedHtml = "<html><body style='font-family:monospace;padding:12px;'>"
                + (decoded != null ? decoded : "<i>No JWT data available</i>")
                + "</body></html>";
        decodedPane.setText(decodedHtml);
        decodedPane.setCaretPosition(0);
    }

    private void clearFindings() {
        findingsModel.setRowCount(0);
        totalFindings = 0;
        detailPane.setText("<html><body style='font-family:sans-serif;padding:10px;'><i>Findings cleared</i></body></html>");
        decodedPane.setText("<html><body style='font-family:sans-serif;padding:10px;'><i>Findings cleared</i></body></html>");
        updateStats();
    }

    private void exportCsv() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Findings as CSV");
        chooser.setSelectedFile(new File("jwtlens_findings.csv"));
        chooser.setFileFilter(new FileNameExtensionFilter("CSV Files", "csv"));

        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                File file = chooser.getSelectedFile();
                StringBuilder csv = new StringBuilder();
                csv.append("#,Severity,Issue Name,Host,URL,Confidence,Time\n");

                for (int i = 0; i < findingsModel.getRowCount(); i++) {
                    for (int j = 0; j < findingsModel.getColumnCount(); j++) {
                        if (j > 0) csv.append(",");
                        String val = String.valueOf(findingsModel.getValueAt(i, j));
                        csv.append("\"").append(val.replace("\"", "\"\"")).append("\"");
                    }
                    csv.append("\n");
                }

                Files.writeString(file.toPath(), csv.toString());
                api.logging().logToOutput("JWTLens: Exported " + findingsModel.getRowCount() + " findings to " + file.getAbsolutePath());
                JOptionPane.showMessageDialog(this,
                        "Exported " + findingsModel.getRowCount() + " findings to:\n" + file.getAbsolutePath(),
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                api.logging().logToError("JWTLens: Export failed: " + ex.getMessage());
                JOptionPane.showMessageDialog(this,
                        "Export failed: " + ex.getMessage(),
                        "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void uploadWordlist() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select JWT Secret Wordlist");
        chooser.setFileFilter(new FileNameExtensionFilter("Text Files (*.txt, *.lst)", "txt", "lst"));

        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                File file = chooser.getSelectedFile();
                List<String> lines = new ArrayList<>();

                try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (!line.isEmpty() && !line.startsWith("#")) {
                            lines.add(line);
                        }
                    }
                }

                customWordlist = lines;
                useCustomWordlist = true;

                _wordlistLabel.setText("Custom: " + lines.size() + " secrets loaded");
                _wordlistLabel.setForeground(new Color(0, 128, 0));

                api.logging().logToOutput("JWTLens: Loaded custom wordlist with " + lines.size() + " entries from " + file.getName());
            } catch (Exception ex) {
                api.logging().logToError("JWTLens: Wordlist load failed: " + ex.getMessage());
                JOptionPane.showMessageDialog(this,
                        "Failed to load wordlist: " + ex.getMessage(),
                        "Load Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void clearCustomWordlist() {
        customWordlist.clear();
        useCustomWordlist = false;
        _wordlistLabel.setText("Custom: Not loaded");
        _wordlistLabel.setForeground(Color.GRAY);
        api.logging().logToOutput("JWTLens: Reset to built-in wordlist.");
    }

    private void updateStats() {
        statsLabel.setText("  JWTs scanned: " + totalJwtsScanned
                + "  |  Findings: " + totalFindings
                + "  |  Dedup entries: " + dedup.size());
    }

    // ================================================================
    // SEVERITY COLOR RENDERER
    // ================================================================
    private static class SeverityCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected && value instanceof String severity) {
                switch (severity) {
                    case "High" -> { c.setForeground(new Color(231, 76, 60)); setFont(getFont().deriveFont(Font.BOLD)); }
                    case "Medium" -> { c.setForeground(new Color(243, 156, 18)); setFont(getFont().deriveFont(Font.BOLD)); }
                    case "Low" -> { c.setForeground(new Color(52, 152, 219)); setFont(getFont().deriveFont(Font.PLAIN)); }
                    default -> { c.setForeground(new Color(149, 165, 166)); setFont(getFont().deriveFont(Font.PLAIN)); }
                }
            } else if (isSelected) {
                c.setForeground(table.getSelectionForeground());
            }
            return c;
        }
    }
}
