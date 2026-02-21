import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.KeyStroke;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * Payload Transcoder tab: dedicated UI for encoding/decoding custom protocols
 * not available in Burp's built-in Decoder.
 */
public class PayloadTranscoderTab extends JPanel {

    private final MontoyaApi montoyaApi;
    private final RawEditor inputEditor;
    private final RawEditor outputEditor;
    private final JComboBox<String> formatCombo;
    private final JPanel inputPanel;
    private final Border tabDefaultBorder;
    private final JLabel statusLabel;
    private final JLabel statsLabel;
    private final DefaultListModel<String> chainModel;
    private final JTextField regexFindField;
    private final JTextField regexReplaceField;
    private final JSpinner regexGroupSpinner;
    private final JButton insertTemplateBtn;
    private final JButton generateOobBtn;
    private final JTextArea batchInputArea;
    private final JTextArea batchOutputArea;
    private final JCheckBox smartDecodeCheckbox;
    private byte[] lastInputBeforeTranscode;
    private final List<String> smartDecodeChain = new ArrayList<>();

    private static final String[] OPERATIONS = {
            "Decode Base64",
            "Decode Base64 URL-safe",
            "Decode Hex",
            "Decode URL",
            "Decode HTML entities",
            "Decode Unicode escapes",
            "Decode Quoted-printable",
            "Decode gzip",
            "Decode deflate",
            "Decode Brotli",
            "Decode zstd",
            "Decode MessagePack",
            "Decode CBOR",
            "Decode BSON",
            "Decode JWT (pretty-print)",
            "Decode gRPC message",
            "Decode gRPC-Web (protobuf view)",
            "Decode gRPC-Web (JSON)",
            "Decode gRPC-Web (JSON with mapping)",
            "Protobuf raw wire view",
            "Protobuf decode (field mapping)",
            "---",
            "Form/query pretty-print",
            "Form/query rebuild",
            "Multipart pretty-print",
            "WebSocket frame inspect",
            "---",
            "Hex dump (view)",
            "Parse hex dump",
            "---",
            "GraphQL introspection pretty-print",
            "---",
            "Validate PKCS7 padding",
            "Strip PKCS7 padding",
            "Add PKCS7 padding",
            "---",
            "Normalize NFC",
            "Normalize NFD",
            "Normalize NFKC",
            "Normalize NFKD",
            "---",
            "Encode homoglyph (Latin→Cyrillic)",
            "Decode homoglyph (Cyrillic→Latin)",
            "---",
            "Generate polyglot (HTML+JS+URL)",
            "Generate polyglot (SQL+HTML)",
            "---",
            "PHP serialize pretty-print",
            "PHP serialize string",
            "---",
            "AWS SigV4 sign",
            "---",
            "Encode Base64",
            "Encode Base64 URL-safe",
            "Encode Hex",
            "Encode URL",
            "Encode HTML entities",
            "Encode Unicode escapes",
            "Encode Quoted-printable",
            "Encode gzip",
            "Encode deflate",
            "Encode Brotli",
            "Encode zstd",
            "Encode MessagePack",
            "Encode CBOR",
            "Encode BSON",
            "Encode gRPC frame",
            "Encode protobuf from JSON",
            "Encode gRPC-Web from JSON",
            "---",
            "JSON pretty-print",
            "JSON minify",
            "GraphQL pretty-print",
            "XML pretty-print",
            "---",
            "Hash MD5",
            "Hash SHA-1",
            "Hash SHA-256",
            "---",
            "JWT alg:none attack",
            "JWT RS256→HS256 (pubkey as secret)",
            "JWT extend expiry (re-sign)",
            "JWT crack (wordlist)",
            "Sign JWT (HS256)",
            "---",
            "HMAC-SHA256 (secret)",
            "HMAC-SHA256 webhook (sha256=hex)",
            "---",
            "Detect Java serialized",
            "Detect .NET ViewState",
            "---",
            "Timestamp: Unix now",
            "Timestamp: Unix ms now",
            "Timestamp: ISO8601 now",
            "Timestamp: RFC2822 now",
    };

    /** Operations that require user input (dialogs) and cannot run in chain or batch. */
    private static final Set<String> PROMPT_OPS = Set.of(
            "Sign JWT (HS256)",
            "JWT RS256→HS256 (pubkey as secret)",
            "JWT extend expiry (re-sign)",
            "JWT crack (wordlist)",
            "HMAC-SHA256 (secret)",
            "HMAC-SHA256 webhook (sha256=hex)",
            "Protobuf decode (field mapping)",
            "AWS SigV4 sign",
            "Decode gRPC-Web (JSON with mapping)",
            "Multipart pretty-print"
    );

    private static final String[] BATCH_OPERATIONS = Arrays.stream(OPERATIONS)
            .filter(op -> !PROMPT_OPS.contains(op))
            .toArray(String[]::new);

    public PayloadTranscoderTab(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        tabDefaultBorder = getBorder();

        inputPanel = new JPanel(new BorderLayout(5, 5));
        JPanel inputHeader = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        inputHeader.add(new JLabel("Input:"));
        statusLabel = new JLabel(" ");
        statusLabel.setForeground(new Color(0, 128, 0));
        inputHeader.add(statusLabel);
        inputPanel.add(inputHeader, BorderLayout.NORTH);
        inputEditor = montoyaApi.userInterface().createRawEditor();
        inputPanel.add(inputEditor.uiComponent(), BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new BorderLayout(5, 5));
        bottomPanel.add(new JLabel("Output:"), BorderLayout.NORTH);
        outputEditor = montoyaApi.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        bottomPanel.add(outputEditor.uiComponent(), BorderLayout.CENTER);

        // Main control panel - split into logical rows
        JPanel controlPanel = new JPanel();
        controlPanel.setLayout(new BoxLayout(controlPanel, BoxLayout.Y_AXIS));
        controlPanel.add(Box.createVerticalStrut(2));

        // Row 1: Operation + primary actions
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        row1.add(new JLabel("Operation:"));
        formatCombo = new JComboBox<>(OPERATIONS);
        formatCombo.setPreferredSize(new Dimension(220, 25));
        formatCombo.setToolTipText("Select transformation operation");
        row1.add(formatCombo);

        JButton transcodeBtn = new JButton("Transcode");
        transcodeBtn.addActionListener(e -> transcode());
        transcodeBtn.setToolTipText("Apply selected operation to input");
        row1.add(transcodeBtn);

        JButton addToChainBtn = new JButton("Add to chain");
        addToChainBtn.addActionListener(e -> addToChain());
        addToChainBtn.setToolTipText("Add selected operation to chain for sequential processing");
        row1.add(addToChainBtn);

        JButton suggestBtn = new JButton("Suggest");
        suggestBtn.addActionListener(e -> showSuggestions());
        suggestBtn.setToolTipText("Analyze input and suggest likely encodings/operations");
        row1.add(suggestBtn);

        JButton smartDecodeBtn = new JButton("Smart decode");
        smartDecodeBtn.addActionListener(e -> runSmartDecode());
        smartDecodeBtn.setToolTipText("Auto-detect and apply decode/format operations");
        row1.add(smartDecodeBtn);

        JButton prettyBtn = new JButton("Pretty");
        prettyBtn.addActionListener(e -> runPretty());
        prettyBtn.setToolTipText("Pretty-print JSON, XML, or GraphQL (no decoding)");
        row1.add(prettyBtn);

        smartDecodeCheckbox = new JCheckBox("Auto on load/send", true);
        smartDecodeCheckbox.setToolTipText("Automatically smart decode when loading file or receiving from context");
        row1.add(smartDecodeCheckbox);
        controlPanel.add(row1);

        // Row 2: I/O actions
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        JButton undoBtn = new JButton("Undo");
        undoBtn.addActionListener(e -> undo());
        undoBtn.setToolTipText("Revert input to state before last transcode");
        row2.add(undoBtn);

        JButton sendToDecoderBtn = new JButton("Send output to Decoder");
        sendToDecoderBtn.addActionListener(e -> sendOutputToDecoder());
        sendToDecoderBtn.setToolTipText("Send output to Burp Decoder");
        row2.add(sendToDecoderBtn);

        JButton swapBtn = new JButton("Swap input ↔ output");
        swapBtn.addActionListener(e -> swapInputOutput());
        swapBtn.setToolTipText("Swap input and output (e.g. decode → modify → swap → encode)");
        row2.add(swapBtn);

        JButton compareBtn = new JButton("Compare input vs output");
        compareBtn.addActionListener(e -> sendToComparer());
        compareBtn.setToolTipText("Send input and output to Burp Comparer");
        row2.add(compareBtn);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> clearAll());
        clearBtn.setToolTipText("Clear input, output, and chain");
        row2.add(clearBtn);
        controlPanel.add(row2);

        // Row 3: File/template actions
        JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        JButton pasteSmartBtn = new JButton("Paste & smart decode");
        pasteSmartBtn.addActionListener(e -> pasteAndSmartDecode());
        pasteSmartBtn.setToolTipText("Paste from clipboard and run smart decode");
        row3.add(pasteSmartBtn);

        JButton loadFileBtn = new JButton("Load file");
        loadFileBtn.addActionListener(e -> loadFile());
        loadFileBtn.setToolTipText("Load file contents into input for analysis");
        row3.add(loadFileBtn);

        JButton saveOutputBtn = new JButton("Save output");
        saveOutputBtn.addActionListener(e -> saveOutput());
        saveOutputBtn.setToolTipText("Save output to file");
        row3.add(saveOutputBtn);

        // Templates
        insertTemplateBtn = new JButton("Insert template");
        insertTemplateBtn.addActionListener(e -> showTemplateMenu());
        insertTemplateBtn.setToolTipText("Insert security testing payload template");
        row3.add(insertTemplateBtn);

        generateOobBtn = new JButton("Generate OOB");
        generateOobBtn.addActionListener(e -> showOobMenu());
        generateOobBtn.setToolTipText("Generate OOB/SSRF callback URL");
        row3.add(generateOobBtn);
        controlPanel.add(row3);

        // Chain panel (collapsible)
        chainModel = new DefaultListModel<>();
        JPanel chainContent = new JPanel(new BorderLayout(5, 5));
        JList<String> chainList = new JList<>(chainModel);
        chainList.setVisibleRowCount(3);
        chainContent.add(new JScrollPane(chainList), BorderLayout.CENTER);
        JPanel chainButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton runChainBtn = new JButton("Run chain");
        runChainBtn.addActionListener(e -> runChain());
        runChainBtn.setToolTipText("Run all chain operations in sequence");
        chainButtons.add(runChainBtn);
        JButton clearChainBtn = new JButton("Clear chain");
        clearChainBtn.addActionListener(e -> chainModel.clear());
        clearChainBtn.setToolTipText("Clear chain");
        chainButtons.add(clearChainBtn);
        JButton removeFromChainBtn = new JButton("Remove selected");
        removeFromChainBtn.addActionListener(e -> {
            int i = chainList.getSelectedIndex();
            if (i >= 0) chainModel.remove(i);
        });
        removeFromChainBtn.setToolTipText("Remove selected operation from chain");
        chainButtons.add(removeFromChainBtn);
        JButton saveChainBtn = new JButton("Save chain");
        saveChainBtn.addActionListener(e -> saveChain());
        saveChainBtn.setToolTipText("Save chain to file");
        chainButtons.add(saveChainBtn);
        JButton loadChainBtn = new JButton("Load chain");
        loadChainBtn.addActionListener(e -> loadChain());
        loadChainBtn.setToolTipText("Load chain from file");
        chainButtons.add(loadChainBtn);
        chainContent.add(chainButtons, BorderLayout.SOUTH);
        JPanel chainPanel = createCollapsiblePanel("pt.panel.chain.expanded", "Chain (run in sequence)", chainContent);

        // Regex panel (collapsible)
        JPanel regexContent = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        regexFindField = new JTextField(20);
        regexFindField.setToolTipText("Regex pattern");
        regexReplaceField = new JTextField(15);
        regexReplaceField.setToolTipText("Replacement ($1, $2 for groups)");
        regexGroupSpinner = new JSpinner(new SpinnerNumberModel(1, 0, 10, 1));
        regexGroupSpinner.setPreferredSize(new Dimension(50, 25));
        JButton regexReplaceBtn = new JButton("Replace all");
        regexReplaceBtn.addActionListener(e -> regexReplace());
        regexReplaceBtn.setToolTipText("Replace all regex matches");
        JButton regexExtractBtn = new JButton("Extract");
        regexExtractBtn.addActionListener(e -> regexExtract());
        regexExtractBtn.setToolTipText("Extract first match by group");
        regexContent.add(new JLabel("Find:"));
        regexContent.add(regexFindField);
        regexContent.add(new JLabel("Replace:"));
        regexContent.add(regexReplaceField);
        regexContent.add(regexReplaceBtn);
        regexContent.add(new JLabel("Group:"));
        regexContent.add(regexGroupSpinner);
        regexContent.add(regexExtractBtn);
        JPanel regexPanel = createCollapsiblePanel("pt.panel.regex.expanded", "Regex replace", regexContent);

        // Batch panel (collapsible)
        JPanel batchContent = new JPanel(new BorderLayout(5, 5));
        batchInputArea = new JTextArea(3, 40);
        batchInputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel batchButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JComboBox<String> batchOpCombo = new JComboBox<>(BATCH_OPERATIONS);
        batchOpCombo.setPreferredSize(new Dimension(180, 25));
        JButton batchTransformBtn = new JButton("Transform all");
        batchTransformBtn.addActionListener(e -> batchTransform(batchOpCombo));
        batchTransformBtn.setToolTipText("Transform each line with selected operation");
        batchButtons.add(new JLabel("Operation:"));
        batchButtons.add(batchOpCombo);
        batchButtons.add(batchTransformBtn);
        batchOutputArea = new JTextArea(3, 40);
        batchOutputArea.setEditable(false);
        batchOutputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JSplitPane batchSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(batchInputArea), new JScrollPane(batchOutputArea));
        batchSplit.setResizeWeight(0.5);
        batchContent.add(batchSplit, BorderLayout.CENTER);
        batchContent.add(batchButtons, BorderLayout.SOUTH);
        JPanel batchPanel = createCollapsiblePanel("pt.panel.batch.expanded", "Batch mode (one payload per line)", batchContent);

        // Stats bar
        statsLabel = new JLabel(" ");
        statsLabel.setBorder(new EmptyBorder(2, 5, 2, 5));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, inputPanel, bottomPanel);
        splitPane.setResizeWeight(0.5);
        splitPane.setDividerLocation(0.5);

        JPanel centerPanel = new JPanel(new BorderLayout(5, 5));
        centerPanel.add(splitPane, BorderLayout.CENTER);
        JPanel extraPanel = new JPanel(new BorderLayout(5, 5));
        extraPanel.add(chainPanel, BorderLayout.NORTH);
        extraPanel.add(regexPanel, BorderLayout.CENTER);
        extraPanel.add(batchPanel, BorderLayout.SOUTH);
        centerPanel.add(extraPanel, BorderLayout.SOUTH);

        removeAll();
        add(centerPanel, BorderLayout.CENTER);
        add(controlPanel, BorderLayout.NORTH);
        add(statsLabel, BorderLayout.SOUTH);

        montoyaApi.userInterface().applyThemeToComponent(this);
        registerKeyboardShortcuts();
    }

    private void registerKeyboardShortcuts() {
        InputMap im = getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        ActionMap am = getActionMap();
        int mod = java.awt.Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        im.put(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ENTER, mod), "transcode");
        am.put("transcode", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                transcode();
            }
        });
        im.put(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_S, mod | java.awt.event.InputEvent.SHIFT_DOWN_MASK), "smartDecode");
        am.put("smartDecode", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                runSmartDecode();
            }
        });
        im.put(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_Z, mod), "undo");
        am.put("undo", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                undo();
            }
        });
    }

    private JPanel createCollapsiblePanel(String prefKey, String title, JPanel content) {
        var prefs = montoyaApi.persistence().preferences();
        Boolean saved = prefs.getBoolean(prefKey);
        boolean expanded = saved == null ? true : saved;
        content.setVisible(expanded);

        JPanel wrapper = new JPanel(new BorderLayout());
        JButton toggle = new JButton((expanded ? "▼ " : "▶ ") + title);
        toggle.setToolTipText("Click to collapse/expand");
        toggle.addActionListener(e -> {
            boolean newExpanded = !content.isVisible();
            content.setVisible(newExpanded);
            toggle.setText((newExpanded ? "▼ " : "▶ ") + title);
            prefs.setBoolean(prefKey, newExpanded);
            wrapper.revalidate();
            wrapper.repaint();
        });
        wrapper.add(toggle, BorderLayout.NORTH);
        wrapper.add(content, BorderLayout.CENTER);
        return wrapper;
    }

    private void addToChain() {
        String op = (String) formatCombo.getSelectedItem();
        if (op != null && !op.startsWith("---")) {
            if (PROMPT_OPS.contains(op)) {
                JOptionPane.showMessageDialog(this,
                        "Operation \"" + op + "\" requires user input and cannot be used in a chain.\n" +
                        "Use it directly in the main tab instead.",
                        "Chain limitation", JOptionPane.WARNING_MESSAGE);
                return;
            }
            chainModel.addElement(op);
        }
    }

    private void runChain() {
        byte[] input = inputEditor.getContents().getBytes();
        if (input == null || input.length == 0) {
            montoyaApi.logging().logToError("Payload Transcoder: No input");
            return;
        }
        if (chainModel.isEmpty()) {
            montoyaApi.logging().logToError("Payload Transcoder: Chain is empty");
            return;
        }
        lastInputBeforeTranscode = input;
        byte[] current = input;
        for (int i = 0; i < chainModel.size(); i++) {
            String op = chainModel.get(i);
            if (PROMPT_OPS.contains(op)) {
                outputEditor.setContents(ByteArray.byteArray(
                        ("Chain failed at step " + (i + 1) + ": \"" + op + "\" requires user input (dialogs) and cannot run in chain mode.").getBytes(StandardCharsets.UTF_8)));
                return;
            }
            byte[] next = performOperation(current, op);
            if (next == null) {
                outputEditor.setContents(ByteArray.byteArray(
                        ("Chain failed at step " + (i + 1) + ": " + op).getBytes(StandardCharsets.UTF_8)));
                return;
            }
            current = next;
        }
        outputEditor.setContents(ByteArray.byteArray(current));
        updateStats(outputEditor.getContents().getBytes());
    }

    private void showSuggestions() {
        byte[] input = inputEditor.getContents().getBytes();
        if (input == null || input.length == 0) {
            JOptionPane.showMessageDialog(this, "No input to analyze.");
            return;
        }
        var suggestions = PayloadTranscoderDetect.suggest(input);
        if (suggestions.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No suggestions for this input.");
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (var s : suggestions) {
            sb.append("• ").append(s.operation).append(" — ").append(s.reason).append("\n");
        }
        String[] options = { "Apply first", "OK" };
        int choice = JOptionPane.showOptionDialog(this, sb.toString(), "Suggestions",
                JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, options, options[1]);
        if (choice == 0) {
            applyFirstSuggestion(input, suggestions.get(0));
        }
    }

    private void applyFirstSuggestion(byte[] input, PayloadTranscoderDetect.Suggestion s) {
        if (s == null || s.operation.startsWith("---")) return;
        if (PROMPT_OPS.contains(s.operation)) {
            JOptionPane.showMessageDialog(this,
                    "The first suggestion \"" + s.operation + "\" requires user input (secret, key, etc.)\n" +
                    "and cannot be applied from Suggest. Use the main tab and select it from the Operation dropdown.",
                    "Apply first", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        byte[] result = performOperation(input, s.operation);
        if (result != null && result.length > 0) {
            lastInputBeforeTranscode = input;
            outputEditor.setContents(ByteArray.byteArray(result));
            updateStats();
            formatCombo.setSelectedItem(s.operation);
        }
    }

    private void undo() {
        if (lastInputBeforeTranscode != null) {
            inputEditor.setContents(ByteArray.byteArray(lastInputBeforeTranscode));
            lastInputBeforeTranscode = null;
            updateStats();
        }
    }

    private void regexReplace() {
        byte[] input = inputEditor.getContents().getBytes();
        String regex = regexFindField.getText();
        String replacement = regexReplaceField.getText();
        if (input == null || input.length == 0) {
            montoyaApi.logging().logToError("Payload Transcoder: No input");
            return;
        }
        if (regex == null || regex.isEmpty()) {
            montoyaApi.logging().logToError("Payload Transcoder: Regex is empty");
            return;
        }
        byte[] result = PayloadTranscoderRegex.replace(input, regex, replacement != null ? replacement : "");
        if (result != null) {
            outputEditor.setContents(ByteArray.byteArray(result));
            updateStats(result);
        } else {
            outputEditor.setContents(ByteArray.byteArray("Regex replace failed (check pattern)".getBytes(StandardCharsets.UTF_8)));
        }
    }

    private void showTemplateMenu() {
        JPopupMenu menu = new JPopupMenu();
        for (var catEntry : PayloadTranscoderTemplates.getTemplatesByCategory().entrySet()) {
            String category = catEntry.getKey();
            var templates = catEntry.getValue();
            if (templates.size() == 1) {
                var e = templates.entrySet().iterator().next();
                JMenuItem item = new JMenuItem(e.getKey());
                byte[] payload = e.getValue();
                item.addActionListener(ev -> inputEditor.setContents(ByteArray.byteArray(payload)));
                menu.add(item);
            } else {
                JMenu submenu = new JMenu(category);
                for (var e : templates.entrySet()) {
                    JMenuItem item = new JMenuItem(e.getKey().substring(category.length() + 2)); // drop "Cat: "
                    byte[] payload = e.getValue();
                    item.addActionListener(ev -> inputEditor.setContents(ByteArray.byteArray(payload)));
                    submenu.add(item);
                }
                montoyaApi.userInterface().applyThemeToComponent(submenu);
                menu.add(submenu);
            }
        }
        menu.show(insertTemplateBtn, 0, insertTemplateBtn.getHeight());
    }

    private void clearAll() {
        inputEditor.setContents(ByteArray.byteArray(new byte[0]));
        outputEditor.setContents(ByteArray.byteArray(new byte[0]));
        chainModel.clear();
        lastInputBeforeTranscode = null;
        updateStats();
    }

    private void updateStats() {
        byte[] input = inputEditor.getContents().getBytes();
        byte[] output = outputEditor.getContents().getBytes();
        String in = formatStats(input);
        String out = formatStats(output);
        statsLabel.setText("Input: " + in + "  |  Output: " + out);
    }

    private void updateStats(byte[] data) {
        updateStats();
    }

    private static String formatStats(byte[] data) {
        if (data == null || data.length == 0) return "0 B | 0 chars | 0 lines";
        int bytes = data.length;
        int chars = new String(data, StandardCharsets.UTF_8).length();
        int lines = (int) new String(data, StandardCharsets.UTF_8).lines().count();
        String size = bytes >= 1024 ? String.format("%.1f KB", bytes / 1024.0) : bytes + " B";
        return size + " | " + chars + " chars | " + lines + " lines";
    }

    private void transcode() {
        byte[] input = inputEditor.getContents().getBytes();
        if (input == null || input.length == 0) {
            montoyaApi.logging().logToError("Payload Transcoder: No input");
            return;
        }

        String op = (String) formatCombo.getSelectedItem();
        if (op == null || op.startsWith("---")) return;

        lastInputBeforeTranscode = input;
        byte[] result;
        if ("Sign JWT (HS256)".equals(op)) {
            String secret = JOptionPane.showInputDialog(this, "Enter HMAC secret (UTF-8):", "JWT HS256 Sign", JOptionPane.QUESTION_MESSAGE);
            if (secret == null) return;
            result = PayloadTranscoderJwt.signJwtHs256(input, secret.getBytes(StandardCharsets.UTF_8));
        } else if ("JWT RS256→HS256 (pubkey as secret)".equals(op)) {
            String pubkey = JOptionPane.showInputDialog(this, "Paste public key (PEM or raw base64):", "JWT RS256→HS256", JOptionPane.QUESTION_MESSAGE);
            if (pubkey == null) return;
            byte[] keyBytes = parseKeyInput(pubkey);
            result = keyBytes != null ? PayloadTranscoderJwt.jwtRs256ToHs256(input, keyBytes) : null;
        } else if ("JWT extend expiry (re-sign)".equals(op)) {
            String secret = JOptionPane.showInputDialog(this, "Enter HMAC secret (UTF-8):", "JWT Extend Expiry", JOptionPane.QUESTION_MESSAGE);
            if (secret == null) return;
            Object secsObj = JOptionPane.showInputDialog(this, "Expiry in seconds from now (default 86400):", "JWT Extend Expiry", JOptionPane.QUESTION_MESSAGE, null, null, "86400");
            if (secsObj == null) return;
            String secs = secsObj.toString();
            long seconds = 86400;
            try { seconds = Long.parseLong(secs.trim().isEmpty() ? "86400" : secs.trim()); } catch (NumberFormatException ignored) {}
            result = PayloadTranscoderJwt.jwtExtendExpiry(input, seconds, secret.getBytes(StandardCharsets.UTF_8));
        } else if ("JWT crack (wordlist)".equals(op)) {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Select wordlist file (one secret per line)");
            if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
            try {
                byte[] wordlist = Files.readAllBytes(fc.getSelectedFile().toPath());
                result = PayloadTranscoderJwt.jwtCrack(input, wordlist);
            } catch (IOException e) {
                montoyaApi.logging().logToError("Payload Transcoder: JWT crack failed - " + e.getMessage());
                result = ("JWT crack failed: " + e.getMessage()).getBytes(StandardCharsets.UTF_8);
            }
        } else if ("HMAC-SHA256 (secret)".equals(op) || "HMAC-SHA256 webhook (sha256=hex)".equals(op)) {
            String secret = JOptionPane.showInputDialog(this, "Enter secret (UTF-8):", "HMAC-SHA256", JOptionPane.QUESTION_MESSAGE);
            if (secret == null) return;
            result = "HMAC-SHA256 webhook (sha256=hex)".equals(op)
                    ? PayloadTranscoderHmac.hmacSha256Webhook(input, secret.getBytes(StandardCharsets.UTF_8))
                    : PayloadTranscoderHmac.hmacSha256Hex(input, secret.getBytes(StandardCharsets.UTF_8));
        } else if ("Protobuf decode (field mapping)".equals(op)) {
            String mapping = JOptionPane.showInputDialog(this, "Field mapping (e.g. 1=name,2=id):", "Protobuf Field Mapping", JOptionPane.QUESTION_MESSAGE);
            if (mapping == null) return;
            byte[] msg = PayloadTranscoderGrpc.getProtobufMessage(input);
            result = PayloadTranscoderGrpc.protobufDecodeWithMapping(msg, mapping);
        } else if ("AWS SigV4 sign".equals(op)) {
            String accessKey = JOptionPane.showInputDialog(this, "AWS Access Key:", "AWS SigV4", JOptionPane.QUESTION_MESSAGE);
            if (accessKey == null) return;
            String secretKey = JOptionPane.showInputDialog(this, "AWS Secret Key:", "AWS SigV4", JOptionPane.QUESTION_MESSAGE);
            if (secretKey == null) return;
            Object regionObj = JOptionPane.showInputDialog(this, "Region (e.g. us-east-1):", "AWS SigV4", JOptionPane.QUESTION_MESSAGE, null, null, "us-east-1");
            if (regionObj == null) return;
            String region = regionObj.toString();
            Object serviceObj = JOptionPane.showInputDialog(this, "Service (e.g. s3, ec2):", "AWS SigV4", JOptionPane.QUESTION_MESSAGE, null, null, "s3");
            if (serviceObj == null) return;
            String service = serviceObj.toString();
            Object methodObj = JOptionPane.showInputDialog(this, "HTTP Method:", "AWS SigV4", JOptionPane.QUESTION_MESSAGE, null, null, "GET");
            if (methodObj == null) return;
            String method = methodObj.toString();
            Object uriObj = JOptionPane.showInputDialog(this, "URI (path + query):", "AWS SigV4", JOptionPane.QUESTION_MESSAGE, null, null, "/");
            if (uriObj == null) return;
            String uri = uriObj.toString();
            Object hostObj = JOptionPane.showInputDialog(this, "Host:", "AWS SigV4", JOptionPane.QUESTION_MESSAGE, null, null, service + "." + region + ".amazonaws.com");
            if (hostObj == null) return;
            String host = hostObj.toString();
            result = PayloadTranscoderAwsSigV4.signRequest(input, accessKey, secretKey, region, service, method, uri, host);
        } else if ("Decode gRPC-Web (JSON with mapping)".equals(op)) {
            String mapping = JOptionPane.showInputDialog(this,
                    "Field mapping from .proto (e.g. 3=version,6001=metadata,6001.1=build_id):",
                    "gRPC-Web JSON with field names", JOptionPane.QUESTION_MESSAGE);
            if (mapping == null) return;
            result = PayloadTranscoderGrpc.grpcWebDecodeJson(input, mapping);
        } else {
            result = performOperation(input, op);
        }
        if (result != null) {
            outputEditor.setContents(ByteArray.byteArray(result));
            updateStats(result);
        } else {
            outputEditor.setContents(ByteArray.byteArray(("Transcode failed for: " + op).getBytes(StandardCharsets.UTF_8)));
            montoyaApi.logging().logToError("Payload Transcoder: " + op + " failed");
        }
    }

    private byte[] performOperation(byte[] input, String op) {
        return switch (op) {
            case "Decode Base64" -> PayloadTranscoderUtils.decodeBase64(input);
            case "Decode Base64 URL-safe" -> PayloadTranscoderUtils.decodeBase64UrlSafe(input);
            case "Decode Hex" -> PayloadTranscoderUtils.decodeHex(input);
            case "Decode URL" -> PayloadTranscoderUtils.decodeUrl(input);
            case "Decode HTML entities" -> PayloadTranscoderUtils.decodeHtmlEntities(input);
            case "Decode Unicode escapes" -> PayloadTranscoderUtils.decodeUnicodeEscapes(input);
            case "Decode Quoted-printable" -> PayloadTranscoderUtils.decodeQuotedPrintable(input);
            case "Decode gzip" -> PayloadTranscoderCompression.decodeGzip(input);
            case "Decode deflate" -> PayloadTranscoderCompression.decodeDeflate(input);
            case "Decode Brotli" -> PayloadTranscoderCompression.decodeBrotli(input);
            case "Decode zstd" -> PayloadTranscoderCompression.decodeZstd(input);
            case "Decode MessagePack" -> PayloadTranscoderBinary.decodeMessagePack(input);
            case "Decode CBOR" -> PayloadTranscoderBinary.decodeCbor(input);
            case "Decode BSON" -> PayloadTranscoderBinary.decodeBson(input);
            case "Decode JWT (pretty-print)" -> PayloadTranscoderJwt.jwtPrettyPrint(input);
            case "Decode gRPC message" -> PayloadTranscoderGrpc.extractGrpcMessage(input);
            case "Decode gRPC-Web (protobuf view)" -> PayloadTranscoderGrpc.grpcWebDecodePretty(input);
            case "Decode gRPC-Web (JSON)" -> PayloadTranscoderGrpc.grpcWebDecodeJson(input);
            case "Protobuf raw wire view" -> PayloadTranscoderGrpc.protobufRawWireView(
                    PayloadTranscoderGrpc.getProtobufMessage(input));
            case "Form/query pretty-print" -> PayloadTranscoderStructured.formDataPrettyPrint(input);
            case "Form/query rebuild" -> PayloadTranscoderStructured.formDataRebuild(input);
            case "Multipart pretty-print" -> {
                String boundary = PayloadTranscoderStructured.extractBoundaryFromRaw(input);
                if (boundary == null || boundary.isEmpty()) {
                    Object b = JOptionPane.showInputDialog(this, "Multipart boundary (from Content-Type):", "Multipart Boundary", JOptionPane.QUESTION_MESSAGE);
                    boundary = b != null ? b.toString().trim() : null;
                }
                yield boundary != null && !boundary.isEmpty()
                        ? PayloadTranscoderStructured.multipartPrettyPrint(input, boundary)
                        : null;
            }
            case "WebSocket frame inspect" -> PayloadTranscoderProtocol.webSocketFramePrettyPrint(input);
            case "Hex dump (view)" -> PayloadTranscoderPadding.hexDump(input);
            case "Parse hex dump" -> PayloadTranscoderPadding.parseHexDump(input);
            case "GraphQL introspection pretty-print" -> PayloadTranscoderProtocol.graphqlIntrospectionPrettyPrint(input);
            case "Validate PKCS7 padding" -> (PayloadTranscoderPadding.validatePkcs7(input) ? "Valid PKCS7 padding" : "Invalid PKCS7 padding").getBytes(StandardCharsets.UTF_8);
            case "Strip PKCS7 padding" -> PayloadTranscoderPadding.stripPkcs7(input);
            case "Add PKCS7 padding" -> PayloadTranscoderPadding.addPkcs7(input);
            case "Normalize NFC" -> PayloadTranscoderUnicode.normalizeNfc(input);
            case "Normalize NFD" -> PayloadTranscoderUnicode.normalizeNfd(input);
            case "Normalize NFKC" -> PayloadTranscoderUnicode.normalizeNfkc(input);
            case "Normalize NFKD" -> PayloadTranscoderUnicode.normalizeNfkd(input);
            case "Encode homoglyph (Latin→Cyrillic)" -> PayloadTranscoderHomoglyph.encodeHomoglyph(input);
            case "Decode homoglyph (Cyrillic→Latin)" -> PayloadTranscoderHomoglyph.decodeHomoglyph(input);
            case "Generate polyglot (HTML+JS+URL)" -> PayloadTranscoderPolyglot.generatePolyglot(input, "HTML+JS+URL");
            case "Generate polyglot (SQL+HTML)" -> PayloadTranscoderPolyglot.generatePolyglot(input, "SQL+HTML");
            case "PHP serialize pretty-print" -> PayloadTranscoderPhp.phpSerializedPrettyPrint(input);
            case "PHP serialize string" -> PayloadTranscoderPhp.phpSerializeString(input);
            case "JWT alg:none attack" -> PayloadTranscoderJwt.jwtAlgNone(input);
            case "Detect Java serialized" -> PayloadTranscoderDeser.detectJavaSerialized(input);
            case "Detect .NET ViewState" -> PayloadTranscoderDeser.detectViewState(input);
            case "Encode Base64" -> toBytes(PayloadTranscoderUtils.encodeBase64(input));
            case "Encode Base64 URL-safe" -> toBytes(PayloadTranscoderUtils.encodeBase64UrlSafe(input));
            case "Encode Hex" -> toBytes(PayloadTranscoderUtils.encodeHex(input));
            case "Encode URL" -> toBytes(PayloadTranscoderUtils.encodeUrlStrict(input));
            case "Encode HTML entities" -> toBytes(PayloadTranscoderUtils.encodeHtmlEntities(input));
            case "Encode Unicode escapes" -> toBytes(PayloadTranscoderUtils.encodeUnicodeEscapes(input));
            case "Encode Quoted-printable" -> toBytes(PayloadTranscoderUtils.encodeQuotedPrintable(input));
            case "Encode gzip" -> PayloadTranscoderCompression.encodeGzip(input);
            case "Encode deflate" -> PayloadTranscoderCompression.encodeDeflate(input);
            case "Encode Brotli" -> PayloadTranscoderCompression.encodeBrotli(input);
            case "Encode zstd" -> PayloadTranscoderCompression.encodeZstd(input);
            case "Encode MessagePack" -> PayloadTranscoderBinary.encodeMessagePack(input);
            case "Encode CBOR" -> PayloadTranscoderBinary.encodeCbor(input);
            case "Encode BSON" -> PayloadTranscoderBinary.encodeBson(input);
            case "Encode gRPC frame" -> PayloadTranscoderGrpc.buildGrpcFrame(input);
            case "Encode protobuf from JSON" -> PayloadTranscoderGrpc.jsonToProtobuf(input);
            case "Encode gRPC-Web from JSON" -> {
                byte[] protobuf = PayloadTranscoderGrpc.jsonToProtobuf(input);
                yield protobuf != null ? PayloadTranscoderGrpc.buildGrpcFrame(protobuf) : null;
            }
            case "JSON pretty-print" -> PayloadTranscoderStructured.jsonPrettyPrint(input);
            case "JSON minify" -> PayloadTranscoderStructured.jsonMinify(input);
            case "GraphQL pretty-print" -> PayloadTranscoderProtocol.graphqlPrettyPrint(input);
            case "XML pretty-print" -> PayloadTranscoderProtocol.xmlPrettyPrint(input);
            case "Hash MD5" -> PayloadTranscoderHash.md5(input);
            case "Hash SHA-1" -> PayloadTranscoderHash.sha1(input);
            case "Hash SHA-256" -> PayloadTranscoderHash.sha256(input);
            case "Timestamp: Unix now" -> PayloadTranscoderTimestamp.unixNow();
            case "Timestamp: Unix ms now" -> PayloadTranscoderTimestamp.unixMillisNow();
            case "Timestamp: ISO8601 now" -> PayloadTranscoderTimestamp.iso8601Now();
            case "Timestamp: RFC2822 now" -> PayloadTranscoderTimestamp.rfc2822Now();
            default -> null;
        };
    }

    private static byte[] toBytes(String s) {
        return s != null ? s.getBytes(StandardCharsets.UTF_8) : null;
    }

    private static byte[] parseKeyInput(String input) {
        if (input == null || input.isEmpty()) return null;
        String s = input.trim();
        try {
            if (s.contains("BEGIN")) {
                int start = s.indexOf("-----BEGIN");
                int end = s.indexOf("-----END");
                if (start < 0 || end < 0) return null;
                start = s.indexOf("\n", start) + 1;
                if (start <= 0) start = s.indexOf("\r\n", s.indexOf("-----BEGIN")) + 2;
                String b64 = s.substring(start, end).replaceAll("\\s", "");
                return java.util.Base64.getMimeDecoder().decode(b64);
            }
            return java.util.Base64.getDecoder().decode(s.replaceAll("\\s", ""));
        } catch (IllegalArgumentException e) {
            return s.getBytes(StandardCharsets.UTF_8);
        }
    }

    private void sendOutputToDecoder() {
        byte[] output = outputEditor.getContents().getBytes();
        if (output != null && output.length > 0) {
            montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(output));
        }
    }

    private void swapInputOutput() {
        byte[] input = inputEditor.getContents().getBytes();
        byte[] output = outputEditor.getContents().getBytes();
        inputEditor.setContents(ByteArray.byteArray(output != null ? output : new byte[0]));
        outputEditor.setContents(ByteArray.byteArray(input != null ? input : new byte[0]));
        updateStats(outputEditor.getContents().getBytes());
    }

    private void pasteAndSmartDecode() {
        try {
            var clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
            if (clipboard.isDataFlavorAvailable(java.awt.datatransfer.DataFlavor.stringFlavor)) {
                String text = (String) clipboard.getData(java.awt.datatransfer.DataFlavor.stringFlavor);
                if (text != null && !text.isEmpty()) {
                    byte[] content = text.getBytes(StandardCharsets.UTF_8);
                    inputEditor.setContents(ByteArray.byteArray(content));
                    updateStats(content);
                    runSmartDecode();
                } else {
                    JOptionPane.showMessageDialog(this, "Clipboard is empty.");
                }
            } else {
                JOptionPane.showMessageDialog(this, "No text in clipboard.");
            }
        } catch (Exception e) {
            montoyaApi.logging().logToError("Payload Transcoder: Paste failed - " + e.getMessage());
            JOptionPane.showMessageDialog(this, "Paste failed: " + e.getMessage());
        }
    }

    private void loadFile() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Load file for analysis");
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                byte[] content = Files.readAllBytes(fc.getSelectedFile().toPath());
                inputEditor.setContents(ByteArray.byteArray(content));
                updateStats(content);
                statusLabel.setText("  ● Loaded: " + fc.getSelectedFile().getName() + " (" + content.length + " bytes)");
                statusLabel.setForeground(new Color(0, 128, 0));
                montoyaApi.logging().logToOutput("Payload Transcoder: Loaded " + fc.getSelectedFile().getName() + " (" + content.length + " bytes)");
                if (smartDecodeCheckbox.isSelected()) {
                    SwingUtilities.invokeLater(() -> runSmartDecode());
                }
            } catch (IOException e) {
                montoyaApi.logging().logToError("Payload Transcoder: Load failed - " + e.getMessage());
                JOptionPane.showMessageDialog(this, "Load failed: " + e.getMessage());
            }
        }
    }

    private void saveOutput() {
        byte[] output = outputEditor.getContents().getBytes();
        if (output == null || output.length == 0) {
            JOptionPane.showMessageDialog(this, "No output to save.");
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Save output");
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                Files.write(fc.getSelectedFile().toPath(), output);
                montoyaApi.logging().logToOutput("Payload Transcoder: Saved " + output.length + " bytes to " + fc.getSelectedFile().getName());
                JOptionPane.showMessageDialog(this, "Saved " + output.length + " bytes.");
            } catch (IOException e) {
                montoyaApi.logging().logToError("Payload Transcoder: Save failed - " + e.getMessage());
                JOptionPane.showMessageDialog(this, "Save failed: " + e.getMessage());
            }
        }
    }

    private void sendToComparer() {
        byte[] input = inputEditor.getContents().getBytes();
        byte[] output = outputEditor.getContents().getBytes();
        if (input != null && output != null && (input.length > 0 || output.length > 0)) {
            montoyaApi.comparer().sendToComparer(ByteArray.byteArray(input), ByteArray.byteArray(output));
        }
    }

    private void saveChain() {
        if (chainModel.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Chain is empty.");
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Save chain");
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                List<String> ops = new ArrayList<>();
                for (int i = 0; i < chainModel.size(); i++) ops.add(chainModel.get(i));
                Files.write(fc.getSelectedFile().toPath(), String.join("\n", ops).getBytes(StandardCharsets.UTF_8));
                JOptionPane.showMessageDialog(this, "Chain saved.");
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Save failed: " + e.getMessage());
            }
        }
    }

    private void loadChain() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Load chain");
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                List<String> lines = Files.readAllLines(fc.getSelectedFile().toPath(), StandardCharsets.UTF_8);
                chainModel.clear();
                for (String line : lines) {
                    String op = line.trim();
                    if (!op.isEmpty()) chainModel.addElement(op);
                }
                JOptionPane.showMessageDialog(this, "Chain loaded (" + chainModel.size() + " operations).");
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Load failed: " + e.getMessage());
            }
        }
    }

    private void regexExtract() {
        byte[] input = inputEditor.getContents().getBytes();
        String regex = regexFindField.getText();
        int group = (Integer) regexGroupSpinner.getValue();
        if (input == null || input.length == 0) {
            montoyaApi.logging().logToError("Payload Transcoder: No input");
            return;
        }
        if (regex == null || regex.isEmpty()) {
            montoyaApi.logging().logToError("Payload Transcoder: Regex is empty");
            return;
        }
        byte[] result = PayloadTranscoderRegex.extract(input, regex, group);
        if (result != null && result.length > 0) {
            outputEditor.setContents(ByteArray.byteArray(result));
            updateStats(result);
        } else {
            outputEditor.setContents(ByteArray.byteArray("No match".getBytes(StandardCharsets.UTF_8)));
        }
    }

    private void showOobMenu() {
        JPopupMenu menu = new JPopupMenu();
        for (var e : PayloadTranscoderOob.generateOobPayloads().entrySet()) {
            JMenuItem item = new JMenuItem(e.getKey());
            byte[] payload = e.getValue();
            item.addActionListener(ev -> inputEditor.setContents(ByteArray.byteArray(payload)));
            menu.add(item);
        }
        menu.show(generateOobBtn, 0, generateOobBtn.getHeight());
    }

    private void batchTransform(JComboBox<String> batchOpCombo) {
        String text = batchInputArea.getText();
        String op = (String) batchOpCombo.getSelectedItem();
        if (text == null || text.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No input.");
            return;
        }
        if (op == null || op.startsWith("---")) {
            JOptionPane.showMessageDialog(this, "Select a valid operation.");
            return;
        }
        String[] lines = text.split("\\r?\\n");
        StringBuilder out = new StringBuilder();
        int ok = 0, fail = 0;
        for (String line : lines) {
            byte[] input = line.getBytes(StandardCharsets.UTF_8);
            byte[] result = PROMPT_OPS.contains(op) ? null : performOperation(input, op);
            if (result != null) {
                out.append(new String(result, StandardCharsets.UTF_8)).append("\n");
                ok++;
            } else {
                out.append("[FAILED] ").append(line).append("\n");
                fail++;
            }
        }
        batchOutputArea.setText(out.toString());
        montoyaApi.logging().logToOutput("Payload Transcoder: Batch " + ok + " ok, " + fail + " failed");
    }

    /**
     * Set input content and bring the tab to focus. Used when "Send to Payload Transcoder"
     * is invoked from the context menu. Triggers a brief border flash to indicate content was loaded.
     */
    public void receiveFromContext(byte[] content) {
        if (content != null && content.length > 0) {
            inputEditor.setContents(ByteArray.byteArray(content));
            updateStats(content);
            if (smartDecodeCheckbox.isSelected()) {
                SwingUtilities.invokeLater(() -> runSmartDecode());
            }
        }
        requestFocusInWindow();
        SwingUtilities.invokeLater(() -> {
            Timer delay = new Timer(150, e -> flashInputPanel());
            delay.setRepeats(false);
            delay.start();
        });
    }

    private void runSmartDecode() {
        byte[] input = inputEditor.getContents().getBytes();
        if (input == null || input.length == 0) return;
        smartDecodeChain.clear();
        byte[] result = smartDecode(input, 0, 5);
        if (result != null && result.length > 0) {
            outputEditor.setContents(ByteArray.byteArray(result));
            updateStats(result);
            if (!smartDecodeChain.isEmpty()) {
                formatCombo.setSelectedItem(smartDecodeChain.get(0));
                chainModel.clear();
                for (String op : smartDecodeChain) {
                    chainModel.addElement(op);
                }
            }
        }
    }

    private void runPretty() {
        byte[] input = inputEditor.getContents().getBytes();
        if (input == null || input.length == 0) return;
        var s = PayloadTranscoderDetect.suggestPretty(input);
        if (s == null) {
            montoyaApi.logging().logToError("Payload Transcoder: No JSON/XML/GraphQL detected for pretty-print");
            return;
        }
        byte[] result = performOperation(input, s.operation);
        if (result != null && result.length > 0) {
            outputEditor.setContents(ByteArray.byteArray(result));
            updateStats(result);
            formatCombo.setSelectedItem(s.operation);
        } else {
            montoyaApi.logging().logToError("Payload Transcoder: Pretty-print failed for: " + s.operation);
        }
    }

    private byte[] smartDecode(byte[] input, int depth, int maxDepth) {
        if (depth >= maxDepth || input == null || input.length == 0) return input;
        var s = PayloadTranscoderDetect.suggestBest(input);
        if (s == null || s.operation.startsWith("---")) return input;
        byte[] result = performOperation(input, s.operation);
        if (result != null && result.length > 0 && !java.util.Arrays.equals(input, result)) {
            if (PayloadTranscoderDetect.isLikelyGibberish(result, s.operation)) return input;
            smartDecodeChain.add(s.operation);
            byte[] next = smartDecode(result, depth + 1, maxDepth);
            return next != null ? next : result;
        }
        return input;
    }

    private void flashInputPanel() {
        statusLabel.setText("  ● Content received");
        statusLabel.setForeground(new Color(255, 140, 0));
        Color highlight = new Color(255, 165, 0);
        setBorder(new LineBorder(highlight, 4));
        repaint();
        Border restore = tabDefaultBorder != null ? tabDefaultBorder : BorderFactory.createEmptyBorder(10, 10, 10, 10);
        Timer timer = new Timer(2000, e -> {
            setBorder(restore);
            statusLabel.setText(" ");
            repaint();
        });
        timer.setRepeats(false);
        timer.start();
    }
}
