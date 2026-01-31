import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

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
    private byte[] lastInputBeforeTranscode;

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
            "Decode MessagePack",
            "Decode CBOR",
            "Decode BSON",
            "Decode JWT (pretty-print)",
            "Decode gRPC message",
            "Protobuf raw wire view",
            "Protobuf decode (field mapping)",
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
            "Encode Base64",
            "Encode Hex",
            "Encode URL",
            "Encode HTML entities",
            "Encode Unicode escapes",
            "Encode Quoted-printable",
            "Encode gzip",
            "Encode deflate",
            "Encode Brotli",
            "Encode MessagePack",
            "Encode CBOR",
            "Encode BSON",
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
            "Sign JWT (HS256)",
            "---",
            "Timestamp: Unix now",
            "Timestamp: Unix ms now",
            "Timestamp: ISO8601 now",
            "Timestamp: RFC2822 now",
    };

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

        // Main control panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        controlPanel.add(new JLabel("Operation:"));
        formatCombo = new JComboBox<>(OPERATIONS);
        formatCombo.setPreferredSize(new Dimension(220, 25));
        controlPanel.add(formatCombo);

        JButton transcodeBtn = new JButton("Transcode");
        transcodeBtn.addActionListener(e -> transcode());
        controlPanel.add(transcodeBtn);

        JButton addToChainBtn = new JButton("Add to chain");
        addToChainBtn.addActionListener(e -> addToChain());
        controlPanel.add(addToChainBtn);

        JButton suggestBtn = new JButton("Suggest");
        suggestBtn.addActionListener(e -> showSuggestions());
        controlPanel.add(suggestBtn);

        JButton undoBtn = new JButton("Undo");
        undoBtn.addActionListener(e -> undo());
        controlPanel.add(undoBtn);

        JButton sendToDecoderBtn = new JButton("Send output to Decoder");
        sendToDecoderBtn.addActionListener(e -> sendOutputToDecoder());
        controlPanel.add(sendToDecoderBtn);

        JButton swapBtn = new JButton("Swap input ↔ output");
        swapBtn.addActionListener(e -> swapInputOutput());
        swapBtn.setToolTipText("Swap input and output (e.g. decode → modify → swap → encode)");
        controlPanel.add(swapBtn);

        JButton compareBtn = new JButton("Compare input vs output");
        compareBtn.addActionListener(e -> sendToComparer());
        controlPanel.add(compareBtn);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> clearAll());
        controlPanel.add(clearBtn);

        JButton loadFileBtn = new JButton("Load file");
        loadFileBtn.addActionListener(e -> loadFile());
        loadFileBtn.setToolTipText("Load file contents into input for analysis");
        controlPanel.add(loadFileBtn);

        JButton saveOutputBtn = new JButton("Save output");
        saveOutputBtn.addActionListener(e -> saveOutput());
        saveOutputBtn.setToolTipText("Save output to file");
        controlPanel.add(saveOutputBtn);

        // Templates
        insertTemplateBtn = new JButton("Insert template");
        insertTemplateBtn.addActionListener(e -> showTemplateMenu());
        controlPanel.add(insertTemplateBtn);

        generateOobBtn = new JButton("Generate OOB");
        generateOobBtn.addActionListener(e -> showOobMenu());
        controlPanel.add(generateOobBtn);

        // Chain panel
        chainModel = new DefaultListModel<>();
        JPanel chainPanel = new JPanel(new BorderLayout(5, 5));
        chainPanel.setBorder(new TitledBorder("Chain (run in sequence)"));
        JList<String> chainList = new JList<>(chainModel);
        chainList.setVisibleRowCount(3);
        chainPanel.add(new JScrollPane(chainList), BorderLayout.CENTER);
        JPanel chainButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton runChainBtn = new JButton("Run chain");
        runChainBtn.addActionListener(e -> runChain());
        chainButtons.add(runChainBtn);
        JButton clearChainBtn = new JButton("Clear chain");
        clearChainBtn.addActionListener(e -> chainModel.clear());
        chainButtons.add(clearChainBtn);
        JButton removeFromChainBtn = new JButton("Remove selected");
        removeFromChainBtn.addActionListener(e -> {
            int i = chainList.getSelectedIndex();
            if (i >= 0) chainModel.remove(i);
        });
        chainButtons.add(removeFromChainBtn);
        JButton saveChainBtn = new JButton("Save chain");
        saveChainBtn.addActionListener(e -> saveChain());
        chainButtons.add(saveChainBtn);
        JButton loadChainBtn = new JButton("Load chain");
        loadChainBtn.addActionListener(e -> loadChain());
        chainButtons.add(loadChainBtn);
        chainPanel.add(chainButtons, BorderLayout.SOUTH);

        // Regex panel
        JPanel regexPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        regexPanel.setBorder(new TitledBorder("Regex replace"));
        regexFindField = new JTextField(20);
        regexFindField.setToolTipText("Regex pattern");
        regexReplaceField = new JTextField(15);
        regexReplaceField.setToolTipText("Replacement ($1, $2 for groups)");
        regexGroupSpinner = new JSpinner(new SpinnerNumberModel(1, 0, 10, 1));
        regexGroupSpinner.setPreferredSize(new Dimension(50, 25));
        JButton regexReplaceBtn = new JButton("Replace all");
        regexReplaceBtn.addActionListener(e -> regexReplace());
        JButton regexExtractBtn = new JButton("Extract");
        regexExtractBtn.addActionListener(e -> regexExtract());
        regexPanel.add(new JLabel("Find:"));
        regexPanel.add(regexFindField);
        regexPanel.add(new JLabel("Replace:"));
        regexPanel.add(regexReplaceField);
        regexPanel.add(regexReplaceBtn);
        regexPanel.add(new JLabel("Group:"));
        regexPanel.add(regexGroupSpinner);
        regexPanel.add(regexExtractBtn);

        // Batch panel
        JPanel batchPanel = new JPanel(new BorderLayout(5, 5));
        batchPanel.setBorder(new TitledBorder("Batch mode (one payload per line)"));
        batchInputArea = new JTextArea(3, 40);
        batchInputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel batchButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JComboBox<String> batchOpCombo = new JComboBox<>(OPERATIONS);
        batchOpCombo.setPreferredSize(new Dimension(180, 25));
        JButton batchTransformBtn = new JButton("Transform all");
        batchTransformBtn.addActionListener(e -> batchTransform(batchOpCombo));
        batchButtons.add(new JLabel("Operation:"));
        batchButtons.add(batchOpCombo);
        batchButtons.add(batchTransformBtn);
        batchOutputArea = new JTextArea(3, 40);
        batchOutputArea.setEditable(false);
        batchOutputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JSplitPane batchSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(batchInputArea), new JScrollPane(batchOutputArea));
        batchSplit.setResizeWeight(0.5);
        batchPanel.add(batchSplit, BorderLayout.CENTER);
        batchPanel.add(batchButtons, BorderLayout.SOUTH);

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
    }

    private void addToChain() {
        String op = (String) formatCombo.getSelectedItem();
        if (op != null && !op.startsWith("---")) {
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
        JOptionPane.showMessageDialog(this, sb.toString(), "Suggestions", JOptionPane.INFORMATION_MESSAGE);
    }

    private void undo() {
        if (lastInputBeforeTranscode != null) {
            inputEditor.setContents(ByteArray.byteArray(lastInputBeforeTranscode));
            lastInputBeforeTranscode = null;
            updateStats(lastInputBeforeTranscode);
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
        for (var e : PayloadTranscoderTemplates.getTemplates().entrySet()) {
            JMenuItem item = new JMenuItem(e.getKey());
            byte[] payload = e.getValue();
            item.addActionListener(ev -> inputEditor.setContents(ByteArray.byteArray(payload)));
            menu.add(item);
        }
        menu.show(insertTemplateBtn, 0, insertTemplateBtn.getHeight());
    }

    private void clearAll() {
        inputEditor.setContents(ByteArray.byteArray(new byte[0]));
        outputEditor.setContents(ByteArray.byteArray(new byte[0]));
        chainModel.clear();
        lastInputBeforeTranscode = null;
        statsLabel.setText(" ");
    }

    private void updateStats(byte[] data) {
        if (data == null || data.length == 0) {
            statsLabel.setText(" ");
            return;
        }
        int bytes = data.length;
        int chars = new String(data, StandardCharsets.UTF_8).length();
        int lines = (int) new String(data, StandardCharsets.UTF_8).lines().count();
        statsLabel.setText(bytes + " bytes | " + chars + " chars | " + lines + " lines");
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
        } else if ("Protobuf decode (field mapping)".equals(op)) {
            String mapping = JOptionPane.showInputDialog(this, "Field mapping (e.g. 1=name,2=id):", "Protobuf Field Mapping", JOptionPane.QUESTION_MESSAGE);
            if (mapping == null) return;
            byte[] msg = PayloadTranscoderGrpc.extractGrpcMessage(input);
            result = PayloadTranscoderGrpc.protobufDecodeWithMapping(msg != null ? msg : input, mapping);
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
            case "Decode MessagePack" -> PayloadTranscoderBinary.decodeMessagePack(input);
            case "Decode CBOR" -> PayloadTranscoderBinary.decodeCbor(input);
            case "Decode BSON" -> PayloadTranscoderBinary.decodeBson(input);
            case "Decode JWT (pretty-print)" -> PayloadTranscoderJwt.jwtPrettyPrint(input);
            case "Decode gRPC message" -> PayloadTranscoderGrpc.extractGrpcMessage(input);
            case "Protobuf raw wire view" -> PayloadTranscoderGrpc.protobufRawWireView(
                    PayloadTranscoderGrpc.extractGrpcMessage(input));
            case "Hex dump (view)" -> PayloadTranscoderPadding.hexDump(input);
            case "Parse hex dump" -> PayloadTranscoderPadding.parseHexDump(input);
            case "GraphQL introspection pretty-print" -> PayloadTranscoderProtocol.graphqlIntrospectionPrettyPrint(input);
            case "Validate PKCS7 padding" -> (PayloadTranscoderPadding.validatePkcs7(input) ? "Valid PKCS7 padding" : "Invalid PKCS7 padding").getBytes(StandardCharsets.UTF_8);
            case "Strip PKCS7 padding" -> PayloadTranscoderPadding.stripPkcs7(input);
            case "Add PKCS7 padding" -> PayloadTranscoderPadding.addPkcs7(input);
            case "Encode Base64" -> toBytes(PayloadTranscoderUtils.encodeBase64(input));
            case "Encode Hex" -> toBytes(PayloadTranscoderUtils.encodeHex(input));
            case "Encode URL" -> toBytes(PayloadTranscoderUtils.encodeUrlStrict(input));
            case "Encode HTML entities" -> toBytes(PayloadTranscoderUtils.encodeHtmlEntities(input));
            case "Encode Unicode escapes" -> toBytes(PayloadTranscoderUtils.encodeUnicodeEscapes(input));
            case "Encode Quoted-printable" -> toBytes(PayloadTranscoderUtils.encodeQuotedPrintable(input));
            case "Encode gzip" -> PayloadTranscoderCompression.encodeGzip(input);
            case "Encode deflate" -> PayloadTranscoderCompression.encodeDeflate(input);
            case "Encode Brotli" -> PayloadTranscoderCompression.encodeBrotli(input);
            case "Encode MessagePack" -> PayloadTranscoderBinary.encodeMessagePack(input);
            case "Encode CBOR" -> PayloadTranscoderBinary.encodeCbor(input);
            case "Encode BSON" -> PayloadTranscoderBinary.encodeBson(input);
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
            byte[] result = "Sign JWT (HS256)".equals(op) ? null : performOperation(input, op);
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
        }
        requestFocusInWindow();
        SwingUtilities.invokeLater(() -> {
            Timer delay = new Timer(150, e -> flashInputPanel());
            delay.setRepeats(false);
            delay.start();
        });
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
