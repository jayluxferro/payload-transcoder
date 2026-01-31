import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Clipboard;
import java.util.ArrayList;
import java.util.List;

public class PayloadTranscoderContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi montoyaApi;

    public PayloadTranscoderContextMenu(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        MessageEditorHttpRequestResponse.SelectionContext selectionContext = null;
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        HttpRequestResponse pair = null;

        MessageEditorHttpRequestResponse editor = null;
        if (event.messageEditorRequestResponse().isPresent()) {
            editor = event.messageEditorRequestResponse().get();
            pair = editor.requestResponse();
            selectionContext = editor.selectionContext();
        } else if (selected != null && !selected.isEmpty()) {
            pair = selected.get(0);
        }

        if (pair == null) return List.of();

        HttpRequest request = pair.request();
        HttpResponse response = pair.hasResponse() ? pair.response() : null;
        boolean hasRequestBody = request.body().length() > 0;
        boolean hasResponseBody = response != null && response.body().length() > 0;

        if (!hasRequestBody && !hasResponseBody) return List.of();

        List<Component> items = new ArrayList<>();
        JMenu menu = new JMenu("Payload Transcoder");

        boolean showRequest = hasRequestBody && (selectionContext == null || selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST);
        boolean showResponse = hasResponseBody && (selectionContext == null || selectionContext == MessageEditorHttpRequestResponse.SelectionContext.RESPONSE);

        if (showRequest) {
            addTranscodeItems(menu, request.body().getBytes());
        }
        if (showResponse) {
            addTranscodeItems(menu, response.body().getBytes());
        }

        // Selection-based transcoding
        if (editor != null && editor.selectionOffsets().isPresent()) {
            var range = editor.selectionOffsets().get();
            byte[] fullMessage = selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST
                    ? pair.request().toByteArray().getBytes()
                    : pair.response().toByteArray().getBytes();
            int start = range.startIndexInclusive();
            int end = Math.min(range.endIndexExclusive(), fullMessage.length);
            if (start < end) {
                byte[] selectedBytes = new byte[end - start];
                System.arraycopy(fullMessage, start, selectedBytes, 0, selectedBytes.length);
                if (menu.getItemCount() > 0) menu.addSeparator();
                addTranscodeItems(menu, selectedBytes);
            }
        }

        // Send to Comparer when 2 selected
        if (selected != null && selected.size() == 2) {
            if (menu.getItemCount() > 0) menu.addSeparator();
            JMenuItem sendToComparer2 = new JMenuItem("Send to Comparer (2 selected)");
            sendToComparer2.addActionListener(e -> {
                byte[] a = selected.get(0).hasResponse() ? selected.get(0).response().body().getBytes() : selected.get(0).request().body().getBytes();
                byte[] b = selected.get(1).hasResponse() ? selected.get(1).response().body().getBytes() : selected.get(1).request().body().getBytes();
                montoyaApi.comparer().sendToComparer(ByteArray.byteArray(a), ByteArray.byteArray(b));
            });
            menu.add(sendToComparer2);
        }

        if (menu.getItemCount() > 0) {
            for (Component c : menu.getMenuComponents()) {
                montoyaApi.userInterface().applyThemeToComponent(c);
                items.add(c);
            }
        }
        return items;
    }

    private void addTranscodeItems(JMenu menu, byte[] body) {
        if (body == null || body.length == 0) return;

        // Decode
        byte[] decodedBase64 = PayloadTranscoderUtils.decodeBase64(body);
        if (decodedBase64 != null && decodedBase64.length > 0) {
            JMenuItem item = new JMenuItem("Decode base64 → send to Decoder");
            item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(decodedBase64)));
            menu.add(item);
        }

        byte[] decodedBase64UrlSafe = PayloadTranscoderUtils.decodeBase64UrlSafe(body);
        if (decodedBase64UrlSafe != null && decodedBase64UrlSafe.length > 0
                && (decodedBase64 == null || !java.util.Arrays.equals(decodedBase64UrlSafe, decodedBase64))) {
            JMenuItem item = new JMenuItem("Decode URL-safe base64 → send to Decoder");
            item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(decodedBase64UrlSafe)));
            menu.add(item);
        }

        byte[] decodedHex = PayloadTranscoderUtils.decodeHex(body);
        if (decodedHex != null && decodedHex.length > 0) {
            JMenuItem item = new JMenuItem("Decode hex → send to Decoder");
            item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(decodedHex)));
            menu.add(item);
        }

        if (menu.getItemCount() > 0) menu.addSeparator();

        // Encode
        JMenuItem encodeBase64 = new JMenuItem("Encode to base64 → send to Decoder");
        encodeBase64.addActionListener(e -> {
            String encoded = PayloadTranscoderUtils.encodeBase64(body);
            montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(encoded.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        });
        menu.add(encodeBase64);

        JMenuItem encodeHex = new JMenuItem("Encode to hex → send to Decoder");
        encodeHex.addActionListener(e -> {
            String encoded = PayloadTranscoderUtils.encodeHex(body);
            montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(encoded.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        });
        menu.add(encodeHex);

        menu.addSeparator();

        // Copy to clipboard
        JMenu copyMenu = new JMenu("Copy to clipboard");
        JMenuItem copyBase64 = new JMenuItem("Copy as base64");
        copyBase64.addActionListener(e -> copyToClipboard(PayloadTranscoderUtils.encodeBase64(body), "base64"));
        JMenuItem copyHex = new JMenuItem("Copy as hex");
        copyHex.addActionListener(e -> copyToClipboard(PayloadTranscoderUtils.encodeHex(body), "hex"));
        JMenuItem copyUrlEncoded = new JMenuItem("Copy as URL-encoded");
        copyUrlEncoded.addActionListener(e -> copyToClipboard(PayloadTranscoderUtils.encodeUrlStrict(body), "URL-encoded"));
        copyMenu.add(copyBase64);
        copyMenu.add(copyHex);
        copyMenu.add(copyUrlEncoded);
        montoyaApi.userInterface().applyThemeToComponent(copyMenu);
        menu.add(copyMenu);

        // Send to Decoder (raw)
        JMenuItem sendToDecoder = new JMenuItem("Send to Decoder");
        sendToDecoder.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(body)));
        menu.add(sendToDecoder);

        JMenuItem sendToComparer = new JMenuItem("Send to Comparer");
        sendToComparer.addActionListener(e -> montoyaApi.comparer().sendToComparer(ByteArray.byteArray(body)));
        menu.add(sendToComparer);
    }

    private void copyToClipboard(String text, String label) {
        if (text == null) return;
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(new StringSelection(text), null);
            montoyaApi.logging().logToOutput("Payload Transcoder: Copied " + label + " to clipboard");
        } catch (Exception ex) {
            montoyaApi.logging().logToError("Payload Transcoder: Failed to copy - " + ex.getMessage());
        }
    }
}
