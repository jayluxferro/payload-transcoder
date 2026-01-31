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
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class PayloadTranscoderContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi montoyaApi;
    private final PayloadTranscoderTab transcoderTab;

    public PayloadTranscoderContextMenu(MontoyaApi montoyaApi, PayloadTranscoderTab transcoderTab) {
        this.montoyaApi = montoyaApi;
        this.transcoderTab = transcoderTab;
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

        // Send to Payload Transcoder tab (selection or body)
        byte[] toSend = getContentToSend(event, pair, editor, selectionContext, hasRequestBody, hasResponseBody);
        if (toSend != null && toSend.length > 0) {
            JMenuItem sendToTab = new JMenuItem("Send to Payload Transcoder");
            byte[] content = toSend;
            sendToTab.addActionListener(e -> {
                transcoderTab.receiveFromContext(content);
            });
            menu.add(sendToTab);
            menu.addSeparator();
        }

        boolean showRequest = hasRequestBody && (selectionContext == null || selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST);
        boolean showResponse = hasResponseBody && (selectionContext == null || selectionContext == MessageEditorHttpRequestResponse.SelectionContext.RESPONSE);

        if (showRequest) {
            String reqContentType = request.headerValue("Content-Type");
            addTranscodeItems(menu, request.body().getBytes(), reqContentType);
        }
        if (showResponse) {
            String resContentType = response != null ? response.headerValue("Content-Type") : null;
            addTranscodeItems(menu, response.body().getBytes(), resContentType);
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
                String selContentType = selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST
                        ? pair.request().headerValue("Content-Type")
                        : (pair.hasResponse() ? pair.response().headerValue("Content-Type") : null);
                if (menu.getItemCount() > 0) menu.addSeparator();
                addTranscodeItems(menu, selectedBytes, selContentType);
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

    private byte[] getContentToSend(ContextMenuEvent event, HttpRequestResponse pair,
            MessageEditorHttpRequestResponse editor, MessageEditorHttpRequestResponse.SelectionContext selectionContext,
            boolean hasRequestBody, boolean hasResponseBody) {
        if (pair == null) return null;
        // Prefer selection if available
        if (editor != null && editor.selectionOffsets().isPresent()) {
            var range = editor.selectionOffsets().get();
            byte[] fullMessage = selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST
                    ? pair.request().toByteArray().getBytes()
                    : pair.response().toByteArray().getBytes();
            int start = range.startIndexInclusive();
            int end = Math.min(range.endIndexExclusive(), fullMessage.length);
            if (start < end) {
                byte[] selected = new byte[end - start];
                System.arraycopy(fullMessage, start, selected, 0, selected.length);
                return selected;
            }
        }
        // Use body based on context
        if (selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST && hasRequestBody) {
            return pair.request().body().getBytes();
        }
        if (selectionContext == MessageEditorHttpRequestResponse.SelectionContext.RESPONSE && hasResponseBody) {
            return pair.response().body().getBytes();
        }
        if (hasResponseBody) return pair.response().body().getBytes();
        if (hasRequestBody) return pair.request().body().getBytes();
        return null;
    }

    @Override
    public List<Component> provideMenuItems(burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        byte[] toSend = null;
        if (event.messageEditorWebSocket().isPresent()) {
            var wsEditor = event.messageEditorWebSocket().get();
            byte[] full = wsEditor.getContents().getBytes();
            if (wsEditor.selectionOffsets().isPresent()) {
                var range = wsEditor.selectionOffsets().get();
                int start = range.startIndexInclusive();
                int end = Math.min(range.endIndexExclusive(), full.length);
                if (start < end) {
                    toSend = new byte[end - start];
                    System.arraycopy(full, start, toSend, 0, toSend.length);
                }
            } else if (full != null && full.length > 0) {
                toSend = full;
            }
        } else if (event.selectedWebSocketMessages() != null && !event.selectedWebSocketMessages().isEmpty()) {
            toSend = event.selectedWebSocketMessages().get(0).payload().getBytes();
        }
        if (toSend != null && toSend.length > 0) {
            JMenu menu = new JMenu("Payload Transcoder");
            JMenuItem sendToTab = new JMenuItem("Send to Payload Transcoder");
            byte[] content = toSend;
            sendToTab.addActionListener(e -> transcoderTab.receiveFromContext(content));
            menu.add(sendToTab);
            JMenuItem replayWs = new JMenuItem("Replay WebSocket message");
            replayWs.addActionListener(e -> replayWebSocket(content));
            menu.add(replayWs);
            montoyaApi.userInterface().applyThemeToComponent(menu);
            return List.of(menu);
        }
        return List.of();
    }

    private void replayWebSocket(byte[] payload) {
        String host = (String) JOptionPane.showInputDialog(null, "Host:", "Replay WebSocket", JOptionPane.QUESTION_MESSAGE);
        if (host == null || host.isBlank()) return;
        String portStr = (String) JOptionPane.showInputDialog(null, "Port (80/443):", "Replay WebSocket", JOptionPane.QUESTION_MESSAGE, null, null, "443");
        int port = 443;
        try { port = Integer.parseInt(portStr != null ? portStr : "443"); } catch (NumberFormatException ignored) {}
        String path = (String) JOptionPane.showInputDialog(null, "Path:", "Replay WebSocket", JOptionPane.QUESTION_MESSAGE, null, null, "/");
        if (path == null) path = "/";
        try {
            var httpService = burp.api.montoya.http.HttpService.httpService(host, port, port == 443);
            var creation = montoyaApi.websockets().createWebSocket(httpService, path);
            if (creation.webSocket().isPresent()) {
                creation.webSocket().get().sendBinaryMessage(burp.api.montoya.core.ByteArray.byteArray(payload));
                montoyaApi.logging().logToOutput("Payload Transcoder: WebSocket message sent to " + host + ":" + port + path);
            } else {
                montoyaApi.logging().logToError("Payload Transcoder: WebSocket creation failed");
            }
        } catch (Exception ex) {
            montoyaApi.logging().logToError("Payload Transcoder: Replay failed - " + ex.getMessage());
        }
    }

    @Override
    public List<Component> provideMenuItems(burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent event) {
        var issues = event.selectedIssues();
        if (issues == null || issues.isEmpty()) return List.of();
        var pair = issues.get(0).requestResponses().stream().findFirst().orElse(null);
        if (pair == null) return List.of();
        byte[] body = pair.hasResponse() && pair.response().body().length() > 0
                ? pair.response().body().getBytes()
                : pair.request().body().getBytes();
        if (body == null || body.length == 0) return List.of();
        JMenu menu = new JMenu("Payload Transcoder");
        JMenuItem sendToTab = new JMenuItem("Send to Payload Transcoder");
        byte[] content = body;
        sendToTab.addActionListener(e -> transcoderTab.receiveFromContext(content));
        menu.add(sendToTab);
        montoyaApi.userInterface().applyThemeToComponent(menu);
        return List.of(menu);
    }

    private void addTranscodeItems(JMenu menu, byte[] body, String contentType) {
        if (body == null || body.length == 0) return;

        // Phase 2: Structured data (Format submenu)
        JMenu formatMenu = new JMenu("Format");
        boolean hasFormatItems = false;

        if (PayloadTranscoderProtocol.looksLikeGraphqlIntrospection(body)) {
            byte[] pretty = PayloadTranscoderProtocol.graphqlIntrospectionPrettyPrint(body);
            if (pretty != null) {
                JMenuItem item = new JMenuItem("GraphQL introspection pretty-print → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(pretty)));
                formatMenu.add(item);
                hasFormatItems = true;
            }
        }
        if (PayloadTranscoderProtocol.looksLikeGraphql(body)) {
            byte[] pretty = PayloadTranscoderProtocol.graphqlPrettyPrint(body);
            if (pretty != null) {
                JMenuItem item = new JMenuItem("GraphQL pretty-print → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(pretty)));
                formatMenu.add(item);
                hasFormatItems = true;
            }
        }

        if (PayloadTranscoderProtocol.looksLikeXml(body)) {
            byte[] pretty = PayloadTranscoderProtocol.xmlPrettyPrint(body);
            if (pretty != null) {
                JMenuItem item = new JMenuItem("XML pretty-print → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(pretty)));
                formatMenu.add(item);
                hasFormatItems = true;
            }
        }

        if (PayloadTranscoderProtocol.looksLikeWebSocketFrame(body)) {
            byte[] pretty = PayloadTranscoderProtocol.webSocketFramePrettyPrint(body);
            if (pretty != null) {
                JMenuItem item = new JMenuItem("WebSocket frame inspect → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(pretty)));
                formatMenu.add(item);
                hasFormatItems = true;
            }
        }

        if (PayloadTranscoderStructured.looksLikeJson(body)) {
            byte[] pretty = PayloadTranscoderStructured.jsonPrettyPrint(body);
            if (pretty != null) {
                JMenuItem item = new JMenuItem("JSON pretty-print → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(pretty)));
                formatMenu.add(item);
                hasFormatItems = true;
            }
            byte[] minified = PayloadTranscoderStructured.jsonMinify(body);
            if (minified != null) {
                JMenuItem item = new JMenuItem("JSON minify → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(minified)));
                formatMenu.add(item);
                hasFormatItems = true;
            }
        }

        if (PayloadTranscoderStructured.looksLikeFormData(body)) {
            byte[] pretty = PayloadTranscoderStructured.formDataPrettyPrint(body);
            if (pretty != null) {
                JMenuItem item = new JMenuItem("Form/query pretty-print → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(pretty)));
                formatMenu.add(item);
                hasFormatItems = true;
            }
            byte[] rebuilt = PayloadTranscoderStructured.formDataRebuild(body);
            if (rebuilt != null) {
                JMenuItem item = new JMenuItem("Form/query rebuild → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(rebuilt)));
                formatMenu.add(item);
                hasFormatItems = true;
            }
        }

        String boundary = PayloadTranscoderStructured.extractBoundaryFromContentType(contentType);
        if (boundary != null && PayloadTranscoderStructured.parseMultipart(body, boundary) != null) {
            byte[] pretty = PayloadTranscoderStructured.multipartPrettyPrint(body, boundary);
            if (pretty != null) {
                JMenuItem item = new JMenuItem("Multipart pretty-print → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(pretty)));
                formatMenu.add(item);
                hasFormatItems = true;
            }
        }

        if (PayloadTranscoderGrpc.parseGrpcFrame(body) != null) {
            byte[] pretty = PayloadTranscoderGrpc.grpcFramePrettyPrint(body);
            if (pretty != null) {
                JMenuItem item = new JMenuItem("gRPC frame pretty-print → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(pretty)));
                formatMenu.add(item);
                hasFormatItems = true;
            }
            byte[] message = PayloadTranscoderGrpc.extractGrpcMessage(body);
            if (message != null) {
                JMenuItem item = new JMenuItem("gRPC message only → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(message)));
                formatMenu.add(item);
                hasFormatItems = true;
            }
            byte[] wireView = PayloadTranscoderGrpc.protobufRawWireView(PayloadTranscoderGrpc.extractGrpcMessage(body));
            if (wireView != null) {
                JMenuItem item = new JMenuItem("Protobuf raw wire view → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(wireView)));
                formatMenu.add(item);
                hasFormatItems = true;
            }
            JMenuItem rebuildGrpc = new JMenuItem("Rebuild gRPC with message from clipboard → send to Decoder");
            rebuildGrpc.addActionListener(e -> {
                byte[] clipboardBytes = getClipboardBytes();
                if (clipboardBytes != null && clipboardBytes.length > 0) {
                    byte[] rebuilt = PayloadTranscoderGrpc.buildGrpcFrame(clipboardBytes);
                    if (rebuilt != null) {
                        montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(rebuilt));
                    }
                }
            });
            formatMenu.add(rebuildGrpc);
            hasFormatItems = true;
        }

        if (PayloadTranscoderJwt.looksLikeJwt(body)) {
            byte[] pretty = PayloadTranscoderJwt.jwtPrettyPrint(body);
            if (pretty != null) {
                JMenuItem item = new JMenuItem("JWT pretty-print → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(pretty)));
                formatMenu.add(item);
                hasFormatItems = true;
            }
            byte[] payloadOnly = PayloadTranscoderJwt.jwtPayloadOnly(body);
            if (payloadOnly != null) {
                JMenuItem item = new JMenuItem("JWT payload only → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(payloadOnly)));
                formatMenu.add(item);
                hasFormatItems = true;
            }
            JMenuItem rebuildJwt = new JMenuItem("Rebuild JWT with payload from clipboard → send to Decoder");
            rebuildJwt.addActionListener(e -> {
                String clipboardPayload = getClipboardText();
                if (clipboardPayload != null && !clipboardPayload.isEmpty()) {
                    byte[] rebuilt = PayloadTranscoderJwt.jwtRebuild(body, clipboardPayload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    if (rebuilt != null) {
                        montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(rebuilt));
                    }
                }
            });
            formatMenu.add(rebuildJwt);
            hasFormatItems = true;
        }

        if (hasFormatItems) {
            montoyaApi.userInterface().applyThemeToComponent(formatMenu);
            menu.add(formatMenu);
        }

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

        byte[] decodedUrl = PayloadTranscoderUtils.decodeUrl(body);
        if (decodedUrl != null && decodedUrl.length > 0) {
            JMenuItem item = new JMenuItem("Decode URL → send to Decoder");
            item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(decodedUrl)));
            menu.add(item);
        }

        byte[] decodedHtml = PayloadTranscoderUtils.decodeHtmlEntities(body);
        if (decodedHtml != null && decodedHtml.length > 0) {
            JMenuItem item = new JMenuItem("Decode HTML entities → send to Decoder");
            item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(decodedHtml)));
            menu.add(item);
        }

        byte[] decodedUnicode = PayloadTranscoderUtils.decodeUnicodeEscapes(body);
        if (decodedUnicode != null && decodedUnicode.length > 0) {
            JMenuItem item = new JMenuItem("Decode Unicode escapes → send to Decoder");
            item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(decodedUnicode)));
            menu.add(item);
        }

        byte[] decodedQp = PayloadTranscoderUtils.decodeQuotedPrintable(body);
        if (decodedQp != null && decodedQp.length > 0) {
            JMenuItem item = new JMenuItem("Decode quoted-printable → send to Decoder");
            item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(decodedQp)));
            menu.add(item);
        }

        byte[] decodedGzip = PayloadTranscoderCompression.decodeGzip(body);
        if (decodedGzip != null && decodedGzip.length > 0) {
            JMenuItem item = new JMenuItem("Decode gzip → send to Decoder");
            item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(decodedGzip)));
            menu.add(item);
        }

        if (PayloadTranscoderCompression.looksLikeDeflate(body)) {
            byte[] decodedDeflate = PayloadTranscoderCompression.decodeDeflate(body);
            if (decodedDeflate != null && decodedDeflate.length > 0) {
                JMenuItem item = new JMenuItem("Decode deflate → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(decodedDeflate)));
                menu.add(item);
            }
        }

        if (PayloadTranscoderCompression.isBrotliAvailable()) {
            byte[] decodedBrotli = PayloadTranscoderCompression.decodeBrotli(body);
            if (decodedBrotli != null && decodedBrotli.length > 0) {
                JMenuItem item = new JMenuItem("Decode Brotli → send to Decoder");
                item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(decodedBrotli)));
                menu.add(item);
            }
        }

        byte[] decodedMsgpack = PayloadTranscoderBinary.decodeMessagePack(body);
        if (decodedMsgpack != null && decodedMsgpack.length > 0) {
            JMenuItem item = new JMenuItem("Decode MessagePack → send to Decoder");
            item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(decodedMsgpack)));
            menu.add(item);
        }

        byte[] decodedCbor = PayloadTranscoderBinary.decodeCbor(body);
        if (decodedCbor != null && decodedCbor.length > 0) {
            JMenuItem item = new JMenuItem("Decode CBOR → send to Decoder");
            item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(decodedCbor)));
            menu.add(item);
        }

        byte[] decodedBson = PayloadTranscoderBinary.decodeBson(body);
        if (decodedBson != null && decodedBson.length > 0) {
            JMenuItem item = new JMenuItem("Decode BSON → send to Decoder");
            item.addActionListener(e -> montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(decodedBson)));
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

        JMenuItem encodeUrl = new JMenuItem("Encode to URL → send to Decoder");
        encodeUrl.addActionListener(e -> {
            String encoded = PayloadTranscoderUtils.encodeUrlStrict(body);
            montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(encoded.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        });
        menu.add(encodeUrl);

        JMenuItem encodeHtml = new JMenuItem("Encode to HTML entities → send to Decoder");
        encodeHtml.addActionListener(e -> {
            String encoded = PayloadTranscoderUtils.encodeHtmlEntities(body);
            if (encoded != null) {
                montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(encoded.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            }
        });
        menu.add(encodeHtml);

        JMenuItem encodeUnicode = new JMenuItem("Encode to Unicode escapes → send to Decoder");
        encodeUnicode.addActionListener(e -> {
            String encoded = PayloadTranscoderUtils.encodeUnicodeEscapes(body);
            if (encoded != null) {
                montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(encoded.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            }
        });
        menu.add(encodeUnicode);

        JMenuItem encodeQp = new JMenuItem("Encode to quoted-printable → send to Decoder");
        encodeQp.addActionListener(e -> {
            String encoded = PayloadTranscoderUtils.encodeQuotedPrintable(body);
            if (encoded != null) {
                montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(encoded.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            }
        });
        menu.add(encodeQp);

        JMenuItem encodeGzip = new JMenuItem("Encode to gzip → send to Decoder");
        encodeGzip.addActionListener(e -> {
            byte[] encoded = PayloadTranscoderCompression.encodeGzip(body);
            if (encoded != null) {
                montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(encoded));
            }
        });
        menu.add(encodeGzip);

        JMenuItem encodeDeflate = new JMenuItem("Encode to deflate → send to Decoder");
        encodeDeflate.addActionListener(e -> {
            byte[] encoded = PayloadTranscoderCompression.encodeDeflate(body);
            if (encoded != null) {
                montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(encoded));
            }
        });
        menu.add(encodeDeflate);

        if (PayloadTranscoderCompression.isBrotliAvailable()) {
            JMenuItem encodeBrotli = new JMenuItem("Encode to Brotli → send to Decoder");
            encodeBrotli.addActionListener(e -> {
                byte[] encoded = PayloadTranscoderCompression.encodeBrotli(body);
                if (encoded != null) {
                    montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(encoded));
                }
            });
            menu.add(encodeBrotli);
        }

        JMenuItem encodeMsgpack = new JMenuItem("Encode to MessagePack → send to Decoder");
        encodeMsgpack.addActionListener(e -> {
            byte[] encoded = PayloadTranscoderBinary.encodeMessagePack(body);
            if (encoded != null) {
                montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(encoded));
            }
        });
        menu.add(encodeMsgpack);

        JMenuItem encodeCbor = new JMenuItem("Encode to CBOR → send to Decoder");
        encodeCbor.addActionListener(e -> {
            byte[] encoded = PayloadTranscoderBinary.encodeCbor(body);
            if (encoded != null) {
                montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(encoded));
            }
        });
        menu.add(encodeCbor);

        JMenuItem encodeBson = new JMenuItem("Encode to BSON → send to Decoder");
        encodeBson.addActionListener(e -> {
            byte[] encoded = PayloadTranscoderBinary.encodeBson(body);
            if (encoded != null) {
                montoyaApi.decoder().sendToDecoder(ByteArray.byteArray(encoded));
            }
        });
        menu.add(encodeBson);

        menu.addSeparator();

        // Copy to clipboard
        JMenu copyMenu = new JMenu("Copy to clipboard");
        JMenuItem copyBase64 = new JMenuItem("Copy as base64");
        copyBase64.addActionListener(e -> copyToClipboard(PayloadTranscoderUtils.encodeBase64(body), "base64"));
        JMenuItem copyHex = new JMenuItem("Copy as hex");
        copyHex.addActionListener(e -> copyToClipboard(PayloadTranscoderUtils.encodeHex(body), "hex"));
        JMenuItem copyUrlEncoded = new JMenuItem("Copy as URL-encoded");
        copyUrlEncoded.addActionListener(e -> copyToClipboard(PayloadTranscoderUtils.encodeUrlStrict(body), "URL-encoded"));
        JMenuItem copyHtmlEntities = new JMenuItem("Copy as HTML entities");
        copyHtmlEntities.addActionListener(e -> copyToClipboard(PayloadTranscoderUtils.encodeHtmlEntities(body), "HTML entities"));
        JMenuItem copyUnicodeEscapes = new JMenuItem("Copy as Unicode escapes");
        copyUnicodeEscapes.addActionListener(e -> copyToClipboard(PayloadTranscoderUtils.encodeUnicodeEscapes(body), "Unicode escapes"));
        JMenuItem copyQuotedPrintable = new JMenuItem("Copy as quoted-printable");
        copyQuotedPrintable.addActionListener(e -> copyToClipboard(PayloadTranscoderUtils.encodeQuotedPrintable(body), "quoted-printable"));
        copyMenu.add(copyBase64);
        copyMenu.add(copyHex);
        copyMenu.add(copyUrlEncoded);
        copyMenu.add(copyHtmlEntities);
        copyMenu.add(copyUnicodeEscapes);
        copyMenu.add(copyQuotedPrintable);
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

    private String getClipboardText() {
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            if (clipboard.isDataFlavorAvailable(DataFlavor.stringFlavor)) {
                return (String) clipboard.getData(DataFlavor.stringFlavor);
            }
        } catch (UnsupportedFlavorException | java.io.IOException ex) {
            montoyaApi.logging().logToError("Payload Transcoder: Failed to read clipboard - " + ex.getMessage());
        }
        return null;
    }

    private byte[] getClipboardBytes() {
        String s = getClipboardText();
        if (s == null || s.isEmpty()) return null;
        s = s.trim();
        byte[] hexDecoded = PayloadTranscoderUtils.decodeHex(s.getBytes(StandardCharsets.US_ASCII));
        if (hexDecoded != null && hexDecoded.length > 0) return hexDecoded;
        byte[] b64Decoded = PayloadTranscoderUtils.decodeBase64(s.getBytes(StandardCharsets.US_ASCII));
        if (b64Decoded != null && b64Decoded.length > 0) return b64Decoded;
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
