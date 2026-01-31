import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * Protocol-specific transcoding: GraphQL, XML, WebSocket.
 */
public final class PayloadTranscoderProtocol {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Pattern GRAPHQL_QUERY = Pattern.compile(
            "\\b(query|mutation|subscription|fragment)\\b",
            Pattern.CASE_INSENSITIVE);

    private PayloadTranscoderProtocol() {}

    // --- GraphQL ---

    public static boolean looksLikeGraphql(byte[] raw) {
        if (raw == null || raw.length < 10) return false;
        try {
            String s = new String(raw, StandardCharsets.UTF_8).trim();
            if (!s.startsWith("{")) return false;
            JsonNode node = OBJECT_MAPPER.readTree(s);
            JsonNode query = node.get("query");
            if (query == null || !query.isTextual()) return false;
            return GRAPHQL_QUERY.matcher(query.asText()).find();
        } catch (Exception e) {
            return false;
        }
    }

    public static byte[] graphqlPrettyPrint(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            String s = new String(raw, StandardCharsets.UTF_8).trim();
            JsonNode node = OBJECT_MAPPER.readTree(s);
            if (!node.isObject()) return null;
            ObjectNode obj = (ObjectNode) node;
            JsonNode queryNode = obj.get("query");
            if (queryNode == null || !queryNode.isTextual()) return null;
            String query = queryNode.asText();
            String prettyQuery = prettyPrintGraphqlQuery(query);
            obj.put("query", prettyQuery);
            return OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(obj).getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Parse and format GraphQL introspection response.
     */
    public static byte[] graphqlIntrospectionPrettyPrint(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            String s = new String(raw, StandardCharsets.UTF_8).trim();
            JsonNode node = OBJECT_MAPPER.readTree(s);
            if (!node.isObject()) return null;
            JsonNode data = node.get("data");
            if (data == null) return OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(node).getBytes(StandardCharsets.UTF_8);
            JsonNode schema = data.get("__schema");
            if (schema == null) return OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(node).getBytes(StandardCharsets.UTF_8);
            StringBuilder sb = new StringBuilder();
            sb.append("=== GraphQL Schema ===\n\n");
            JsonNode types = schema.get("types");
            if (types != null && types.isArray()) {
                sb.append("Types (").append(types.size()).append("):\n");
                for (JsonNode t : types) {
                    String name = t.has("name") ? t.get("name").asText() : "?";
                    String kind = t.has("kind") ? t.get("kind").asText() : "";
                    sb.append("  - ").append(name).append(" (").append(kind).append(")\n");
                }
            }
            JsonNode queryType = schema.get("queryType");
            if (queryType != null) sb.append("\nQuery root: ").append(queryType.has("name") ? queryType.get("name").asText() : "?").append("\n");
            JsonNode mutationType = schema.get("mutationType");
            if (mutationType != null && !mutationType.isNull()) sb.append("Mutation root: ").append(mutationType.has("name") ? mutationType.get("name").asText() : "?").append("\n");
            sb.append("\n=== Full introspection (pretty) ===\n");
            sb.append(OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(node));
            return sb.toString().getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean looksLikeGraphqlIntrospection(byte[] raw) {
        if (raw == null || raw.length < 20) return false;
        try {
            String s = new String(raw, StandardCharsets.UTF_8).trim();
            if (!s.startsWith("{")) return false;
            JsonNode node = OBJECT_MAPPER.readTree(s);
            JsonNode data = node.get("data");
            return data != null && data.has("__schema");
        } catch (Exception e) {
            return false;
        }
    }

    private static String prettyPrintGraphqlQuery(String query) {
        if (query == null) return "";
        StringBuilder sb = new StringBuilder();
        int indent = 0;
        boolean afterNewline = true;
        String trimmed = query.trim();
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (Character.isWhitespace(c)) {
                if (c == '\n') afterNewline = true;
                continue;
            }
            if (afterNewline && (c == '}' || c == ')')) {
                indent = Math.max(0, indent - 1);
            }
            if (afterNewline && indent > 0) {
                sb.append("  ".repeat(indent));
            }
            sb.append(c);
            afterNewline = false;
            if (c == '{' || c == '(') {
                indent++;
            } else if (c == '}' || c == ')') {
                indent = Math.max(0, indent - 1);
            } else if (c == ',') {
                sb.append('\n');
                afterNewline = true;
            }
        }
        return sb.toString().trim();
    }

    // --- XML ---

    public static boolean looksLikeXml(byte[] raw) {
        if (raw == null || raw.length < 5) return false;
        String s = new String(raw, StandardCharsets.UTF_8).trim();
        return s.startsWith("<?xml") || s.startsWith("<");
    }

    public static byte[] xmlPrettyPrint(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            var factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            var builder = factory.newDocumentBuilder();
            var doc = builder.parse(new ByteArrayInputStream(raw));
            var transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            var writer = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(writer));
            return writer.toString().getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    // --- WebSocket ---

    public static class WebSocketFrame {
        public final boolean fin;
        public final int opcode;
        public final boolean masked;
        public final long payloadLength;
        public final byte[] payload;

        public WebSocketFrame(boolean fin, int opcode, boolean masked, long payloadLength, byte[] payload) {
            this.fin = fin;
            this.opcode = opcode;
            this.masked = masked;
            this.payloadLength = payloadLength;
            this.payload = payload;
        }
    }

    public static WebSocketFrame parseWebSocketFrame(byte[] raw) {
        if (raw == null || raw.length < 2) return null;
        try {
            boolean fin = (raw[0] & 0x80) != 0;
            int opcode = raw[0] & 0x0F;
            boolean masked = (raw[1] & 0x80) != 0;
            long payloadLen = raw[1] & 0x7F;
            int headerLen = 2;
            if (payloadLen == 126) {
                if (raw.length < 4) return null;
                payloadLen = ByteBuffer.wrap(raw, 2, 2).order(ByteOrder.BIG_ENDIAN).getShort() & 0xFFFF;
                headerLen = 4;
            } else if (payloadLen == 127) {
                if (raw.length < 10) return null;
                payloadLen = ByteBuffer.wrap(raw, 2, 8).order(ByteOrder.BIG_ENDIAN).getLong();
                headerLen = 10;
            }
            int maskOffset = masked ? 4 : 0;
            int totalLen = headerLen + maskOffset + (int) payloadLen;
            if (raw.length < totalLen) return null;
            byte[] payload = new byte[(int) payloadLen];
            System.arraycopy(raw, headerLen + maskOffset, payload, 0, (int) payloadLen);
            if (masked) {
                byte[] mask = new byte[4];
                System.arraycopy(raw, headerLen, mask, 0, 4);
                for (int i = 0; i < payload.length; i++) {
                    payload[i] ^= mask[i % 4];
                }
            }
            return new WebSocketFrame(fin, opcode, masked, payloadLen, payload);
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean looksLikeWebSocketFrame(byte[] raw) {
        if (raw == null || raw.length < 2) return false;
        int opcode = raw[0] & 0x0F;
        return opcode <= 10; // 0-2 text/binary/close, 8-10 close/ping/pong
    }

    public static byte[] webSocketFramePrettyPrint(byte[] raw) {
        WebSocketFrame frame = parseWebSocketFrame(raw);
        if (frame == null) return null;
        StringBuilder sb = new StringBuilder();
        sb.append("=== WebSocket Frame ===\n");
        sb.append("FIN: ").append(frame.fin).append("\n");
        sb.append("Opcode: ").append(frame.opcode).append(" (")
                .append(opcodeName(frame.opcode)).append(")\n");
        sb.append("Masked: ").append(frame.masked).append("\n");
        sb.append("Payload length: ").append(frame.payloadLength).append(" bytes\n\n");
        sb.append("=== Payload ===\n");
        if (frame.opcode == 1 && isPrintableUtf8(frame.payload)) {
            sb.append(new String(frame.payload, StandardCharsets.UTF_8));
        } else {
            sb.append(bytesToHex(frame.payload));
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String opcodeName(int opcode) {
        return switch (opcode) {
            case 0 -> "continuation";
            case 1 -> "text";
            case 2 -> "binary";
            case 8 -> "close";
            case 9 -> "ping";
            case 10 -> "pong";
            default -> "reserved";
        };
    }

    private static boolean isPrintableUtf8(byte[] bytes) {
        try {
            String s = new String(bytes, StandardCharsets.UTF_8);
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c < 32 && c != '\n' && c != '\r' && c != '\t') return false;
                if (c > 126 && !Character.isValidCodePoint(c)) return false;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
