import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.WireFormat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * gRPC and Protobuf transcoding: frame parse, raw wire-format view, rebuild.
 */
public final class PayloadTranscoderGrpc {

    private PayloadTranscoderGrpc() {}

    public static class GrpcFrame {
        public final boolean compressed;
        public final int messageLength;
        public final byte[] message;

        public GrpcFrame(boolean compressed, int messageLength, byte[] message) {
            this.compressed = compressed;
            this.messageLength = messageLength;
            this.message = message;
        }
    }

    public static boolean looksLikeGrpc(String contentType) {
        if (contentType == null) return false;
        String lower = contentType.toLowerCase();
        return lower.contains("application/grpc");
    }

    /** Check if Content-Type indicates raw protobuf (application/proto, application/x-protobuf). */
    public static boolean looksLikeProtoContentType(String contentType) {
        if (contentType == null) return false;
        String lower = contentType.toLowerCase();
        return lower.contains("application/proto") || lower.contains("application/x-protobuf");
    }

    /** Check if raw bytes look like gRPC/gRPC-Web framing (5-byte header: flag + 4-byte length). */
    public static boolean looksLikeGrpcBytes(byte[] raw) {
        if (raw == null || raw.length < 5) return false;
        byte flag = raw[0];
        int len = ByteBuffer.wrap(raw, 1, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        return len >= 0 && len <= raw.length - 5 && (flag == 0 || flag == 1 || (flag & 0x80) != 0);
    }

    /** gRPC-Web trailer frame flag (0x80); data frames use 0x00 */
    private static final byte TRAILER_FLAG = (byte) 0x80;

    public static GrpcFrame parseGrpcFrame(byte[] raw) {
        return parseGrpcFrameAt(raw, 0);
    }

    private static GrpcFrame parseGrpcFrameAt(byte[] raw, int offset) {
        if (raw == null || offset < 0 || raw.length - offset < 5) return null;
        try {
            byte flag = raw[offset];
            boolean compressed = (flag & 0x7F) != 0; // 0x00 = data uncompressed, 0x01 = data compressed, 0x80 = trailer
            int messageLength = ByteBuffer.wrap(raw, offset + 1, 4).order(ByteOrder.BIG_ENDIAN).getInt();
            if (messageLength < 0 || messageLength > raw.length - offset - 5) return null;
            byte[] message = new byte[messageLength];
            System.arraycopy(raw, offset + 5, message, 0, messageLength);
            return new GrpcFrame(compressed, messageLength, message);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] grpcFramePrettyPrint(byte[] raw) {
        GrpcFrame frame = parseGrpcFrame(raw);
        if (frame == null) return null;
        StringBuilder sb = new StringBuilder();
        sb.append("=== gRPC Frame ===\n");
        sb.append("Compressed: ").append(frame.compressed).append("\n");
        sb.append("Message length: ").append(frame.messageLength).append(" bytes\n\n");
        sb.append("=== Message (hex) ===\n");
        sb.append(bytesToHex(frame.message));
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Protobuf decode with field mapping. Mapping format: "1=name,2=id" (field_number=field_name).
     */
    public static byte[] protobufDecodeWithMapping(byte[] message, String mappingStr) {
        if (message == null || message.length == 0) return null;
        Map<Integer, String> mapping = parseFieldMapping(mappingStr);
        try {
            List<String> lines = new ArrayList<>();
            CodedInputStream input = CodedInputStream.newInstance(message);
            while (true) {
                int tag = input.readTag();
                if (tag == 0) break;
                int fieldNumber = WireFormat.getTagFieldNumber(tag);
                int wireType = WireFormat.getTagWireType(tag);
                String fieldName = mapping.getOrDefault(fieldNumber, "field" + fieldNumber);
                try {
                    String value = readWireValue(input, wireType);
                    if (value != null) {
                        lines.add(String.format("%s (%d): %s", fieldName, fieldNumber, value));
                    } else {
                        input.skipField(tag);
                        lines.add(String.format("%s (%d): [skipped]", fieldName, fieldNumber));
                    }
                } catch (IOException ex) {
                    input.skipField(tag);
                    lines.add(String.format("%s (%d): [parse error]", fieldName, fieldNumber));
                }
            }
            if (lines.isEmpty()) return null;
            return String.join("\n", lines).getBytes(StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    private static Map<Integer, String> parseFieldMapping(String s) {
        Map<Integer, String> m = new HashMap<>();
        if (s == null || s.isBlank()) return m;
        for (String part : s.split("[,;]")) {
            String t = part.trim();
            int eq = t.indexOf('=');
            if (eq > 0) {
                try {
                    int num = Integer.parseInt(t.substring(0, eq).trim());
                    String name = t.substring(eq + 1).trim();
                    if (!name.isEmpty()) m.put(num, name);
                } catch (NumberFormatException ignored) {}
            }
        }
        return m;
    }

    public static byte[] protobufRawWireView(byte[] message) {
        return protobufRawWireView(message, 0);
    }

    private static byte[] protobufRawWireView(byte[] message, int indentLevel) {
        if (message == null || message.length == 0) return null;
        try {
            List<String> lines = new ArrayList<>();
            String indent = "  ".repeat(indentLevel);
            CodedInputStream input = CodedInputStream.newInstance(message);
            while (true) {
                int tag = input.readTag();
                if (tag == 0) break;
                int fieldNumber = WireFormat.getTagFieldNumber(tag);
                int wireType = WireFormat.getTagWireType(tag);
                try {
                    String value = readWireValue(input, wireType, indentLevel);
                    if (value != null) {
                        lines.add(indent + String.format("field %d (wire %d): %s", fieldNumber, wireType, value));
                    } else {
                        input.skipField(tag);
                        lines.add(indent + String.format("field %d (wire %d): [skipped]", fieldNumber, wireType));
                    }
                } catch (IOException ex) {
                    input.skipField(tag);
                    lines.add(indent + String.format("field %d (wire %d): [parse error]", fieldNumber, wireType));
                }
            }
            if (lines.isEmpty()) return null;
            return String.join("\n", lines).getBytes(StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    private static String readWireValue(CodedInputStream input, int wireType) throws IOException {
        return readWireValue(input, wireType, 0);
    }

    private static String readWireValue(CodedInputStream input, int wireType, int indentLevel) throws IOException {
        return switch (wireType) {
            case WireFormat.WIRETYPE_VARINT -> String.valueOf(input.readInt64());
            case WireFormat.WIRETYPE_FIXED64 -> String.valueOf(input.readFixed64());
            case WireFormat.WIRETYPE_LENGTH_DELIMITED -> {
                byte[] bytes = input.readByteArray();
                if (isPrintableAscii(bytes)) {
                    yield "\"" + new String(bytes, StandardCharsets.UTF_8) + "\"";
                }
                if (indentLevel < 10) {
                    byte[] nested = protobufRawWireView(bytes, indentLevel + 1);
                    if (nested != null && nested.length > 0) {
                        yield "{\n" + new String(nested, StandardCharsets.UTF_8) + "\n" + "  ".repeat(indentLevel) + "}";
                    }
                }
                yield "[bytes, " + bytes.length + " bytes]";
            }
            case WireFormat.WIRETYPE_FIXED32 -> String.valueOf(input.readFixed32());
            case WireFormat.WIRETYPE_START_GROUP, WireFormat.WIRETYPE_END_GROUP -> null; // deprecated
            default -> null;
        };
    }

    private static boolean isPrintableAscii(byte[] bytes) {
        for (byte b : bytes) {
            if (b < 32 && b != 9 && b != 10 && b != 13) return false;
            if (b > 126) return false;
        }
        return true;
    }

    public static byte[] buildGrpcFrame(byte[] message) {
        if (message == null) return null;
        try {
            byte[] header = new byte[5];
            header[0] = 0; // uncompressed
            ByteBuffer.wrap(header, 1, 4).order(ByteOrder.BIG_ENDIAN).putInt(message.length);
            byte[] result = new byte[5 + message.length];
            System.arraycopy(header, 0, result, 0, 5);
            System.arraycopy(message, 0, result, 5, message.length);
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extract first data message from gRPC/gRPC-Web body. Skips trailer frames (0x80).
     */
    public static byte[] extractGrpcMessage(byte[] raw) {
        if (raw == null || raw.length < 5) return null;
        int pos = 0;
        while (pos + 5 <= raw.length) {
            byte flag = raw[pos];
            int messageLength = ByteBuffer.wrap(raw, pos + 1, 4).order(ByteOrder.BIG_ENDIAN).getInt();
            if (messageLength < 0 || messageLength > raw.length - pos - 5) return null;
            if ((flag & TRAILER_FLAG) == 0) {
                byte[] message = new byte[messageLength];
                System.arraycopy(raw, pos + 5, message, 0, messageLength);
                return message;
            }
            pos += 5 + messageLength;
        }
        return null;
    }

    private static final ObjectMapper JSON_MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    /**
     * Decode protobuf to JSON. Repeated fields become arrays, nested messages become objects.
     * @param mappingStr optional "3=version,6001=metadata,6001.1=build_id" for field names (from .proto)
     */
    public static byte[] protobufToJson(byte[] message, String mappingStr) {
        if (message == null || message.length == 0) return null;
        try {
            Map<String, String> mapping = parseJsonFieldMapping(mappingStr);
            Map<String, Object> root = protobufToMap(message, 0, mapping, "");
            if (root == null || root.isEmpty()) return null;
            return JSON_MAPPER.writeValueAsBytes(root);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] protobufToJson(byte[] message) {
        return protobufToJson(message, null);
    }

    private static Map<String, String> parseJsonFieldMapping(String s) {
        Map<String, String> m = new HashMap<>();
        if (s == null || s.isBlank()) return m;
        for (String part : s.split("[,;]")) {
            int eq = part.trim().indexOf('=');
            if (eq > 0) {
                String key = part.substring(0, eq).trim();
                String name = part.substring(eq + 1).trim();
                if (!key.isEmpty() && !name.isEmpty()) m.put(key, name);
            }
        }
        return m;
    }

    private static Map<String, Object> protobufToMap(byte[] message, int depth,
            Map<String, String> mapping, String prefix) throws IOException {
        if (depth > 10) return null;
        Map<String, Object> result = new LinkedHashMap<>();
        Map<String, List<Object>> repeated = new HashMap<>();
        CodedInputStream input = CodedInputStream.newInstance(message);
        while (true) {
            int tag = input.readTag();
            if (tag == 0) break;
            int fieldNumber = WireFormat.getTagFieldNumber(tag);
            int wireType = WireFormat.getTagWireType(tag);
            String path = prefix.isEmpty() ? String.valueOf(fieldNumber) : prefix + "." + fieldNumber;
            String key = mapping.getOrDefault(path, mapping.getOrDefault(String.valueOf(fieldNumber), path));
            try {
                Object value = readWireValueAsObject(input, wireType, depth, mapping, path);
                if (value != null) {
                    repeated.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
                } else {
                    input.skipField(tag);
                }
            } catch (IOException ex) {
                input.skipField(tag);
            }
        }
        for (Map.Entry<String, List<Object>> e : repeated.entrySet()) {
            List<Object> list = e.getValue();
            result.put(e.getKey(), list.size() == 1 ? list.get(0) : list);
        }
        return result;
    }

    private static Map<String, Object> protobufToMap(byte[] message, int depth) throws IOException {
        return protobufToMap(message, depth, Map.of(), "");
    }

    private static Object readWireValueAsObject(CodedInputStream input, int wireType, int depth) throws IOException {
        return readWireValueAsObject(input, wireType, depth, Map.of(), "");
    }

    private static Object readWireValueAsObject(CodedInputStream input, int wireType, int depth,
            Map<String, String> mapping, String prefix) throws IOException {
        return switch (wireType) {
            case WireFormat.WIRETYPE_VARINT -> input.readInt64();
            case WireFormat.WIRETYPE_FIXED64 -> input.readFixed64();
            case WireFormat.WIRETYPE_LENGTH_DELIMITED -> {
                byte[] bytes = input.readByteArray();
                if (isPrintableAscii(bytes)) {
                    yield new String(bytes, StandardCharsets.UTF_8);
                }
                if (depth < 10) {
                    Map<String, Object> nested = protobufToMap(bytes, depth + 1, mapping, prefix);
                    if (nested != null && !nested.isEmpty()) {
                        yield nested;
                    }
                }
                yield Base64.getEncoder().encodeToString(bytes);
            }
            case WireFormat.WIRETYPE_FIXED32 -> input.readFixed32();
            case WireFormat.WIRETYPE_START_GROUP, WireFormat.WIRETYPE_END_GROUP -> null;
            default -> null;
        };
    }

    /** Get protobuf message: from gRPC frame if present, otherwise treat raw body as protobuf (application/proto). */
    public static byte[] getProtobufMessage(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        byte[] extracted = extractGrpcMessage(raw);
        return extracted != null ? extracted : raw;
    }

    /**
     * Decode gRPC-Web/gRPC or raw protobuf (application/proto) to human-readable protobuf wire view.
     */
    public static byte[] grpcWebDecodePretty(byte[] raw) {
        byte[] message = getProtobufMessage(raw);
        if (message == null || message.length == 0) return null;
        byte[] view = protobufRawWireView(message);
        if (view != null) return view;
        StringBuilder sb = new StringBuilder();
        sb.append("=== gRPC Message (protobuf parse failed, hex) ===\n");
        sb.append(bytesToHex(message));
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Decode gRPC-Web/gRPC or raw protobuf (application/proto) to JSON.
     * @param mappingStr optional "3=version,6001=metadata,6001.1=build_id" for field names from .proto
     */
    public static byte[] grpcWebDecodeJson(byte[] raw, String mappingStr) {
        byte[] message = getProtobufMessage(raw);
        if (message == null || message.length == 0) return null;
        byte[] json = protobufToJson(message, mappingStr);
        if (json != null) return json;
        return grpcWebDecodePretty(raw);
    }

    public static byte[] grpcWebDecodeJson(byte[] raw) {
        return grpcWebDecodeJson(raw, null);
    }

    /**
     * Encode JSON to protobuf binary. JSON keys must be field numbers (e.g. "1", "2", "1.1").
     * Supports: numbers (VARINT), strings (LENGTH_DELIMITED), objects (nested message), arrays (repeated).
     */
    public static byte[] jsonToProtobuf(byte[] json) {
        if (json == null || json.length == 0) return null;
        try {
            JsonNode root = JSON_MAPPER.readTree(json);
            if (root == null || !root.isObject()) return null;
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            CodedOutputStream out = CodedOutputStream.newInstance(bout);
            writeJsonToProtobuf(out, root);
            out.flush();
            return bout.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    private static void writeJsonToProtobuf(CodedOutputStream out, JsonNode node) throws IOException {
        if (node == null || !node.isObject()) return;
        Iterator<Map.Entry<String, JsonNode>> it = node.fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> e = it.next();
            int fieldNum;
            try {
                fieldNum = Integer.parseInt(e.getKey().trim());
            } catch (NumberFormatException ex) {
                continue;
            }
            JsonNode val = e.getValue();
            if (val.isArray()) {
                for (JsonNode elem : val) {
                    writeField(out, fieldNum, elem);
                }
            } else {
                writeField(out, fieldNum, val);
            }
        }
    }

    private static void writeField(CodedOutputStream out, int fieldNum, JsonNode val) throws IOException {
        if (val.isNumber()) {
            if (val.isIntegralNumber()) {
                out.writeTag(fieldNum, WireFormat.WIRETYPE_VARINT);
                out.writeUInt64NoTag(val.asLong());
            } else {
                out.writeTag(fieldNum, WireFormat.WIRETYPE_FIXED64);
                out.writeFixed64NoTag(Double.doubleToLongBits(val.asDouble()));
            }
        } else if (val.isTextual()) {
            byte[] bytes = val.asText().getBytes(StandardCharsets.UTF_8);
            out.writeTag(fieldNum, WireFormat.WIRETYPE_LENGTH_DELIMITED);
            out.writeByteArrayNoTag(bytes);
        } else if (val.isObject()) {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            CodedOutputStream nested = CodedOutputStream.newInstance(bout);
            writeJsonToProtobuf(nested, val);
            nested.flush();
            byte[] nestedBytes = bout.toByteArray();
            out.writeTag(fieldNum, WireFormat.WIRETYPE_LENGTH_DELIMITED);
            out.writeByteArrayNoTag(nestedBytes);
        } else if (val.isBoolean()) {
            out.writeTag(fieldNum, WireFormat.WIRETYPE_VARINT);
            out.writeBoolNoTag(val.asBoolean());
        } else if (val.isBinary()) {
            try {
                byte[] bytes = val.binaryValue();
                out.writeTag(fieldNum, WireFormat.WIRETYPE_LENGTH_DELIMITED);
                out.writeByteArrayNoTag(bytes);
            } catch (IOException ex) {
                byte[] bytes = Base64.getDecoder().decode(val.asText());
                out.writeTag(fieldNum, WireFormat.WIRETYPE_LENGTH_DELIMITED);
                out.writeByteArrayNoTag(bytes);
            }
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
