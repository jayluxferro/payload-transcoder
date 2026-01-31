import com.google.protobuf.CodedInputStream;
import com.google.protobuf.WireFormat;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
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

    public static GrpcFrame parseGrpcFrame(byte[] raw) {
        if (raw == null || raw.length < 5) return null;
        try {
            boolean compressed = raw[0] != 0;
            int messageLength = ByteBuffer.wrap(raw, 1, 4).order(ByteOrder.BIG_ENDIAN).getInt();
            if (messageLength < 0 || messageLength > raw.length - 5) return null;
            byte[] message = new byte[messageLength];
            System.arraycopy(raw, 5, message, 0, messageLength);
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
        if (message == null || message.length == 0) return null;
        try {
            List<String> lines = new ArrayList<>();
            CodedInputStream input = CodedInputStream.newInstance(message);
            while (true) {
                int tag = input.readTag();
                if (tag == 0) break;
                int fieldNumber = WireFormat.getTagFieldNumber(tag);
                int wireType = WireFormat.getTagWireType(tag);
                try {
                    String value = readWireValue(input, wireType);
                    if (value != null) {
                        lines.add(String.format("field %d (wire %d): %s", fieldNumber, wireType, value));
                    } else {
                        input.skipField(tag);
                        lines.add(String.format("field %d (wire %d): [skipped]", fieldNumber, wireType));
                    }
                } catch (IOException ex) {
                    input.skipField(tag);
                    lines.add(String.format("field %d (wire %d): [parse error]", fieldNumber, wireType));
                }
            }
            if (lines.isEmpty()) return null;
            return String.join("\n", lines).getBytes(StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    private static String readWireValue(CodedInputStream input, int wireType) throws IOException {
        return switch (wireType) {
            case WireFormat.WIRETYPE_VARINT -> String.valueOf(input.readInt64());
            case WireFormat.WIRETYPE_FIXED64 -> String.valueOf(input.readFixed64());
            case WireFormat.WIRETYPE_LENGTH_DELIMITED -> {
                byte[] bytes = input.readByteArray();
                if (isPrintableAscii(bytes)) {
                    yield "\"" + new String(bytes, StandardCharsets.UTF_8) + "\"";
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

    public static byte[] extractGrpcMessage(byte[] raw) {
        GrpcFrame frame = parseGrpcFrame(raw);
        return frame != null ? frame.message : null;
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
