import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
/**
 * Structured data transcoding: JSON, form data, query string, multipart.
 */
public final class PayloadTranscoderStructured {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private PayloadTranscoderStructured() {}

    // --- JSON ---

    public static byte[] jsonPrettyPrint(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            String s = new String(raw, StandardCharsets.UTF_8).trim();
            if (s.isEmpty()) return null;
            JsonNode node = OBJECT_MAPPER.readTree(s);
            ObjectMapper prettyMapper = new ObjectMapper();
            prettyMapper.enable(SerializationFeature.INDENT_OUTPUT);
            DefaultPrettyPrinter printer = new DefaultPrettyPrinter();
            printer.indentArraysWith(DefaultIndenter.SYSTEM_LINEFEED_INSTANCE);
            printer.indentObjectsWith(DefaultIndenter.SYSTEM_LINEFEED_INSTANCE);
            String pretty = prettyMapper.writer(printer).writeValueAsString(node);
            return pretty.getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    public static byte[] jsonMinify(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            String s = new String(raw, StandardCharsets.UTF_8).trim();
            if (s.isEmpty()) return null;
            JsonNode node = OBJECT_MAPPER.readTree(s);
            String minified = OBJECT_MAPPER.writeValueAsString(node);
            return minified.getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    public static boolean looksLikeJson(byte[] raw) {
        if (raw == null || raw.length < 2) return false;
        String s = new String(raw, StandardCharsets.UTF_8).trim();
        return (s.startsWith("{") && s.endsWith("}")) || (s.startsWith("[") && s.endsWith("]"));
    }

    // --- Form data (application/x-www-form-urlencoded) ---

    public static byte[] formDataPrettyPrint(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            String s = new String(raw, StandardCharsets.UTF_8);
            if (!s.contains("=")) return null;
            List<String> pairs = parseFormPairs(s);
            if (pairs.isEmpty()) return null;
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < pairs.size(); i++) {
                if (i > 0) sb.append("\n");
                sb.append(pairs.get(i));
            }
            return sb.toString().getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] formDataRebuild(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            String s = new String(raw, StandardCharsets.UTF_8);
            List<String> pairs = parseFormPairs(s);
            if (pairs.isEmpty()) return null;
            return String.join("&", pairs).getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private static List<String> parseFormPairs(String s) {
        List<String> pairs = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '&' && current.length() > 0) {
                pairs.add(current.toString());
                current.setLength(0);
            } else if (c == '\n' || c == '\r') {
                if (current.length() > 0) {
                    pairs.add(current.toString().trim());
                    current.setLength(0);
                }
            } else {
                current.append(c);
            }
        }
        if (current.length() > 0) {
            pairs.add(current.toString().trim());
        }
        return pairs;
    }

    public static boolean looksLikeFormData(byte[] raw) {
        if (raw == null || raw.length < 3) return false;
        String s = new String(raw, StandardCharsets.UTF_8);
        return s.contains("=") && (s.contains("&") || s.indexOf('=') < s.length() - 1);
    }

    // --- Query string ---

    public static byte[] queryStringPrettyPrint(byte[] raw) {
        return formDataPrettyPrint(raw);
    }

    public static byte[] queryStringRebuild(byte[] raw) {
        return formDataRebuild(raw);
    }

    public static boolean looksLikeQueryString(byte[] raw) {
        return looksLikeFormData(raw);
    }

    // --- Multipart form-data ---

    public static class MultipartPart {
        public final Map<String, String> headers;
        public final byte[] body;
        public final String name;
        public final String filename;

        public MultipartPart(Map<String, String> headers, byte[] body, String name, String filename) {
            this.headers = headers;
            this.body = body;
            this.name = name;
            this.filename = filename;
        }
    }

    public static List<MultipartPart> parseMultipart(byte[] raw, String boundary) {
        if (raw == null || boundary == null || boundary.isEmpty()) return null;
        try {
            byte[] boundaryBytes = ("--" + boundary).getBytes(StandardCharsets.US_ASCII);
            byte[] endBoundary = ("--" + boundary + "--").getBytes(StandardCharsets.US_ASCII);
            List<MultipartPart> parts = new ArrayList<>();
            int i = 0;
            while (i < raw.length) {
                int start = indexOf(raw, boundaryBytes, i);
                if (start == -1) break;
                int partStart = start + boundaryBytes.length;
                if (partStart < raw.length && raw[partStart] == '\r') partStart += 2;
                else if (partStart < raw.length && raw[partStart] == '\n') partStart += 1;
                int nextBoundary = indexOf(raw, boundaryBytes, partStart);
                int endBoundaryPos = indexOf(raw, endBoundary, partStart);
                int partEnd = raw.length;
                if (nextBoundary != -1 && (endBoundaryPos == -1 || nextBoundary <= endBoundaryPos)) {
                    partEnd = nextBoundary;
                    if (partEnd >= 2 && raw[partEnd - 2] == '\r' && raw[partEnd - 1] == '\n') partEnd -= 2;
                    else if (partEnd >= 1 && raw[partEnd - 1] == '\n') partEnd -= 1;
                } else if (endBoundaryPos != -1) {
                    partEnd = endBoundaryPos;
                    if (partEnd >= 2 && raw[partEnd - 2] == '\r' && raw[partEnd - 1] == '\n') partEnd -= 2;
                    else if (partEnd >= 1 && raw[partEnd - 1] == '\n') partEnd -= 1;
                }
                int partLen = Math.max(0, partEnd - partStart);
                byte[] partData = new byte[partLen];
                if (partLen > 0) {
                    System.arraycopy(raw, partStart, partData, 0, partLen);
                }
                MultipartPart part = parseMultipartPart(partData);
                if (part != null) parts.add(part);
                i = partEnd;
                if (endBoundaryPos != -1 && partEnd == endBoundaryPos) break;
            }
            return parts.isEmpty() ? null : parts;
        } catch (Exception e) {
            return null;
        }
    }

    private static MultipartPart parseMultipartPart(byte[] partData) {
        int headerEnd = indexOf(partData, "\r\n\r\n".getBytes(StandardCharsets.US_ASCII), 0);
        if (headerEnd == -1) headerEnd = indexOf(partData, "\n\n".getBytes(StandardCharsets.US_ASCII), 0);
        if (headerEnd == -1) return null;
        String headerBlock = new String(partData, 0, headerEnd, StandardCharsets.UTF_8);
        int bodyStart = headerEnd + 4;
        if (partData.length > headerEnd + 2 && partData[headerEnd] == '\r' && partData[headerEnd + 1] == '\n') {
            bodyStart = headerEnd + 4;
        } else if (partData.length > headerEnd + 1 && partData[headerEnd] == '\n') {
            bodyStart = headerEnd + 2;
        }
        byte[] body = bodyStart < partData.length
                ? java.util.Arrays.copyOfRange(partData, bodyStart, partData.length)
                : new byte[0];
        Map<String, String> headers = new LinkedHashMap<>();
        String name = null;
        String filename = null;
        for (String line : headerBlock.split("[\r\n]+")) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                String key = line.substring(0, colon).trim().toLowerCase();
                String value = line.substring(colon + 1).trim();
                headers.put(key, value);
                if ("content-disposition".equals(key)) {
                    name = extractDispositionParam(value, "name");
                    filename = extractDispositionParam(value, "filename");
                }
            }
        }
        return new MultipartPart(headers, body, name, filename);
    }

    private static String extractDispositionParam(String value, String param) {
        String search = param + "=\"";
        int start = value.toLowerCase().indexOf(search);
        if (start == -1) {
            search = param + "=";
            start = value.toLowerCase().indexOf(search);
            if (start == -1) return null;
            start += search.length();
            int end = value.indexOf(';', start);
            if (end == -1) end = value.length();
            return value.substring(start, end).trim();
        }
        start += search.length();
        int end = value.indexOf('"', start);
        if (end == -1) return null;
        return value.substring(start, end);
    }

    public static byte[] buildMultipart(List<MultipartPart> parts, String boundary) {
        if (parts == null || parts.isEmpty() || boundary == null) return null;
        try {
            byte[] boundaryBytes = ("--" + boundary + "\r\n").getBytes(StandardCharsets.US_ASCII);
            byte[] crlf = "\r\n".getBytes(StandardCharsets.US_ASCII);
            byte[] endBoundary = ("--" + boundary + "--\r\n").getBytes(StandardCharsets.US_ASCII);
            List<byte[]> chunks = new ArrayList<>();
            for (MultipartPart part : parts) {
                chunks.add(boundaryBytes);
                for (Map.Entry<String, String> h : part.headers.entrySet()) {
                    chunks.add((h.getKey() + ": " + h.getValue() + "\r\n").getBytes(StandardCharsets.UTF_8));
                }
                chunks.add(crlf);
                chunks.add(part.body);
                chunks.add(crlf);
            }
            chunks.add(endBoundary);
            int total = 0;
            for (byte[] c : chunks) total += c.length;
            byte[] result = new byte[total];
            int pos = 0;
            for (byte[] c : chunks) {
                System.arraycopy(c, 0, result, pos, c.length);
                pos += c.length;
            }
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    public static String extractBoundaryFromContentType(String contentType) {
        if (contentType == null) return null;
        String lower = contentType.toLowerCase();
        int boundaryIdx = lower.indexOf("boundary=");
        if (boundaryIdx == -1) return null;
        boundaryIdx += 9;
        String rest = contentType.substring(boundaryIdx).trim();
        if (rest.startsWith("\"")) {
            int end = rest.indexOf('"', 1);
            if (end == -1) return null;
            return rest.substring(1, end).trim();
        }
        int end = 0;
        while (end < rest.length() && rest.charAt(end) != ';' && rest.charAt(end) != ' ' && rest.charAt(end) != '\t') {
            end++;
        }
        return rest.substring(0, end).trim();
    }

    public static byte[] multipartPrettyPrint(byte[] raw, String boundary) {
        List<MultipartPart> parts = parseMultipart(raw, boundary);
        if (parts == null || parts.isEmpty()) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.size(); i++) {
            MultipartPart p = parts.get(i);
            if (i > 0) sb.append("\n\n---\n\n");
            sb.append("Part ").append(i + 1);
            if (p.name != null) sb.append(" (name=").append(p.name).append(")");
            if (p.filename != null) sb.append(" [filename=").append(p.filename).append("]");
            sb.append("\n");
            for (Map.Entry<String, String> h : p.headers.entrySet()) {
                sb.append("  ").append(h.getKey()).append(": ").append(h.getValue()).append("\n");
            }
            sb.append("\n");
            String bodyStr = new String(p.body, StandardCharsets.UTF_8);
            if (isPrintable(bodyStr)) {
                sb.append(bodyStr);
            } else {
                sb.append("[binary, ").append(p.body.length).append(" bytes]");
            }
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static boolean isPrintable(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 32 && c != '\n' && c != '\r' && c != '\t') return false;
            if (c > 126) return false;
        }
        return true;
    }

    private static int indexOf(byte[] haystack, byte[] needle, int from) {
        if (from < 0 || needle.length == 0 || haystack.length - from < needle.length) return -1;
        for (int i = from; i <= haystack.length - needle.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }
}
