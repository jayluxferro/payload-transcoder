import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Smart detection of likely encodings from payload content.
 */
public final class PayloadTranscoderDetect {

    private static final int DETECT_SAMPLE_LIMIT = 32 * 1024;

    private PayloadTranscoderDetect() {}

    public static class Suggestion {
        public final String operation;
        public final String reason;

        public Suggestion(String operation, String reason) {
            this.operation = operation;
            this.reason = reason;
        }
    }

    /**
     * Returns the single best suggestion for smart decode. Fast path: only one operation
     * is tried per recursion level. Order: binary magic first, then encodings, then pretty-print.
     */
    public static Suggestion suggestBest(byte[] input) {
        if (input == null || input.length == 0) return null;

        // Binary magic bytes - O(1), no string allocation
        if (input.length >= 2 && (input[0] & 0xff) == 0x1f && (input[1] & 0xff) == 0x8b) {
            return new Suggestion("Decode gzip", "gzip magic bytes (1f 8b)");
        }
        if (input.length >= 4 && PayloadTranscoderCompression.looksLikeZstd(input)) {
            return new Suggestion("Decode zstd", "zstd magic bytes (28 b5 2f fd)");
        }
        if (PayloadTranscoderGrpc.looksLikeGrpcBytes(input)) {
            return new Suggestion("Decode gRPC-Web (JSON)", "Looks like gRPC/gRPC-Web framing");
        }
        if (PayloadTranscoderProtocol.looksLikeWebSocketFrame(input)) {
            return new Suggestion("WebSocket frame inspect", "Looks like WebSocket frame");
        }
        if (PayloadTranscoderStructured.extractBoundaryFromRaw(input) != null) {
            return new Suggestion("Multipart pretty-print", "Looks like multipart form-data");
        }
        if (PayloadTranscoderStructured.looksLikeFormData(input)) {
            return new Suggestion("Form/query pretty-print", "Looks like form/query data");
        }

        int sampleLen = Math.min(input.length, DETECT_SAMPLE_LIMIT);
        String s = new String(input, 0, sampleLen, StandardCharsets.UTF_8).trim();
        if (s.isEmpty()) return null;

        // JWT - distinctive, cheap check
        if (s.matches("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$")) {
            return new Suggestion("Decode JWT (pretty-print)", "Looks like JWT");
        }

        // GraphQL introspection - specific
        if (PayloadTranscoderProtocol.looksLikeGraphqlIntrospection(input)) {
            return new Suggestion("GraphQL introspection pretty-print", "Looks like GraphQL introspection");
        }

        // Encodings (decode first, then we can pretty-print decoded content)
        if (s.matches("^[A-Za-z0-9+/=\\s]+$") && s.length() >= 4 && s.length() % 4 == 0) {
            return new Suggestion("Decode Base64", "Looks like Base64");
        }
        if (s.matches("^[A-Za-z0-9_-]+$") && s.length() >= 4) {
            return new Suggestion("Decode Base64 URL-safe", "Looks like URL-safe Base64");
        }
        String hexOnly = s.replaceAll("\\s", "");
        if (s.matches("^[0-9a-fA-F\\s]+$") && hexOnly.length() % 2 == 0 && hexOnly.length() >= 2) {
            return new Suggestion("Decode Hex", "Looks like hex");
        }
        if (s.contains("%") && s.matches(".*%[0-9a-fA-F]{2}.*")) {
            return new Suggestion("Decode URL", "Contains %XX URL encoding");
        }
        if (s.contains("&") && (s.contains(";") || s.contains("amp") || s.contains("lt") || s.contains("gt"))) {
            return new Suggestion("Decode HTML entities", "Contains HTML entities");
        }
        if (s.contains("\\u") && s.matches(".*\\\\u[0-9a-fA-F]{4}.*")) {
            return new Suggestion("Decode Unicode escapes", "Contains \\uXXXX escapes");
        }

        // Pretty-print for structured text (no decoding needed)
        // When sample is truncated (large gzip→JSON etc), endsWith fails; use startsWith only
        String trimmed = s.trim();
        boolean fullSample = sampleLen >= input.length;
        boolean looksLikeJson = (trimmed.startsWith("{") && (trimmed.endsWith("}") || !fullSample))
                || (trimmed.startsWith("[") && (trimmed.endsWith("]") || !fullSample));
        if (looksLikeJson) {
            return new Suggestion("JSON pretty-print", "Looks like JSON");
        }
        if (trimmed.startsWith("{") && (s.contains("query") || s.contains("mutation"))) {
            return new Suggestion("GraphQL pretty-print", "Looks like GraphQL");
        }
        if (trimmed.startsWith("<") && s.contains(">")) {
            return new Suggestion("XML pretty-print", "Looks like XML");
        }

        // Raw protobuf (application/proto) - no gRPC framing; try parse as protobuf
        if (input.length >= 4 && input.length <= DETECT_SAMPLE_LIMIT) {
            byte[] wireView = PayloadTranscoderGrpc.protobufRawWireView(input);
            if (wireView != null) {
                return new Suggestion("Protobuf raw wire view", "Looks like raw protobuf (application/proto)");
            }
        }

        return null;
    }

    /** Returns a pretty-print suggestion only (JSON, XML, GraphQL). No decoding. */
    public static Suggestion suggestPretty(byte[] input) {
        if (input == null || input.length == 0) return null;
        int sampleLen = Math.min(input.length, DETECT_SAMPLE_LIMIT);
        String s = new String(input, 0, sampleLen, StandardCharsets.UTF_8).trim();
        if (s.isEmpty()) return null;
        String trimmed = s.trim();
        boolean fullSample = sampleLen >= input.length;
        boolean looksLikeJson = (trimmed.startsWith("{") && (trimmed.endsWith("}") || !fullSample))
                || (trimmed.startsWith("[") && (trimmed.endsWith("]") || !fullSample));
        if (looksLikeJson) {
            return new Suggestion("JSON pretty-print", "Looks like JSON");
        }
        if (trimmed.startsWith("<") && s.contains(">")) {
            return new Suggestion("XML pretty-print", "Looks like XML");
        }
        if (trimmed.startsWith("{") && (s.contains("query") || s.contains("mutation"))) {
            return new Suggestion("GraphQL pretty-print", "Looks like GraphQL");
        }
        if (PayloadTranscoderProtocol.looksLikeGraphqlIntrospection(input)) {
            return new Suggestion("GraphQL introspection pretty-print", "Looks like GraphQL introspection");
        }
        if (PayloadTranscoderStructured.looksLikeFormData(input)) {
            return new Suggestion("Form/query pretty-print", "Looks like form/query data");
        }
        if (PayloadTranscoderStructured.extractBoundaryFromRaw(input) != null) {
            return new Suggestion("Multipart pretty-print", "Looks like multipart form-data");
        }
        if (PayloadTranscoderProtocol.looksLikeWebSocketFrame(input)) {
            return new Suggestion("WebSocket frame inspect", "Looks like WebSocket frame");
        }
        return null;
    }

    public static List<Suggestion> suggest(byte[] input) {
        List<Suggestion> out = new ArrayList<>();
        if (input == null || input.length == 0) return out;

        int sampleLen = Math.min(input.length, DETECT_SAMPLE_LIMIT);
        String s = new String(input, 0, sampleLen, StandardCharsets.UTF_8).trim();

        // Base64
        if (s.matches("^[A-Za-z0-9+/=\\s]+$") && s.length() >= 4 && s.length() % 4 == 0) {
            out.add(new Suggestion("Decode Base64", "Looks like Base64 (alphanumeric + / =)"));
        }
        if (s.matches("^[A-Za-z0-9_-]+$") && s.length() >= 4) {
            out.add(new Suggestion("Decode Base64 URL-safe", "Looks like URL-safe Base64"));
        }

        // Hex
        if (s.matches("^[0-9a-fA-F\\s]+$") && s.replaceAll("\\s", "").length() % 2 == 0 && s.length() >= 2) {
            out.add(new Suggestion("Decode Hex", "Looks like hex-encoded"));
        }

        // URL
        if (s.contains("%") && s.matches(".*%[0-9a-fA-F]{2}.*")) {
            out.add(new Suggestion("Decode URL", "Contains %XX URL encoding"));
        }

        // HTML entities
        if (s.contains("&") && (s.contains(";") || s.contains("amp") || s.contains("lt") || s.contains("gt"))) {
            out.add(new Suggestion("Decode HTML entities", "Contains &...; HTML entities"));
        }

        // Unicode escapes
        if (s.contains("\\u") && s.matches(".*\\\\u[0-9a-fA-F]{4}.*")) {
            out.add(new Suggestion("Decode Unicode escapes", "Contains \\uXXXX escapes"));
        }

        // JSON
        if ((s.startsWith("{") && s.endsWith("}")) || (s.startsWith("[") && s.endsWith("]"))) {
            out.add(new Suggestion("JSON pretty-print", "Looks like JSON"));
        }

        // JWT
        if (s.matches("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$")) {
            out.add(new Suggestion("Decode JWT (pretty-print)", "Looks like JWT (header.payload.signature)"));
            out.add(new Suggestion("JWT alg:none attack", "Try alg:none to bypass signature verification"));
        }

        // gzip magic
        if (input.length >= 2 && (input[0] & 0xff) == 0x1f && (input[1] & 0xff) == 0x8b) {
            out.add(new Suggestion("Decode gzip", "gzip magic bytes (1f 8b)"));
        }

        // zstd magic
        if (PayloadTranscoderCompression.looksLikeZstd(input)) {
            out.add(new Suggestion("Decode zstd", "zstd magic bytes (28 b5 2f fd)"));
        }

        // GraphQL
        if (s.trim().startsWith("{") && (s.contains("query") || s.contains("mutation"))) {
            out.add(new Suggestion("GraphQL pretty-print", "Looks like GraphQL"));
        }
        if (PayloadTranscoderProtocol.looksLikeGraphqlIntrospection(input)) {
            out.add(new Suggestion("GraphQL introspection pretty-print", "Looks like GraphQL introspection"));
        }

        // XML
        if (s.trim().startsWith("<") && s.contains(">")) {
            out.add(new Suggestion("XML pretty-print", "Looks like XML"));
        }

        // Form/query
        if (PayloadTranscoderStructured.looksLikeFormData(input)) {
            out.add(new Suggestion("Form/query pretty-print", "Looks like form/query data"));
        }

        // Multipart
        if (PayloadTranscoderStructured.extractBoundaryFromRaw(input) != null) {
            out.add(new Suggestion("Multipart pretty-print", "Looks like multipart form-data"));
        }

        // WebSocket frame
        if (PayloadTranscoderProtocol.looksLikeWebSocketFrame(input)) {
            out.add(new Suggestion("WebSocket frame inspect", "Looks like WebSocket frame"));
        }

        // Unicode normalization - suggest when text has non-ASCII (potential bypass testing)
        if (s.codePoints().anyMatch(cp -> cp > 127)) {
            out.add(new Suggestion("Normalize NFC", "Unicode NFC normalization"));
            out.add(new Suggestion("Normalize NFD", "Unicode NFD normalization"));
        }

        return out;
    }
}
