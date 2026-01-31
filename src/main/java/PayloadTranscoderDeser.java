import java.nio.charset.StandardCharsets;

/**
 * Deserialization detection: Java serialized objects, .NET ViewState.
 */
public final class PayloadTranscoderDeser {

    private PayloadTranscoderDeser() {}

    /**
     * Detect and describe Java serialized object. Returns hex dump of magic + header, or "Not Java serialized".
     */
    public static byte[] detectJavaSerialized(byte[] input) {
        if (input == null || input.length < 4) return "Input too short or null".getBytes(StandardCharsets.UTF_8);
        if ((input[0] & 0xFF) != 0xAC || (input[1] & 0xFF) != 0xED) return "Not Java serialized (expected magic AC ED)".getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder();
        sb.append("=== Java Serialized Object ===\n");
        sb.append("Magic: AC ED (Java serialization stream)\n");
        sb.append("Version: ").append(input[2] & 0xFF).append(" ").append(input[3] & 0xFF).append("\n");
        int len = Math.min(input.length, 64);
        sb.append("Hex (first ").append(len).append(" bytes):\n");
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02x ", input[i] & 0xFF));
            if ((i + 1) % 16 == 0) sb.append("\n");
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Detect .NET ViewState. Input should be base64 ViewState or full HTML with __VIEWSTATE.
     */
    public static byte[] detectViewState(byte[] input) {
        if (input == null || input.length < 20) return "Input too short or null".getBytes(StandardCharsets.UTF_8);
        String s = new String(input, StandardCharsets.UTF_8);
        if (!s.contains("__VIEWSTATE")) return "No __VIEWSTATE found".getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder();
        sb.append("=== .NET ViewState ===\n");
        sb.append("Contains __VIEWSTATE (base64 encoded .NET serialized state)\n");
        sb.append("Decode with: Base64 decode, then parse .NET binary format\n");
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Check if input looks like Java serialized.
     */
    public static boolean looksLikeJavaSerialized(byte[] input) {
        return input != null && input.length >= 4
                && (input[0] & 0xFF) == 0xAC && (input[1] & 0xFF) == 0xED;
    }
}
