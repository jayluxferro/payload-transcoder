import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Utility methods for transcoding payloads between formats.
 */
public final class PayloadTranscoderUtils {

    private PayloadTranscoderUtils() {}

    // --- Base64 ---

    public static byte[] decodeBase64(byte[] raw) {
        if (raw == null || raw.length < 4) return null;
        try {
            String s = new String(raw, StandardCharsets.US_ASCII);
            if (!s.matches("^[A-Za-z0-9+/=\\s\\r\\n]+$")) return null;
            return Base64.getDecoder().decode(s.replaceAll("\\s", ""));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public static byte[] decodeBase64UrlSafe(byte[] raw) {
        if (raw == null || raw.length < 4) return null;
        try {
            String s = new String(raw, StandardCharsets.US_ASCII);
            if (!s.matches("^[A-Za-z0-9_-]+$")) return null;
            return Base64.getUrlDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public static String encodeBase64(byte[] bytes) {
        if (bytes == null) return null;
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static String encodeBase64UrlSafe(byte[] bytes) {
        if (bytes == null) return null;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // --- Hex ---

    public static byte[] decodeHex(byte[] raw) {
        if (raw == null || raw.length < 2) return null;
        try {
            String s = new String(raw, StandardCharsets.US_ASCII).replaceAll("\\s", "");
            if (!s.matches("^[0-9a-fA-F]+$") || s.length() % 2 != 0) return null;
            byte[] out = new byte[s.length() / 2];
            for (int i = 0; i < out.length; i++) {
                out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
            }
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    public static String encodeHex(byte[] bytes) {
        if (bytes == null) return null;
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    // --- URL encoding ---

    public static String encodeUrl(byte[] bytes) {
        if (bytes == null) return null;
        try {
            String s = new String(bytes, StandardCharsets.UTF_8);
            return URLEncoder.encode(s, StandardCharsets.UTF_8)
                    .replace("+", "%20"); // Use %20 for space per RFC 3986
        } catch (Exception e) {
            return null;
        }
    }

    public static String encodeUrlStrict(byte[] bytes) {
        if (bytes == null) return null;
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            int v = b & 0xFF;
            if ((v >= 'A' && v <= 'Z') || (v >= 'a' && v <= 'z') || (v >= '0' && v <= '9')
                    || v == '-' || v == '_' || v == '.' || v == '~') {
                sb.append((char) v);
            } else {
                sb.append(String.format("%%%02X", v));
            }
        }
        return sb.toString();
    }
}
