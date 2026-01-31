import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility methods for transcoding payloads between formats.
 */
public final class PayloadTranscoderUtils {

    private PayloadTranscoderUtils() {}

    private static final Map<String, String> HTML_ENTITIES = new HashMap<>();
    static {
        HTML_ENTITIES.put("&amp;", "&");
        HTML_ENTITIES.put("&lt;", "<");
        HTML_ENTITIES.put("&gt;", ">");
        HTML_ENTITIES.put("&quot;", "\"");
        HTML_ENTITIES.put("&apos;", "'");
        HTML_ENTITIES.put("&nbsp;", "\u00A0");
        HTML_ENTITIES.put("&copy;", "\u00A9");
        HTML_ENTITIES.put("&reg;", "\u00AE");
        HTML_ENTITIES.put("&trade;", "\u2122");
        HTML_ENTITIES.put("&euro;", "\u20AC");
        HTML_ENTITIES.put("&mdash;", "\u2014");
        HTML_ENTITIES.put("&ndash;", "\u2013");
        HTML_ENTITIES.put("&hellip;", "\u2026");
    }

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

    public static byte[] decodeUrl(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            String s = new String(raw, StandardCharsets.UTF_8);
            if (!s.contains("%") && !s.contains("+")) return null; // Nothing to decode
            String decoded = URLDecoder.decode(s, StandardCharsets.UTF_8);
            return decoded.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    // --- HTML entities ---

    public static byte[] decodeHtmlEntities(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            String s = new String(raw, StandardCharsets.UTF_8);
            if (!s.contains("&")) return null;
            StringBuilder sb = new StringBuilder(s.length());
            int i = 0;
            while (i < s.length()) {
                if (s.charAt(i) == '&') {
                    int end = s.indexOf(';', i);
                    if (end == -1) {
                        sb.append(s.charAt(i));
                        i++;
                        continue;
                    }
                    String entity = s.substring(i, end + 1);
                    String decoded = HTML_ENTITIES.get(entity);
                    if (decoded != null) {
                        sb.append(decoded);
                        i = end + 1;
                        continue;
                    }
                    if (entity.startsWith("&#x") || entity.startsWith("&#X")) {
                        try {
                            int codePoint = Integer.parseInt(entity.substring(3, entity.length() - 1), 16);
                            sb.appendCodePoint(codePoint);
                            i = end + 1;
                            continue;
                        } catch (NumberFormatException ignored) {}
                    }
                    if (entity.startsWith("&#")) {
                        try {
                            int codePoint = Integer.parseInt(entity.substring(2, entity.length() - 1), 10);
                            sb.appendCodePoint(codePoint);
                            i = end + 1;
                            continue;
                        } catch (NumberFormatException ignored) {}
                    }
                    sb.append(entity);
                    i = end + 1;
                } else {
                    sb.append(s.charAt(i));
                    i++;
                }
            }
            return sb.toString().getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    public static String encodeHtmlEntities(byte[] bytes) {
        if (bytes == null) return null;
        try {
            String s = new String(bytes, StandardCharsets.UTF_8);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < s.length(); i++) {
                int cp = s.codePointAt(i);
                if (cp == '&') sb.append("&amp;");
                else if (cp == '<') sb.append("&lt;");
                else if (cp == '>') sb.append("&gt;");
                else if (cp == '"') sb.append("&quot;");
                else if (cp == '\'') sb.append("&apos;");
                else if (cp < 32 || cp > 126) sb.append("&#").append(cp).append(";");
                else sb.appendCodePoint(cp);
                if (Character.isSupplementaryCodePoint(cp)) i++;
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    // --- Unicode escapes ---

    private static final Pattern UNICODE_ESCAPE_U8 = Pattern.compile("\\\\U([0-9a-fA-F]{8})");
    private static final Pattern UNICODE_ESCAPE_U4 = Pattern.compile("\\\\u([0-9a-fA-F]{4})");
    private static final Pattern UNICODE_ESCAPE_X2 = Pattern.compile("\\\\x([0-9a-fA-F]{2})");
    private static final Pattern OCTAL_ESCAPE = Pattern.compile("\\\\([0-7]{1,3})");

    public static byte[] decodeUnicodeEscapes(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            String s = new String(raw, StandardCharsets.UTF_8);
            if (!s.contains("\\")) return null;
            // Process in order: U+8hex, u+4hex, x+2hex, octal
            String result = s;
            Matcher m = UNICODE_ESCAPE_U8.matcher(result);
            StringBuilder sb = new StringBuilder();
            while (m.find()) {
                int cp = Integer.parseInt(m.group(1), 16);
                m.appendReplacement(sb, Matcher.quoteReplacement(new String(Character.toChars(cp))));
            }
            m.appendTail(sb);
            result = sb.toString();
            sb.setLength(0);
            m = UNICODE_ESCAPE_U4.matcher(result);
            while (m.find()) {
                int cp = Integer.parseInt(m.group(1), 16);
                m.appendReplacement(sb, Matcher.quoteReplacement(new String(Character.toChars(cp))));
            }
            m.appendTail(sb);
            result = sb.toString();
            sb.setLength(0);
            m = UNICODE_ESCAPE_X2.matcher(result);
            while (m.find()) {
                int b = Integer.parseInt(m.group(1), 16);
                m.appendReplacement(sb, Matcher.quoteReplacement(String.valueOf((char) b)));
            }
            m.appendTail(sb);
            result = sb.toString();
            sb.setLength(0);
            m = OCTAL_ESCAPE.matcher(result);
            while (m.find()) {
                int b = Integer.parseInt(m.group(1), 8);
                if (b <= 0xFF) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(String.valueOf((char) b)));
                } else {
                    m.appendReplacement(sb, Matcher.quoteReplacement(m.group(0)));
                }
            }
            m.appendTail(sb);
            result = sb.toString();
            return result.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    public static String encodeUnicodeEscapes(byte[] bytes) {
        if (bytes == null) return null;
        try {
            String s = new String(bytes, StandardCharsets.UTF_8);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < s.length(); i++) {
                int cp = s.codePointAt(i);
                if (cp <= 0x7F) sb.append((char) cp);
                else if (cp <= 0xFFFF) sb.append(String.format("\\u%04X", cp));
                else sb.append(String.format("\\U%08X", cp));
                if (Character.isSupplementaryCodePoint(cp)) i++;
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    // --- Quoted-printable (RFC 2045) ---

    public static byte[] decodeQuotedPrintable(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            String s = new String(raw, StandardCharsets.US_ASCII);
            if (!s.contains("=")) return null;
            StringBuilder sb = new StringBuilder();
            int i = 0;
            while (i < s.length()) {
                if (s.charAt(i) == '=') {
                    if (i + 2 < s.length()) {
                        char c1 = s.charAt(i + 1);
                        char c2 = s.charAt(i + 2);
                        if (isHexDigit(c1) && isHexDigit(c2)) {
                            int b = Integer.parseInt(s.substring(i + 1, i + 3), 16);
                            sb.append((char) b);
                            i += 3;
                            continue;
                        }
                    }
                    // Soft line break: = followed by CRLF or LF
                    if (i + 1 < s.length()) {
                        char next = s.charAt(i + 1);
                        if (next == '\n') {
                            i += 2; // skip =\n
                            continue;
                        }
                        if (next == '\r' && i + 2 < s.length() && s.charAt(i + 2) == '\n') {
                            i += 3; // skip =\r\n
                            continue;
                        }
                    }
                }
                sb.append(s.charAt(i));
                i++;
            }
            return sb.toString().getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }

    public static String encodeQuotedPrintable(byte[] bytes) {
        if (bytes == null) return null;
        StringBuilder sb = new StringBuilder();
        int lineLen = 0;
        for (byte b : bytes) {
            int v = b & 0xFF;
            if (v >= 33 && v <= 126 && v != 61) {
                if (lineLen >= 75) {
                    sb.append("=\r\n");
                    lineLen = 0;
                }
                sb.append((char) v);
                lineLen++;
            } else {
                if (lineLen >= 73) {
                    sb.append("=\r\n");
                    lineLen = 0;
                }
                sb.append(String.format("=%02X", v));
                lineLen += 3;
            }
        }
        return sb.toString();
    }
}
