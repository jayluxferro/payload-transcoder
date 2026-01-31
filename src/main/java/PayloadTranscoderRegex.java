import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Regex find/replace for payload manipulation.
 */
public final class PayloadTranscoderRegex {

    private PayloadTranscoderRegex() {}

    /**
     * Replace all matches of regex with replacement string.
     * @param input raw bytes
     * @param regex pattern (Java regex)
     * @param replacement replacement string (supports $1, $2, etc. for groups)
     * @return replaced bytes, or null on error
     */
    public static byte[] replace(byte[] input, String regex, String replacement) {
        if (input == null || regex == null || replacement == null) return null;
        try {
            String str = new String(input, StandardCharsets.UTF_8);
            String result = str.replaceAll(regex, replacement);
            return result.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Replace first match only.
     */
    public static byte[] replaceFirst(byte[] input, String regex, String replacement) {
        if (input == null || regex == null || replacement == null) return null;
        try {
            String str = new String(input, StandardCharsets.UTF_8);
            String result = str.replaceFirst(regex, replacement);
            return result.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extract first match of regex group (group 1 by default).
     */
    public static byte[] extract(byte[] input, String regex, int group) {
        if (input == null || regex == null) return null;
        try {
            String str = new String(input, StandardCharsets.UTF_8);
            Matcher m = Pattern.compile(regex).matcher(str);
            if (m.find() && m.groupCount() >= group) {
                String match = m.group(group);
                return match != null ? match.getBytes(StandardCharsets.UTF_8) : null;
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }
}
