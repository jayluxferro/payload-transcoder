import java.nio.charset.StandardCharsets;

/**
 * PHP serialize/unserialize pretty-print and encode.
 */
public final class PayloadTranscoderPhp {

    private PayloadTranscoderPhp() {}

    /**
     * Pretty-print PHP serialized format to human-readable structure.
     */
    public static byte[] phpSerializedPrettyPrint(byte[] input) {
        if (input == null || input.length == 0) return null;
        try {
            String s = new String(input, StandardCharsets.UTF_8).trim();
            StringBuilder out = new StringBuilder();
            int[] pos = {0};
            if (parseValue(s, pos, out, 0)) {
                return out.toString().getBytes(StandardCharsets.UTF_8);
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static boolean parseValue(String s, int[] pos, StringBuilder out, int indent) {
        if (pos[0] >= s.length()) return false;
        String ind = "  ".repeat(indent);
        char type = s.charAt(pos[0]++);
        return switch (type) {
            case 'N' -> { if (pos[0] < s.length() && s.charAt(pos[0]) == ';') { pos[0]++; out.append(ind).append("null"); yield true; } yield false; }
            case 'b' -> parseBool(s, pos, out, ind);
            case 'i' -> parseInt(s, pos, out, ind);
            case 'd' -> parseDouble(s, pos, out, ind);
            case 's' -> parseString(s, pos, out, ind);
            case 'a' -> parseArray(s, pos, out, indent);
            case 'O' -> parseObject(s, pos, out, indent);
            case 'r', 'R' -> { out.append(ind).append("[reference]"); yield false; }
            default -> false;
        };
    }

    private static boolean parseBool(String s, int[] pos, StringBuilder out, String ind) {
        if (pos[0] + 2 > s.length() || s.charAt(pos[0]) != ':') return false;
        pos[0]++;
        int end = s.indexOf(';', pos[0]);
        if (end < 0) return false;
        String v = s.substring(pos[0], end);
        pos[0] = end + 1;
        out.append(ind).append("bool: ").append("1".equals(v));
        return true;
    }

    private static boolean parseInt(String s, int[] pos, StringBuilder out, String ind) {
        if (pos[0] >= s.length() || s.charAt(pos[0]) != ':') return false;
        pos[0]++;
        int end = s.indexOf(';', pos[0]);
        if (end < 0) return false;
        out.append(ind).append("int: ").append(s.substring(pos[0], end));
        pos[0] = end + 1;
        return true;
    }

    private static boolean parseDouble(String s, int[] pos, StringBuilder out, String ind) {
        if (pos[0] >= s.length() || s.charAt(pos[0]) != ':') return false;
        pos[0]++;
        int end = s.indexOf(';', pos[0]);
        if (end < 0) return false;
        out.append(ind).append("double: ").append(s.substring(pos[0], end));
        pos[0] = end + 1;
        return true;
    }

    private static boolean parseString(String s, int[] pos, StringBuilder out, String ind) {
        if (pos[0] >= s.length() || s.charAt(pos[0]) != ':') return false;
        pos[0]++;
        int lenEnd = s.indexOf(':', pos[0]);
        if (lenEnd < 0) return false;
        int len = Integer.parseInt(s.substring(pos[0], lenEnd).trim());
        pos[0] = lenEnd + 1;
        if (pos[0] >= s.length() || s.charAt(pos[0]) != '"') return false;
        pos[0]++;
        if (pos[0] + len > s.length()) return false;
        String val = s.substring(pos[0], pos[0] + len);
        pos[0] += len;
        if (pos[0] < s.length() && s.charAt(pos[0]) == '"') pos[0]++;
        if (pos[0] < s.length() && s.charAt(pos[0]) == ';') pos[0]++;
        out.append(ind).append("string: \"").append(val.replace("\\", "\\\\").replace("\"", "\\\"")).append("\"");
        return true;
    }

    private static boolean parseArray(String s, int[] pos, StringBuilder out, int indent) {
        if (pos[0] + 2 > s.length() || s.charAt(pos[0]) != ':') return false;
        pos[0]++;
        int countEnd = s.indexOf(':', pos[0]);
        if (countEnd < 0) return false;
        int count = Integer.parseInt(s.substring(pos[0], countEnd).trim());
        pos[0] = countEnd + 1;
        if (pos[0] >= s.length() || s.charAt(pos[0]) != '{') return false;
        pos[0]++;
        out.append("  ".repeat(indent)).append("array(").append(count).append(") {\n");
        for (int i = 0; i < count && pos[0] < s.length() && s.charAt(pos[0]) != '}'; i++) {
            out.append("  ".repeat(indent + 1));
            StringBuilder keyOut = new StringBuilder();
            if (!parseValue(s, pos, keyOut, 0)) return false;
            out.append(keyOut).append(" => ");
            if (!parseValue(s, pos, out, indent + 1)) return false;
            if (out.charAt(out.length() - 1) != '\n') out.append("\n");
        }
        if (pos[0] < s.length() && s.charAt(pos[0]) == '}') pos[0]++;
        out.append("  ".repeat(indent)).append("}\n");
        return true;
    }

    private static boolean parseObject(String s, int[] pos, StringBuilder out, int indent) {
        if (pos[0] >= s.length() || s.charAt(pos[0]) != ':') return false;
        pos[0]++;
        int lenEnd = s.indexOf(':', pos[0]);
        if (lenEnd < 0) return false;
        int classLen = Integer.parseInt(s.substring(pos[0], lenEnd).trim());
        pos[0] = lenEnd + 1;
        if (pos[0] + classLen + 2 > s.length() || s.charAt(pos[0]) != '"') return false;
        pos[0]++;
        String className = s.substring(pos[0], pos[0] + classLen);
        pos[0] += classLen + 1;
        if (pos[0] < s.length() && s.charAt(pos[0]) == '"') pos[0]++;
        if (pos[0] < s.length() && s.charAt(pos[0]) == ':') pos[0]++;
        int countEnd = s.indexOf(':', pos[0]);
        if (countEnd < 0) return false;
        int count = Integer.parseInt(s.substring(pos[0], countEnd).trim());
        pos[0] = countEnd + 1;
        if (pos[0] >= s.length() || s.charAt(pos[0]) != '{') return false;
        pos[0]++;
        out.append("  ".repeat(indent)).append("object(").append(className).append(") {\n");
        for (int i = 0; i < count && pos[0] < s.length() && s.charAt(pos[0]) != '}'; i++) {
            out.append("  ".repeat(indent + 1));
            StringBuilder keyOut = new StringBuilder();
            if (!parseValue(s, pos, keyOut, 0)) break;
            out.append(keyOut).append(" => ");
            if (!parseValue(s, pos, out, indent + 1)) break;
            if (out.charAt(out.length() - 1) != '\n') out.append("\n");
        }
        if (pos[0] < s.length() && s.charAt(pos[0]) == '}') pos[0]++;
        out.append("  ".repeat(indent)).append("}\n");
        return true;
    }

    /**
     * Encode simple string to PHP serialized format.
     */
    public static byte[] phpSerializeString(byte[] input) {
        if (input == null) return null;
        String s = new String(input, StandardCharsets.UTF_8);
        return ("s:" + s.getBytes(StandardCharsets.UTF_8).length + ":\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\";").getBytes(StandardCharsets.UTF_8);
    }

    public static boolean looksLikePhpSerialized(byte[] input) {
        if (input == null || input.length < 2) return false;
        String s = new String(input, StandardCharsets.UTF_8).trim();
        return s.matches("^[NbisdaOrR].*");
    }
}
