import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Homoglyph encode/decode for WAF bypass (Latin ↔ Cyrillic lookalikes).
 */
public final class PayloadTranscoderHomoglyph {

    private static final Map<Character, Character> LATIN_TO_CYRILLIC = new HashMap<>();
    private static final Map<Character, Character> CYRILLIC_TO_LATIN = new HashMap<>();

    static {
        // Lowercase: Latin -> Cyrillic
        put('a', '\u0430'); // Cyrillic a
        put('e', '\u0435'); // Cyrillic e
        put('o', '\u043E'); // Cyrillic o
        put('p', '\u0440'); // Cyrillic r
        put('c', '\u0441'); // Cyrillic s
        put('x', '\u0445'); // Cyrillic kh
        put('y', '\u0443'); // Cyrillic u
        put('i', '\u0456'); // Cyrillic i (Ukrainian)
        // Uppercase
        put('A', '\u0410'); // Cyrillic A
        put('B', '\u0412'); // Cyrillic Ve
        put('E', '\u0415'); // Cyrillic E
        put('K', '\u041A'); // Cyrillic K
        put('M', '\u041C'); // Cyrillic M
        put('H', '\u041D'); // Cyrillic N
        put('O', '\u041E'); // Cyrillic O
        put('P', '\u0420'); // Cyrillic R
        put('C', '\u0421'); // Cyrillic S
        put('T', '\u0422'); // Cyrillic T
        put('X', '\u0425'); // Cyrillic Kh
        put('Y', '\u0423'); // Cyrillic U
    }

    private static void put(char latin, char cyrillic) {
        LATIN_TO_CYRILLIC.put(latin, cyrillic);
        CYRILLIC_TO_LATIN.put(cyrillic, latin);
    }

    private PayloadTranscoderHomoglyph() {}

    /** Replace Latin with Cyrillic homoglyphs (WAF bypass). */
    public static byte[] encodeHomoglyph(byte[] input) {
        if (input == null || input.length == 0) return input;
        String s = new String(input, StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            sb.append(LATIN_TO_CYRILLIC.getOrDefault(c, c));
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** Replace Cyrillic homoglyphs with Latin. */
    public static byte[] decodeHomoglyph(byte[] input) {
        if (input == null || input.length == 0) return input;
        String s = new String(input, StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            sb.append(CYRILLIC_TO_LATIN.getOrDefault(c, c));
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }
}
