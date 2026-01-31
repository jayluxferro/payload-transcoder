import java.nio.charset.StandardCharsets;
import java.text.Normalizer;

/**
 * Unicode normalization for bypass testing (NFC, NFD, NFKC, NFKD).
 */
public final class PayloadTranscoderUnicode {

    private PayloadTranscoderUnicode() {}

    public static byte[] normalizeNfc(byte[] input) {
        if (input == null || input.length == 0) return input;
        String s = new String(input, StandardCharsets.UTF_8);
        return Normalizer.normalize(s, Normalizer.Form.NFC).getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] normalizeNfd(byte[] input) {
        if (input == null || input.length == 0) return input;
        String s = new String(input, StandardCharsets.UTF_8);
        return Normalizer.normalize(s, Normalizer.Form.NFD).getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] normalizeNfkc(byte[] input) {
        if (input == null || input.length == 0) return input;
        String s = new String(input, StandardCharsets.UTF_8);
        return Normalizer.normalize(s, Normalizer.Form.NFKC).getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] normalizeNfkd(byte[] input) {
        if (input == null || input.length == 0) return input;
        String s = new String(input, StandardCharsets.UTF_8);
        return Normalizer.normalize(s, Normalizer.Form.NFKD).getBytes(StandardCharsets.UTF_8);
    }
}
