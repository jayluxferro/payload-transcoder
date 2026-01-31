import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class PayloadTranscoderDeserTest {

    @Test
    void looksLikeJavaSerialized_true() {
        byte[] javaSerialized = new byte[] { (byte) 0xAC, (byte) 0xED, 0x00, 0x05 };
        assertTrue(PayloadTranscoderDeser.looksLikeJavaSerialized(javaSerialized));
    }

    @Test
    void looksLikeJavaSerialized_false() {
        assertFalse(PayloadTranscoderDeser.looksLikeJavaSerialized(new byte[] { 0x00, 0x00 }));
        assertFalse(PayloadTranscoderDeser.looksLikeJavaSerialized(null));
    }

    @Test
    void detectJavaSerialized() {
        byte[] javaSerialized = new byte[] { (byte) 0xAC, (byte) 0xED, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00 };
        byte[] result = PayloadTranscoderDeser.detectJavaSerialized(javaSerialized);
        assertNotNull(result);
        String s = new String(result, StandardCharsets.UTF_8);
        assertTrue(s.contains("Java Serialized"));
        assertTrue(s.contains("AC ED"));
    }

    @Test
    void detectViewState() {
        byte[] html = "<form><input name=\"__VIEWSTATE\" value=\"abc\"/></form>".getBytes(StandardCharsets.UTF_8);
        byte[] result = PayloadTranscoderDeser.detectViewState(html);
        assertNotNull(result);
        assertTrue(new String(result, StandardCharsets.UTF_8).contains("__VIEWSTATE"));
    }
}
