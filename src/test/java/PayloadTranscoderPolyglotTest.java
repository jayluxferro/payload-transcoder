import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class PayloadTranscoderPolyglotTest {

    @Test
    void generatePolyglot_htmlJsUrl() {
        byte[] payload = "alert(1)".getBytes(StandardCharsets.UTF_8);
        byte[] result = PayloadTranscoderPolyglot.generatePolyglot(payload, "HTML+JS+URL");
        assertNotNull(result);
        String s = new String(result, StandardCharsets.UTF_8);
        assertTrue(s.contains("alert(1)"));
        assertTrue(s.contains("jaVasCript"));
    }

    @Test
    void getPolyglots_notEmpty() {
        assertFalse(PayloadTranscoderPolyglot.getPolyglots().isEmpty());
    }
}
