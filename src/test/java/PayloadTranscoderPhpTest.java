import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class PayloadTranscoderPhpTest {

    @Test
    void looksLikePhpSerialized() {
        assertTrue(PayloadTranscoderPhp.looksLikePhpSerialized("s:6:\"hello\";".getBytes(StandardCharsets.UTF_8)));
        assertTrue(PayloadTranscoderPhp.looksLikePhpSerialized("i:42;".getBytes(StandardCharsets.UTF_8)));
        assertTrue(PayloadTranscoderPhp.looksLikePhpSerialized("N;".getBytes(StandardCharsets.UTF_8)));
        assertFalse(PayloadTranscoderPhp.looksLikePhpSerialized("hello".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void phpSerializeString() {
        byte[] input = "test".getBytes(StandardCharsets.UTF_8);
        byte[] result = PayloadTranscoderPhp.phpSerializeString(input);
        assertNotNull(result);
        String s = new String(result, StandardCharsets.UTF_8);
        assertTrue(s.startsWith("s:4:\"test\""));
    }

    @Test
    void phpSerializedPrettyPrint_string() {
        byte[] input = "s:5:\"hello\";".getBytes(StandardCharsets.UTF_8);
        byte[] result = PayloadTranscoderPhp.phpSerializedPrettyPrint(input);
        assertNotNull(result);
        assertTrue(new String(result, StandardCharsets.UTF_8).contains("hello"));
    }
}
