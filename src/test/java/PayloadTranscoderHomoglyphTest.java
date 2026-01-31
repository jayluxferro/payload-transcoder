import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class PayloadTranscoderHomoglyphTest {

    @Test
    void encodeDecode_roundTrip() {
        byte[] input = "script".getBytes(StandardCharsets.UTF_8);
        byte[] encoded = PayloadTranscoderHomoglyph.encodeHomoglyph(input);
        assertNotNull(encoded);
        byte[] decoded = PayloadTranscoderHomoglyph.decodeHomoglyph(encoded);
        assertNotNull(decoded);
        assertArrayEquals(input, decoded);
    }

    @Test
    void encode_replacesLatin() {
        byte[] input = "a".getBytes(StandardCharsets.UTF_8);
        byte[] encoded = PayloadTranscoderHomoglyph.encodeHomoglyph(input);
        assertNotNull(encoded);
        String s = new String(encoded, StandardCharsets.UTF_8);
        assertEquals("\u0430", s);
    }
}
