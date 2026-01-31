import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class PayloadTranscoderUnicodeTest {

    @Test
    void normalizeNfc_roundTrip() {
        byte[] input = "café".getBytes(StandardCharsets.UTF_8);
        byte[] nfc = PayloadTranscoderUnicode.normalizeNfc(input);
        assertNotNull(nfc);
        assertArrayEquals(input, PayloadTranscoderUnicode.normalizeNfc(nfc));
    }

    @Test
    void normalizeNfd_roundTrip() {
        byte[] input = "café".getBytes(StandardCharsets.UTF_8);
        byte[] nfd = PayloadTranscoderUnicode.normalizeNfd(input);
        assertNotNull(nfd);
    }

    @Test
    void normalizeNfkc_empty() {
        assertNull(PayloadTranscoderUnicode.normalizeNfkc(null));
        assertArrayEquals(new byte[0], PayloadTranscoderUnicode.normalizeNfkc(new byte[0]));
    }
}
