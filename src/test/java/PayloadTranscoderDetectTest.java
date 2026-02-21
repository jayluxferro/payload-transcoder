import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class PayloadTranscoderDetectTest {

    @Test
    void isLikelyGibberish_highEntropyLowPrintable_returnsTrue() {
        // High entropy, low printable: only non-printable bytes (control + high bytes)
        byte[] data = new byte[512];
        Random r = new Random(42);
        for (int i = 0; i < data.length; i++) {
            int v = r.nextInt(256);
            while (v >= 0x20 && v <= 0x7E) v = r.nextInt(256);
            data[i] = (byte) v;
        }
        assertTrue(PayloadTranscoderDetect.isLikelyGibberish(data, "Decode Base64"));
        assertTrue(PayloadTranscoderDetect.isLikelyGibberish(data, "Decode Hex"));
    }

    @Test
    void isLikelyGibberish_jsonLike_returnsFalse() {
        byte[] json = "{\"a\":1,\"b\":2}".getBytes(StandardCharsets.UTF_8);
        assertFalse(PayloadTranscoderDetect.isLikelyGibberish(json, "Decode Base64"));
    }

    @Test
    void isLikelyGibberish_gzipMagic_returnsFalse() {
        byte[] gzip = new byte[] { 0x1f, (byte) 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0 };
        assertFalse(PayloadTranscoderDetect.isLikelyGibberish(gzip, "Decode Base64"));
    }

    @Test
    void isLikelyGibberish_shortResult_returnsFalse() {
        byte[] short_ = new byte[] { 0x42, 0x43, 0x44 };
        assertFalse(PayloadTranscoderDetect.isLikelyGibberish(short_, "Decode Hex"));
    }

    @Test
    void isLikelyGibberish_nonTextOp_returnsFalse() {
        byte[] any = new byte[100];
        new Random(123).nextBytes(any);
        assertFalse(PayloadTranscoderDetect.isLikelyGibberish(any, "Decode gzip"));
    }
}
