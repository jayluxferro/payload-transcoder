import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class PayloadTranscoderCompressionTest {

    private static final byte[] SAMPLE = "Hello, World!".getBytes(StandardCharsets.UTF_8);

    // --- gzip ---

    @Test
    void gzip_roundTrip() {
        byte[] compressed = PayloadTranscoderCompression.encodeGzip(SAMPLE);
        assertNotNull(compressed);
        assertTrue(compressed.length > 0);
        byte[] decompressed = PayloadTranscoderCompression.decodeGzip(compressed);
        assertArrayEquals(SAMPLE, decompressed);
    }

    @Test
    void looksLikeGzip_valid() {
        byte[] gzip = PayloadTranscoderCompression.encodeGzip(SAMPLE);
        assertTrue(PayloadTranscoderCompression.looksLikeGzip(gzip));
    }

    @Test
    void looksLikeGzip_invalid() {
        assertFalse(PayloadTranscoderCompression.looksLikeGzip(SAMPLE));
    }

    @Test
    void decodeGzip_invalid_returnsNull() {
        assertNull(PayloadTranscoderCompression.decodeGzip(SAMPLE));
    }

    // --- deflate ---

    @Test
    void deflate_roundTrip() {
        byte[] compressed = PayloadTranscoderCompression.encodeDeflate(SAMPLE);
        assertNotNull(compressed);
        byte[] decompressed = PayloadTranscoderCompression.decodeDeflate(compressed);
        assertArrayEquals(SAMPLE, decompressed);
    }

    @Test
    void looksLikeDeflate_zlibHeader() {
        byte[] deflate = PayloadTranscoderCompression.encodeDeflate(SAMPLE);
        assertTrue(PayloadTranscoderCompression.looksLikeDeflate(deflate));
    }

    @Test
    void looksLikeDeflate_plainText_returnsFalse() {
        assertFalse(PayloadTranscoderCompression.looksLikeDeflate(SAMPLE));
    }

    // --- Brotli ---

    @Test
    void brotli_roundTrip() {
        assumeTrue(PayloadTranscoderCompression.isBrotliAvailable());
        byte[] compressed = PayloadTranscoderCompression.encodeBrotli(SAMPLE);
        assumeTrue(compressed != null, "Brotli native libs not loaded (encode returns null)");
        byte[] decompressed = PayloadTranscoderCompression.decodeBrotli(compressed);
        assertArrayEquals(SAMPLE, decompressed);
    }
}
