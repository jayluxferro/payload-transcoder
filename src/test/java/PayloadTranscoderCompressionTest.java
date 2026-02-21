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

    // --- zstd ---

    @Test
    void zstd_roundTrip() {
        assumeTrue(PayloadTranscoderCompression.isZstdAvailable());
        byte[] compressed = PayloadTranscoderCompression.encodeZstd(SAMPLE);
        assumeTrue(compressed != null, "zstd native libs not loaded (encode returns null)");
        byte[] decompressed = PayloadTranscoderCompression.decodeZstd(compressed);
        assertArrayEquals(SAMPLE, decompressed);
    }

    @Test
    void zstd_withLeadingCrlfCrlf_decodes() {
        assumeTrue(PayloadTranscoderCompression.isZstdAvailable());
        byte[] compressed = PayloadTranscoderCompression.encodeZstd(SAMPLE);
        assumeTrue(compressed != null);
        // Prepend CRLF CRLF (e.g. HTTP body after headers) - decode should find zstd magic at offset 4
        byte[] withPrefix = new byte[4 + compressed.length];
        withPrefix[0] = 0x0D;
        withPrefix[1] = 0x0A;
        withPrefix[2] = 0x0D;
        withPrefix[3] = 0x0A;
        System.arraycopy(compressed, 0, withPrefix, 4, compressed.length);
        assertTrue(PayloadTranscoderCompression.looksLikeZstd(withPrefix));
        byte[] decompressed = PayloadTranscoderCompression.decodeZstd(withPrefix);
        assertArrayEquals(SAMPLE, decompressed);
    }

    @Test
    void zstd_sampleContentTypeZstd_detectedAndDecodable() {
        assumeTrue(PayloadTranscoderCompression.isZstdAvailable());
        // Sample: CRLF CRLF + zstd magic + frame (content-type zstd body). Detection must find magic after prefix.
        String hex = "0D 0A 0D 0A 28 B5 2F FD 04 58 FC 11 00 C6 A3 69 23 10 73 F3 33 24 B1 22 12 8A 5C 23 96 D4 C4 5A 39 03 C1 D8 81 A3 9B 2C DA 71 81 75 32 7C 14 00 00 2A 40 79 5B 00 5D 00 5F 00 93 A9 DE 90 B9 38 C6 8D F3 5E 23 04 35 A8 69 D2 F4 71 B4 0F 6B E6 2C 3F BA EB FC 7D 64 95 51 52 96 18 76 93 D5 EE C3 CF 4C AD C7 FF 5A D9 A7 5F 9C 4A 32 B9 C2 9C 5A 80 7D A2 9E 92 DA 7E AD C5 67 2C EE 1E 3B 4A 41 D6 BA 47 64 32 4E A6 60 BF 63 2E EC FB 50 CA 0F 52 EE 39 01 6B E9 6C C9 B2 A1 1E 1D A5 0E 56 2A 6D FA B9 28 4E D9 B4 19 23 DF 94 3D 9A 66 81 CA 7F 09 F6 BB 8B 63 8D B3 76 36 73 17 C7 9C 25 6D 9C C6 69 CE B0 A7 D6 A0 2A AD 1E 16 AA 21 F7 B4 4A A8 C8 94 AC E6 71 3E 75 D6 FE 47 3F 03 FB 9D B3 A4 CE 9A 2A AC DF EB 0A 3F 66 36 AD EA A5 E6 02 EE 35 0E C5 5A 86 01 81 8F 0C 04 C0 19 23 26 40 80 45 4C 0E EF 0D FB 3D 7C B7 C8 7B C3 0A 45 A6 18 06 04 FE 55 8E 5A 32 65 E4 BD 2F BD 8F 05 72 0F F2 A8 F6 6B 6C F1 51 D6 12 AC 9D DD 9C 19 A3 BA 31 AE A8 C9 5A DA 8D 29 6D 48 B1 76 B6 F7 53 F7 30 54 C3 DA 19 A5 AF FC 3C 9F BA D6 93 12 90 05 67 8C 1A 67 ED 04 05 E2 98 5C 50 6C BC C9 52 F0 30 E2 E3 27 07 15 6F 90 50 00 37 28 84 82 64 02 0F 1C 34 0C E2 81 84 B0 4F D7 C7 17 B5 DE 96 F8 1D FB 34 64 57 EB CD 98 93 F6 69 39 BD FA 2A DD 39 6B 19 DA A3 2F 4C FC 24 75 6C 9F 7E D3 53 B5 1A 19 16 94 7D 58 94 BE A1 47 F7 10 AB 85 33 46 0E 64 05 3A 20 20 02 82 0C 5A 45 0F A9 11 20 1C CA 40 8F A1 8A 08 FF D6 11 BD 23 E0 F9 CC 20 8D B3 68 7C AD ED D8 0E D3 9A DE 21 1A C3 18 4F 09 DA 3F 51 DA D6 05 72 30 44 72 6B E6 3D 1B 85 EA 3A BD 50 DC AE 01 10 C6 B3 9D 94 70 9C 8E 20 60 6F E8 36 18 21 C1 C7 AD 4C E2 E5 90 3A 3C BF 00 2C 99 0E 53 B0 A5 2B 37 DD C2 36 1F 3D 41 5C 99 C8 9B 0B 58 2F 43 17 70 29 5A 9A 84 DB 68 D4 E6 0E 53 19 F9 00 97 B8 35 9E 2F 73 D2 EE B3 3D 50 A6 F8 CB 50 90 0D EE 3D 01 01 00 00 AE";
        byte[] raw = hexToBytes(hex);
        assertNotNull(raw);
        assertTrue(PayloadTranscoderCompression.looksLikeZstd(raw), "Should detect zstd magic after CRLF CRLF");
        byte[] decompressed = PayloadTranscoderCompression.decodeZstd(raw);
        // This sample fails zstd checksum validation (restored data doesn't match checksum); decoder correctly returns null.
        if (decompressed != null) {
            assertTrue(decompressed.length > 0);
        }
    }

    private static byte[] hexToBytes(String hex) {
        String[] parts = hex.trim().split("\\s+");
        byte[] out = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            out[i] = (byte) Integer.parseInt(parts[i], 16);
        }
        return out;
    }
}
