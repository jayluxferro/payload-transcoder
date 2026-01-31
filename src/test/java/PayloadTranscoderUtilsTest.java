import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class PayloadTranscoderUtilsTest {

    // --- Base64 ---

    @Test
    void decodeBase64_roundTrip() {
        byte[] original = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        String encoded = PayloadTranscoderUtils.encodeBase64(original);
        byte[] decoded = PayloadTranscoderUtils.decodeBase64(encoded.getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(original, decoded);
    }

    @Test
    void decodeBase64_nullOrShort_returnsNull() {
        assertNull(PayloadTranscoderUtils.decodeBase64(null));
        assertNull(PayloadTranscoderUtils.decodeBase64("ab".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void decodeBase64UrlSafe_roundTrip() {
        byte[] original = "test+data".getBytes(StandardCharsets.UTF_8);
        String encoded = PayloadTranscoderUtils.encodeBase64UrlSafe(original);
        byte[] decoded = PayloadTranscoderUtils.decodeBase64UrlSafe(encoded.getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(original, decoded);
    }

    // --- Hex ---

    @Test
    void decodeHex_roundTrip() {
        byte[] original = new byte[] { 0x48, 0x65, 0x6c, 0x6c, 0x6f };
        String encoded = PayloadTranscoderUtils.encodeHex(original);
        byte[] decoded = PayloadTranscoderUtils.decodeHex(encoded.getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(original, decoded);
    }

    @Test
    void decodeHex_withSpaces() {
        byte[] decoded = PayloadTranscoderUtils.decodeHex("48 65 6c 6c 6f".getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals("Hello".getBytes(StandardCharsets.US_ASCII), decoded);
    }

    @Test
    void decodeHex_oddLength_returnsNull() {
        assertNull(PayloadTranscoderUtils.decodeHex("123".getBytes(StandardCharsets.US_ASCII)));
    }

    // --- URL encoding ---

    @Test
    void decodeUrl_roundTrip() {
        byte[] original = "hello world".getBytes(StandardCharsets.UTF_8);
        String encoded = PayloadTranscoderUtils.encodeUrlStrict(original);
        byte[] decoded = PayloadTranscoderUtils.decodeUrl(encoded.getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(original, decoded);
    }

    @Test
    void decodeUrl_formStyle_plusAsSpace() {
        byte[] decoded = PayloadTranscoderUtils.decodeUrl("hello+world".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals("hello world".getBytes(StandardCharsets.UTF_8), decoded);
    }

    @Test
    void decodeUrl_nothingToDecode_returnsNull() {
        assertNull(PayloadTranscoderUtils.decodeUrl("plaintext".getBytes(StandardCharsets.UTF_8)));
    }

    // --- HTML entities ---

    @Test
    void decodeHtmlEntities_named() {
        byte[] decoded = PayloadTranscoderUtils.decodeHtmlEntities("&amp;&lt;&gt;".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals("&<>".getBytes(StandardCharsets.UTF_8), decoded);
    }

    @Test
    void decodeHtmlEntities_numericDecimal() {
        byte[] decoded = PayloadTranscoderUtils.decodeHtmlEntities("&#65;&#66;".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals("AB".getBytes(StandardCharsets.UTF_8), decoded);
    }

    @Test
    void decodeHtmlEntities_numericHex() {
        byte[] decoded = PayloadTranscoderUtils.decodeHtmlEntities("&#x41;&#x42;".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals("AB".getBytes(StandardCharsets.UTF_8), decoded);
    }

    @Test
    void encodeHtmlEntities_roundTrip() {
        byte[] original = "<script>".getBytes(StandardCharsets.UTF_8);
        String encoded = PayloadTranscoderUtils.encodeHtmlEntities(original);
        byte[] decoded = PayloadTranscoderUtils.decodeHtmlEntities(encoded.getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(original, decoded);
    }

    // --- Unicode escapes ---

    @Test
    void decodeUnicodeEscapes_u4() {
        byte[] decoded = PayloadTranscoderUtils.decodeUnicodeEscapes("\\u0048\\u0065\\u006c\\u006c\\u006f".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals("Hello".getBytes(StandardCharsets.UTF_8), decoded);
    }

    @Test
    void decodeUnicodeEscapes_x2() {
        byte[] decoded = PayloadTranscoderUtils.decodeUnicodeEscapes("\\x48\\x65\\x6c\\x6c\\x6f".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals("Hello".getBytes(StandardCharsets.UTF_8), decoded);
    }

    @Test
    void encodeUnicodeEscapes_roundTrip() {
        byte[] original = "café".getBytes(StandardCharsets.UTF_8);
        String encoded = PayloadTranscoderUtils.encodeUnicodeEscapes(original);
        byte[] decoded = PayloadTranscoderUtils.decodeUnicodeEscapes(encoded.getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(original, decoded);
    }

    // --- Quoted-printable ---

    @Test
    void decodeQuotedPrintable_roundTrip() {
        byte[] original = "Hello=World".getBytes(StandardCharsets.UTF_8);
        String encoded = PayloadTranscoderUtils.encodeQuotedPrintable(original);
        byte[] decoded = PayloadTranscoderUtils.decodeQuotedPrintable(encoded.getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(original, decoded);
    }

    @Test
    void decodeQuotedPrintable_softLineBreak() {
        byte[] decoded = PayloadTranscoderUtils.decodeQuotedPrintable("Hello=\r\nWorld".getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals("HelloWorld".getBytes(StandardCharsets.UTF_8), decoded);
    }

    // --- looksLike* helpers ---

    @Test
    void looksLikeBase64_valid() {
        assertTrue(PayloadTranscoderUtils.looksLikeBase64("YWJj".getBytes(StandardCharsets.US_ASCII)));
        assertTrue(PayloadTranscoderUtils.looksLikeBase64("SGVsbG8gV29ybGQ=".getBytes(StandardCharsets.US_ASCII)));
        assertTrue(PayloadTranscoderUtils.looksLikeBase64("YWJj \n".getBytes(StandardCharsets.US_ASCII))); // whitespace ok
    }

    @Test
    void looksLikeBase64_invalid() {
        assertFalse(PayloadTranscoderUtils.looksLikeBase64(null));
        assertFalse(PayloadTranscoderUtils.looksLikeBase64("ab".getBytes(StandardCharsets.US_ASCII)));
        assertFalse(PayloadTranscoderUtils.looksLikeBase64("YWJ".getBytes(StandardCharsets.US_ASCII))); // length % 4 != 0
        assertFalse(PayloadTranscoderUtils.looksLikeBase64("{}".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void looksLikeBase64UrlSafe_valid() {
        assertTrue(PayloadTranscoderUtils.looksLikeBase64UrlSafe("YWJj".getBytes(StandardCharsets.US_ASCII)));
        assertTrue(PayloadTranscoderUtils.looksLikeBase64UrlSafe("YWJjZA".getBytes(StandardCharsets.US_ASCII))); // no padding ok
    }

    @Test
    void looksLikeBase64UrlSafe_invalid() {
        assertFalse(PayloadTranscoderUtils.looksLikeBase64UrlSafe(null));
        assertFalse(PayloadTranscoderUtils.looksLikeBase64UrlSafe("ab".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void looksLikeHex_valid() {
        assertTrue(PayloadTranscoderUtils.looksLikeHex("48656c6c6f".getBytes(StandardCharsets.US_ASCII)));
        assertTrue(PayloadTranscoderUtils.looksLikeHex("48 65 6c 6c 6f".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void looksLikeHex_invalid() {
        assertFalse(PayloadTranscoderUtils.looksLikeHex(null));
        assertFalse(PayloadTranscoderUtils.looksLikeHex("1".getBytes(StandardCharsets.US_ASCII)));
        assertFalse(PayloadTranscoderUtils.looksLikeHex("123".getBytes(StandardCharsets.US_ASCII))); // odd
        assertFalse(PayloadTranscoderUtils.looksLikeHex("{}".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void looksLikeUrlEncoded_valid() {
        assertTrue(PayloadTranscoderUtils.looksLikeUrlEncoded("hello%20world".getBytes(StandardCharsets.US_ASCII)));
        assertTrue(PayloadTranscoderUtils.looksLikeUrlEncoded("%2Fpath".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void looksLikeUrlEncoded_invalid() {
        assertFalse(PayloadTranscoderUtils.looksLikeUrlEncoded(null));
        assertFalse(PayloadTranscoderUtils.looksLikeUrlEncoded("plain".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void looksLikeHtmlEntities_valid() {
        assertTrue(PayloadTranscoderUtils.looksLikeHtmlEntities("&amp;".getBytes(StandardCharsets.US_ASCII)));
        assertTrue(PayloadTranscoderUtils.looksLikeHtmlEntities("&lt;script&gt;".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void looksLikeHtmlEntities_invalid() {
        assertFalse(PayloadTranscoderUtils.looksLikeHtmlEntities(null));
        assertFalse(PayloadTranscoderUtils.looksLikeHtmlEntities("plain".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void looksLikeUnicodeEscapes_valid() {
        assertTrue(PayloadTranscoderUtils.looksLikeUnicodeEscapes("\\u0048ello".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void looksLikeUnicodeEscapes_invalid() {
        assertFalse(PayloadTranscoderUtils.looksLikeUnicodeEscapes(null));
        assertFalse(PayloadTranscoderUtils.looksLikeUnicodeEscapes("plain".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void looksLikeQuotedPrintable_valid() {
        assertTrue(PayloadTranscoderUtils.looksLikeQuotedPrintable("Hello=0D=0A".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void looksLikeQuotedPrintable_invalid() {
        assertFalse(PayloadTranscoderUtils.looksLikeQuotedPrintable(null));
        assertFalse(PayloadTranscoderUtils.looksLikeQuotedPrintable("plain".getBytes(StandardCharsets.US_ASCII)));
    }
}
