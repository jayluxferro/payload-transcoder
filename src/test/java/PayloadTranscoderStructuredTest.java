import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PayloadTranscoderStructuredTest {

    // --- JSON ---

    @Test
    void jsonPrettyPrint_validJson() {
        byte[] minified = "{\"a\":1,\"b\":2}".getBytes(StandardCharsets.UTF_8);
        byte[] pretty = PayloadTranscoderStructured.jsonPrettyPrint(minified);
        assertNotNull(pretty);
        String s = new String(pretty, StandardCharsets.UTF_8);
        assertTrue(s.contains("\n"));
        assertTrue(s.contains("  "));
    }

    @Test
    void jsonMinify_validJson() {
        byte[] pretty = "{\n  \"a\": 1,\n  \"b\": 2\n}".getBytes(StandardCharsets.UTF_8);
        byte[] minified = PayloadTranscoderStructured.jsonMinify(pretty);
        assertNotNull(minified);
        String s = new String(minified, StandardCharsets.UTF_8);
        assertFalse(s.contains("\n"));
    }

    @Test
    void jsonPrettyPrint_invalidJson_returnsNull() {
        assertNull(PayloadTranscoderStructured.jsonPrettyPrint("not json".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void looksLikeJson_object() {
        assertTrue(PayloadTranscoderStructured.looksLikeJson("{\"x\":1}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void looksLikeJson_array() {
        assertTrue(PayloadTranscoderStructured.looksLikeJson("[1,2,3]".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void looksLikeJson_plainText_returnsFalse() {
        assertFalse(PayloadTranscoderStructured.looksLikeJson("plain text".getBytes(StandardCharsets.UTF_8)));
    }

    // --- Form data ---

    @Test
    void formDataPrettyPrint_singlePair() {
        byte[] raw = "key=value".getBytes(StandardCharsets.UTF_8);
        byte[] pretty = PayloadTranscoderStructured.formDataPrettyPrint(raw);
        assertNotNull(pretty);
        assertEquals("key=value", new String(pretty, StandardCharsets.UTF_8));
    }

    @Test
    void formDataPrettyPrint_multiplePairs() {
        byte[] raw = "a=1&b=2&c=3".getBytes(StandardCharsets.UTF_8);
        byte[] pretty = PayloadTranscoderStructured.formDataPrettyPrint(raw);
        assertNotNull(pretty);
        String s = new String(pretty, StandardCharsets.UTF_8);
        assertTrue(s.contains("a=1"));
        assertTrue(s.contains("b=2"));
        assertTrue(s.contains("c=3"));
        assertTrue(s.contains("\n"));
    }

    @Test
    void formDataRebuild_roundTrip() {
        byte[] raw = "a=1&b=2".getBytes(StandardCharsets.UTF_8);
        byte[] pretty = PayloadTranscoderStructured.formDataPrettyPrint(raw);
        byte[] rebuilt = PayloadTranscoderStructured.formDataRebuild(pretty);
        assertNotNull(rebuilt);
        assertEquals("a=1&b=2", new String(rebuilt, StandardCharsets.UTF_8));
    }

    @Test
    void looksLikeFormData() {
        assertTrue(PayloadTranscoderStructured.looksLikeFormData("key=value".getBytes(StandardCharsets.UTF_8)));
        assertTrue(PayloadTranscoderStructured.looksLikeFormData("a=1&b=2".getBytes(StandardCharsets.UTF_8)));
        assertFalse(PayloadTranscoderStructured.looksLikeFormData("no equals".getBytes(StandardCharsets.UTF_8)));
    }

    // --- Multipart ---

    @Test
    void extractBoundaryFromContentType() {
        String ct = "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW";
        assertEquals("----WebKitFormBoundary7MA4YWxkTrZu0gW",
                PayloadTranscoderStructured.extractBoundaryFromContentType(ct));
    }

    @Test
    void extractBoundaryFromContentType_quoted() {
        String ct = "multipart/form-data; boundary=\"boundary123\"";
        assertEquals("boundary123", PayloadTranscoderStructured.extractBoundaryFromContentType(ct));
    }

    @Test
    void parseMultipart_singlePart() {
        String boundary = "boundary123";
        byte[] body = ("--boundary123\r\n" +
                "Content-Disposition: form-data; name=\"field1\"\r\n" +
                "\r\n" +
                "value1\r\n" +
                "--boundary123--\r\n").getBytes(StandardCharsets.US_ASCII);
        List<PayloadTranscoderStructured.MultipartPart> parts = PayloadTranscoderStructured.parseMultipart(body, boundary);
        assertNotNull(parts);
        assertEquals(1, parts.size());
        assertEquals("field1", parts.get(0).name);
        assertEquals("value1", new String(parts.get(0).body, StandardCharsets.UTF_8));
    }

    @Test
    void buildMultipart_roundTrip() {
        String boundary = "boundary123";
        Map<String, String> headers = Map.of("content-disposition", "form-data; name=\"x\"");
        PayloadTranscoderStructured.MultipartPart part = new PayloadTranscoderStructured.MultipartPart(
                headers, "data".getBytes(StandardCharsets.UTF_8), "x", null);
        byte[] built = PayloadTranscoderStructured.buildMultipart(List.of(part), boundary);
        assertNotNull(built);
        List<PayloadTranscoderStructured.MultipartPart> parsed = PayloadTranscoderStructured.parseMultipart(built, boundary);
        assertNotNull(parsed);
        assertEquals(1, parsed.size());
        assertEquals("data", new String(parsed.get(0).body, StandardCharsets.UTF_8));
    }
}
