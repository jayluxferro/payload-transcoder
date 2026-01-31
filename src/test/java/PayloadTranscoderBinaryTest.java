import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class PayloadTranscoderBinaryTest {

    private static final byte[] SAMPLE_JSON = "{\"a\":1,\"b\":\"hello\"}".getBytes(StandardCharsets.UTF_8);

    // --- MessagePack ---

    @Test
    void messagePack_roundTrip() {
        byte[] encoded = PayloadTranscoderBinary.encodeMessagePack(SAMPLE_JSON);
        assertNotNull(encoded);
        byte[] decoded = PayloadTranscoderBinary.decodeMessagePack(encoded);
        assertNotNull(decoded);
        String decodedStr = new String(decoded, StandardCharsets.UTF_8);
        assertTrue(decodedStr.contains("\"a\""));
        assertTrue(decodedStr.contains("1"));
        assertTrue(decodedStr.contains("\"b\""));
        assertTrue(decodedStr.contains("hello"));
    }

    // --- CBOR ---

    @Test
    void cbor_roundTrip() {
        byte[] encoded = PayloadTranscoderBinary.encodeCbor(SAMPLE_JSON);
        assertNotNull(encoded);
        byte[] decoded = PayloadTranscoderBinary.decodeCbor(encoded);
        assertNotNull(decoded);
        String decodedStr = new String(decoded, StandardCharsets.UTF_8);
        assertTrue(decodedStr.contains("\"a\""));
        assertTrue(decodedStr.contains("1"));
    }

    // --- BSON ---

    @Test
    void bson_roundTrip() {
        byte[] encoded = PayloadTranscoderBinary.encodeBson(SAMPLE_JSON);
        assertNotNull(encoded);
        byte[] decoded = PayloadTranscoderBinary.decodeBson(encoded);
        assertNotNull(decoded);
        String decodedStr = new String(decoded, StandardCharsets.UTF_8);
        assertTrue(decodedStr.contains("\"a\""));
        assertTrue(decodedStr.contains("1"));
    }
}
