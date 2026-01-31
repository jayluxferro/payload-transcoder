import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class PayloadTranscoderProtocolTest {

    // --- GraphQL ---

    @Test
    void graphqlPrettyPrint_valid() {
        byte[] raw = "{\"query\":\"query{user{id name}}\"}".getBytes(StandardCharsets.UTF_8);
        assertTrue(PayloadTranscoderProtocol.looksLikeGraphql(raw));
        byte[] pretty = PayloadTranscoderProtocol.graphqlPrettyPrint(raw);
        assertNotNull(pretty);
        String s = new String(pretty, StandardCharsets.UTF_8);
        assertTrue(s.contains("query"));
        assertTrue(s.contains("user"));
    }

    // --- XML ---

    @Test
    void xmlPrettyPrint_valid() {
        byte[] raw = "<root><a>1</a><b>2</b></root>".getBytes(StandardCharsets.UTF_8);
        assertTrue(PayloadTranscoderProtocol.looksLikeXml(raw));
        byte[] pretty = PayloadTranscoderProtocol.xmlPrettyPrint(raw);
        assertNotNull(pretty);
        String s = new String(pretty, StandardCharsets.UTF_8);
        assertTrue(s.contains("<root>"));
        assertTrue(s.contains("<a>"));
    }

    // --- WebSocket ---

    @Test
    void webSocketFrameParse_unmasked() {
        // Minimal frame: fin=1, opcode=1 (text), mask=0, payload_len=5, "hello"
        byte[] frame = new byte[7];
        frame[0] = (byte) 0x81; // fin + text
        frame[1] = 5;           // unmasked, len 5
        System.arraycopy("hello".getBytes(StandardCharsets.UTF_8), 0, frame, 2, 5);
        var parsed = PayloadTranscoderProtocol.parseWebSocketFrame(frame);
        assertNotNull(parsed);
        assertTrue(parsed.fin);
        assertEquals(1, parsed.opcode);
        assertFalse(parsed.masked);
        assertEquals(5, parsed.payloadLength);
        assertEquals("hello", new String(parsed.payload, StandardCharsets.UTF_8));
    }

    @Test
    void webSocketFramePrettyPrint() {
        byte[] frame = new byte[7];
        frame[0] = (byte) 0x81;
        frame[1] = 5;
        System.arraycopy("hello".getBytes(StandardCharsets.UTF_8), 0, frame, 2, 5);
        byte[] pretty = PayloadTranscoderProtocol.webSocketFramePrettyPrint(frame);
        assertNotNull(pretty);
        String s = new String(pretty, StandardCharsets.UTF_8);
        assertTrue(s.contains("WebSocket Frame"));
        assertTrue(s.contains("text"));
        assertTrue(s.contains("hello"));
    }
}
