import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class PayloadTranscoderGrpcTest {

    private static byte[] makeGrpcFrame(byte[] message) {
        byte[] header = new byte[5];
        header[0] = 0; // uncompressed
        ByteBuffer.wrap(header, 1, 4).order(ByteOrder.BIG_ENDIAN).putInt(message.length);
        byte[] result = new byte[5 + message.length];
        System.arraycopy(header, 0, result, 0, 5);
        System.arraycopy(message, 0, result, 5, message.length);
        return result;
    }

    @Test
    void parseGrpcFrame_valid() {
        byte[] message = "hello".getBytes(StandardCharsets.UTF_8);
        byte[] frame = makeGrpcFrame(message);
        var parsed = PayloadTranscoderGrpc.parseGrpcFrame(frame);
        assertNotNull(parsed);
        assertFalse(parsed.compressed);
        assertEquals(5, parsed.messageLength);
        assertArrayEquals(message, parsed.message);
    }

    @Test
    void parseGrpcFrame_tooShort_returnsNull() {
        assertNull(PayloadTranscoderGrpc.parseGrpcFrame(new byte[4]));
    }

    @Test
    void looksLikeGrpc_contentType() {
        assertTrue(PayloadTranscoderGrpc.looksLikeGrpc("application/grpc"));
        assertTrue(PayloadTranscoderGrpc.looksLikeGrpc("application/grpc+proto"));
        assertFalse(PayloadTranscoderGrpc.looksLikeGrpc("application/json"));
    }

    @Test
    void buildGrpcFrame_roundTrip() {
        byte[] message = "test message".getBytes(StandardCharsets.UTF_8);
        byte[] frame = PayloadTranscoderGrpc.buildGrpcFrame(message);
        assertNotNull(frame);
        var parsed = PayloadTranscoderGrpc.parseGrpcFrame(frame);
        assertNotNull(parsed);
        assertArrayEquals(message, parsed.message);
    }

    @Test
    void extractGrpcMessage() {
        byte[] message = "payload".getBytes(StandardCharsets.UTF_8);
        byte[] frame = makeGrpcFrame(message);
        byte[] extracted = PayloadTranscoderGrpc.extractGrpcMessage(frame);
        assertArrayEquals(message, extracted);
    }

    @Test
    void protobufRawWireView_simpleMessage() {
        // Protobuf: field 1 (varint) = 42
        // Tag: (1 << 3) | 0 = 8, value: 42 (varint)
        byte[] message = new byte[] { 0x08, 0x2A }; // tag 8, varint 42
        byte[] view = PayloadTranscoderGrpc.protobufRawWireView(message);
        assertNotNull(view);
        String s = new String(view, StandardCharsets.UTF_8);
        assertTrue(s.contains("field 1"));
        assertTrue(s.contains("42"));
    }
}
