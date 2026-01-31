import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class PayloadTranscoderHmacTest {

    @Test
    void hmacSha256Hex() {
        byte[] input = "message".getBytes(StandardCharsets.UTF_8);
        byte[] secret = "secret".getBytes(StandardCharsets.UTF_8);
        byte[] result = PayloadTranscoderHmac.hmacSha256Hex(input, secret);
        assertNotNull(result);
        String hex = new String(result, StandardCharsets.UTF_8);
        assertTrue(hex.matches("^[0-9a-f]{64}$"));
    }

    @Test
    void hmacSha256Webhook() {
        byte[] input = "payload".getBytes(StandardCharsets.UTF_8);
        byte[] secret = "key".getBytes(StandardCharsets.UTF_8);
        byte[] result = PayloadTranscoderHmac.hmacSha256Webhook(input, secret);
        assertNotNull(result);
        String s = new String(result, StandardCharsets.UTF_8);
        assertTrue(s.startsWith("sha256="));
        assertTrue(s.substring(7).matches("^[0-9a-f]{64}$"));
    }
}
