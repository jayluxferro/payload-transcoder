import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class PayloadTranscoderJwtTest {

    // Minimal valid JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
    private static final String HEADER = "{\"alg\":\"HS256\"}";
    private static final String PAYLOAD = "{\"sub\":\"1234567890\"}";
    private static final String SIGNATURE = "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

    private static String base64UrlEncode(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] makeJwt(String header, String payload, String signature) {
        String h = base64UrlEncode(header);
        String p = base64UrlEncode(payload);
        String jwt = h + "." + p + "." + (signature != null ? signature : "");
        return jwt.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void looksLikeJwt_valid() {
        byte[] jwt = makeJwt(HEADER, PAYLOAD, SIGNATURE);
        assertTrue(PayloadTranscoderJwt.looksLikeJwt(jwt));
    }

    @Test
    void looksLikeJwt_invalid() {
        assertFalse(PayloadTranscoderJwt.looksLikeJwt("only.one".getBytes(StandardCharsets.UTF_8))); // only 1 dot
        assertFalse(PayloadTranscoderJwt.looksLikeJwt("short".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void parseJwt_valid() {
        byte[] jwt = makeJwt(HEADER, PAYLOAD, SIGNATURE);
        var parts = PayloadTranscoderJwt.parseJwt(jwt);
        assertNotNull(parts);
        assertEquals(HEADER, new String(parts.headerBytes, StandardCharsets.UTF_8));
        assertEquals(PAYLOAD, new String(parts.payloadBytes, StandardCharsets.UTF_8));
        assertTrue(parts.signatureBytes.length > 0);
    }

    @Test
    void jwtPrettyPrint_valid() {
        byte[] jwt = makeJwt(HEADER, PAYLOAD, SIGNATURE);
        byte[] pretty = PayloadTranscoderJwt.jwtPrettyPrint(jwt);
        assertNotNull(pretty);
        String s = new String(pretty, StandardCharsets.UTF_8);
        assertTrue(s.contains("JWT Header"));
        assertTrue(s.contains("JWT Payload"));
        assertTrue(s.contains("JWT Signature"));
        assertTrue(s.contains("HS256"));
        assertTrue(s.contains("1234567890"));
    }

    @Test
    void jwtPayloadOnly_valid() {
        byte[] jwt = makeJwt(HEADER, PAYLOAD, SIGNATURE);
        byte[] payload = PayloadTranscoderJwt.jwtPayloadOnly(jwt);
        assertNotNull(payload);
        String s = new String(payload, StandardCharsets.UTF_8);
        assertTrue(s.contains("sub"));
        assertTrue(s.contains("1234567890"));
    }

    @Test
    void jwtRebuild_modifiedPayload() {
        byte[] jwt = makeJwt(HEADER, PAYLOAD, SIGNATURE);
        String modifiedPayload = "{\"sub\":\"modified\"}";
        byte[] rebuilt = PayloadTranscoderJwt.jwtRebuild(jwt, modifiedPayload.getBytes(StandardCharsets.UTF_8));
        assertNotNull(rebuilt);
        var parts = PayloadTranscoderJwt.parseJwt(rebuilt);
        assertNotNull(parts);
        assertEquals(modifiedPayload, new String(parts.payloadBytes, StandardCharsets.UTF_8));
    }
}
