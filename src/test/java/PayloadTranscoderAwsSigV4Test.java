import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class PayloadTranscoderAwsSigV4Test {

    @Test
    void signRequestReturnsNonNullWithValidInputs() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        byte[] result = PayloadTranscoderAwsSigV4.signRequest(
                body, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "us-east-1", "s3", "GET", "/", "s3.us-east-1.amazonaws.com");
        assertNotNull(result);
    }

    @Test
    void signRequestOutputContainsExpectedHeaders() {
        byte[] body = new byte[0];
        byte[] result = PayloadTranscoderAwsSigV4.signRequest(
                body, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "us-east-1", "s3", "GET", "/", "s3.us-east-1.amazonaws.com");
        assertNotNull(result);
        String output = new String(result, StandardCharsets.UTF_8);
        assertTrue(output.contains("Authorization: AWS4-HMAC-SHA256"));
        assertTrue(output.contains("x-amz-date:"));
        assertTrue(output.contains("x-amz-content-sha256:"));
        assertTrue(output.contains("Credential=AKIAIOSFODNN7EXAMPLE"));
        assertTrue(output.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
        assertTrue(output.contains("Signature="));
    }

    @Test
    void signRequestReturnsNullWhenAccessKeyNull() {
        byte[] result = PayloadTranscoderAwsSigV4.signRequest(
                new byte[0], null, "secret", "us-east-1", "s3", "GET", "/", "host");
        assertNull(result);
    }

    @Test
    void signRequestReturnsNullWhenSecretKeyNull() {
        byte[] result = PayloadTranscoderAwsSigV4.signRequest(
                new byte[0], "AKIA", null, "us-east-1", "s3", "GET", "/", "host");
        assertNull(result);
    }

    @Test
    void signRequestUsesDefaultMethodAndUri() {
        byte[] result = PayloadTranscoderAwsSigV4.signRequest(
                new byte[0], "AKIA", "secret", "us-east-1", "s3", null, null, null);
        assertNotNull(result);
    }
}
