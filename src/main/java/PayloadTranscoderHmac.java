import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * HMAC signing for request authentication (e.g. X-Hub-Signature, webhooks).
 */
public final class PayloadTranscoderHmac {

    private PayloadTranscoderHmac() {}

    /**
     * Compute HMAC-SHA256 of input with given secret. Returns hex-encoded signature.
     */
    public static byte[] hmacSha256Hex(byte[] input, byte[] secret) {
        if (input == null || secret == null) return null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            byte[] sig = mac.doFinal(input);
            StringBuilder sb = new StringBuilder(sig.length * 2);
            for (byte b : sig) {
                sb.append(String.format("%02x", b & 0xFF));
            }
            return sb.toString().getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Compute HMAC-SHA256 of input. Returns sha256=hex format (GitHub webhook style).
     */
    public static byte[] hmacSha256Webhook(byte[] input, byte[] secret) {
        byte[] hex = hmacSha256Hex(input, secret);
        if (hex == null) return null;
        return ("sha256=" + new String(hex, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
    }
}
