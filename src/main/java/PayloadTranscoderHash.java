import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Hash and checksum utilities for payload analysis.
 */
public final class PayloadTranscoderHash {

    private PayloadTranscoderHash() {}

    public static byte[] md5(byte[] input) {
        return digest(input, "MD5");
    }

    public static byte[] sha1(byte[] input) {
        return digest(input, "SHA-1");
    }

    public static byte[] sha256(byte[] input) {
        return digest(input, "SHA-256");
    }

    public static byte[] sha384(byte[] input) {
        return digest(input, "SHA-384");
    }

    public static byte[] sha512(byte[] input) {
        return digest(input, "SHA-512");
    }

    private static byte[] digest(byte[] input, String algorithm) {
        if (input == null) return null;
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] hash = md.digest(input);
            return bytesToHex(hash).getBytes(StandardCharsets.US_ASCII);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public static byte[] hmacSha256(byte[] input, byte[] key) {
        return hmac(input, key, "HmacSHA256");
    }

    public static byte[] hmacSha1(byte[] input, byte[] key) {
        return hmac(input, key, "HmacSHA1");
    }

    private static byte[] hmac(byte[] input, byte[] key, String algorithm) {
        if (input == null || key == null) return null;
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            byte[] hash = mac.doFinal(input);
            return bytesToHex(hash).getBytes(StandardCharsets.US_ASCII);
        } catch (Exception e) {
            return null;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
