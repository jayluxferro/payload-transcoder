import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * AWS Signature Version 4 for API request signing.
 */
public final class PayloadTranscoderAwsSigV4 {

    private static final String ALGORITHM = "AWS4-HMAC-SHA256";

    private PayloadTranscoderAwsSigV4() {}

    /**
     * Sign request and return Authorization header + x-amz-date + x-amz-content-sha256.
     * Output format: header lines ready to add to request.
     */
    public static byte[] signRequest(byte[] body, String accessKey, String secretKey,
            String region, String service, String method, String uri, String host) {
        if (accessKey == null || secretKey == null || region == null || service == null) return null;
        if (method == null || method.isEmpty()) method = "GET";
        if (uri == null || uri.isEmpty()) uri = "/";
        if (host == null || host.isEmpty()) host = service + "." + region + ".amazonaws.com";

        try {
            Instant now = Instant.now();
            String amzDate = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(java.time.ZoneOffset.UTC).format(now);
            String dateStamp = amzDate.substring(0, 8);

            String payloadHash = sha256Hex(body != null ? body : new byte[0]);
            String canonicalHeaders = "host:" + host + "\n" + "x-amz-content-sha256:" + payloadHash + "\n" + "x-amz-date:" + amzDate + "\n";
            String signedHeaders = "host;x-amz-content-sha256;x-amz-date";
            String canonicalRequest = method + "\n" + canonicalUri(uri) + "\n" + canonicalQueryString(uri) + "\n"
                    + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash;

            String credentialScope = dateStamp + "/" + region + "/" + service + "/aws4_request";
            String stringToSign = ALGORITHM + "\n" + amzDate + "\n" + credentialScope + "\n" + sha256Hex(canonicalRequest.getBytes(StandardCharsets.UTF_8));

            byte[] signingKey = getSignatureKey(secretKey, dateStamp, region, service);
            String signature = hmacSha256Hex(signingKey, stringToSign);

            String authHeader = ALGORITHM + " Credential=" + accessKey + "/" + credentialScope
                    + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature;

            return ("Authorization: " + authHeader + "\nx-amz-date: " + amzDate + "\nx-amz-content-sha256: " + payloadHash).getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private static String canonicalUri(String uri) {
        int q = uri.indexOf('?');
        String path = q >= 0 ? uri.substring(0, q) : uri;
        if (path.isEmpty()) return "/";
        return path;
    }

    private static String canonicalQueryString(String uri) {
        int q = uri.indexOf('?');
        if (q < 0 || q + 1 >= uri.length()) return "";
        return uri.substring(q + 1);
    }

    private static byte[] getSignatureKey(String key, String dateStamp, String region, String service) throws Exception {
        byte[] kSecret = ("AWS4" + key).getBytes(StandardCharsets.UTF_8);
        byte[] kDate = hmacSha256(kSecret, dateStamp);
        byte[] kRegion = hmacSha256(kDate, region);
        byte[] kService = hmacSha256(kRegion, service);
        return hmacSha256(kService, "aws4_request");
    }

    private static byte[] hmacSha256(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String hmacSha256Hex(byte[] key, String data) throws Exception {
        byte[] sig = hmacSha256(key, data);
        return bytesToHex(sig);
    }

    private static String sha256Hex(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return bytesToHex(md.digest(data));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }
}
