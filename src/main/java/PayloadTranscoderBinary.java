import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.msgpack.jackson.dataformat.MessagePackFactory;

import java.nio.charset.StandardCharsets;

/**
 * Binary serialization transcoding: MessagePack, CBOR, BSON.
 */
public final class PayloadTranscoderBinary {

    private static final ObjectMapper JSON_MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private static final ObjectMapper MSGPACK_MAPPER = new ObjectMapper(new MessagePackFactory());
    private static final ObjectMapper CBOR_MAPPER = new ObjectMapper(new CBORFactory());

    private PayloadTranscoderBinary() {}

    // --- MessagePack ---

    public static byte[] decodeMessagePack(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            JsonNode node = MSGPACK_MAPPER.readTree(raw);
            return JSON_MAPPER.writeValueAsString(node).getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] encodeMessagePack(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        try {
            String json = new String(bytes, StandardCharsets.UTF_8);
            JsonNode node = JSON_MAPPER.readTree(json);
            return MSGPACK_MAPPER.writeValueAsBytes(node);
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean looksLikeMessagePack(byte[] raw) {
        if (raw == null || raw.length < 1) return false;
        // MessagePack first byte: 0x80-0x9f (fixmap), 0x90-0x9f (fixarray), 0xa0-0xbf (fixstr), etc.
        int b = raw[0] & 0xFF;
        return b >= 0x80 || b == 0x7f || (b >= 0xc0 && b <= 0xdf) || (b >= 0xe0 && b <= 0xff);
    }

    // --- CBOR ---

    public static byte[] decodeCbor(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            JsonNode node = CBOR_MAPPER.readTree(raw);
            return JSON_MAPPER.writeValueAsString(node).getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] encodeCbor(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        try {
            String json = new String(bytes, StandardCharsets.UTF_8);
            JsonNode node = JSON_MAPPER.readTree(json);
            return CBOR_MAPPER.writeValueAsBytes(node);
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean looksLikeCbor(byte[] raw) {
        if (raw == null || raw.length < 1) return false;
        // CBOR major type in first byte: 0x00-0x1b (unsigned), 0x20-0x3b (negative), 0x40-0x5f (bytes), etc.
        int b = raw[0] & 0xFF;
        return b <= 0x1b || (b >= 0x20 && b <= 0x3b) || (b >= 0x40 && b <= 0x5f)
                || (b >= 0x60 && b <= 0x7b) || (b >= 0x80 && b <= 0x9b) || (b >= 0xa0 && b <= 0xbb)
                || (b >= 0xc0 && b <= 0xdb) || (b >= 0xe0 && b <= 0xf3);
    }

    // --- BSON ---

    public static byte[] decodeBson(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            org.bson.RawBsonDocument doc = new org.bson.RawBsonDocument(raw);
            return doc.toJson().getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] encodeBson(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        try {
            String json = new String(bytes, StandardCharsets.UTF_8);
            org.bson.BsonDocument doc = org.bson.BsonDocument.parse(json);
            org.bson.io.BasicOutputBuffer buffer = new org.bson.io.BasicOutputBuffer();
            org.bson.codecs.BsonDocumentCodec codec = new org.bson.codecs.BsonDocumentCodec();
            codec.encode(new org.bson.BsonBinaryWriter(buffer), doc, org.bson.codecs.EncoderContext.builder().build());
            return buffer.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean looksLikeBson(byte[] raw) {
        if (raw == null || raw.length < 5) return false;
        // BSON document: 4-byte little-endian length + document
        try {
            int len = (raw[0] & 0xFF) | ((raw[1] & 0xFF) << 8) | ((raw[2] & 0xFF) << 16) | ((raw[3] & 0xFF) << 24);
            return len >= 5 && len <= raw.length;
        } catch (Exception e) {
            return false;
        }
    }
}
