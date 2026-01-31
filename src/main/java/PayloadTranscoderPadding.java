import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * CBC padding oracle helpers for block-cipher attacks.
 */
public final class PayloadTranscoderPadding {

    private static final int BLOCK_SIZE = 16;

    private PayloadTranscoderPadding() {}

    /**
     * Validate PKCS7 padding. Returns true if padding is valid.
     */
    public static boolean validatePkcs7(byte[] data) {
        if (data == null || data.length == 0) return false;
        int padLen = data[data.length - 1] & 0xff;
        if (padLen <= 0 || padLen > BLOCK_SIZE) return false;
        for (int i = 0; i < padLen; i++) {
            if ((data[data.length - 1 - i] & 0xff) != padLen) return false;
        }
        return true;
    }

    /**
     * Strip PKCS7 padding. Returns unpadded bytes or null if invalid.
     */
    public static byte[] stripPkcs7(byte[] data) {
        if (data == null || data.length == 0) return null;
        if (!validatePkcs7(data)) return null;
        int padLen = data[data.length - 1] & 0xff;
        return Arrays.copyOf(data, data.length - padLen);
    }

    /**
     * Add PKCS7 padding to data (block size 16).
     */
    public static byte[] addPkcs7(byte[] data) {
        if (data == null) return null;
        int padLen = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        if (padLen == 0) padLen = BLOCK_SIZE;
        byte[] result = Arrays.copyOf(data, data.length + padLen);
        Arrays.fill(result, data.length, result.length, (byte) padLen);
        return result;
    }

    /**
     * XOR two byte arrays (must be same length).
     */
    public static byte[] xor(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return null;
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    /**
     * Flip byte at index for padding oracle (modify second-to-last block).
     * For CBC: C'[i] = C[i] ^ P[i] ^ desired_pad
     */
    public static byte[] flipByteForPadding(byte[] ciphertext, int blockIndex, int byteInBlock, byte desiredValue) {
        if (ciphertext == null || ciphertext.length < BLOCK_SIZE * 2) return null;
        int idx = blockIndex * BLOCK_SIZE + byteInBlock;
        if (idx < 0 || idx >= ciphertext.length - BLOCK_SIZE) return null;
        byte[] result = Arrays.copyOf(ciphertext, ciphertext.length);
        result[idx] ^= desiredValue ^ (byte) (BLOCK_SIZE - byteInBlock);
        return result;
    }

    /**
     * Hex dump format for binary view (offset: hex bytes | ascii).
     */
    public static byte[] hexDump(byte[] data) {
        if (data == null) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i += 16) {
            sb.append(String.format("%08x: ", i));
            for (int j = 0; j < 16; j++) {
                if (i + j < data.length) {
                    sb.append(String.format("%02x ", data[i + j] & 0xff));
                } else {
                    sb.append("   ");
                }
            }
            sb.append(" |");
            for (int j = 0; j < 16 && i + j < data.length; j++) {
                byte b = data[i + j];
                sb.append((b >= 32 && b < 127) ? (char) b : '.');
            }
            sb.append("|\n");
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Parse hex dump back to bytes (handles format: offset: hex hex ... | ascii |).
     */
    public static byte[] parseHexDump(byte[] dump) {
        if (dump == null || dump.length == 0) return null;
        try {
            String s = new String(dump, StandardCharsets.UTF_8);
            StringBuilder hex = new StringBuilder();
            for (String line : s.split("\\r?\\n")) {
                int pipe = line.indexOf('|');
                String hexPart = pipe > 0 ? line.substring(0, pipe) : line;
                int colon = hexPart.indexOf(':');
                if (colon > 0) hexPart = hexPart.substring(colon + 1);
                hex.append(hexPart.replaceAll("\\s", ""));
            }
            String hexStr = hex.toString().replaceAll("[^0-9a-fA-F]", "");
            if (hexStr.length() % 2 != 0) return null;
            byte[] out = new byte[hexStr.length() / 2];
            for (int i = 0; i < out.length; i++) {
                out[i] = (byte) Integer.parseInt(hexStr.substring(i * 2, i * 2 + 2), 16);
            }
            return out;
        } catch (Exception e) {
            return null;
        }
    }
}
