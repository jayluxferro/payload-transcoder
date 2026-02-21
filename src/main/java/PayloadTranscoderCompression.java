import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.Inflater;
import java.util.zip.Deflater;

/**
 * Compression transcoding: gzip, deflate (zlib), Brotli, Zstandard (zstd).
 */
public final class PayloadTranscoderCompression {

    private PayloadTranscoderCompression() {}

    // --- gzip ---

    public static byte[] decodeGzip(byte[] raw) {
        if (raw == null || raw.length < 10) return null;
        if (raw[0] != (byte) 0x1f || raw[1] != (byte) 0x8b) return null; // gzip magic
        try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(raw));
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = gzip.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    public static byte[] encodeGzip(byte[] bytes) {
        if (bytes == null) return null;
        try (ByteArrayOutputStream out = new ByteArrayOutputStream();
             GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(bytes);
            gzip.finish();
            return out.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    public static boolean looksLikeGzip(byte[] raw) {
        return raw != null && raw.length >= 2 && raw[0] == (byte) 0x1f && raw[1] == (byte) 0x8b;
    }

    // --- deflate (zlib format - HTTP Content-Encoding: deflate) ---

    public static byte[] decodeDeflate(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        // Try zlib format first (RFC 1950), then raw deflate (RFC 1951)
        byte[] result = decodeZlib(raw);
        if (result == null) {
            result = decodeDeflateRaw(raw);
        }
        return result;
    }

    public static byte[] encodeDeflate(byte[] bytes) {
        return encodeZlib(bytes);
    }

    private static byte[] decodeZlib(byte[] raw) {
        if (raw == null || raw.length < 2) return null;
        try {
            Inflater inflater = new Inflater(false); // zlib header
            inflater.setInput(raw);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            while (!inflater.finished()) {
                int n = inflater.inflate(buf);
                if (n == 0) {
                    if (inflater.needsInput()) break;
                    throw new IOException("Inflater needs input");
                }
                out.write(buf, 0, n);
            }
            inflater.end();
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] decodeDeflateRaw(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            Inflater inflater = new Inflater(true); // raw deflate, no header
            inflater.setInput(raw);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            while (!inflater.finished()) {
                int n = inflater.inflate(buf);
                if (n == 0) {
                    if (inflater.needsInput()) break;
                    throw new IOException("Inflater needs input");
                }
                out.write(buf, 0, n);
            }
            inflater.end();
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] encodeZlib(byte[] bytes) {
        if (bytes == null) return null;
        try {
            Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, false); // zlib header
            deflater.setInput(bytes);
            deflater.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            while (!deflater.finished()) {
                int n = deflater.deflate(buf);
                out.write(buf, 0, n);
            }
            deflater.end();
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean looksLikeDeflate(byte[] raw) {
        if (raw == null || raw.length < 2) return false;
        // zlib: first byte 0x78, second byte = 0x01, 0x5e, 0x9c, 0xda, 0x22
        if (raw[0] == (byte) 0x78) return true;
        return false;
    }

    // --- Brotli ---

    private static final boolean BROTLI_AVAILABLE = checkBrotliAvailable();

    private static boolean checkBrotliAvailable() {
        try {
            Class.forName("com.aayushatharva.brotli4j.decoder.Decoder");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    public static boolean isBrotliAvailable() {
        return BROTLI_AVAILABLE;
    }

    public static byte[] decodeBrotli(byte[] raw) {
        if (!BROTLI_AVAILABLE || raw == null || raw.length == 0) return null;
        try {
            var result = com.aayushatharva.brotli4j.decoder.Decoder.decompress(raw);
            return result.getDecompressedData();
        } catch (LinkageError e) {
            // Native Brotli libs may not load (e.g. UnsatisfiedLinkError in Burp's JVM)
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] encodeBrotli(byte[] bytes) {
        if (!BROTLI_AVAILABLE || bytes == null) return null;
        try {
            return com.aayushatharva.brotli4j.encoder.Encoder.compress(bytes);
        } catch (LinkageError e) {
            // Native Brotli libs may not load (e.g. UnsatisfiedLinkError in Burp's JVM)
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean looksLikeBrotli(byte[] raw) {
        if (!BROTLI_AVAILABLE || raw == null || raw.length < 2) return false;
        // Brotli stream starts with window size bits - hard to detect reliably
        // Just allow attempt when Brotli is available
        return raw.length >= 2;
    }

    // --- Zstandard (zstd) ---

    private static final boolean ZSTD_AVAILABLE = checkZstdAvailable();

    private static boolean checkZstdAvailable() {
        try {
            Class.forName("com.github.luben.zstd.Zstd");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    public static boolean isZstdAvailable() {
        return ZSTD_AVAILABLE;
    }

    private static final byte[] ZSTD_MAGIC = {(byte) 0x28, (byte) 0xB5, (byte) 0x2F, (byte) 0xFD};

    /** Zstd frame magic: 0x28 0xB5 0x2F 0xFD. Checks from start or within first 32 bytes (e.g. after CRLF CRLF). */
    public static boolean looksLikeZstd(byte[] raw) {
        return indexOfZstdMagic(raw) >= 0;
    }

    /** Returns offset of zstd magic in raw, or -1 if not found. Searches first 32 bytes. */
    private static int indexOfZstdMagic(byte[] raw) {
        if (raw == null || raw.length < 4) return -1;
        int limit = Math.min(raw.length - 4, 32);
        for (int i = 0; i <= limit; i++) {
            if (raw[i] == ZSTD_MAGIC[0] && raw[i + 1] == ZSTD_MAGIC[1]
                    && raw[i + 2] == ZSTD_MAGIC[2] && raw[i + 3] == ZSTD_MAGIC[3]) {
                return i;
            }
        }
        return -1;
    }

    public static byte[] decodeZstd(byte[] raw) {
        if (!ZSTD_AVAILABLE || raw == null || raw.length == 0) return null;
        int offset = indexOfZstdMagic(raw);
        if (offset < 0) return null;
        int srcLen = raw.length - offset;
        try {
            long size = com.github.luben.zstd.Zstd.decompressedSize(raw, offset, srcLen);
            if (size > 0 && size <= 512 * 1024 * 1024) {
                byte[] dst = new byte[(int) size];
                long n = com.github.luben.zstd.Zstd.decompressByteArray(dst, 0, (int) size, raw, offset, srcLen);
                if (!com.github.luben.zstd.Zstd.isError(n) && n > 0) return Arrays.copyOf(dst, (int) n);
            }
            // Frame may not store content size, or there may be trailing bytes; try with max buffer (16MB)
            int maxOut = 16 * 1024 * 1024;
            byte[] dst = new byte[maxOut];
            for (int tryLen = srcLen; tryLen >= srcLen - 256 && tryLen > 0; tryLen--) {
                try {
                    long n = com.github.luben.zstd.Zstd.decompressByteArray(dst, 0, maxOut, raw, offset, tryLen);
                    if (!com.github.luben.zstd.Zstd.isError(n) && n > 0 && n <= maxOut) return Arrays.copyOf(dst, (int) n);
                } catch (Exception ignored) {
                    // e.g. checksum mismatch when trailing bytes included; try shorter length
                }
            }
            return null;
        } catch (LinkageError e) {
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] encodeZstd(byte[] bytes) {
        if (!ZSTD_AVAILABLE || bytes == null) return null;
        try {
            long bound = com.github.luben.zstd.Zstd.compressBound(bytes.length);
            if (bound > Integer.MAX_VALUE) return null;
            byte[] dst = new byte[(int) bound];
            long n = com.github.luben.zstd.Zstd.compress(dst, bytes, 3); // level 3 default
            if (n < 0) return null;
            return Arrays.copyOf(dst, (int) n);
        } catch (LinkageError e) {
            return null;
        } catch (Exception e) {
            return null;
        }
    }
}
