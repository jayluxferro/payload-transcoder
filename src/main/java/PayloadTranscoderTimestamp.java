import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * Timestamp generation for token manipulation.
 */
public final class PayloadTranscoderTimestamp {

    private PayloadTranscoderTimestamp() {}

    public static byte[] unixNow() {
        return String.valueOf(System.currentTimeMillis() / 1000).getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] unixMillisNow() {
        return String.valueOf(System.currentTimeMillis()).getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] iso8601Now() {
        return Instant.now().toString().getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] rfc2822Now() {
        return DateTimeFormatter.RFC_1123_DATE_TIME
                .withZone(ZoneOffset.UTC)
                .withLocale(Locale.US)
                .format(Instant.now())
                .getBytes(StandardCharsets.UTF_8);
    }

    /** Unix timestamp N seconds ago (for testing expiry). */
    public static byte[] unixAgo(int seconds) {
        return String.valueOf((System.currentTimeMillis() / 1000) - seconds).getBytes(StandardCharsets.UTF_8);
    }

    /** Unix timestamp N seconds from now. */
    public static byte[] unixFuture(int seconds) {
        return String.valueOf((System.currentTimeMillis() / 1000) + seconds).getBytes(StandardCharsets.UTF_8);
    }
}
