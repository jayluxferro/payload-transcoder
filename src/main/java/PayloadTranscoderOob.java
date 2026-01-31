import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * SSRF/OOB payload generator for out-of-band testing.
 */
public final class PayloadTranscoderOob {

    private PayloadTranscoderOob() {}

    public static byte[] generateUuid() {
        return UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] generateShortId() {
        return UUID.randomUUID().toString().substring(0, 8).getBytes(StandardCharsets.UTF_8);
    }

    /** Generate OOB URL templates with unique ID. */
    public static Map<String, byte[]> generateOobPayloads() {
        String id = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        Map<String, byte[]> m = new LinkedHashMap<>();
        m.put("HTTP callback (replace host): http://YOUR-SERVER.com/cb?id=" + id,
                ("http://YOUR-SERVER.com/cb?id=" + id).getBytes(StandardCharsets.UTF_8));
        m.put("HTTPS callback (replace host): https://YOUR-SERVER.com/cb?id=" + id,
                ("https://YOUR-SERVER.com/cb?id=" + id).getBytes(StandardCharsets.UTF_8));
        m.put("DNS callback (replace domain): " + id + ".YOUR-DOMAIN.com",
                (id + ".YOUR-DOMAIN.com").getBytes(StandardCharsets.UTF_8));
        m.put("Interactsh style: " + id + ".oast.fun",
                (id + ".oast.fun").getBytes(StandardCharsets.UTF_8));
        m.put("Webhook.site style: https://webhook.site/" + id,
                ("https://webhook.site/" + id).getBytes(StandardCharsets.UTF_8));
        m.put("RequestBin style: https://requestbin.io/" + id,
                ("https://requestbin.io/" + id).getBytes(StandardCharsets.UTF_8));
        m.put("Plain UUID: " + UUID.randomUUID(),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        return m;
    }
}
