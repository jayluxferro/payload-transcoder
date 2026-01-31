# Payload Transcoder

A Burp Suite extension for transcoding HTTP and WebSocket payloads between formats.

- **Payload Transcoder tab**: A dedicated tab in Burp for encoding/decoding custom protocols. Paste input, choose an operation from the dropdown, and transcode. Access via the **Payload Transcoder** tab or **Payload Transcoder > Open Payload Transcoder** in the menu bar.
- **Send to Payload Transcoder**: Right-click anywhere (HTTP messages, WebSocket messages, Scanner issues) and choose **Payload Transcoder > Send to Payload Transcoder** to send the selection or body to the tab.
- **Context menu**: Right-click a request, response, or WebSocket message to encode, decode, or transform the body.

## Supported Formats

- **Encoding**: Base64, Base64 URL-safe, Hex, URL, HTML entities, Unicode escapes, Quoted-printable
- **Unicode normalization**: NFC, NFD, NFKC, NFKD (for bypass testing)
- **Structured data**: JSON (pretty-print, minify), Form/query (pretty-print, rebuild), Multipart (pretty-print)
- **Compression**: gzip, deflate, Brotli
- **Security tokens**: JWT (decode, **alg:none attack**, **RS256→HS256 key confusion**, **extend expiry**, **crack wordlist**, Sign HS256)
- **gRPC & Protobuf**: Frame parse, message extract, **gRPC-Web decode** (protobuf view, JSON, JSON with field mapping), Protobuf raw wire view, rebuild from clipboard
- **Binary serialization**: MessagePack, CBOR, BSON (JSON ↔ binary)
- **Protocol-specific**: GraphQL pretty-print, GraphQL introspection, XML pretty-print, WebSocket frame inspection
- **Hash/checksum**: MD5, SHA-1, SHA-256
- **HMAC**: HMAC-SHA256 (hex, webhook sha256=hex)
- **Deserialization**: Detect Java serialized (AC ED), Detect .NET ViewState
- **Homoglyph**: Encode (Latin→Cyrillic), Decode (Cyrillic→Latin) for WAF bypass
- **Polyglot**: Generate HTML+JS+URL, SQL+HTML polyglots from payload
- **PHP**: Serialize pretty-print, serialize string
- **AWS**: SigV4 request signing
- **Timestamps**: Unix, Unix ms, ISO8601, RFC2822

## Tab Features

- **Chain transcoding**: Add multiple operations to a chain and run them in sequence (e.g., Base64 → URL decode → Hex decode). *Note: Operations that require user input (Sign JWT, HMAC, Protobuf mapping, gRPC-Web JSON with mapping, AWS SigV4) cannot be used in chain or batch mode.*
- **Export/import chains**: Save and load transformation chains to/from file
- **Smart decode**: Auto-detect and apply decode/format operations when loading, receiving, or pasting. Use "Paste & smart decode" for clipboard, or "Smart decode" after manual paste. Toggle "Auto on load/send" to enable/disable automatic smart decode.
- **Smart detection**: "Suggest" button analyzes input and suggests likely encodings
- **Regex find/replace**: Replace all matches with support for capture groups ($1, $2); **Extract** first match by group
- **Payload templates**: XSS, SQLi, command injection, path traversal, SSTI (Jinja2, Freemarker, Velocity, etc.), NoSQL injection, SSRF (cloud metadata, localhost bypasses), CORS bypass, HPP, polyglot, homoglyphs, cache poisoning, GraphQL batch/alias
- **OOB payload generator**: Generate unique SSRF/OOB callback URLs (UUID, webhook templates, etc.)
- **Batch mode**: Transform multiple payloads (one per line) with a single operation. *Prompt-based operations (Sign JWT, HMAC, etc.) are not available in batch.*
- **Diff view**: "Compare input vs output" sends both to Burp Comparer
- **Load file / Save output**: Load dumped files for analysis; save output to file
- **Swap input ↔ output**: Swap input and output (e.g. decode → modify → swap → encode)
- **History/undo**: Revert to previous input after transcoding
- **Length/byte analysis**: Status bar shows Input and Output stats (bytes, chars, lines for each)
- **Hex dump / parse**: View binary as hex dump; parse hex dump back to bytes
- **CBC padding oracle**: Validate/strip/add PKCS7 padding
- **Protobuf field mapping**: Decode Protobuf with field name mapping (e.g. 1=name,2=id)
- **WebSocket replay**: Replay WebSocket messages (context menu on WebSocket messages)
- **Intruder integration**: Payload Transcoder operations available as Intruder payload processors

## UI

- **Control layout**: Operations grouped into 3 rows (primary actions, I/O actions, file/template actions)
- **Collapsible panels**: Chain, Regex replace, and Batch mode panels can be collapsed/expanded via header click; state persists across sessions
- **Context menu**: Decode and Encode items grouped into submenus; Format items context-aware; shorter labels
- **Templates**: Grouped by category (XSS, SQLi, SSTI, SSRF, etc.) in submenus
- **Tooltips**: All buttons have tooltips for quick reference
- **Keyboard shortcuts** (when tab focused): Ctrl+Enter / ⌘+Enter (Transcode), Ctrl+Shift+S / ⌘+Shift+S (Smart decode), Ctrl+Z / ⌘+Z (Undo)

## Requirements

- Java 17 or later
- Burp Suite with Montoya API support

## Building

```bash
./gradlew jar
```

The JAR is written to `build/libs/payload-transcoder.jar`.

## Testing

```bash
./gradlew test
```

## Installation

1. In Burp, go to **Extensions > Installed**.
2. Click **Add** and select `payload-transcoder.jar`.
3. Click **Next** to load the extension.

To reload after changes: hold **Ctrl** (Windows/Linux) or **⌘** (macOS) and click the **Loaded** checkbox.

## Resources

- [Montoya API JavaDoc](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html)
- [Burp extension documentation](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating)
