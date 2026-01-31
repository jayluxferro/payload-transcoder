# Payload Transcoder

A Burp Suite extension for transcoding HTTP and WebSocket payloads between formats.

- **Payload Transcoder tab**: A dedicated tab in Burp for encoding/decoding custom protocols. Paste input, choose an operation from the dropdown, and transcode. Access via the **Payload Transcoder** tab or **Payload Transcoder > Open Payload Transcoder** in the menu bar.
- **Send to Payload Transcoder**: Right-click anywhere (HTTP messages, WebSocket messages, Scanner issues) and choose **Payload Transcoder > Send to Payload Transcoder** to send the selection or body to the tab.
- **Context menu**: Right-click a request, response, or WebSocket message to encode, decode, or transform the body.

## Supported Formats

- **Encoding**: Base64, Base64 URL-safe, Hex, URL, HTML entities, Unicode escapes, Quoted-printable
- **Structured data**: JSON (pretty-print, minify), Form/query (pretty-print, rebuild), Multipart (pretty-print)
- **Compression**: gzip, deflate, Brotli
- **Security tokens**: JWT (decode, payload edit, rebuild from clipboard, **Sign HS256**)
- **gRPC & Protobuf**: Frame parse, message extract, Protobuf raw wire view, rebuild from clipboard
- **Binary serialization**: MessagePack, CBOR, BSON (JSON ↔ binary)
- **Protocol-specific**: GraphQL pretty-print, GraphQL introspection, XML pretty-print, WebSocket frame inspection
- **Hash/checksum**: MD5, SHA-1, SHA-256
- **Timestamps**: Unix, Unix ms, ISO8601, RFC2822

## Tab Features

- **Chain transcoding**: Add multiple operations to a chain and run them in sequence (e.g., Base64 → URL decode → Hex decode)
- **Export/import chains**: Save and load transformation chains to/from file
- **Smart detection**: "Suggest" button analyzes input and suggests likely encodings
- **Regex find/replace**: Replace all matches with support for capture groups ($1, $2); **Extract** first match by group
- **Payload templates**: Insert common test payloads (XSS, SQLi, command injection, path traversal, SSTI, etc.)
- **OOB payload generator**: Generate unique SSRF/OOB callback URLs (UUID, webhook templates, etc.)
- **Batch mode**: Transform multiple payloads (one per line) with a single operation
- **Diff view**: "Compare input vs output" sends both to Burp Comparer
- **Load file / Save output**: Load dumped files for analysis; save output to file
- **Swap input ↔ output**: Swap input and output (e.g. decode → modify → swap → encode)
- **History/undo**: Revert to previous input after transcoding
- **Length/byte analysis**: Status bar shows bytes, chars, and lines
- **Hex dump / parse**: View binary as hex dump; parse hex dump back to bytes
- **CBC padding oracle**: Validate/strip/add PKCS7 padding
- **Protobuf field mapping**: Decode Protobuf with field name mapping (e.g. 1=name,2=id)
- **WebSocket replay**: Replay WebSocket messages (context menu on WebSocket messages)
- **Intruder integration**: Payload Transcoder operations available as Intruder payload processors

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
