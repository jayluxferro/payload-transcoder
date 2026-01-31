# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Version constant**: Extension logs version on load (e.g. "Payload Transcoder v1.0.0 loaded"); version sourced from `build.gradle.kts`
- **Encode gRPC frame**: Tab, context menu Encode submenu, and Intruder processor for wrapping raw protobuf bytes in gRPC framing
- **Context menu parity**: Homoglyph decode (Cyrillic→Latin), homoglyph encode (Latin→Cyrillic), Detect .NET ViewState, Base64 URL-safe encode, Copy as base64 URL-safe
- **Tab operations**: Form/query pretty-print, Form/query rebuild, Multipart pretty-print, WebSocket frame inspect, Encode Base64 URL-safe
- **Smart decode**: Suggests Form/query pretty-print, Multipart pretty-print, and WebSocket frame inspect when input matches those formats
- **Intruder**: Base64 URL-safe encode processor

### Changed
- **Release workflow**: Uses version from Gradle (`printVersion` task) for JAR path and release name

## [1.0.0] - 2025-01-31

### Added

#### Transcoding operations
- **Encoding**: Base64, Base64 URL-safe, Hex, URL, HTML entities, Unicode escapes, Quoted-printable
- **Compression**: gzip, deflate, Brotli
- **Structured data**: JSON (pretty-print, minify), Form/query (pretty-print, rebuild), Multipart (pretty-print)
- **Binary serialization**: MessagePack, CBOR, BSON (JSON ↔ binary)
- **Unicode normalization**: NFC, NFD, NFKC, NFKD (for bypass testing)
- **Hash/checksum**: MD5, SHA-1, SHA-256
- **HMAC**: HMAC-SHA256 (hex, webhook sha256=hex)
- **Timestamps**: Unix, Unix ms, ISO8601, RFC2822

#### Security & protocol support
- **JWT**: Decode (pretty-print), alg:none attack, RS256→HS256 key confusion, extend expiry, crack wordlist, Sign HS256
- **gRPC & Protobuf**: Frame parse, message extract, gRPC-Web decode (protobuf view, JSON, JSON with field mapping), Protobuf raw wire view, rebuild from clipboard
- **Protocol-specific**: GraphQL pretty-print, GraphQL introspection, XML pretty-print, WebSocket frame inspection
- **Deserialization detection**: Java serialized (AC ED), .NET ViewState
- **Homoglyph**: Encode (Latin→Cyrillic), Decode (Cyrillic→Latin) for WAF bypass
- **Polyglot generator**: HTML+JS+URL, SQL+HTML polyglots from payload
- **PHP**: Serialize pretty-print, serialize string
- **AWS**: SigV4 request signing

#### Tab features
- Chain transcoding with export/import
- Smart decode (auto-detect and apply decode/format)
- Suggest button with "Apply first" option
- Regex find/replace with capture groups; Extract by group
- Payload templates (XSS, SQLi, SSTI, SSRF, NoSQL, CORS, HPP, etc.) grouped by category
- OOB payload generator
- Batch mode (one payload per line)
- Hex dump / parse
- PKCS7 padding validate/strip/add
- Load file / Save output
- Swap input ↔ output
- Undo
- Compare input vs output (Burp Comparer)
- WebSocket replay

#### UI/UX
- Control bar in 3 logical rows
- Collapsible panels (Chain, Regex, Batch) with persisted state
- Status bar showing Input and Output stats
- Context menu: Format, Decode, Encode submenus; shorter labels
- Templates grouped by category in submenus
- Tooltips on all buttons and operation dropdown
- Keyboard shortcuts (when tab focused): Ctrl+Enter / ⌘+Enter (Transcode), Ctrl+Shift+S / ⌘+Shift+S (Smart decode), Ctrl+Z / ⌘+Z (Undo)
- WebSocket replay: single dialog (Host, Port, Path)

#### Intruder integration
- Payload processors for Base64, Hex, URL, Unicode normalization, JWT alg:none, homoglyph, hash, and more

#### Context menu
- Send to Payload Transcoder (HTTP, WebSocket, Scanner issues)
- Format submenu (context-aware: JSON, GraphQL, XML, gRPC, JWT, etc.)
- Decode submenu (Base64, Hex, URL, gzip, MessagePack, etc.)
- Encode submenu
- Copy to clipboard
- Send to Decoder / Comparer

#### Performance
- Context menu: cheap pre-checks (`looksLike*`) before expensive decode operations

#### Known limitations
- Chain/batch: operations requiring user input (Sign JWT, HMAC, Protobuf mapping, gRPC-Web JSON with mapping, AWS SigV4, Multipart pretty-print) are filtered and cannot run in chain or batch mode
- Suggest "Apply first": shows message when first suggestion is a prompt-based operation

### Fixed
- `looksLikeBase64`: count base64 chars (excluding whitespace) for correct handling of content with trailing whitespace
