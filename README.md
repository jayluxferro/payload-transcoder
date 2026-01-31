# Payload Transcoder

A Burp Suite extension for transcoding HTTP and WebSocket payloads between formats (base64, hex, URL-encode, etc.). Right-click a request, response, or WebSocket message to encode, decode, or transform the body.

## Requirements

- Java 17 or later
- Burp Suite with Montoya API support

## Building

```bash
./gradlew jar
```

The JAR is written to `build/libs/payload-transcoder.jar`.

## Installation

1. In Burp, go to **Extensions > Installed**.
2. Click **Add** and select `payload-transcoder.jar`.
3. Click **Next** to load the extension.

To reload after changes: hold **Ctrl** (Windows/Linux) or **⌘** (macOS) and click the **Loaded** checkbox.

## Planned Features

See [docs/FEATURES.md](docs/FEATURES.md) for the full feature roadmap.

## Resources

- [Montoya API JavaDoc](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html)
- [Burp extension documentation](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating)
