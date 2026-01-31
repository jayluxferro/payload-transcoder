import burp.api.montoya.MontoyaApi;
import burp.api.montoya.intruder.PayloadProcessor;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Registers Payload Transcoder operations as Intruder payload processors.
 */
public final class PayloadTranscoderIntruderProcessors {

    private PayloadTranscoderIntruderProcessors() {}

    public static List<PayloadProcessor> createProcessors(MontoyaApi montoyaApi) {
        List<PayloadProcessor> list = new ArrayList<>();
        add(list, montoyaApi, "Base64 decode", PayloadTranscoderUtils::decodeBase64);
        add(list, montoyaApi, "Base64 URL-safe decode", PayloadTranscoderUtils::decodeBase64UrlSafe);
        add(list, montoyaApi, "Hex decode", PayloadTranscoderUtils::decodeHex);
        add(list, montoyaApi, "URL decode", PayloadTranscoderUtils::decodeUrl);
        add(list, montoyaApi, "HTML entities decode", PayloadTranscoderUtils::decodeHtmlEntities);
        add(list, montoyaApi, "Unicode escapes decode", PayloadTranscoderUtils::decodeUnicodeEscapes);
        add(list, montoyaApi, "Quoted-printable decode", PayloadTranscoderUtils::decodeQuotedPrintable);
        add(list, montoyaApi, "Base64 encode", in -> toBytes(PayloadTranscoderUtils.encodeBase64(in)));
        add(list, montoyaApi, "Hex encode", in -> toBytes(PayloadTranscoderUtils.encodeHex(in)));
        add(list, montoyaApi, "URL encode", in -> toBytes(PayloadTranscoderUtils.encodeUrlStrict(in)));
        add(list, montoyaApi, "HTML entities encode", in -> toBytes(PayloadTranscoderUtils.encodeHtmlEntities(in)));
        add(list, montoyaApi, "Unicode escapes encode", in -> toBytes(PayloadTranscoderUtils.encodeUnicodeEscapes(in)));
        add(list, montoyaApi, "gzip decode", PayloadTranscoderCompression::decodeGzip);
        add(list, montoyaApi, "deflate decode", PayloadTranscoderCompression::decodeDeflate);
        add(list, montoyaApi, "gzip encode", PayloadTranscoderCompression::encodeGzip);
        add(list, montoyaApi, "deflate encode", PayloadTranscoderCompression::encodeDeflate);
        add(list, montoyaApi, "JSON pretty-print", PayloadTranscoderStructured::jsonPrettyPrint);
        add(list, montoyaApi, "JSON minify", PayloadTranscoderStructured::jsonMinify);
        add(list, montoyaApi, "Hash MD5", PayloadTranscoderHash::md5);
        add(list, montoyaApi, "Hash SHA-256", PayloadTranscoderHash::sha256);
        return list;
    }

    private static void add(List<PayloadProcessor> list, MontoyaApi api, String name,
            PayloadTranscoderIntruderProcessor.PayloadTranscoderOperation op) {
        list.add(new PayloadTranscoderIntruderProcessor(api, name, op));
    }

    private static byte[] toBytes(String s) {
        return s != null ? s.getBytes(StandardCharsets.UTF_8) : null;
    }
}
