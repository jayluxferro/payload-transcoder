import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessor;
import burp.api.montoya.intruder.PayloadProcessingResult;

import java.nio.charset.StandardCharsets;

/**
 * Intruder payload processor that applies Payload Transcoder operations.
 */
public class PayloadTranscoderIntruderProcessor implements PayloadProcessor {

    private final MontoyaApi montoyaApi;
    private final String operation;
    private final PayloadTranscoderOperation op;

    public PayloadTranscoderIntruderProcessor(MontoyaApi montoyaApi, String operation, PayloadTranscoderOperation op) {
        this.montoyaApi = montoyaApi;
        this.operation = operation;
        this.op = op;
    }

    @Override
    public String displayName() {
        return "Payload Transcoder: " + operation;
    }

    @Override
    public PayloadProcessingResult processPayload(PayloadData payloadData) {
        byte[] input = payloadData.currentPayload().getBytes();
        if (input == null || input.length == 0) {
            return PayloadProcessingResult.skipPayload();
        }
        byte[] result = op.apply(input);
        if (result != null && result.length > 0) {
            return PayloadProcessingResult.usePayload(ByteArray.byteArray(result));
        }
        return PayloadProcessingResult.skipPayload();
    }

    @FunctionalInterface
    public interface PayloadTranscoderOperation {
        byte[] apply(byte[] input);
    }
}
