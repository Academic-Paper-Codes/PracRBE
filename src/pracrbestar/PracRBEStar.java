package pracrbestar;

import common.AbstractPracRBEScheme;
import common.ReportUtils;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class PracRBEStar extends AbstractPracRBEScheme {
    private static final ThreadLocal<MessageDigest> SHA256 =
            ThreadLocal.withInitial(() -> {
                try {
                    return MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException ex) {
                    throw new IllegalStateException("SHA-256 is not available.", ex);
                }
            });

    public PracRBEStar(int maxUsers, int seed) {
        super(maxUsers, seed);
    }

    @Override
    public Map<String, Object> encrypt(List<Integer> userIds, BigInteger message) {
        requireSetup();
        long start = System.nanoTime();

        List<Integer> orderedUserIds = normalizeUserIds(userIds);
        Map<Integer, Map<String, Object>> perUserCiphertexts = new LinkedHashMap<Integer, Map<String, Object>>();
        BigInteger normalizedMessage = message.mod(group.getOrder());

        for (Integer userId : orderedUserIds) {
            int[] location = locate(userId);
            int groupIndex = location[0];
            int position = location[1];
            BigInteger sigma = new BigInteger(securityBits, random);
            BigInteger derivedR = h1(userId, normalizedMessage, sigma);
            BigInteger c0 = pp.commitments().get(groupIndex);
            BigInteger c1 = group.gPow(g, derivedR);
            BigInteger mask = group.gtPow(group.pair(c0, h.get(position)), derivedR);
            BigInteger c2 = h2(mask).xor(sigma);
            BigInteger c3 = group.gtMul(mask, normalizedMessage);

            Map<String, Object> ciphertext = new LinkedHashMap<String, Object>();
            ciphertext.put("c0", c0);
            ciphertext.put("c1", c1);
            ciphertext.put("c2", c2);
            ciphertext.put("c3", c3);

            Map<String, Object> userCiphertext = new LinkedHashMap<String, Object>();
            userCiphertext.put("user_id", userId);
            userCiphertext.put("message", normalizedMessage);
            userCiphertext.put("sigma", sigma);
            userCiphertext.put("derived_r", derivedR);
            userCiphertext.put("ciphertext", ciphertext);
            perUserCiphertexts.put(userId, userCiphertext);
        }

        Map<String, Object> result = new LinkedHashMap<String, Object>();
        result.put("calculation_complete", true);
        result.put("processed_users", orderedUserIds.size());
        result.put("per_user", perUserCiphertexts);
        ReportUtils.printReport("Encrypt", start, result);
        return result;
    }

    @Override
    public Map<String, Object> decrypt(
            Map<Integer, BigInteger> secretKeys,
            Map<String, Object> encryptionOutput,
            Map<String, Object> updateOutput
    ) {
        requireSetup();
        long start = System.nanoTime();

        @SuppressWarnings("unchecked")
        Map<Integer, Map<String, Object>> encryptionMap =
                (Map<Integer, Map<String, Object>>) encryptionOutput.get("per_user");
        @SuppressWarnings("unchecked")
        Map<Integer, Map<String, Object>> updateMap = updateOutput == null
                ? new LinkedHashMap<Integer, Map<String, Object>>()
                : (Map<Integer, Map<String, Object>>) updateOutput.get("per_user");

        List<Integer> orderedUserIds = normalizeUserIds(new ArrayList<Integer>(encryptionMap.keySet()));
        Map<Integer, Map<String, Object>> perUserResults = new LinkedHashMap<Integer, Map<String, Object>>();

        for (Integer userId : orderedUserIds) {
            @SuppressWarnings("unchecked")
            Map<String, Object> ciphertext = (Map<String, Object>) encryptionMap.get(userId).get("ciphertext");
            BigInteger secretKey = secretKeys.get(userId);
            int[] location = locate(userId);
            int groupIndex = location[0];
            int position = location[1];
            BigInteger c0 = (BigInteger) ciphertext.get("c0");
            BigInteger c1 = (BigInteger) ciphertext.get("c1");
            BigInteger c2 = (BigInteger) ciphertext.get("c2");
            BigInteger c3 = (BigInteger) ciphertext.get("c3");

            Map<String, Object> providedUpdate = updateMap.get(userId);
            boolean proofIsFresh = providedUpdate != null && c0.equals(providedUpdate.get("commitment"));
            BigInteger proofUsed = proofIsFresh
                    ? (BigInteger) providedUpdate.get("proof")
                    : proofFromHistory(groupIndex, position, c0);
            BigInteger keyTerm = group.gPow(h.get(position), secretKey);
            BigInteger mask = group.gtMul(
                    group.pair(proofUsed, c1),
                    group.pair(c1, keyTerm)
            );
            BigInteger recoveredSigma = c2.xor(h2(mask));
            BigInteger recoveredMessage = group.gtDiv(c3, mask);
            BigInteger recomputedR = h1(userId, recoveredMessage, recoveredSigma);
            boolean accepted = c1.equals(group.gPow(g, recomputedR));

            Map<String, Object> userResult = new LinkedHashMap<String, Object>();
            userResult.put("user_id", userId);
            userResult.put("proof_is_fresh", proofIsFresh);
            userResult.put("used_refreshed_proof", !proofIsFresh);
            userResult.put("proof_used", proofUsed);
            userResult.put("recovered_sigma", recoveredSigma);
            userResult.put("recovered_message", recoveredMessage);
            userResult.put("accepted", accepted);
            perUserResults.put(userId, userResult);
        }

        Map<String, Object> result = new LinkedHashMap<String, Object>();
        result.put("calculation_complete", true);
        result.put("processed_users", orderedUserIds.size());
        result.put("per_user", perUserResults);
        ReportUtils.printReport("Decrypt", start, result);
        return result;
    }

    private BigInteger h1(int userId, BigInteger message, BigInteger sigma) {
        group.countHashH1();
        byte[] digest = sha256(serializeH1Input(userId, message, sigma));
        return new BigInteger(1, digest).mod(group.getOrder());
    }

    private BigInteger h2(BigInteger gtElement) {
        group.countHashH2();
        byte[] digest = sha256(gtElement.mod(group.getOrder()).toByteArray());
        return new BigInteger(1, digest).and(BigInteger.ONE.shiftLeft(securityBits).subtract(BigInteger.ONE));
    }

    private byte[] serializeH1Input(int userId, BigInteger message, BigInteger sigma) {
        byte[] userIdBytes = ByteBuffer.allocate(Integer.BYTES).putInt(userId).array();
        byte[] messageBytes = message.mod(group.getOrder()).toByteArray();
        byte[] sigmaBytes = sigma.toByteArray();
        byte[] serialized = new byte[userIdBytes.length + 1 + messageBytes.length + 1 + sigmaBytes.length];

        int offset = 0;
        System.arraycopy(userIdBytes, 0, serialized, offset, userIdBytes.length);
        offset += userIdBytes.length;
        serialized[offset++] = 0;
        System.arraycopy(messageBytes, 0, serialized, offset, messageBytes.length);
        offset += messageBytes.length;
        serialized[offset++] = 0;
        System.arraycopy(sigmaBytes, 0, serialized, offset, sigmaBytes.length);
        return serialized;
    }

    private static byte[] sha256(byte[] input) {
        MessageDigest digest = SHA256.get();
        digest.reset();
        return digest.digest(input);
    }
}
