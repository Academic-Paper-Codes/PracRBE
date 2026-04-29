package pracrbe;

import common.AbstractPracRBEScheme;
import common.ReportUtils;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class PracRBE extends AbstractPracRBEScheme {
    public PracRBE(int maxUsers, int seed) {
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
            BigInteger randomness = group.sampleScalar();
            BigInteger c0 = pp.commitments().get(groupIndex);
            BigInteger c1 = group.gPow(g, randomness);
            BigInteger mask = group.gtPow(group.pair(c0, h.get(position)), randomness);
            BigInteger c2 = group.gtMul(mask, normalizedMessage);

            Map<String, Object> ciphertext = new LinkedHashMap<String, Object>();
            ciphertext.put("c0", c0);
            ciphertext.put("c1", c1);
            ciphertext.put("c2", c2);

            Map<String, Object> userCiphertext = new LinkedHashMap<String, Object>();
            userCiphertext.put("user_id", userId);
            userCiphertext.put("message", normalizedMessage);
            userCiphertext.put("randomness", randomness);
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

        List<Integer> orderedUserIds = normalizeUserIds(List.copyOf(encryptionMap.keySet()));
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

            Map<String, Object> providedUpdate = updateMap.get(userId);
            boolean proofIsFresh = providedUpdate != null && c0.equals(providedUpdate.get("commitment"));
            BigInteger proofUsed = proofIsFresh
                    ? (BigInteger) providedUpdate.get("proof")
                    : proofFromHistory(groupIndex, position, c0);

            BigInteger keyTerm = group.gPow(h.get(position), secretKey);
            BigInteger denominator = group.gtMul(
                    group.pair(proofUsed, c1),
                    group.pair(c1, keyTerm)
            );
            BigInteger recoveredMessage = group.gtDiv(c2, denominator);

            Map<String, Object> userResult = new LinkedHashMap<String, Object>();
            userResult.put("user_id", userId);
            userResult.put("proof_is_fresh", proofIsFresh);
            userResult.put("used_refreshed_proof", !proofIsFresh);
            userResult.put("proof_used", proofUsed);
            userResult.put("recovered_message", recoveredMessage);
            perUserResults.put(userId, userResult);
        }

        Map<String, Object> result = new LinkedHashMap<String, Object>();
        result.put("calculation_complete", true);
        result.put("processed_users", orderedUserIds.size());
        result.put("per_user", perUserResults);
        ReportUtils.printReport("Decrypt", start, result);
        return result;
    }
}
