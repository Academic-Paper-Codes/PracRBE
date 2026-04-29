package common;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

public abstract class AbstractPracRBEScheme {
    protected static final int SECURITY_BITS = 256;
    protected static final BigInteger GROUP_MODULUS =
            BigInteger.ONE.shiftLeft(SECURITY_BITS).subtract(BigInteger.valueOf(189L));

    protected final int maxUsers;
    protected final int securityBits;
    protected final Random random;
    protected final PairingBackedBilinearGroup group;
    protected final BigInteger g;
    protected final int n;
    protected List<BigInteger> h;
    protected Map<String, Object> crs;
    protected PublicParameters pp;
    protected AuxiliaryParameters aux;
    protected final Set<Integer> registeredIds;

    protected AbstractPracRBEScheme(int maxUsers, int seed) {
        if (maxUsers <= 0) {
            throw new IllegalArgumentException("max_users must be positive.");
        }
        this.maxUsers = maxUsers;
        this.securityBits = SECURITY_BITS;
        this.random = new Random(seed);
        this.group = new PairingBackedBilinearGroup(seed, random);
        this.g = BigInteger.ONE;
        this.n = ceilSqrt(maxUsers);
        this.h = new ArrayList<BigInteger>();
        this.crs = null;
        this.pp = null;
        this.aux = null;
        this.registeredIds = new LinkedHashSet<Integer>();
    }

    public static BigInteger groupModulus() {
        return GROUP_MODULUS;
    }

    public static int securityBits() {
        return SECURITY_BITS;
    }

    public Map<String, Object> setup() {
        long start = System.nanoTime();

        h = new ArrayList<BigInteger>(n + 1);
        h.add(BigInteger.ZERO);
        for (int i = 1; i <= n; i++) {
            h.add(group.sampleScalar());
        }

        List<BigInteger> commitments = filledBigIntegerList(n + 1, group.gIdentity());
        List<List<BigInteger>> proofs = new ArrayList<List<BigInteger>>(n + 1);
        for (int i = 0; i <= n; i++) {
            proofs.add(filledBigIntegerList(n + 1, group.gIdentity()));
        }

        List<Map<BigInteger, List<BigInteger>>> history = new ArrayList<Map<BigInteger, List<BigInteger>>>(n + 1);
        history.add(new LinkedHashMap<BigInteger, List<BigInteger>>());
        for (int groupIndex = 1; groupIndex <= n; groupIndex++) {
            Map<BigInteger, List<BigInteger>> rowHistory = new LinkedHashMap<BigInteger, List<BigInteger>>();
            rowHistory.put(commitments.get(groupIndex), immutableBigIntegerList(proofs.get(groupIndex)));
            history.add(rowHistory);
        }

        this.pp = new PublicParameters(commitments);
        this.aux = new AuxiliaryParameters(proofs, history);

        Map<String, Object> currentCrs = new LinkedHashMap<String, Object>();
        currentCrs.put("modulus", group.getOrder());
        currentCrs.put("generator_g", g);
        currentCrs.put("n", n);
        currentCrs.put("N", maxUsers);
        currentCrs.put("security_bits", securityBits);
        this.crs = currentCrs;

        Map<String, Object> result = new LinkedHashMap<String, Object>();
        result.put("calculation_complete", true);
        result.put("crs", currentCrs);
        result.put("commitment_slots", commitments.size() - 1);
        result.put("proof_matrix_shape", listOfIntegers(n, n));
        ReportUtils.printReport("Setup", start, result);
        return result;
    }

    public Map<String, Object> keygen(List<Integer> userIds) {
        requireSetup();
        long start = System.nanoTime();

        List<Integer> orderedUserIds = normalizeUserIds(userIds);
        Map<Integer, BigInteger> secretKeys = new LinkedHashMap<Integer, BigInteger>();
        Map<Integer, Map<String, Object>> rawOutputs = new LinkedHashMap<Integer, Map<String, Object>>();
        for (Integer userId : orderedUserIds) {
            Map<String, Object> singleOutput = keygenSingle(userId);
            secretKeys.put(userId, (BigInteger) singleOutput.get("secret_key"));
            rawOutputs.put(userId, singleOutput);
        }

        Map<String, Object> summary = new LinkedHashMap<String, Object>();
        for (Integer userId : orderedUserIds) {
            int[] location = locate(userId);
            @SuppressWarnings("unchecked")
            Map<Integer, BigInteger> crossTerms = (Map<Integer, BigInteger>) rawOutputs.get(userId).get("cross_terms");
            Map<String, Object> summaryRow = new LinkedHashMap<String, Object>();
            summaryRow.put("group_index", location[0]);
            summaryRow.put("position", location[1]);
            summaryRow.put("cross_terms_count", crossTerms.size());
            summary.put(String.valueOf(userId), summaryRow);
        }

        Map<String, Object> result = new LinkedHashMap<String, Object>();
        result.put("calculation_complete", true);
        result.put("processed_users", orderedUserIds.size());
        result.put("user_ids", orderedUserIds);
        result.put("secret_keys", secretKeys);
        result.put("raw_outputs", rawOutputs);
        result.put("summary", summary);
        ReportUtils.printReport("KeyGen", start, result);
        return result;
    }

    public Map<String, Object> register(Map<String, Object> keygenOutput) {
        requireSetup();
        long start = System.nanoTime();

        @SuppressWarnings("unchecked")
        List<Integer> userIds = (List<Integer>) keygenOutput.get("user_ids");
        @SuppressWarnings("unchecked")
        Map<Integer, Map<String, Object>> rawOutputs = (Map<Integer, Map<String, Object>>) keygenOutput.get("raw_outputs");

        List<Integer> orderedUserIds = normalizeUserIds(userIds);
        Map<Integer, Map<String, Object>> perUserResults = new LinkedHashMap<Integer, Map<String, Object>>();
        int appliedCount = 0;

        for (Integer userId : orderedUserIds) {
            Map<String, Object> singleOutput = rawOutputs.get(userId);
            int[] location = locate(userId);
            int groupIndex = location[0];
            int hiddenPosition = location[1];
            BigInteger gToX = (BigInteger) singleOutput.get("g_to_x");
            @SuppressWarnings("unchecked")
            Map<Integer, BigInteger> crossTerms = new LinkedHashMap<Integer, BigInteger>(
                    (Map<Integer, BigInteger>) singleOutput.get("cross_terms")
            );

            boolean duplicateRequest = registeredIds.contains(userId);
            boolean verified = true;
            int verificationChecks = 0;
            for (int position = 1; position <= n; position++) {
                if (position == hiddenPosition) {
                    continue;
                }
                verificationChecks++;
                BigInteger lhs = group.pair(gToX, h.get(position));
                BigInteger rhs = group.pair(g, crossTerms.get(position));
                if (!lhs.equals(rhs)) {
                    verified = false;
                }
            }

            BigInteger candidateCommitment = group.gMul(pp.commitments().get(groupIndex), gToX);
            List<BigInteger> candidateProofs = new ArrayList<BigInteger>(aux.proofs().get(groupIndex));
            int updatedPositions = 0;
            for (int position = 1; position <= n; position++) {
                if (position == hiddenPosition) {
                    continue;
                }
                BigInteger nextProof = group.gMul(candidateProofs.get(position), crossTerms.get(position));
                candidateProofs.set(position, nextProof);
                updatedPositions++;
            }

            boolean stateApplied = verified && !duplicateRequest;
            if (stateApplied) {
                pp.commitments().set(groupIndex, candidateCommitment);
                aux.proofs().set(groupIndex, candidateProofs);
                aux.history().get(groupIndex).put(candidateCommitment, immutableBigIntegerList(candidateProofs));
                registeredIds.add(userId);
                appliedCount++;
            }

            Map<String, Object> userResult = new LinkedHashMap<String, Object>();
            userResult.put("user_id", userId);
            userResult.put("verified", verified);
            userResult.put("duplicate_request", duplicateRequest);
            userResult.put("state_applied", stateApplied);
            userResult.put("group_index", groupIndex);
            userResult.put("verification_checks", verificationChecks);
            userResult.put("updated_positions", updatedPositions);
            userResult.put("current_commitment", pp.commitments().get(groupIndex));
            userResult.put("history_versions_for_group", aux.history().get(groupIndex).size());
            perUserResults.put(userId, userResult);
        }

        Map<String, Object> result = new LinkedHashMap<String, Object>();
        result.put("calculation_complete", true);
        result.put("processed_users", orderedUserIds.size());
        result.put("applied_count", appliedCount);
        result.put("per_user", perUserResults);
        ReportUtils.printReport("Register", start, result);
        return result;
    }

    public Map<String, Object> update(List<Integer> userIds, Map<Integer, BigInteger> commitmentMap) {
        requireSetup();
        long start = System.nanoTime();

        List<Integer> orderedUserIds = normalizeUserIds(userIds);
        Map<Integer, BigInteger> normalizedCommitmentMap =
                commitmentMap == null ? new LinkedHashMap<Integer, BigInteger>() : new LinkedHashMap<Integer, BigInteger>(commitmentMap);
        Map<Integer, Map<String, Object>> perUserUpdates = new LinkedHashMap<Integer, Map<String, Object>>();

        for (Integer userId : orderedUserIds) {
            int[] location = locate(userId);
            int groupIndex = location[0];
            int position = location[1];
            BigInteger commitment = normalizedCommitmentMap.containsKey(userId)
                    ? normalizedCommitmentMap.get(userId)
                    : pp.commitments().get(groupIndex);
            BigInteger proof = proofFromHistory(groupIndex, position, commitment);

            Map<String, Object> updateRow = new LinkedHashMap<String, Object>();
            updateRow.put("user_id", userId);
            updateRow.put("group_index", groupIndex);
            updateRow.put("position", position);
            updateRow.put("commitment", commitment);
            updateRow.put("proof", proof);
            perUserUpdates.put(userId, updateRow);
        }

        Map<String, Object> result = new LinkedHashMap<String, Object>();
        result.put("calculation_complete", true);
        result.put("processed_users", orderedUserIds.size());
        result.put("per_user", perUserUpdates);
        ReportUtils.printReport("Update", start, result);
        return result;
    }

    public abstract Map<String, Object> encrypt(List<Integer> userIds, BigInteger message);

    public abstract Map<String, Object> decrypt(
            Map<Integer, BigInteger> secretKeys,
            Map<String, Object> encryptionOutput,
            Map<String, Object> updateOutput
    );

    protected Map<String, Object> keygenSingle(int userId) {
        int[] location = locate(userId);
        int hiddenPosition = location[1];
        BigInteger secretKey = group.sampleScalar();
        BigInteger gToX = group.gPow(g, secretKey);
        Map<Integer, BigInteger> crossTerms = new LinkedHashMap<Integer, BigInteger>();
        for (int position = 1; position <= n; position++) {
            if (position == hiddenPosition) {
                continue;
            }
            crossTerms.put(position, group.gPow(h.get(position), secretKey));
        }

        Map<String, Object> output = new LinkedHashMap<String, Object>();
        output.put("user_id", userId);
        output.put("secret_key", secretKey);
        output.put("g_to_x", gToX);
        output.put("cross_terms", crossTerms);
        return output;
    }

    protected BigInteger proofFromHistory(int groupIndex, int position, BigInteger commitment) {
        requireSetup();
        List<BigInteger> proofRow = aux.history().get(groupIndex).get(commitment);
        if (proofRow == null) {
            return aux.proofs().get(groupIndex).get(position);
        }
        return proofRow.get(position);
    }

    protected void requireSetup() {
        if (crs == null || pp == null || aux == null) {
            throw new IllegalStateException("setup() must be called first.");
        }
    }

    protected int[] locate(int userId) {
        if (userId < 0 || userId >= maxUsers) {
            throw new IllegalArgumentException("user_id must be in [0, " + (maxUsers - 1) + "].");
        }
        int groupIndex = userId / n + 1;
        int position = userId % n + 1;
        return new int[]{groupIndex, position};
    }

    protected List<Integer> normalizeUserIds(List<Integer> userIds) {
        List<Integer> ordered = new ArrayList<Integer>();
        Set<Integer> seen = new LinkedHashSet<Integer>();
        for (Integer userId : userIds) {
            locate(userId);
            if (seen.add(userId)) {
                ordered.add(userId);
            }
        }
        return ordered;
    }

    protected static int ceilSqrt(int value) {
        int root = (int) Math.sqrt(value);
        if (root * root < value) {
            root++;
        }
        return root;
    }

    protected static List<BigInteger> filledBigIntegerList(int size, BigInteger value) {
        List<BigInteger> result = new ArrayList<BigInteger>(size);
        for (int i = 0; i < size; i++) {
            result.add(value);
        }
        return result;
    }

    protected static List<Integer> listOfIntegers(int... values) {
        List<Integer> result = new ArrayList<Integer>(values.length);
        for (int value : values) {
            result.add(value);
        }
        return result;
    }

    protected static List<BigInteger> immutableBigIntegerList(List<BigInteger> values) {
        return Collections.unmodifiableList(new ArrayList<BigInteger>(values));
    }
}
