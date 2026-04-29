package common;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.math.BigInteger;

public final class DemoSupport {
    private DemoSupport() {
    }

    public static List<Integer> buildActiveUserIds(int maxUsers, int registerCount, Integer targetId) {
        List<Integer> activeUserIds = new ArrayList<Integer>();
        for (int i = 0; i < registerCount; i++) {
            activeUserIds.add(i);
        }
        if (targetId != null) {
            if (targetId < 0 || targetId >= maxUsers) {
                throw new IllegalArgumentException("target_id must be in [0, " + (maxUsers - 1) + "].");
            }
            if (!activeUserIds.contains(targetId)) {
                activeUserIds.add(targetId);
                Collections.sort(activeUserIds);
            }
        }
        return activeUserIds;
    }

    public static int selectDecryptUserId(List<Integer> activeUserIds, Integer targetId) {
        if (targetId != null) {
            return targetId;
        }
        if (activeUserIds.isEmpty()) {
            throw new IllegalArgumentException("activeUserIds cannot be empty.");
        }
        return activeUserIds.get(0);
    }

    public static Map<Integer, BigInteger> singleSecretKey(Map<Integer, BigInteger> secretKeys, int userId) {
        BigInteger secretKey = secretKeys.get(userId);
        if (secretKey == null) {
            throw new IllegalArgumentException("Missing secret key for user_id=" + userId + ".");
        }

        Map<Integer, BigInteger> result = new LinkedHashMap<Integer, BigInteger>();
        result.put(userId, secretKey);
        return result;
    }

    public static Map<String, Object> singleUserPerUserOutput(Map<String, Object> output, int userId) {
        @SuppressWarnings("unchecked")
        Map<Integer, Map<String, Object>> perUser =
                (Map<Integer, Map<String, Object>>) output.get("per_user");
        Map<String, Object> selected = perUser.get(userId);
        if (selected == null) {
            throw new IllegalArgumentException("Missing per_user entry for user_id=" + userId + ".");
        }

        Map<Integer, Map<String, Object>> singlePerUser = new LinkedHashMap<Integer, Map<String, Object>>();
        singlePerUser.put(userId, selected);

        Map<String, Object> result = new LinkedHashMap<String, Object>(output);
        result.put("processed_users", 1);
        result.put("per_user", singlePerUser);
        return result;
    }
}
