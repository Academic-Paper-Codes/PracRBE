package pracrbe;

import common.AbstractPracRBEScheme;
import common.DemoSupport;
import common.SchemeCliOptions;

import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class PracRBEDemo {
    private PracRBEDemo() {
    }

    public static void main(String[] args) {
        SchemeCliOptions options = SchemeCliOptions.parse(args);
        runDemo(
                options.maxUsers(),
                options.registerCount(),
                options.targetId(),
                options.message().mod(AbstractPracRBEScheme.groupModulus()),
                options.seed()
        );
    }

    private static void runDemo(int maxUsers, int registerCount, Integer targetId, BigInteger message, int seed) {
        if (registerCount <= 0) {
            throw new IllegalArgumentException("register_count must be positive.");
        }
        if (registerCount > maxUsers) {
            throw new IllegalArgumentException("register_count cannot exceed max_users.");
        }

        PracRBE scheme = new PracRBE(maxUsers, seed);
        System.out.println();
        System.out.println("##### PracRBE Demo #####");
        System.out.printf(
                Locale.ROOT,
                "config: max_users=%d, register_count=%d, security_bits=%d, seed=%d%n",
                maxUsers,
                registerCount,
                AbstractPracRBEScheme.securityBits(),
                seed
        );

        List<Integer> activeUserIds = DemoSupport.buildActiveUserIds(maxUsers, registerCount, targetId);
        int decryptUserId = DemoSupport.selectDecryptUserId(activeUserIds, targetId);
        List<Integer> targetUserIds = Collections.singletonList(decryptUserId);
        scheme.setup();
        Map<String, Object> keygenOutput = scheme.keygen(activeUserIds);
        scheme.register(keygenOutput);
        Map<String, Object> updateOutput = scheme.update(targetUserIds, null);
        Map<String, Object> encryptionOutput = scheme.encrypt(targetUserIds, message);
        @SuppressWarnings("unchecked")
        Map<Integer, BigInteger> secretKeys = (Map<Integer, BigInteger>) keygenOutput.get("secret_keys");
        Map<Integer, BigInteger> decryptSecretKeys = DemoSupport.singleSecretKey(secretKeys, decryptUserId);
        Map<String, Object> decryptEncryptionOutput = DemoSupport.singleUserPerUserOutput(encryptionOutput, decryptUserId);
        Map<String, Object> decryptUpdateOutput = DemoSupport.singleUserPerUserOutput(updateOutput, decryptUserId);

        System.out.printf(Locale.ROOT, "decrypt_target_id=%d%n", decryptUserId);
        scheme.decrypt(decryptSecretKeys, decryptEncryptionOutput, decryptUpdateOutput);
    }
}
