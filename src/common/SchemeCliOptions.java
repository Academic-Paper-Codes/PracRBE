package common;

import java.math.BigInteger;

public final class SchemeCliOptions {
    private final int maxUsers;
    private final int registerCount;
    private final Integer targetId;
    private final BigInteger message;
    private final int seed;
    private final int arity;
    private final int nonmemberCount;

    private SchemeCliOptions(
            int maxUsers,
            int registerCount,
            Integer targetId,
            BigInteger message,
            int seed,
            int arity,
            int nonmemberCount
    ) {
        this.maxUsers = maxUsers;
        this.registerCount = registerCount;
        this.targetId = targetId;
        this.message = message;
        this.seed = seed;
        this.arity = arity;
        this.nonmemberCount = nonmemberCount;
    }

    public int maxUsers() {
        return maxUsers;
    }

    public int registerCount() {
        return registerCount;
    }

    public Integer targetId() {
        return targetId;
    }

    public BigInteger message() {
        return message;
    }

    public int seed() {
        return seed;
    }

    public int arity() {
        return arity;
    }

    public int nonmemberCount() {
        return nonmemberCount;
    }

    public static SchemeCliOptions parse(String[] args) {
        int maxUsers = 1;
        int registerCount = 1;
        Integer targetId = null;
        BigInteger message = BigInteger.valueOf(2026L);
        int seed = 20260421;
        int arity = 2;
        int nonmemberCount = 0;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (!arg.startsWith("--")) {
                throw new IllegalArgumentException("Unknown argument: " + arg);
            }
            if (i + 1 >= args.length) {
                throw new IllegalArgumentException("Missing value for argument: " + arg);
            }
            String value = args[++i];
            if ("--max-users".equals(arg)) {
                maxUsers = Integer.parseInt(value);
            } else if ("--register-count".equals(arg)) {
                registerCount = Integer.parseInt(value);
            } else if ("--target-id".equals(arg)) {
                targetId = Integer.parseInt(value);
            } else if ("--message".equals(arg)) {
                message = new BigInteger(value);
            } else if ("--seed".equals(arg)) {
                seed = Integer.parseInt(value);
            } else if ("--arity".equals(arg)) {
                arity = Integer.parseInt(value);
            } else if ("--nonmember-count".equals(arg)) {
                nonmemberCount = Integer.parseInt(value);
            } else {
                throw new IllegalArgumentException("Unknown argument: " + arg);
            }
        }
        return new SchemeCliOptions(maxUsers, registerCount, targetId, message, seed, arity, nonmemberCount);
    }
}
