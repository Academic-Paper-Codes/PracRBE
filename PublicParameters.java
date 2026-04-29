package common;

import java.math.BigInteger;
import java.util.List;

public final class PublicParameters {
    private final List<BigInteger> commitments;

    public PublicParameters(List<BigInteger> commitments) {
        this.commitments = commitments;
    }

    public List<BigInteger> commitments() {
        return commitments;
    }
}
