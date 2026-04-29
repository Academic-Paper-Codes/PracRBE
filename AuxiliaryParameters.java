package common;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

public final class AuxiliaryParameters {
    private final List<List<BigInteger>> proofs;
    private final List<Map<BigInteger, List<BigInteger>>> history;

    public AuxiliaryParameters(List<List<BigInteger>> proofs, List<Map<BigInteger, List<BigInteger>>> history) {
        this.proofs = proofs;
        this.history = history;
    }

    public List<List<BigInteger>> proofs() {
        return proofs;
    }

    public List<Map<BigInteger, List<BigInteger>>> history() {
        return history;
    }
}
