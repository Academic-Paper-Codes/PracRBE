package common;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

public final class PairingBackedBilinearGroup {
    private final Pairing pairing;
    private final Field<?> g1Field;
    private final Field<?> g2Field;
    private final Field<?> gtField;
    private final Field<?> zrField;
    private final BigInteger order;
    private final Random scalarRandom;
    private final Element g1Base;
    private final Element g2Base;
    private final Element gtGenerator;
    private final Map<String, Integer> counters;
    private final Map<BigInteger, Element> g1Cache;
    private final Map<BigInteger, Element> g2Cache;
    private final Map<BigInteger, Element> gtCache;

    public PairingBackedBilinearGroup(int seed, Random scalarRandom) {
        PairingFactory.getInstance().setUsePBCWhenPossible(false);
        PairingFactory.getInstance().setReuseInstance(false);
        PairingFactory.getInstance().setImmutable(true);

        SecureRandom parameterRandom = createSeededSecureRandom(seed);
        PairingParameters parameters =
                new TypeACurveGenerator(parameterRandom, AbstractPracRBEScheme.SECURITY_BITS, AbstractPracRBEScheme.SECURITY_BITS * 2, false)
                        .generate();
        this.pairing = PairingFactory.getPairing(parameters);
        this.g1Field = pairing.getG1();
        this.g2Field = pairing.getG2();
        this.gtField = pairing.getGT();
        this.zrField = pairing.getZr();
        this.order = zrField.getOrder();
        this.scalarRandom = scalarRandom;
        this.g1Base = nonZeroRandomElement(g1Field);
        this.g2Base = pairing.isSymmetric() ? g1Base.duplicate().getImmutable() : nonZeroRandomElement(g2Field);
        this.gtGenerator = pairing.pairing(g1Base, g2Base).getImmutable();

        this.counters = new LinkedHashMap<String, Integer>();
        counters.put("sample_scalar", 0);
        counters.put("g_mul", 0);
        counters.put("g_pow", 0);
        counters.put("gt_mul", 0);
        counters.put("gt_div", 0);
        counters.put("gt_pow", 0);
        counters.put("pair", 0);
        counters.put("inverse", 0);
        counters.put("hash_h1", 0);
        counters.put("hash_h2", 0);

        this.g1Cache = new LinkedHashMap<BigInteger, Element>();
        this.g2Cache = new LinkedHashMap<BigInteger, Element>();
        this.gtCache = new LinkedHashMap<BigInteger, Element>();
        g1Cache.put(BigInteger.ZERO, g1Field.newZeroElement().getImmutable());
        g1Cache.put(BigInteger.ONE, g1Base);
        g2Cache.put(BigInteger.ZERO, g2Field.newZeroElement().getImmutable());
        g2Cache.put(BigInteger.ONE, g2Base);
        gtCache.put(BigInteger.ZERO, gtField.newOneElement().getImmutable());
        gtCache.put(BigInteger.ONE, gtGenerator);
    }

    public BigInteger getOrder() {
        return order;
    }

    public Map<String, Integer> getCounters() {
        return Collections.unmodifiableMap(counters);
    }

    public BigInteger sampleScalar() {
        incrementCounter("sample_scalar");
        BigInteger candidate;
        do {
            candidate = new BigInteger(order.bitLength(), scalarRandom);
        } while (candidate.signum() <= 0 || candidate.compareTo(order) >= 0);
        return candidate;
    }

    public BigInteger gIdentity() {
        return BigInteger.ZERO;
    }

    public BigInteger gtIdentity() {
        return BigInteger.ZERO;
    }

    public BigInteger gMul(BigInteger left, BigInteger right) {
        incrementCounter("g_mul");
        BigInteger normalizedLeft = canon(left);
        BigInteger normalizedRight = canon(right);
        BigInteger result = normalizedLeft.add(normalizedRight).mod(order);
        Element element = g1Point(normalizedLeft).duplicate().add(g1Point(normalizedRight)).getImmutable();
        g1Cache.put(result, element);
        return result;
    }

    public BigInteger gPow(BigInteger base, BigInteger exponent) {
        incrementCounter("g_pow");
        BigInteger normalizedBase = canon(base);
        BigInteger normalizedExponent = canon(exponent);
        BigInteger result = normalizedBase.multiply(normalizedExponent).mod(order);
        Element element = g1Point(normalizedBase).duplicate().powZn(zr(normalizedExponent)).getImmutable();
        g1Cache.put(result, element);
        return result;
    }

    public BigInteger gtMul(BigInteger left, BigInteger right) {
        incrementCounter("gt_mul");
        BigInteger normalizedLeft = canon(left);
        BigInteger normalizedRight = canon(right);
        BigInteger result = normalizedLeft.add(normalizedRight).mod(order);
        Element element = gtValue(normalizedLeft).duplicate().mul(gtValue(normalizedRight)).getImmutable();
        gtCache.put(result, element);
        return result;
    }

    public BigInteger gtDiv(BigInteger numerator, BigInteger denominator) {
        incrementCounter("gt_div");
        BigInteger normalizedNumerator = canon(numerator);
        BigInteger normalizedDenominator = canon(denominator);
        BigInteger result = normalizedNumerator.subtract(normalizedDenominator).mod(order);
        Element element = gtValue(normalizedNumerator).duplicate().div(gtValue(normalizedDenominator)).getImmutable();
        gtCache.put(result, element);
        return result;
    }

    public BigInteger gtPow(BigInteger base, BigInteger exponent) {
        incrementCounter("gt_pow");
        BigInteger normalizedBase = canon(base);
        BigInteger normalizedExponent = canon(exponent);
        BigInteger result = normalizedBase.multiply(normalizedExponent).mod(order);
        Element element = gtValue(normalizedBase).duplicate().powZn(zr(normalizedExponent)).getImmutable();
        gtCache.put(result, element);
        return result;
    }

    public BigInteger pair(BigInteger left, BigInteger right) {
        incrementCounter("pair");
        BigInteger normalizedLeft = canon(left);
        BigInteger normalizedRight = canon(right);
        BigInteger result = normalizedLeft.multiply(normalizedRight).mod(order);
        Element element = pairing.pairing(g1Point(normalizedLeft), g2Point(normalizedRight)).getImmutable();
        gtCache.put(result, element);
        return result;
    }

    public void countHashH1() {
        incrementCounter("hash_h1");
    }

    public void countHashH2() {
        incrementCounter("hash_h2");
    }

    public BigInteger inverseScalar(BigInteger value) {
        incrementCounter("inverse");
        BigInteger normalized = canon(value);
        if (normalized.signum() == 0) {
            throw new IllegalArgumentException("Cannot invert zero in Zr.");
        }
        return normalized.modInverse(order);
    }

    private static SecureRandom createSeededSecureRandom(int seed) {
        try {
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(BigInteger.valueOf(seed).toByteArray());
            return secureRandom;
        } catch (NoSuchAlgorithmException ex) {
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.setSeed(BigInteger.valueOf(seed).toByteArray());
            return secureRandom;
        }
    }

    private static Element nonZeroRandomElement(Field<?> field) {
        Element element = field.newRandomElement().getImmutable();
        while (element.isZero()) {
            element = field.newRandomElement().getImmutable();
        }
        return element;
    }

    private BigInteger canon(BigInteger value) {
        BigInteger normalized = value.mod(order);
        return normalized.signum() >= 0 ? normalized : normalized.add(order);
    }

    private Element zr(BigInteger value) {
        return zrField.newElement(canon(value)).getImmutable();
    }

    private Element g1Point(BigInteger exponent) {
        BigInteger key = canon(exponent);
        Element cached = g1Cache.get(key);
        if (cached == null) {
            cached = g1Base.duplicate().powZn(zr(key)).getImmutable();
            g1Cache.put(key, cached);
        }
        return cached;
    }

    private Element g2Point(BigInteger exponent) {
        BigInteger key = canon(exponent);
        Element cached = g2Cache.get(key);
        if (cached == null) {
            cached = g2Base.duplicate().powZn(zr(key)).getImmutable();
            g2Cache.put(key, cached);
        }
        return cached;
    }

    private Element gtValue(BigInteger exponent) {
        BigInteger key = canon(exponent);
        Element cached = gtCache.get(key);
        if (cached == null) {
            cached = gtGenerator.duplicate().powZn(zr(key)).getImmutable();
            gtCache.put(key, cached);
        }
        return cached;
    }

    private void incrementCounter(String name) {
        counters.put(name, counters.get(name) + 1);
    }
}
