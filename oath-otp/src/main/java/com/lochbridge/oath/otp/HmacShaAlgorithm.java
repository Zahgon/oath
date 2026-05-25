package com.lochbridge.oath.otp;

/**
 * Enumeration of HMAC-SHA algorithm types.
 */
public enum HmacShaAlgorithm {

    /**
     * {@code HmacSHA1}
     */
    HMAC_SHA_1("HmacSHA1"),
    /**
     * {@code HmacSHA256}
     */
    HMAC_SHA_256("HmacSHA256"),
    /**
     * {@code HmacSHA512}
     */
    HMAC_SHA_512("HmacSHA512");

    private final String algorithm;

    private HmacShaAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public static HmacShaAlgorithm from(String algorithm) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    /**
     * Return a string representation of this HMAC-SHA algorithm.
     */
    @Override
    public String toString() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }
}
