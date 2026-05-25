package com.lochbridge.oath.otp;

/**
 * Class which represents a Time-based One-time Password as per RFC 6238.
 * <p>
 * Refer to {@link TOTPBuilder} on how to generate a {@code TOTP}.
 * </p>
 *
 * @see <a href="https://tools.ietf.org/html/rfc6238">RFC 6238</a>
 */
public final class TOTP {

    private final String value;

    private final long time;

    private final HmacShaAlgorithm hmacShaAlgorithm;

    private final int digits;

    private final long timeStep;

    /**
     * Creates a new instance of a Time-based one time password. Use the static
     * method to obtain a {@link TOTPBuilder} instance and obtain a {@code TOTP}
     * from that. Note that all parameters are assumed to be valid since the
     * {@link TOTPBuilder} is responsible for validation, and creation of
     * {@link TOTP}s.
     *
     * @param code
     *            the time-based one time password
     * @param time
     *            the time (in milliseconds)
     * @param hmacShaAlgorithm
     *            the {@link HmacShaAlgorithm}
     * @param digits
     *            the number of digits the generated TOTP value contains
     * @param timeStep
     *            the time step size (in milliseconds)
     */
    TOTP(String value, long time, HmacShaAlgorithm hmacShaAlgorithm, int digits, long timeStep) {
        this.value = value;
        this.time = time;
        this.hmacShaAlgorithm = hmacShaAlgorithm;
        this.digits = digits;
        this.timeStep = timeStep;
    }

    /**
     * Returns a new {@link TOTPBuilder} instance initialized with the specified
     * {@code key}.
     *
     * @param key
     *            the shared secret key
     *
     * @return a new {@link TOTPBuilder} instance.
     *
     * @throws NullPointerException
     *             if {@code key} is {@code null}.
     */
    public static TOTPBuilder key(byte[] key) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    /**
     * Returns the time-based one time password value.
     *
     * @return the time-based one time password value.
     */
    public String value() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    /**
     * Returns the time (in milliseconds) used to generate this {@code TOTP}.
     *
     * @return the time (in milliseconds) used to generate this {@code TOTP}.
     */
    public long time() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    /**
     * Returns the {@link HmacShaAlgorithm} used to generate this {@code TOTP}.
     *
     * @return the {@link HmacShaAlgorithm} used to generate this {@code TOTP}.
     */
    public HmacShaAlgorithm hmacShaAlgorithm() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    /**
     * Returns the number of digits of this {@code TOTP}.
     *
     * @return the number of digits of this {@code TOTP}.
     */
    public int digits() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    /**
     * Returns the time step size (in milliseconds) used to generate this
     * {@code TOTP}.
     *
     * @return the time step size (in milliseconds) used to generate this
     *         {@code TOTP}.
     */
    public long timeStep() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object obj) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }
}
