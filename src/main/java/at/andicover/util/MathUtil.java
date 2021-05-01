package at.andicover.util;

/**
 * Utility class for some calculations.
 */
public final class MathUtil {

    private MathUtil() {
    }

    /**
     * Calculates the 2 to the power of n.
     * Note: Does not perform any range checks.
     *
     * @param n the exponent.
     * @return the result 2^n.
     */
    public static int pow(final int n) {
        return 1 << n;
    }
}
