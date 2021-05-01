package at.andicover.util;

import at.andicover.lmots.api.LMOTSType;
import at.andicover.lms.api.LMSType;

import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;

/**
 * Utility class for calculating key and signature sizes.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
public final class KeySizeUtil {

    private KeySizeUtil() {
    }

    /**
     * Calculates the size of a 2D byte array.
     *
     * @param array the given 2D byte array.
     * @return the size of the array.
     */
    public static int getByteArraySize(@Nonnull final byte[][] array) {
        final int rows = array.length;

        if (rows == 0) {
            return 0;
        }

        return rows * array[0].length;
    }

    /**
     * Calculates the LM-OTS private key size according to the given parameters.
     *
     * @param lmotsType the LM-OTS parameters.
     * @return the private key size.
     */
    public static long getOtsPrivateKeySize(@Nonnull final LMOTSType lmotsType) {
        requireNonNull(lmotsType);

        return 24L + lmotsType.getN();
    }

    /**
     * Calculates the LM-OTS public key size according to the given parameters.
     *
     * @param lmotsType the LM-OTS parameters.
     * @return the public key size.
     */
    public static long getOtsPublicKeySize(@Nonnull final LMOTSType lmotsType) {
        requireNonNull(lmotsType);

        return 24L + lmotsType.getN();
    }

    /**
     * Calculates the LM-OTS signature size according to the given parameters.
     *
     * @param lmotsType the LM-OTS parameters.
     * @return the signature size.
     */
    public static long getOtsSignatureSize(@Nonnull final LMOTSType lmotsType) {
        requireNonNull(lmotsType);

        return 4L + lmotsType.getN() + ((long) lmotsType.getN() * lmotsType.getP());
    }

    /**
     * Calculates the LMS private key size according to the given parameters.
     *
     * @param lmotsType the LM-OTS parameters.
     * @param lmsType   the LMS parameters.
     * @return the private key size.
     */
    public static long getLmsPrivateKeySize(@Nonnull final LMOTSType lmotsType, @Nonnull final LMSType lmsType) {
        requireNonNull(lmotsType);
        requireNonNull(lmsType);

        final long lmotsPrivateKeySize = getOtsPrivateKeySize(lmotsType);
        return 28L + MathUtil.pow(lmsType.getH()) * lmotsPrivateKeySize;
    }

    /**
     * Calculates the LMS public key size according to the given parameters.
     *
     * @param lmotsType the LM-OTS parameters.
     * @param lmsType   the LMS parameters.
     * @return the public key size.
     */
    public static long getLmsPublicKeySize(@Nonnull final LMOTSType lmotsType, @Nonnull final LMSType lmsType) {
        requireNonNull(lmotsType);
        requireNonNull(lmsType);

        return 24L + lmsType.getM();
    }

    /**
     * Calculates the LMS signature size according to the given parameters.
     *
     * @param lmotsType the LM-OTS parameters.
     * @param lmsType   the LMS parameters.
     * @return the siganture size.
     */
    public static long getLmsSignatureSize(@Nonnull final LMOTSType lmotsType, @Nonnull final LMSType lmsType) {
        requireNonNull(lmotsType);
        requireNonNull(lmsType);

        final long lmotsSignatureSize = getOtsSignatureSize(lmotsType);
        return 8L + lmotsSignatureSize + ((long) lmsType.getH() * lmsType.getM());
    }

    /**
     * Caclulates the HSS private key size according to the given parameters.
     *
     * @param lmotsType the LM-OTS parameters.
     * @param lmsType   the LMS parameters.
     * @param level     the HSS levels.
     * @return the private key size.
     */
    public static long getHssPrivateKeySize(@Nonnull final LMOTSType lmotsType, @Nonnull final LMSType lmsType,
                                           final int level) {
        requireNonNull(lmotsType);
        requireNonNull(lmsType);

        final long lmsPrivateKeySize = getLmsPrivateKeySize(lmotsType, lmsType);
        final long lmsPublicKeySize = getLmsPublicKeySize(lmotsType, lmsType);
        final long lmsSignatureSize = getLmsSignatureSize(lmotsType, lmsType);

        return 4 + (level * lmsPrivateKeySize) + (level * lmsPublicKeySize) + (level * lmsSignatureSize);
    }

    /**
     * Calculates the HSS public key size according to the given parameters.
     *
     * @param lmotsType the LM-OTS parameters.
     * @param lmsType   the LMS parameters.
     * @param level     the HSS levels.
     * @return the public key size.
     */
    public static long getHssPublicKeySize(@Nonnull final LMOTSType lmotsType, @Nonnull final LMSType lmsType,
                                          final int level) {
        requireNonNull(lmotsType);
        requireNonNull(lmsType);

        return 4L + getLmsPublicKeySize(lmotsType, lmsType);
    }

    /**
     * Calculates the HSS signature size according to the given parameters.
     *
     * @param lmotsType the LM-OTS parameters.
     * @param lmsType   the LMS parameters.
     * @param level     the HSS levels.
     * @return the signature size.
     */
    public static long getHssSignatureSize(@Nonnull final LMOTSType lmotsType, @Nonnull final LMSType lmsType,
                                          final int level) {
        requireNonNull(lmotsType);
        requireNonNull(lmsType);

        final long lmsPublicKeySize = getLmsPublicKeySize(lmotsType, lmsType);
        final long lmsSignatureSize = getLmsSignatureSize(lmotsType, lmsType);

        return 4L + ((level - 1) * lmsPublicKeySize) + (level * lmsSignatureSize);
    }
}
