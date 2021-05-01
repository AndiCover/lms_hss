package at.andicover.lms.api;

import javax.annotation.Nonnull;

import static at.andicover.digest.api.CustomMessageDigest.SHAKE_256;
import static at.andicover.digest.api.CustomMessageDigest.SHAKE_256_192;
import static at.andicover.digest.api.CustomMessageDigest.SHA_256;
import static at.andicover.digest.api.CustomMessageDigest.SHA_256_192;

/**
 * Predefined LMS parameters.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-5.1">RFC 8554 - LMS Parameters</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
public enum LMSType {

    LMS_SHA256_M32_H5(5, SHA_256, 32, 5),
    LMS_SHA256_M32_H10(6, SHA_256, 32, 10),
    LMS_SHA256_M32_H15(7, SHA_256, 32, 15),
    LMS_SHA256_M32_H20(8, SHA_256, 32, 20),
    LMS_SHA256_M32_H25(9, SHA_256, 32, 25),

    LMS_SHA256_M24_H5(10, SHA_256_192, 24, 5),
    LMS_SHA256_M24_H10(11, SHA_256_192, 24, 10),
    LMS_SHA256_M24_H15(12, SHA_256_192, 24, 15),
    LMS_SHA256_M24_H20(13, SHA_256_192, 24, 20),
    LMS_SHA256_M24_H25(14, SHA_256_192, 24, 25),

    LMS_SHAKE_M32_H5(15, SHAKE_256, 32, 5),
    LMS_SHAKE_M32_H10(16, SHAKE_256, 32, 10),
    LMS_SHAKE_M32_H15(17, SHAKE_256, 32, 15),
    LMS_SHAKE_M32_H20(18, SHAKE_256, 32, 20),
    LMS_SHAKE_M32_H25(19, SHAKE_256, 32, 25),

    LMS_SHAKE_M24_H5(20, SHAKE_256_192, 24, 5),
    LMS_SHAKE_M24_H10(21, SHAKE_256_192, 24, 10),
    LMS_SHAKE_M24_H15(22, SHAKE_256_192, 24, 15),
    LMS_SHAKE_M24_H20(23, SHAKE_256_192, 24, 20),
    LMS_SHAKE_M24_H25(24, SHAKE_256_192, 24, 25);

    private final int typecode;
    private final String hashAlgorithm;
    private final int m;
    private final int h;

    /**
     * @param typecode      Typecode of the parameter set.
     * @param hashAlgorithm a second-preimage-resistant cryptographic hash function that accepts byte strings of any
     *                      length and returns an m-byte string.
     * @param m:            the number of bytes associated with each node.
     * @param h:            the height of the tree.
     */
    LMSType(final int typecode, final String hashAlgorithm, final int m, final int h) {
        this.typecode = typecode;
        this.hashAlgorithm = hashAlgorithm;
        this.m = m;
        this.h = h;
    }

    /**
     * Lookup the parameter set by its typecode.
     *
     * @param typecode of the parameter set retrieved from the private/public key.
     * @return the parameter set.
     */
    @Nonnull
    public static LMSType lookUp(final int typecode) {
        for (final LMSType parameters : LMSType.values()) {
            if (parameters.typecode == typecode) {
                return parameters;
            }
        }
        throw new IllegalArgumentException("Invalid typecode: " + typecode);
    }

    /**
     * @return typecode of the parameter set.
     */
    public int getTypecode() {
        return typecode;
    }

    /**
     * @return a second-preimage-resistant cryptographic hash function that accepts byte strings of any
     * length and returns an m-byte string.
     */
    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * @return the number of bytes associated with each node.
     */
    public int getM() {
        return m;
    }

    /**
     * @return the height of the tree.
     */
    public int getH() {
        return h;
    }
}
