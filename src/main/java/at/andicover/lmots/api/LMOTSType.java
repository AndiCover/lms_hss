package at.andicover.lmots.api;

import javax.annotation.Nonnull;

import static at.andicover.digest.api.CustomMessageDigest.SHAKE_256;
import static at.andicover.digest.api.CustomMessageDigest.SHAKE_256_192;
import static at.andicover.digest.api.CustomMessageDigest.SHA_256;
import static at.andicover.digest.api.CustomMessageDigest.SHA_256_192;

/**
 * Predefined LMOTS parameters.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-4.1">RFC 8554 - LM-OTS Parameters</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
public enum LMOTSType {

    LMOTS_SHA256_N32_W1(1, SHA_256, 32, 1, 265),
    LMOTS_SHA256_N32_W2(2, SHA_256, 32, 2, 133),
    LMOTS_SHA256_N32_W4(3, SHA_256, 32, 4, 67),
    LMOTS_SHA256_N32_W8(4, SHA_256, 32, 8, 34),

    LMOTS_SHA256_N24_W1(5, SHA_256_192, 24, 1, 200),
    LMOTS_SHA256_N24_W2(6, SHA_256_192, 24, 2, 101),
    LMOTS_SHA256_N24_W4(7, SHA_256_192, 24, 4, 51),
    LMOTS_SHA256_N24_W8(8, SHA_256_192, 24, 8, 26),

    LMOTS_SHAKE_N32_W1(9, SHAKE_256, 32, 1, 265),
    LMOTS_SHAKE_N32_W2(10, SHAKE_256, 32, 2, 133),
    LMOTS_SHAKE_N32_W4(11, SHAKE_256, 32, 4, 67),
    LMOTS_SHAKE_N32_W8(12, SHAKE_256, 32, 8, 34),

    LMOTS_SHAKE_N24_W1(13, SHAKE_256_192, 24, 1, 200),
    LMOTS_SHAKE_N24_W2(14, SHAKE_256_192, 24, 2, 101),
    LMOTS_SHAKE_N24_W4(15, SHAKE_256_192, 24, 4, 51),
    LMOTS_SHAKE_N24_W8(16, SHAKE_256_192, 24, 8, 26);

    private final int typecode;
    private final String hashAlgorithm;
    private final int n;
    private final int w;
    private final int p;
    private final int ls;

    /**
     * @param typecode      Typecode of the parameter set.
     * @param hashAlgorithm a second-preimage-resistant cryptographic hash function that accepts byte strings
     *                      of any length and returns an n-byte string.
     * @param n             the number of bytes of the output of the hash function.
     * @param w             the width (in bits) of the Winternitz coefficients; that is,
     *                      the number of bits from the hash or checksum that is used with a
     *                      single Winternitz chain.  It is a member of the set
     *                      { 1, 2, 4, 8 }.
     * @param p             the number of n-byte string elements that make up the LM-LMOTS signature.
     */
    LMOTSType(final int typecode, final String hashAlgorithm, final int n, final int w, final int p) {
        this.typecode = typecode;
        this.hashAlgorithm = hashAlgorithm;
        this.n = n;
        this.w = w;
        this.p = p;

        final int u = (int) Math.ceil(8d * n / w);
        final int v = (int) Math.ceil((Math.floor(Math.log(((1 << w) - 1) * u) / Math.log(2)) + 1) / w);
        this.ls = 16 - (v * w);
    }

    /**
     * Lookup the parameter set by its typecode.
     *
     * @param typecode of the parameter set retrieved from the private/public key.
     * @return the parameter set.
     */
    @Nonnull
    public static LMOTSType lookUp(final int typecode) {
        for (final LMOTSType parameters : LMOTSType.values()) {
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

    public String getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    /**
     * @return the number of bytes of the output of the hash function.
     */
    public int getN() {
        return this.n;
    }

    /**
     * @return the width (in bits) of the Winternitz coefficients; that is,
     * the number of bits from the hash or checksum that is used with a
     * single Winternitz chain.  It is a member of the set
     * { 1, 2, 4, 8 }.
     */
    public int getW() {
        return w;
    }

    /**
     * @return the number of n-byte string elements that make up the LM-LMOTS signature.
     */
    public int getP() {
        return p;
    }

    /**
     * @return the number of left-shift bits used in the checksum function Cksm.
     */
    public int getLs() {
        return ls;
    }
}
