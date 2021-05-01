package at.andicover.lmots.api;

import at.andicover.common.api.KeySize;
import at.andicover.common.api.Storable;

import javax.annotation.Nonnull;

/**
 * Interface for the Winternitz LMOTS signature. Holds the signature keys.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-4">RFC 8554 - LM-OTS Signature</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
public interface LMOTSSignature extends Storable, KeySize {

    /**
     * @return All keys of the signature.
     */
    @Nonnull
    byte[][] getKeys();

    /**
     * @return an n-byte randomizer that is included with the message whenever it is being hashed to improve security.
     */
    @Nonnull
    byte[] getC();

    /**
     * @return the typecode of the used LMOTS parameter set.
     */
    @Nonnull
    LMOTSType getLmotsType();
}
