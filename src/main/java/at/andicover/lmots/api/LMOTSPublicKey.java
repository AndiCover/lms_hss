package at.andicover.lmots.api;

import at.andicover.common.api.KeySize;
import at.andicover.common.api.Storable;

import javax.annotation.Nonnull;

/**
 * Interface for the Winternitz LMOTS public key. Holds the public keys.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-4.3">RFC 8554 - LM-OTS Public Key</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
public interface LMOTSPublicKey extends Storable, KeySize {

    /**
     * @return the public key K.
     */
    @Nonnull
    byte[] getKey();

    /**
     * @return the 16 byte identifier for the LMS public/private key pair.
     */
    @Nonnull
    byte[] getIdentifier();

    /**
     * @return the leaf number q of the hash tree.
     */
    int getQIdentifier();

    /**
     * @return the typecode of the used LMOTS parameter set.
     */
    @Nonnull
    LMOTSType getLmotsType();
}
