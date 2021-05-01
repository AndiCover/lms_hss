package at.andicover.lms.api;

import at.andicover.common.api.KeySize;
import at.andicover.common.api.Storable;
import at.andicover.lmots.api.LMOTSType;

import javax.annotation.Nonnull;

/**
 * Interface for the Leighton-Micali-Signature public key.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-5.3">RFC 8554 - LMS Public Key</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
public interface LMSPublicKey extends Storable, KeySize {

    /**
     * @return the typecode of the used LMS parameter set.
     */
    @Nonnull
    LMSType getLmsType();

    /**
     * @return the typecode of the used LMOTS parameter set.
     */
    @Nonnull
    LMOTSType getLmotsType();

    /**
     * @return the 16 byte identifier for the LMS public/private key pair.
     */
    @Nonnull
    byte[] getIdentifier();

    /**
     * @return the calculated LMS public key.
     */
    @Nonnull
    byte[] getKey();
}
