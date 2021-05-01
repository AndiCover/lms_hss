package at.andicover.lms.api;

import at.andicover.common.api.KeySize;
import at.andicover.common.api.Storable;
import at.andicover.lmots.api.LMOTSSignature;

import javax.annotation.Nonnull;

/**
 * Interface for the Leighton-Micali-Signature.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-5.4">RFC 8554 - LMS Signature</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
public interface LMSSignature extends Storable, KeySize {

    /**
     * @return the typecode of the used LMS parameter set.
     */
    @Nonnull
    LMSType getLmsType();

    /**
     * @return the 16 byte identifier for the LMS public/private key pair.
     */
    int getQIdentifier();

    /**
     * @return the related LMOTS signature.
     */
    @Nonnull
    LMOTSSignature getLmotsSignature();

    /**
     * @return the calculated path to the tree root.
     */
    @Nonnull
    byte[][] getPath();
}
