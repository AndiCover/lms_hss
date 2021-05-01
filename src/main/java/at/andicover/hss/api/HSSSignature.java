package at.andicover.hss.api;

import at.andicover.common.api.KeySize;
import at.andicover.common.api.Storable;
import at.andicover.lms.api.LMSPublicKey;
import at.andicover.lms.api.LMSSignature;

import javax.annotation.Nonnull;

/**
 * Interface for the HSS signature.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-6.2">RFC 8554 - HSS Signature Generation</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
public interface HSSSignature extends Storable, KeySize {

    /**
     * @return the number of signed public keys.
     */
    int getNumberOfSignedPublicKeys();

    /**
     * @return the LMS signatures.
     */
    @Nonnull
    LMSSignature[] getSignatures();

    /**
     * @return the LMS public keys.
     */
    @Nonnull
    LMSPublicKey[] getLmsPublicKeys();
}
