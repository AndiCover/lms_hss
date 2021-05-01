package at.andicover.hss.api;

import at.andicover.common.api.KeySize;
import at.andicover.common.api.Storable;
import at.andicover.lms.api.LMSPublicKey;

import javax.annotation.Nonnull;

/**
 * Interface for the HSS public key.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-6.1">RFC 8554 - HSS Key Generation</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
public interface HSSPublicKey extends Storable, KeySize {

    /**
     * @return the LMS levels.
     */
    int getLevels();

    /**
     * @return the LMS public key.
     */
    @Nonnull
    LMSPublicKey getPublicKey();
}
