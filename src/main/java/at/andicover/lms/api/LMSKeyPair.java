package at.andicover.lms.api;

import javax.annotation.Nonnull;

/**
 * Interface for the LMS key pair. Holds one private and one public key.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
public interface LMSKeyPair {

    /**
     * @return the LMS private key.
     */
    @Nonnull
    LMSPrivateKey getPrivateKey();

    /**
     * @return the LMS public key.
     */
    @Nonnull
    LMSPublicKey getPublicKey();
}
