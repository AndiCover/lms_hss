package at.andicover.hss.api;

import javax.annotation.Nonnull;

/**
 * Interface for the HSS key pair. Holds one private and one public key.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
public interface HSSKeyPair {

    /**
     * @return the HSS private key.
     */
    @Nonnull
    HSSPrivateKey getPrivateKey();

    /**
     * @return the HSS public key.
     */
    @Nonnull
    HSSPublicKey getPublicKey();
}
