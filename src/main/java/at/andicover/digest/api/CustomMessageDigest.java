package at.andicover.digest.api;

import javax.annotation.Nonnull;

/**
 * Custom message digest. Implementations are supposed to create one MessageDigest instance once.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
public interface CustomMessageDigest {

    /**
     * Standard SHA-256.
     */
    String SHA_256 = "SHA-256";

    /**
     * SHA-256 trimmed to 24 bytes.
     */
    String SHA_256_192 = "SHA-256/192";

    /**
     * Standard SHAKE-256.
     */
    String SHAKE_256 = "SHAKE256";

    /**
     * SHAKE-256 trimmed to 24 bytes.
     */
    String SHAKE_256_192 = "SHAKE256/192";

    /**
     * Performs the digest computation.
     *
     * @param message the message to hash.
     * @return the hashed message.
     */
    @Nonnull
    byte[] digest(@Nonnull byte[] message);
}
