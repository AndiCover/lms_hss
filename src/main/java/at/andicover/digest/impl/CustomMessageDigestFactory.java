package at.andicover.digest.impl;

import at.andicover.digest.api.CustomMessageDigest;

import javax.annotation.Nonnull;
import java.security.NoSuchAlgorithmException;

/**
 * Factory to create the correct {@link CustomMessageDigest} according to the given algorithm.
 * Keeping the same instance for several iterations is a big performance improvement.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
final class CustomMessageDigestFactory {

    private CustomMessageDigestFactory() {
    }

    /**
     * Create a new {@link CustomMessageDigest} instance for the given algorithm.
     *
     * @param algorithm The hashing algorithm (SHA-256, SHA-256/192, SHAKE256, SHAKE256/192).
     * @return the new message digest instance.
     * @throws NoSuchAlgorithmException if the given algorithm does not exist.
     */
    @Nonnull
    public static CustomMessageDigest getDigest(@Nonnull final String algorithm) throws NoSuchAlgorithmException {
        switch (algorithm) {
            case "SHA-256":
                return new CustomSha256Digest(32);
            case "SHA-256/192":
                return new CustomSha256Digest(24);
            case "SHAKE256":
                return new CustomShakeDigest(32);
            case "SHAKE256/192":
                return new CustomShakeDigest(24);
            default:
                throw new NoSuchAlgorithmException(String.format("Algorithm '%s' not implemented", algorithm));
        }
    }
}
