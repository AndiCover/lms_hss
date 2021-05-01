package at.andicover.digest.impl;

import at.andicover.digest.api.CustomMessageDigest;
import org.apache.commons.lang3.ArrayUtils;

import javax.annotation.Nonnull;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA-256 implementation with customized output length. Internally uses {@link MessageDigest} and trims
 * the output to the defined length.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
@SuppressWarnings("PMD.AvoidMessageDigestField")
final class CustomSha256Digest implements CustomMessageDigest {

    private static final String SHA_256 = "SHA-256";
    private static final int DEFAULT_LENGTH = 32;
    private final int outputLength;
    private final MessageDigest messageDigest;

    CustomSha256Digest(final int outputLength) throws NoSuchAlgorithmException {
        this.outputLength = outputLength;
        this.messageDigest = MessageDigest.getInstance(SHA_256);
    }

    @Override
    @Nonnull
    public byte[] digest(@Nonnull final byte[] message) {
        final byte[] hash = messageDigest.digest(message);
        if (outputLength == DEFAULT_LENGTH) {
            return hash;
        }
        return ArrayUtils.subarray(hash, 0, outputLength);
    }
}
