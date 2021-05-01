package at.andicover.digest.impl;

import at.andicover.digest.api.CustomMessageDigest;

import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;

/**
 * Cache value holding the {@link CustomShakeDigest} instance, the algorithm, and the timeout timestamp in milliseconds.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
final class CacheValue {

    private final CustomMessageDigest messageDigest;
    private final String algorithm;
    private final long lifetime;
    private long timeout;

    CacheValue(@Nonnull final CustomMessageDigest messageDigest, @Nonnull final String algorithm, final long lifetime) {
        requireNonNull(messageDigest);
        requireNonNull(algorithm);

        this.messageDigest = messageDigest;
        this.algorithm = algorithm;
        this.lifetime = lifetime;
        updateTimeout();
    }

    /**
     * @return if the value is not valid anymore.
     */
    boolean isTimedOut() {
        return System.currentTimeMillis() > timeout;
    }

    /**
     * @return the used hash algorithm.
     */
    String getAlgorithm() {
        return algorithm;
    }

    /**
     * @return the message digest instance.
     */
    public CustomMessageDigest getMessageDigest() {
        updateTimeout();
        return messageDigest;
    }

    /**
     * Everytime the value is used we update the timeout timestamp.
     */
    private void updateTimeout() {
        this.timeout = System.currentTimeMillis() + lifetime;
    }
}
