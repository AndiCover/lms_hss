package at.andicover.lms.impl;

import at.andicover.lms.api.LMSKeyPair;
import at.andicover.lms.api.LMSPrivateKey;
import at.andicover.lms.api.LMSPublicKey;

import javax.annotation.Nonnull;
import java.util.Objects;

/**
 * Default LMS key pair implementation. Holds one LMS private key and one LMS public key.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
final class LMSKeyPairImpl implements LMSKeyPair {

    private final LMSPrivateKey privateKey;
    private final LMSPublicKey publicKey;

    LMSKeyPairImpl(@Nonnull final LMSPrivateKey privateKey, @Nonnull final LMSPublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    @Override
    @Nonnull
    public LMSPrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    @Nonnull
    public LMSPublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final LMSKeyPairImpl that = (LMSKeyPairImpl) o;
        return Objects.equals(privateKey, that.privateKey) && Objects.equals(publicKey, that.publicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(privateKey, publicKey);
    }
}
