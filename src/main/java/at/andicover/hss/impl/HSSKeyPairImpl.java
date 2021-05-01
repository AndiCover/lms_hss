package at.andicover.hss.impl;

import at.andicover.hss.api.HSSKeyPair;
import at.andicover.hss.api.HSSPrivateKey;
import at.andicover.hss.api.HSSPublicKey;

import javax.annotation.Nonnull;
import java.util.Objects;

/**
 * Default implementation of the HSS key pair.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
final class HSSKeyPairImpl implements HSSKeyPair {

    private final HSSPrivateKey privateKey;
    private final HSSPublicKey publicKey;

    HSSKeyPairImpl(@Nonnull final HSSPrivateKey privateKey, @Nonnull final HSSPublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    @Override
    @Nonnull
    public HSSPrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    @Nonnull
    public HSSPublicKey getPublicKey() {
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
        final HSSKeyPairImpl that = (HSSKeyPairImpl) o;
        return Objects.equals(privateKey, that.privateKey) && Objects.equals(publicKey, that.publicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(privateKey, publicKey);
    }
}
