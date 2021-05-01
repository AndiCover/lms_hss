package at.andicover.digest.impl;

import at.andicover.digest.api.CustomMessageDigest;
import com.github.aelstad.keccakj.fips202.Shake256;

import javax.annotation.Nonnull;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * SHAKE-256 implementation with customized output length. Internally uses {@link Shake256}.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
final class CustomShakeDigest implements CustomMessageDigest {

    private static final Logger LOGGER = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

    private final int outputLength;
    private final Shake256 sponge;

    CustomShakeDigest(final int outputLength) {
        this.outputLength = outputLength;
        this.sponge = new Shake256();
    }

    @Override
    @Nonnull
    public byte[] digest(@Nonnull final byte[] message) {
        final byte[] digest = new byte[this.outputLength];
        sponge.getAbsorbStream().write(message);
        if (-1 == sponge.getSqueezeStream().read(digest)) {
            LOGGER.log(Level.SEVERE, "SHAKE-256: Error reading data");
        }
        sponge.reset();
        return digest;
    }
}
