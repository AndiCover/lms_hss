package at.andicover.hss.impl;

import at.andicover.hss.api.HSSPublicKey;
import at.andicover.lms.api.LMSPublicKey;
import at.andicover.lms.impl.LMS;

import javax.annotation.Nonnull;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.PipedOutputStream;
import java.util.Objects;

import static at.andicover.util.ByteUtil.byteArrayToInt;
import static at.andicover.util.ByteUtil.intTo4ByteArray;
import static java.util.Objects.requireNonNull;

/**
 * Default implementation of the HSS public key.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-6.1">RFC 8554 - HSS Key Generation</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
final class HSSPublicKeyImpl implements HSSPublicKey {

    private final int levels;
    private final LMSPublicKey rootPublicKey;

    HSSPublicKeyImpl(final int levels, @Nonnull final LMSPublicKey rootPublicKey) {
        this.levels = levels;
        this.rootPublicKey = rootPublicKey;
    }

    HSSPublicKeyImpl(@Nonnull final DataInputStream inputStream) throws IOException {
        requireNonNull(inputStream);

        final byte[] data = new byte[4];
        inputStream.readFully(data, 0, 4);

        this.levels = byteArrayToInt(data, 0, 4);
        this.rootPublicKey = LMS.buildPublicKey(inputStream);
    }

    @Override
    public int getLevels() {
        return this.levels;
    }

    @Override
    @Nonnull
    public LMSPublicKey getPublicKey() {
        return this.rootPublicKey;
    }

    /**
     * Returns the public key as byte array. Might throw an OutOfMemory exception!
     *
     * @return the bytes of the key object in the format:  u32str(L) || pub[0]
     */
    @Override
    @Nonnull
    public byte[] getBytes() {
        final byte[] result = new byte[calculateSize()];
        System.arraycopy(intTo4ByteArray(this.levels), 0, result, 0, 4);
        final byte[] rootPublicKeyBytes = this.rootPublicKey.getBytes();
        System.arraycopy(rootPublicKeyBytes, 0, result, 4, rootPublicKeyBytes.length);

        return result;
    }

    @Override
    public void writeToPipedOutputStream(@Nonnull final PipedOutputStream outputStream) throws IOException {
        outputStream.write(this.getBytes());
        outputStream.flush();
    }

    @Override
    @Nonnull
    public String toString() {
        return "--------------------------------------------"
                + "\nHSS public key"
                + "\nlevels      " + String.format("%08d%n", levels)
                + this.rootPublicKey.toString();
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final HSSPublicKeyImpl that = (HSSPublicKeyImpl) o;
        return levels == that.levels && Objects.equals(rootPublicKey, that.rootPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(levels, rootPublicKey);
    }

    /**
     * @return The calculated key size: 4 byte L + pub[0].
     */
    @Override
    public int calculateSize() {
        return Integer.BYTES + rootPublicKey.calculateSize();
    }
}
