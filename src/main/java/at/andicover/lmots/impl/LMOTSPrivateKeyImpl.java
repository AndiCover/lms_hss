package at.andicover.lmots.impl;

import at.andicover.lmots.api.LMOTSPrivateKey;
import at.andicover.lmots.api.LMOTSType;
import org.apache.commons.codec.binary.Hex;

import javax.annotation.Nonnull;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.PipedOutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import static at.andicover.config.Defaults.RANDOM_NUMBER_ALGORITHM;
import static at.andicover.util.ByteUtil.byteArrayToInt;
import static at.andicover.util.ByteUtil.intTo4ByteArray;
import static java.util.Objects.requireNonNull;

/**
 * Implementation of the Winternitz LMOTS private key. Holds the private keys.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-4.2">RFC 8554 - LM-OTS Private Key</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
@SuppressWarnings({"PMD.ArrayIsStoredDirectly", "PMD.MethodReturnsInternalArray"})
final class LMOTSPrivateKeyImpl implements LMOTSPrivateKey {

    private final LMOTSType lmotsType;
    private final byte[] identifier;
    private final int qIdentifier;
    private final byte[] seed;

    LMOTSPrivateKeyImpl(@Nonnull final LMOTSType lmotsType,
                        @Nonnull final byte[] identifier,
                        final int qIdentifier,
                        @Nonnull final byte[] seed) {
        requireNonNull(lmotsType);
        requireNonNull(identifier);

        this.lmotsType = lmotsType;
        this.identifier = identifier;
        this.qIdentifier = qIdentifier;
        this.seed = seed;
    }

    LMOTSPrivateKeyImpl(@Nonnull final DataInputStream inputStream) throws IOException {
        requireNonNull(inputStream);

        final byte[] data = new byte[4];
        inputStream.readFully(data, 0, 4);

        this.lmotsType = LMOTSType.lookUp(byteArrayToInt(data, 0, 4));
        this.identifier = new byte[16];
        inputStream.readFully(identifier, 0, 16);
        inputStream.readFully(data, 0, 4);
        this.qIdentifier = byteArrayToInt(data, 0, 4);
        this.seed = new byte[lmotsType.getN()];
        inputStream.readFully(seed, 0, lmotsType.getN());
    }

    @Override
    @Nonnull
    public byte[][] getKeys() throws NoSuchAlgorithmException {
        final byte[][] keys = new byte[lmotsType.getP()][lmotsType.getN()];
        final SecureRandom secureRandom = SecureRandom.getInstance(RANDOM_NUMBER_ALGORITHM);
        secureRandom.setSeed(this.seed);
        for (int i = 0; i < lmotsType.getP(); i++) {
            secureRandom.nextBytes(keys[i]);
        }

        return keys;
    }

    @Override
    @Nonnull
    public byte[] getIdentifier() {
        return Arrays.copyOf(this.identifier, this.identifier.length);
    }

    @Override
    public int getQIdentifier() {
        return this.qIdentifier;
    }

    @Override
    @Nonnull
    public LMOTSType getLmotsType() {
        return this.lmotsType;
    }

    @Override
    @Nonnull
    public byte[] getSeed() {
        return seed;
    }

    /**
     * @return the bytes of the key object in the format: u32str(type) || I || u32str(q) || x[0] || x[1] || ... || x[p-1]
     */
    @Override
    @Nonnull
    public byte[] getBytes() {
        final byte[] result = new byte[calculateSize()];
        System.arraycopy(intTo4ByteArray(this.lmotsType.getTypecode()), 0, result, 0, 4);
        System.arraycopy(this.identifier, 0, result, 4, 16);
        System.arraycopy(intTo4ByteArray(this.qIdentifier), 0, result, 20, 4);
        System.arraycopy(this.seed, 0, result, 24, lmotsType.getN());
        return result;
    }

    @Override
    public void writeToPipedOutputStream(@Nonnull final PipedOutputStream outputStream) throws IOException {
        outputStream.write(getBytes());
    }

    @Override
    @Nonnull
    public String toString() {
        return "--------------------------------------------"
                + "\nLMOTS private key"
                + "\nLMOTS type  " + String.format("%08d", lmotsType.getTypecode())
                + "\nI           " + Hex.encodeHexString(identifier)
                + "\nq           " + String.format("%032d", qIdentifier);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final LMOTSPrivateKeyImpl that = (LMOTSPrivateKeyImpl) o;
        return qIdentifier == that.qIdentifier && lmotsType == that.lmotsType
                && Arrays.equals(identifier, that.identifier) && Arrays.equals(seed, that.seed);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(lmotsType, qIdentifier);
        result = 31 * result + Arrays.hashCode(identifier);
        result = 31 * result + Arrays.hashCode(seed);
        return result;
    }

    /**
     * @return The calculated key size: 4 byte typecode + 16 byte I + 4 byte q + n byte seed.
     */
    @Override
    public int calculateSize() {
        return Integer.BYTES + this.identifier.length + Integer.BYTES + this.seed.length;
    }
}
