package at.andicover.lmots.impl;

import at.andicover.lmots.api.LMOTSPrivateKey;
import at.andicover.lmots.api.LMOTSPublicKey;
import at.andicover.lmots.api.LMOTSType;
import org.apache.commons.codec.binary.Hex;

import javax.annotation.Nonnull;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.PipedOutputStream;
import java.util.Arrays;
import java.util.Objects;

import static at.andicover.util.ByteUtil.byteArrayToInt;
import static at.andicover.util.ByteUtil.intTo4ByteArray;
import static java.util.Objects.requireNonNull;

/**
 * Implementation of the Winternitz LMOTS public key. Holds the public keys.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-4.3">RFC 8554 - LM-OTS Public Key</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
@SuppressWarnings({"PMD.ArrayIsStoredDirectly", "PMD.MethodReturnsInternalArray"})
final class LMOTSPublicKeyImpl implements LMOTSPublicKey {

    private final LMOTSType lmotsType;
    private final byte[] identifier;
    private final int qIdentifier;
    private final byte[] key;

    LMOTSPublicKeyImpl(@Nonnull final LMOTSType lmotsType,
                       @Nonnull final LMOTSPrivateKey privateKey,
                       @Nonnull final byte[] key) {
        requireNonNull(lmotsType);
        requireNonNull(privateKey);
        requireNonNull(key);

        this.lmotsType = lmotsType;
        this.identifier = privateKey.getIdentifier();
        this.qIdentifier = privateKey.getQIdentifier();
        this.key = key;
    }

    LMOTSPublicKeyImpl(final LMOTSType lmotsType,
                       @Nonnull final byte[] identifier,
                       final int qIdentifer,
                       @Nonnull final byte[] key) {
        this.lmotsType = lmotsType;
        this.identifier = identifier;
        this.qIdentifier = qIdentifer;
        this.key = key;
    }

    LMOTSPublicKeyImpl(@Nonnull final DataInputStream inputStream) throws IOException {
        requireNonNull(inputStream);

        final byte[] data = new byte[24];
        inputStream.readFully(data, 0, 24);

        this.lmotsType = LMOTSType.lookUp(byteArrayToInt(data, 0, 4));
        this.identifier = new byte[16];
        System.arraycopy(data, 4, this.identifier, 0, 16);
        this.qIdentifier = byteArrayToInt(data, 20, 24);
        this.key = new byte[this.lmotsType.getN()];

        inputStream.readFully(key, 0, lmotsType.getN());
    }

    @Override
    @Nonnull
    public byte[] getKey() {
        return Arrays.copyOf(this.key, this.key.length);
    }

    @Override
    @Nonnull
    public LMOTSType getLmotsType() {
        return this.lmotsType;
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

    /**
     * @return the bytes of the key object in the format: u32str(type) || I || u32str(q) || K
     */
    @Override
    @Nonnull
    public byte[] getBytes() {
        final byte[] result = new byte[calculateSize()];
        System.arraycopy(intTo4ByteArray(this.lmotsType.getTypecode()), 0, result, 0, 4);
        System.arraycopy(this.identifier, 0, result, 4, 16);
        System.arraycopy(intTo4ByteArray(this.qIdentifier), 0, result, 20, 4);
        System.arraycopy(this.key, 0, result, 24, this.lmotsType.getN());

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
                + "\nLMOTS public key"
                + "\nLMOTS type  " + String.format("%08d", lmotsType.getTypecode())
                + "\nI           " + Hex.encodeHexString(identifier)
                + "\nq           " + String.format("%032d", qIdentifier)
                + "\nK:          " + Hex.encodeHexString(key);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final LMOTSPublicKeyImpl that = (LMOTSPublicKeyImpl) o;
        return qIdentifier == that.qIdentifier && lmotsType == that.lmotsType
                && Arrays.equals(identifier, that.identifier) && Arrays.equals(key, that.key);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(lmotsType, qIdentifier);
        result = 31 * result + Arrays.hashCode(identifier);
        result = 31 * result + Arrays.hashCode(key);
        return result;
    }

    /**
     * @return The calculated key size: 4 byte typecode + 16 byte I + 4 byte q + n byte K.
     */
    @Override
    public int calculateSize() {
        return Integer.BYTES + identifier.length + Integer.BYTES + key.length;
    }
}
