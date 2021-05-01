package at.andicover.lms.impl;

import at.andicover.lmots.api.LMOTSType;
import at.andicover.lms.api.LMSPrivateKey;
import at.andicover.lms.api.LMSPublicKey;
import at.andicover.lms.api.LMSType;
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
 * Default LMS public key model.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-5.3">RFC 8554 - LMS Public Key</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
@SuppressWarnings({"PMD.ArrayIsStoredDirectly", "PMD.MethodReturnsInternalArray"})
final class LMSPublicKeyImpl implements LMSPublicKey {

    private final LMSType lmsType;
    private final LMOTSType lmotsType;
    private final byte[] identifier;
    private final byte[] key;

    LMSPublicKeyImpl(@Nonnull final LMSPrivateKey privateKey,
                     @Nonnull final byte[] key) {
        this(privateKey.getLmsType(), privateKey.getLmotsType(), privateKey.getIdentifier(), key);
    }

    LMSPublicKeyImpl(@Nonnull final LMSType lmsType,
                     @Nonnull final LMOTSType lmotsType,
                     @Nonnull final byte[] identifier,
                     @Nonnull final byte[] key) {
        requireNonNull(lmsType);
        requireNonNull(lmotsType);
        requireNonNull(identifier);
        requireNonNull(key);

        this.lmsType = lmsType;
        this.lmotsType = lmotsType;
        this.identifier = identifier;
        this.key = key;
    }

    LMSPublicKeyImpl(@Nonnull final DataInputStream inputStream) throws IOException {
        requireNonNull(inputStream);

        final byte[] data = new byte[8];
        inputStream.readFully(data, 0, 8);

        this.lmsType = LMSType.lookUp(byteArrayToInt(data, 0, 4));
        this.lmotsType = LMOTSType.lookUp(byteArrayToInt(data, 4, 8));
        this.identifier = new byte[16];
        inputStream.readFully(identifier);

        this.key = new byte[lmsType.getM()];
        inputStream.readFully(key, 0, lmsType.getM());
    }

    @Override
    @Nonnull
    public LMSType getLmsType() {
        return this.lmsType;
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
    @Nonnull
    public byte[] getKey() {
        return Arrays.copyOf(this.key, this.key.length);
    }

    /**
     * Returns the public key as byte array. Might throw an OutOfMemory exception!
     *
     * @return the bytes of the key object in the format:  u32str(lmsType) || u32str(lmotsType) || I || K
     */
    @Override
    @Nonnull
    public byte[] getBytes() {
        final byte[] result = new byte[calculateSize()];
        System.arraycopy(intTo4ByteArray(this.getLmsType().getTypecode()), 0, result, 0, 4);
        System.arraycopy(intTo4ByteArray(this.getLmotsType().getTypecode()), 0, result, 4, 4);
        System.arraycopy(this.getIdentifier(), 0, result, 8, 16);
        System.arraycopy(this.key, 0, result, 24, lmsType.getM());

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
                + "\nLMS public key"
                + "\nLMS type    " + String.format("%08d", lmsType.getTypecode())
                + "\nLMOTS type  " + String.format("%08d", lmotsType.getTypecode())
                + "\nI           " + Hex.encodeHexString(identifier)
                + "\nK           " + Hex.encodeHexString(key);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final LMSPublicKeyImpl that = (LMSPublicKeyImpl) o;
        return lmsType == that.lmsType && lmotsType == that.lmotsType && Arrays.equals(identifier, that.identifier)
                && Arrays.equals(key, that.key);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(lmsType, lmotsType);
        result = 31 * result + Arrays.hashCode(identifier);
        result = 31 * result + Arrays.hashCode(key);
        return result;
    }

    /**
     * @return The calculated key size: 4 byte LMS typecode + 4 byte LMOTS typecode + 16 byte I + m bytes.
     */
    @Override
    public int calculateSize() {
        return Integer.BYTES + Integer.BYTES + identifier.length + key.length;
    }
}
