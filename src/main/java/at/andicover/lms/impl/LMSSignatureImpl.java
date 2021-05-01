package at.andicover.lms.impl;

import at.andicover.lmots.api.LMOTSSignature;
import at.andicover.lmots.impl.LMOTS;
import at.andicover.lms.api.LMSSignature;
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
 * Default LMS signature model.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-5.4">RFC 8554 - LMS Signature</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
@SuppressWarnings({"PMD.ArrayIsStoredDirectly", "PMD.MethodReturnsInternalArray"})
final class LMSSignatureImpl implements LMSSignature {

    private final LMSType lmsType;
    private final int qIdentifier;
    private final LMOTSSignature lmotsSignature;
    private final byte[][] path;

    LMSSignatureImpl(@Nonnull final LMSType lmsType,
                     @Nonnull final LMOTSSignature lmotsSignature,
                     final int qIdentifier,
                     @Nonnull final byte[][] path) {
        requireNonNull(lmsType);
        requireNonNull(lmotsSignature);
        requireNonNull(path);

        this.lmsType = lmsType;
        this.qIdentifier = qIdentifier;
        this.lmotsSignature = lmotsSignature;
        this.path = path;
    }

    LMSSignatureImpl(@Nonnull final DataInputStream inputStream) throws IOException {
        requireNonNull(inputStream);

        final byte[] data = new byte[4];
        inputStream.readFully(data, 0, 4);

        this.qIdentifier = byteArrayToInt(data, 0, 4);
        this.lmotsSignature = LMOTS.buildSignature(inputStream);

        inputStream.readFully(data, 0, 4);
        this.lmsType = LMSType.lookUp(byteArrayToInt(data, 0, 4));
        this.path = new byte[lmsType.getH()][lmsType.getM()];
        for (int i = 0; i < lmsType.getH(); i++) {
            inputStream.readFully(path[i], 0, lmsType.getM());
        }
    }

    @Override
    @Nonnull
    public LMSType getLmsType() {
        return this.lmsType;
    }

    @Override
    public int getQIdentifier() {
        return this.qIdentifier;
    }

    @Override
    @Nonnull
    public LMOTSSignature getLmotsSignature() {
        return this.lmotsSignature;
    }

    @Override
    @Nonnull
    public byte[][] getPath() {
        return Arrays.copyOf(this.path, this.path.length);
    }

    /**
     * Returns the signature as byte array. Might throw an OutOfMemory exception!
     *
     * @return the bytes of the key object in the format:  u32str(q) || lmots_signature || u32str(type)
     * || path[0] || path[1] || ... || path[h-1]
     */
    @Override
    @Nonnull
    public byte[] getBytes() {
        final byte[] result = new byte[calculateSize()];
        System.arraycopy(intTo4ByteArray(this.qIdentifier), 0, result, 0, 4);
        final byte[] lmotsSignatureBytes = this.lmotsSignature.getBytes();
        System.arraycopy(lmotsSignatureBytes, 0, result, 4, lmotsSignatureBytes.length);
        System.arraycopy(intTo4ByteArray(this.lmsType.getTypecode()), 0, result, 4 + lmotsSignatureBytes.length, 4);

        for (int i = 0; i < this.path.length; i++) {
            System.arraycopy(this.path[i], 0, result, i * lmsType.getM() + 8 + lmotsSignatureBytes.length,
                    lmsType.getM());
        }

        return result;
    }

    @Override
    public void writeToPipedOutputStream(@Nonnull final PipedOutputStream outputStream) throws IOException {
        outputStream.write(intTo4ByteArray(this.qIdentifier));
        outputStream.write(this.lmotsSignature.getBytes());
        outputStream.write(intTo4ByteArray(this.lmsType.getTypecode()));
        outputStream.flush();

        for (final byte[] bytes : this.path) {
            outputStream.write(bytes);
        }
        outputStream.flush();
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final LMSSignatureImpl that = (LMSSignatureImpl) o;
        return qIdentifier == that.qIdentifier && lmsType == that.lmsType
                && Objects.equals(lmotsSignature, that.lmotsSignature) && Arrays.deepEquals(path, that.path);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(lmsType, qIdentifier, lmotsSignature);
        result = 31 * result + Arrays.deepHashCode(path);
        return result;
    }

    @Override
    @Nonnull
    @SuppressWarnings("PMD.ConsecutiveLiteralAppends")
    public String toString() {
        final StringBuilder builder = new StringBuilder(1024);
        builder.append("--------------------------------------------\nLMS signature\nq:          ")
                .append(String.format("%08d%n", qIdentifier))
                .append(this.lmotsSignature.toString())
                .append("\n--------------------------------------------\nLMS type    ")
                .append(String.format("%08d", lmsType.getTypecode()))
                .append("\npath[0]     ").append(Hex.encodeHexString(path[0]));

        for (int i = 1; i < this.path.length; i++) {
            builder.append("\npath[").append(i).append(']');
            builder.append(" ".repeat(Math.max(0, 5 - (int) (Math.log10(i) + 1))));
            builder.append(Hex.encodeHexString(this.path[i]));
        }
        return builder.toString();
    }

    /**
     * @return The calculated key size: 4 byte q + LMOTS Signature size + 4 byte LMS typecode + h * m bytes.
     */
    @Override
    public int calculateSize() {
        final int lmotsSignatureSize = this.lmotsSignature.calculateSize();
        return Integer.BYTES + lmotsSignatureSize + Integer.BYTES + lmsType.getH() * lmsType.getM();
    }
}
