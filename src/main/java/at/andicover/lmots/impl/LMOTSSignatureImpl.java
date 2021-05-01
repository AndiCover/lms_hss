package at.andicover.lmots.impl;

import at.andicover.lmots.api.LMOTSSignature;
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
import static at.andicover.util.KeySizeUtil.getByteArraySize;
import static java.util.Objects.requireNonNull;

/**
 * Implementation of the Winternitz LMOTS signature. Holds the signature keys.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-4">RFC 8554 - LM-OTS Signature</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
@SuppressWarnings({"PMD.ArrayIsStoredDirectly", "PMD.MethodReturnsInternalArray"})
final class LMOTSSignatureImpl implements LMOTSSignature {

    private final byte[][] keys;
    private final LMOTSType lmotsType;
    private final byte[] c;

    LMOTSSignatureImpl(@Nonnull final LMOTSType lmotsType, @Nonnull final byte[] c, @Nonnull final byte[][] keys) {
        requireNonNull(lmotsType);
        requireNonNull(c);
        requireNonNull(keys);

        this.lmotsType = lmotsType;
        this.c = c;
        this.keys = keys;
    }

    LMOTSSignatureImpl(@Nonnull final DataInputStream inputStream) throws IOException {
        requireNonNull(inputStream);

        final byte[] data = new byte[32];
        inputStream.readFully(data, 0, 4);

        this.lmotsType = LMOTSType.lookUp(byteArrayToInt(data, 0, 4));
        this.c = new byte[this.lmotsType.getN()];
        inputStream.readFully(c, 0, lmotsType.getN());

        this.keys = new byte[this.lmotsType.getP()][this.lmotsType.getN()];
        for (int i = 0; i < this.lmotsType.getP(); i++) {
            inputStream.readFully(this.keys[i], 0, lmotsType.getN());
        }
    }

    @Override
    @Nonnull
    public byte[][] getKeys() {
        return Arrays.copyOf(this.keys, this.keys.length);
    }

    @Override
    @Nonnull
    public LMOTSType getLmotsType() {
        return lmotsType;
    }

    @Override
    @Nonnull
    public byte[] getC() {
        return Arrays.copyOf(this.c, this.c.length);
    }

    /**
     * @return the bytes of the key object in the format: u32str(type) || C || y[0] || ... || y[p-1]
     */
    @Override
    @Nonnull
    public byte[] getBytes() {
        final byte[] result = new byte[calculateSize()];
        System.arraycopy(intTo4ByteArray(this.lmotsType.getTypecode()), 0, result, 0, 4);
        System.arraycopy(this.c, 0, result, 4, lmotsType.getN());
        for (int i = 0; i < this.keys.length; i++) {
            System.arraycopy(this.keys[i], 0, result, i * this.lmotsType.getN() + 4 + lmotsType.getN(),
                    this.lmotsType.getN());
        }

        return result;
    }

    @Override
    public void writeToPipedOutputStream(@Nonnull final PipedOutputStream outputStream) throws IOException {
        outputStream.write(getBytes());
    }

    @Override
    @Nonnull
    @SuppressWarnings("PMD.ConsecutiveLiteralAppends")
    public String toString() {
        final StringBuilder builder = new StringBuilder(1024);
        builder.append("--------------------------------------------\nLMOTS signature\nLMOTS type  ")
                .append(String.format("%08d", lmotsType.getTypecode()))
                .append("\nC           ").append(Hex.encodeHexString(c)).append("\ny[0]        ")
                .append(Hex.encodeHexString(this.keys[0]));
        for (int i = 1; i < this.keys.length; i++) {
            builder.append("\ny[").append(i).append(']');
            builder.append(" ".repeat(Math.max(0, 9 - (int) (Math.log10(i) + 1))));
            builder.append(Hex.encodeHexString(this.keys[i]));
        }
        return builder.toString();
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final LMOTSSignatureImpl that = (LMOTSSignatureImpl) o;
        return Arrays.deepEquals(keys, that.keys) && lmotsType == that.lmotsType && Arrays.equals(c, that.c);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(lmotsType);
        result = 31 * result + Arrays.deepHashCode(keys);
        result = 31 * result + Arrays.hashCode(c);
        return result;
    }

    /**
     * @return The calculated key size: 4 byte typecode + n byte c + n * p byte keys.
     */
    @Override
    public int calculateSize() {
        return Integer.BYTES + c.length + getByteArraySize(keys);
    }
}
