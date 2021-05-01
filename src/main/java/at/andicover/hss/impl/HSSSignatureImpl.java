package at.andicover.hss.impl;

import at.andicover.hss.api.HSSSignature;
import at.andicover.lms.api.LMSPublicKey;
import at.andicover.lms.api.LMSSignature;
import at.andicover.lms.impl.LMS;

import javax.annotation.Nonnull;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.PipedOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static at.andicover.config.Defaults.DEFAULT_OUTPUT_BUFFER;
import static at.andicover.util.ByteUtil.byteArrayToInt;
import static at.andicover.util.ByteUtil.intTo4ByteArray;
import static java.util.Objects.requireNonNull;

/**
 * Default implementation of the HSS signature.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-6.2">RFC 8554 - HSS Signature Generation</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
@SuppressWarnings({"PMD.ArrayIsStoredDirectly", "PMD.MethodReturnsInternalArray", "PMD.UseVarargs"})
final class HSSSignatureImpl implements HSSSignature {

    private final int numberOfSignedPublicKeys;
    private final LMSSignature[] lmsSignatures;
    private final LMSPublicKey[] lmsPublicKeys;

    HSSSignatureImpl(final int nspk,
                     @Nonnull final LMSSignature[] lmsSignatures,
                     @Nonnull final LMSPublicKey[] lmsPublicKeys) {
        this.numberOfSignedPublicKeys = nspk;
        this.lmsSignatures = lmsSignatures;
        this.lmsPublicKeys = lmsPublicKeys;
    }

    HSSSignatureImpl(@Nonnull final DataInputStream inputStream) throws IOException {
        requireNonNull(inputStream);

        final byte[] data = new byte[DEFAULT_OUTPUT_BUFFER];
        inputStream.readFully(data, 0, 4);

        this.numberOfSignedPublicKeys = byteArrayToInt(data, 0, 4);
        final List<LMSSignature> lmsSignatures = new ArrayList<>();
        final List<LMSPublicKey> lmsPublicKeys = new ArrayList<>();

        final LMSSignature signature = LMS.buildSignature(inputStream);
        lmsSignatures.add(signature);
        for (int i = 0; i < this.numberOfSignedPublicKeys; i++) {
            final LMSPublicKey lmsPublicKey = LMS.buildPublicKey(inputStream);
            lmsPublicKeys.add(lmsPublicKey);

            final LMSSignature lmsSignature = LMS.buildSignature(inputStream);
            lmsSignatures.add(lmsSignature);
        }
        lmsPublicKeys.add(null);
        this.lmsSignatures = lmsSignatures.toArray(LMSSignature[]::new);
        this.lmsPublicKeys = lmsPublicKeys.toArray(LMSPublicKey[]::new);
    }

    @Override
    public int getNumberOfSignedPublicKeys() {
        return this.numberOfSignedPublicKeys;
    }

    @Override
    @Nonnull
    public LMSSignature[] getSignatures() {
        return Arrays.copyOf(this.lmsSignatures, this.lmsSignatures.length);
    }

    @Override
    @Nonnull
    public LMSPublicKey[] getLmsPublicKeys() {
        return Arrays.copyOf(this.lmsPublicKeys, this.lmsPublicKeys.length);
    }

    /**
     * Returns the signature as byte array. Might throw an OutOfMemory exception!
     *
     * @return the bytes of the key object in the format:  u32str(L-1) || signed_pub_key[0] || ...
     * || signed_pub_key[L-2] || sig[L-1]
     */
    @Override
    @Nonnull
    public byte[] getBytes() {
        final byte[] result = new byte[calculateSize()];
        System.arraycopy(intTo4ByteArray(this.numberOfSignedPublicKeys), 0, result, 0, 4);
        final byte[] rootSig = this.lmsSignatures[0].getBytes();
        System.arraycopy(rootSig, 0, result, 4, rootSig.length);

        int destPos = 4 + rootSig.length;
        for (int i = 0; i < numberOfSignedPublicKeys; i++) {
            final byte[] pub = this.lmsPublicKeys[i].getBytes();
            System.arraycopy(pub, 0, result, destPos, pub.length);
            destPos += pub.length;

            final byte[] sig = this.lmsSignatures[i + 1].getBytes();
            System.arraycopy(sig, 0, result, destPos, sig.length);
            destPos += sig.length;
        }

        return result;
    }

    @Override
    public void writeToPipedOutputStream(@Nonnull final PipedOutputStream outputStream) throws IOException {
        outputStream.write(intTo4ByteArray(this.numberOfSignedPublicKeys));
        outputStream.flush();
        lmsSignatures[0].writeToPipedOutputStream(outputStream);

        for (int i = 0; i < numberOfSignedPublicKeys; i++) {
            lmsPublicKeys[i].writeToPipedOutputStream(outputStream);
            lmsSignatures[i + 1].writeToPipedOutputStream(outputStream);
        }
        outputStream.flush();
    }

    @Override
    @Nonnull
    @SuppressWarnings("PMD.ConsecutiveLiteralAppends")
    public String toString() {
        final StringBuilder builder = new StringBuilder(256);
        builder.append("--------------------------------------------\nHSS signature\nNspk        ")
                .append(String.format("%08d", numberOfSignedPublicKeys))
                .append("\nsig[0]      ").append(this.lmsSignatures[0].toString());
        for (int i = 1; i < this.lmsSignatures.length; i++) {
            builder.append("\npub[").append(i).append(']')
                    .append(" ".repeat(Math.max(0, 6 - (int) (Math.log10(i) + 1))))
                    .append(lmsPublicKeys[i - 1].toString())
                    .append("\nsig[").append(i).append(']')
                    .append(" ".repeat(Math.max(0, 6 - (int) (Math.log10(i) + 1))))
                    .append(lmsSignatures[i].toString());
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
        final HSSSignatureImpl that = (HSSSignatureImpl) o;
        return numberOfSignedPublicKeys == that.numberOfSignedPublicKeys
                && Arrays.equals(lmsSignatures, that.lmsSignatures)
                && Arrays.equals(lmsPublicKeys, that.lmsPublicKeys);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(numberOfSignedPublicKeys);
        result = 31 * result + Arrays.hashCode(lmsSignatures);
        result = 31 * result + Arrays.hashCode(lmsPublicKeys);
        return result;
    }

    /**
     * @return The calculated key size: 4 byte nspk + nspk * sig size + nspk - 1 * pub size.
     */
    @Override
    public int calculateSize() {
        int size = 0;
        for (int i = 0; i < numberOfSignedPublicKeys + 1; i++) {
            size += lmsSignatures[i].calculateSize();
        }
        for (int i = 0; i < numberOfSignedPublicKeys; i++) {
            size += lmsPublicKeys[i].calculateSize();
        }

        // 4 byte Nspk + nspk * sig size + nspk - 1 * pub size
        return Integer.BYTES + size;
    }
}
