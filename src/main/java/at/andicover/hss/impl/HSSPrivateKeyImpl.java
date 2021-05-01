package at.andicover.hss.impl;

import at.andicover.hss.api.HSSPrivateKey;
import at.andicover.lms.api.LMSKeyPair;
import at.andicover.lms.api.LMSPrivateKey;
import at.andicover.lms.api.LMSPublicKey;
import at.andicover.lms.api.LMSSignature;
import at.andicover.lms.impl.LMS;
import at.andicover.util.PersistenceUtil;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.PipedOutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

import static at.andicover.util.ByteUtil.byteArrayToInt;
import static at.andicover.util.ByteUtil.intTo4ByteArray;
import static java.util.Objects.requireNonNull;

/**
 * Default implementation of the HSS private key.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-6.1">RFC 8554 - HSS Key Generation</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
@SuppressWarnings({"PMD.ArrayIsStoredDirectly", "PMD.MethodReturnsInternalArray", "PMD.UseVarargs"})
final class HSSPrivateKeyImpl implements HSSPrivateKey {

    private final int levels;
    private final LMSPrivateKey[] lmsPrivateKeys;
    private final LMSPublicKey[] lmsPublicKeys;
    private final LMSSignature[] lmsSignatures;
    private final String filename;

    HSSPrivateKeyImpl(final int levels,
                      @Nonnull final LMSPrivateKey[] privateKeys,
                      @Nonnull final LMSPublicKey[] publicKeys,
                      @Nonnull final LMSSignature[] lmsSignatures) {
        this(levels, privateKeys, publicKeys, lmsSignatures, null);
    }

    HSSPrivateKeyImpl(final int levels,
                      @Nonnull final LMSPrivateKey[] privateKeys,
                      @Nonnull final LMSPublicKey[] publicKeys,
                      @Nonnull final LMSSignature[] lmsSignatures,
                      final String filename) {
        this.levels = levels;
        this.lmsPrivateKeys = privateKeys;
        this.lmsPublicKeys = publicKeys;
        this.lmsSignatures = lmsSignatures;
        this.filename = filename;
    }

    HSSPrivateKeyImpl(@Nonnull final DataInputStream inputStream, @Nonnull final String filename)
            throws NoSuchAlgorithmException, IOException {
        requireNonNull(inputStream);

        final byte[] data = new byte[4];
        inputStream.readFully(data, 0, 4);

        this.levels = byteArrayToInt(data, 0, 4);
        this.lmsPrivateKeys = new LMSPrivateKey[levels];

        for (int i = 0; i < levels; i++) {
            final LMSPrivateKey lmsPrivateKey = LMS.buildPrivateKey(inputStream);
            lmsPrivateKeys[i] = lmsPrivateKey;
        }

        this.lmsPublicKeys = new LMSPublicKey[levels];
        for (int i = 0; i < levels; i++) {
            final LMSPublicKey lmsPublicKey = LMS.buildPublicKey(inputStream);
            lmsPublicKeys[i] = lmsPublicKey;
        }

        this.lmsSignatures = new LMSSignature[levels];
        for (int i = 0; i < levels; i++) {
            if (inputStream.available() != 0) {
                final LMSSignature lmsSignature = LMS.buildSignature(inputStream);
                lmsSignatures[i] = lmsSignature;
            }
        }
        this.filename = filename;
    }

    @Override
    public int getLevels() {
        return levels;
    }

    @Override
    @Nonnull
    public LMSPrivateKey[] getLmsPrivateKeys() {
        return this.lmsPrivateKeys;
    }

    @Override
    @Nonnull
    public LMSPublicKey[] getLmsPublicKeys() {
        return this.lmsPublicKeys;
    }

    @Override
    @Nonnull
    public LMSSignature[] getSignatures() {
        return this.lmsSignatures;
    }

    @Override
    @CheckForNull
    public String getFilename() {
        return filename;
    }

    @Override
    public void reserveKeys(final int numberOfKeys) throws NoSuchAlgorithmException, IOException {
        final int d = levels - 1;
        LMSPrivateKey lmsPrivateKey = this.lmsPrivateKeys[d];
        if (lmsPrivateKey.isExhausted() && d > 0) {
            final LMSKeyPair lmsKeyPair = LMS.generateKeys(this.lmsPrivateKeys[0].getLmsType(),
                    this.lmsPrivateKeys[0].getLmotsType());
            this.lmsPrivateKeys[d] = lmsKeyPair.getPrivateKey();
            this.lmsPublicKeys[d] = lmsKeyPair.getPublicKey();
            lmsPrivateKey = this.lmsPrivateKeys[d];
            this.lmsPrivateKeys[d - 1].reserveKeys(1);
            lmsSignatures[d - 1] = LMS.generateSignature(lmsPublicKeys[d].getKey(), this.lmsPrivateKeys[d - 1]);
        }
        lmsPrivateKey.reserveKeys(numberOfKeys);
        PersistenceUtil.storeKey(this);
    }

    @Override
    public int getReservedKeys() {
        return lmsPrivateKeys[levels - 1].getReservedKeys();
    }

    /**
     * Returns the private key as byte array. Might throw an OutOfMemory exception!
     *
     * @return the bytes of the key object in the format:  u32str(L) || priv[0] || ... || priv[L-1] || pub[0]
     * || ... || pub[L-1] || sig[0] || ... || sig[L-1]
     */
    @Override
    @Nonnull
    public byte[] getBytes() {
        final byte[] result = new byte[calculateSize()];

        System.arraycopy(intTo4ByteArray(this.levels), 0, result, 0, 4);
        int destPos = 4;
        for (int i = 0; i < levels; i++) {
            final byte[] lmsPrivateKeyBytes = this.lmsPrivateKeys[i].getBytes();
            System.arraycopy(lmsPrivateKeyBytes, 0, result, destPos, lmsPrivateKeyBytes.length);
            destPos += lmsPrivateKeyBytes.length;
        }
        for (int i = 0; i < levels; i++) {
            final byte[] lmsPublicKeyBytes = this.lmsPublicKeys[i].getBytes();
            System.arraycopy(lmsPublicKeyBytes, 0, result, destPos, lmsPublicKeyBytes.length);
            destPos += lmsPublicKeyBytes.length;
        }
        for (int i = 0; i < levels; i++) {
            final LMSSignature lmsSignature = this.lmsSignatures[i];
            if (lmsSignature != null) {
                final byte[] signatureBytes = lmsSignature.getBytes();
                System.arraycopy(signatureBytes, 0, result, destPos, signatureBytes.length);
                destPos += signatureBytes.length;
            }
        }
        return result;
    }

    @Override
    public void writeToPipedOutputStream(@Nonnull final PipedOutputStream outputStream) throws IOException {
        outputStream.write(intTo4ByteArray(levels));
        outputStream.flush();
        for (int i = 0; i < levels; i++) {
            lmsPrivateKeys[i].writeToPipedOutputStream(outputStream);
        }
        for (int i = 0; i < levels; i++) {
            lmsPublicKeys[i].writeToPipedOutputStream(outputStream);
        }
        for (int i = 0; i < levels; i++) {
            final LMSSignature lmsSignature = this.lmsSignatures[i];
            if (lmsSignature != null) {
                lmsSignature.writeToPipedOutputStream(outputStream);
            }
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
        final HSSPrivateKeyImpl that = (HSSPrivateKeyImpl) o;
        return levels == that.levels && Arrays.equals(lmsPrivateKeys, that.lmsPrivateKeys)
                && Arrays.equals(lmsPublicKeys, that.lmsPublicKeys)
                && Arrays.equals(lmsSignatures, that.lmsSignatures);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(levels);
        result = 31 * result + Arrays.hashCode(lmsPrivateKeys);
        result = 31 * result + Arrays.hashCode(lmsPublicKeys);
        result = 31 * result + Arrays.hashCode(lmsSignatures);
        return result;
    }

    /**
     * @return The calculated key size: 4 byte L + priv[] + pub[] + sig[].
     */
    @Override
    public int calculateSize() {
        int size = 0;
        for (final LMSPrivateKey lmsPrivateKey : lmsPrivateKeys) {
            size += lmsPrivateKey.calculateSize();
        }
        for (final LMSPublicKey lmsPublicKey : lmsPublicKeys) {
            size += lmsPublicKey.calculateSize();
        }
        for (final LMSSignature lmsSignature : lmsSignatures) {
            if (lmsSignature != null) {
                size += lmsSignature.calculateSize();
            }
        }

        return Integer.BYTES + size;
    }
}
