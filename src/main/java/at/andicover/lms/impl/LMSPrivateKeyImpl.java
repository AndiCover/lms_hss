package at.andicover.lms.impl;

import at.andicover.digest.api.CustomMessageDigest;
import at.andicover.digest.impl.MessageDigestCache;
import at.andicover.lmots.api.LMOTSPrivateKey;
import at.andicover.lmots.api.LMOTSPublicKey;
import at.andicover.lmots.api.LMOTSType;
import at.andicover.lmots.impl.LMOTS;
import at.andicover.lms.api.LMSPrivateKey;
import at.andicover.lms.api.LMSType;
import at.andicover.util.MathUtil;
import org.apache.commons.codec.binary.Hex;

import javax.annotation.Nonnull;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.PipedOutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Objects;
import java.util.Queue;

import static at.andicover.config.Defaults.STORED_TOP_LEVEL_NODES;
import static at.andicover.util.ByteUtil.byteArrayToInt;
import static at.andicover.util.ByteUtil.intTo4ByteArray;
import static at.andicover.util.ByteUtil.merge;
import static at.andicover.util.SecurityString.getdIntr;
import static at.andicover.util.SecurityString.getdLeaf;
import static java.util.Objects.requireNonNull;

/**
 * Default LMS private key model.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-5.2">RFC 8554 - LMS Private Key</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
@SuppressWarnings({"PMD.ArrayIsStoredDirectly", "PMD.MethodReturnsInternalArray", "PMD.UseVarargs"})
final class LMSPrivateKeyImpl implements LMSPrivateKey {

    private final LMOTSPrivateKey[] lmotsPrivateKeys;
    private byte[][] leafNodes;
    private byte[][] topLevelNodes;
    private final byte[] identifier;
    private volatile int qIdentifier;
    private volatile int reservedKeys;
    private final LMOTSType lmotsType;
    private final LMSType lmsType;

    LMSPrivateKeyImpl(@Nonnull final LMSType lmsType,
                      @Nonnull final LMOTSType lmotsType,
                      @Nonnull final LMOTSPrivateKey[] privateKeys,
                      @Nonnull final byte[] identifier) {
        this(lmsType, lmotsType, privateKeys, identifier, 0);
    }

    LMSPrivateKeyImpl(@Nonnull final LMSType lmsType,
                      @Nonnull final LMOTSType lmotsType,
                      @Nonnull final LMOTSPrivateKey[] privateKeys,
                      @Nonnull final byte[] identifier,
                      final int qIdentifier) {
        requireNonNull(lmsType);
        requireNonNull(lmotsType);
        requireNonNull(privateKeys);
        requireNonNull(identifier);

        this.lmotsPrivateKeys = privateKeys;
        this.identifier = identifier;
        this.lmotsType = lmotsType;
        this.lmsType = lmsType;
        this.qIdentifier = qIdentifier;
    }

    LMSPrivateKeyImpl(@Nonnull final DataInputStream inputStream) throws NoSuchAlgorithmException, IOException {
        requireNonNull(inputStream);

        final byte[] data = new byte[12];
        inputStream.readFully(data, 0, 12);

        this.lmsType = LMSType.lookUp(byteArrayToInt(data, 0, 4));
        this.lmotsType = LMOTSType.lookUp(byteArrayToInt(data, 4, 8));
        this.qIdentifier = byteArrayToInt(data, 8, 12);
        this.reservedKeys = this.qIdentifier;
        this.identifier = new byte[16];
        inputStream.readFully(identifier, 0, 16);

        this.lmotsPrivateKeys = new LMOTSPrivateKey[MathUtil.pow(lmsType.getH())];
        for (int i = 0; i < lmotsPrivateKeys.length; i++) {
            lmotsPrivateKeys[i] = LMOTS.buildPrivateKey(inputStream);
        }

        LMS.generatePublicKey(this, lmotsPrivateKeys); //Recreate public key to generate the tree again.
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
    public int getQIdentifier() {
        return this.qIdentifier;
    }

    @Override
    @Nonnull
    public synchronized LMOTSPrivateKey getNextLmotsKey() throws IllegalStateException {
        if (isExhausted()) {
            throw new IllegalStateException("No unused LMOTS private key available");
        }
        if (!hasReservedKey()) {
            throw new IllegalStateException("No reserved keys available");
        }

        return this.lmotsPrivateKeys[this.qIdentifier++];
    }

    @Override
    public boolean isExhausted() {
        return this.qIdentifier >= this.lmotsPrivateKeys.length;
    }

    @Override
    public synchronized void reserveKeys(final int numberOfKeys) {
        if (this.reservedKeys + numberOfKeys <= this.lmotsPrivateKeys.length) {
            this.reservedKeys += numberOfKeys;
        } else {
            this.reservedKeys = this.lmotsPrivateKeys.length;
        }
    }

    @Override
    public int getReservedKeys() {
        return this.reservedKeys - this.qIdentifier;
    }

    @Override
    public boolean hasReservedKey() {
        return this.qIdentifier < this.reservedKeys;
    }

    @Override
    @Nonnull
    @SuppressWarnings("PMD.CyclomaticComplexity")
    public byte[][] getPath(final int nodeNumber) throws NoSuchAlgorithmException {
        final int keys = MathUtil.pow(lmsType.getH());
        final byte[][] tree = buildTree(keys);

        if (tree.length + leafNodes.length + topLevelNodes.length != MathUtil.pow(this.lmsType.getH() + 1)
                || tree[0].length != this.lmsType.getM()) {
            throw new IllegalStateException("Incorrect tree size");
        }

        byte[][] path = new byte[lmsType.getH()][lmsType.getM()];
        int nodeNum = nodeNumber;
        int i = 0;
        while (nodeNum > 1) {
            if (nodeNum >= keys) {
                if (nodeNum % 2 == 0) {
                    path[i] = leafNodes[nodeNum + 1 - tree.length - topLevelNodes.length];
                } else {
                    path[i] = leafNodes[nodeNum - 1 - tree.length - topLevelNodes.length];
                }
            } else if (nodeNum < topLevelNodes.length) {
                if (nodeNum % 2 == 0) {
                    path[i] = topLevelNodes[nodeNum];
                } else {
                    path[i] = topLevelNodes[nodeNum - 2];
                }
            } else {
                if (nodeNum % 2 == 0) {
                    path[i] = tree[nodeNum + 1 - topLevelNodes.length];
                } else {
                    path[i] = tree[nodeNum - 1 - topLevelNodes.length];
                }
            }
            nodeNum /= 2;
            i++;
        }
        return path;
    }

    @Nonnull
    private byte[][] buildTree(final int keys) throws NoSuchAlgorithmException {
        final byte[][] tree = new byte[keys - topLevelNodes.length][lmsType.getM()];
        final CustomMessageDigest messageDigest =
                MessageDigestCache.getInstance().getMessageDigest(lmsType.getHashAlgorithm());

        for (int r = keys - 1; r >= topLevelNodes.length; r--) {
            if (2 * r >= keys - 1) {
                tree[r - topLevelNodes.length] = messageDigest
                        .digest(merge(identifier, intTo4ByteArray(r), getdIntr(), this.leafNodes[2 * r - keys],
                                this.leafNodes[2 * r + 1 - keys]));
            } else {
                tree[r - topLevelNodes.length] = messageDigest
                        .digest(merge(identifier, intTo4ByteArray(r), getdIntr(), tree[2 * r - topLevelNodes.length],
                                tree[2 * r + 1 - topLevelNodes.length]));
            }
        }
        return tree;
    }

    @Override
    @Nonnull
    @SuppressWarnings("PMD.CyclomaticComplexity")
    public byte[] calculateRoot(@Nonnull final LMOTSPublicKey[] lmotsPublicKeys) throws NoSuchAlgorithmException {
        final int keys = MathUtil.pow(lmsType.getH());

        if (lmotsPublicKeys.length != keys) {
            throw new IllegalArgumentException("Incorrect number of LMOTS public keys");
        }

        final Queue<byte[]> queue = new ArrayDeque<>(keys);
        final int nodes = keys * 2 - 1;
        final CustomMessageDigest messageDigest =
                MessageDigestCache.getInstance().getMessageDigest(lmsType.getHashAlgorithm());
        this.leafNodes = new byte[keys][lmsType.getM()];
        this.topLevelNodes = new byte[getNumberOfTopLevelNodesToStore()][lmsType.getM()];

        for (int r = nodes; r >= 1; r--) {
            final int keyIndex = r - keys;
            if (r >= keys) {
                final byte[] hash = messageDigest
                        .digest(merge(identifier, intTo4ByteArray(r), getdLeaf(), lmotsPublicKeys[keyIndex].getKey()));
                this.leafNodes[keyIndex] = hash;
                queue.add(hash);
            } else {
                final byte[] right = queue.poll();
                final byte[] left = queue.poll();
                if (right == null || left == null) {
                    throw new IllegalStateException("Uneven number of hashes");
                }
                final byte[] hash =
                        messageDigest.digest(merge(identifier, intTo4ByteArray(r), getdIntr(), left, right));
                queue.add(hash);
                if (r <= topLevelNodes.length) {
                    topLevelNodes[r - 1] = hash;
                }
            }
        }
        if (queue.peek() == null) {
            throw new IllegalStateException("Incorrect number of nodes");
        }
        return queue.poll();
    }

    private int getNumberOfTopLevelNodesToStore() {
        return Math.min(MathUtil.pow(lmsType.getH()) - 2, STORED_TOP_LEVEL_NODES);
    }

    /**
     * Returns the private key as byte array. Might throw an OutOfMemory exception!
     *
     * @return the bytes of the key object in the format:  u32str(lmsType) || u32str(lmotsType) || u32str(q) || I
     * || lmotsPrivateKey[0] || ... || lmotsPrivateKey[2^h].
     */
    @Override
    @Nonnull
    public byte[] getBytes() {
        final byte[] result = new byte[calculateSize()];

        System.arraycopy(intTo4ByteArray(this.getLmsType().getTypecode()), 0, result, 0, 4);
        System.arraycopy(intTo4ByteArray(this.getLmotsType().getTypecode()), 0, result, 4, 4);
        System.arraycopy(intTo4ByteArray(this.reservedKeys), 0, result, 8, 4);
        System.arraycopy(this.getIdentifier(), 0, result, 12, 16);

        for (int i = 0; i < this.lmotsPrivateKeys.length; i++) {
            final byte[] privateKeyBytes = lmotsPrivateKeys[i].getBytes();
            final int keyLength = privateKeyBytes.length;
            System.arraycopy(privateKeyBytes, 0, result, 28 + keyLength * i, keyLength);
        }

        return result;
    }

    @Override
    public void writeToPipedOutputStream(@Nonnull final PipedOutputStream outputStream) throws IOException {
        outputStream.write(intTo4ByteArray(this.getLmsType().getTypecode()));
        outputStream.write(intTo4ByteArray(this.getLmotsType().getTypecode()));
        outputStream.write(intTo4ByteArray(this.reservedKeys));
        outputStream.write(this.getIdentifier());
        outputStream.flush();
        for (final LMOTSPrivateKey lmotsPrivateKey : this.lmotsPrivateKeys) {
            outputStream.write(lmotsPrivateKey.getBytes());
            outputStream.flush();
        }
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final LMSPrivateKeyImpl that = (LMSPrivateKeyImpl) o;
        return qIdentifier == that.qIdentifier && Arrays.equals(lmotsPrivateKeys, that.lmotsPrivateKeys)
                && Arrays.equals(identifier, that.identifier) && lmotsType == that.lmotsType
                && lmsType == that.lmsType;
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(qIdentifier, lmotsType, lmsType);
        result = 31 * result + Arrays.hashCode(lmotsPrivateKeys);
        result = 31 * result + Arrays.hashCode(identifier);
        return result;
    }

    @Override
    @Nonnull
    public String toString() {
        return "--------------------------------------------"
                + "\nLMS private key"
                + "\nLMS type    " + String.format("%08d", lmsType.getTypecode())
                + "\nLMOTS type  " + String.format("%08d", lmotsType.getTypecode())
                + "\nI           " + Hex.encodeHexString(identifier)
                + "\nq           " + String.format("%032d", qIdentifier);
    }

    /**
     * @return The calculated key size: 4 byte LMOTS typecode + 4 byte LMS typecode + 4 byte q + 16 byte I
     * + 2^h LMOTS key size.
     */
    @Override
    public int calculateSize() {
        final int lmotsPrivateKeySize = lmotsPrivateKeys[0].calculateSize();
        return Integer.BYTES + Integer.BYTES + Integer.BYTES + identifier.length
                + MathUtil.pow(lmsType.getH()) * lmotsPrivateKeySize;
    }
}
