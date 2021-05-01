package at.andicover.hss.impl;

import at.andicover.hss.api.HSSKeyPair;
import at.andicover.hss.api.HSSPrivateKey;
import at.andicover.hss.api.HSSPublicKey;
import at.andicover.hss.api.HSSSignature;
import at.andicover.lmots.api.LMOTSType;
import at.andicover.lms.api.LMSKeyPair;
import at.andicover.lms.api.LMSPrivateKey;
import at.andicover.lms.api.LMSPublicKey;
import at.andicover.lms.api.LMSSignature;
import at.andicover.lms.api.LMSType;
import at.andicover.lms.impl.LMS;
import at.andicover.util.MathUtil;
import at.andicover.util.PersistenceUtil;
import net.jcip.annotations.ThreadSafe;

import javax.annotation.Nonnull;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static at.andicover.config.Defaults.DEFAULT_KEY_RESERVE_COUNT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

/**
 * Utility class that provides methods to create private keys, public keys, sign messages and verify
 * signatures using the Hierarchical Signature Schema.
 *
 * <p>
 * Note: This class is thread-safe if you make sure that no private key file is accessed by more than one thread.
 * Using the same file for different private keys does not make sense anyway.
 * </p>
 * <p>
 * To improve the performance of the large parameter sets on the first run you can perform a few warmup runs with a
 * smaller parameter set. This can save time of several minutes! e.g. before generating keys with
 * {@link LMSType#LMS_SHA256_M32_H25} you can generate 20 keys with {@link LMSType#LMS_SHA256_M32_H5}. With that you
 * will gain the bonus of Just-In-Time compilation and the cache will also be ready and those 10 calls will cost almost
 * no time compared to the savings later.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-6">RFC 8554 - Hierarchical Signatures</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
@ThreadSafe
@SuppressWarnings("PMD.ShortClassName")
public final class HSS {

    private HSS() {
    }

    /**
     * Generates the HSS private/public key pair based on the given level, LMS, and LMOTS parameters.
     *
     * @param levels    The tree levels.
     * @param lmsType   The LMS parameters.
     * @param lmotsType The LMOTS parameters.
     * @return The HSS keypair.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     * @throws IOException              if storing the key to disk encountered a problem.
     */
    @Nonnull
    public static HSSKeyPair generateKeys(final int levels,
                                          @Nonnull final LMSType lmsType,
                                          @Nonnull final LMOTSType lmotsType)
            throws NoSuchAlgorithmException, IOException {
        return generateKeys(levels, lmsType, lmsType, lmotsType, null, null);
    }

    /**
     * Generates the HSS private/public key pair based on the given level, LMS, and LMOTS parameters.
     *
     * @param levels    The tree levels.
     * @param lmsType   The LMS parameters.
     * @param lmotsType The LMOTS parameters.
     * @param filename  Where to store the private key on disk.
     * @return The HSS keypair.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     * @throws IOException              if storing the key to disk encountered a problem.
     */
    @Nonnull
    public static HSSKeyPair generateKeys(final int levels,
                                          @Nonnull final LMSType lmsType,
                                          @Nonnull final LMOTSType lmotsType,
                                          @Nonnull final String filename)
            throws NoSuchAlgorithmException, IOException {
        return generateKeys(levels, lmsType, lmsType, lmotsType, null, filename);
    }

    /**
     * Generates the HSS private/public key pair based on the given level, LMS, and LMOTS parameters.
     *
     * @param levels    The tree levels.
     * @param lmsType   The LMS parameters.
     * @param lmotsType The LMOTS parameters.
     * @param seed      The seed for the RNG.
     * @return The HSS keypair.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     * @throws IOException              if storing the key to disk encountered a problem.
     */
    @Nonnull
    public static HSSKeyPair generateKeys(final int levels,
                                          @Nonnull final LMSType lmsType,
                                          @Nonnull final LMOTSType lmotsType,
                                          final byte[] seed) throws NoSuchAlgorithmException, IOException {
        return generateKeys(levels, lmsType, lmsType, lmotsType, seed, null);
    }

    /**
     * Generates the HSS private/public key pair based on the given level, LMS, and LMOTS parameters.
     *
     * @param levels    The tree levels.
     * @param lmsType   The LMS parameters.
     * @param lmotsType The LMOTS parameters.
     * @param seed      The seed for the RNG.
     * @param filename  Where to store the private key on disk.
     * @return The HSS keypair.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     * @throws IOException              if storing the key to disk encountered a problem.
     */
    @Nonnull
    public static HSSKeyPair generateKeys(final int levels,
                                          @Nonnull final LMSType lmsType,
                                          @Nonnull final LMOTSType lmotsType,
                                          final byte[] seed,
                                          @Nonnull final String filename) throws NoSuchAlgorithmException, IOException {
        return generateKeys(levels, lmsType, lmsType, lmotsType, seed, filename);
    }

    /**
     * Generates the HSS private/public key pair based on the given level, LMS, and LMOTS parameters.
     *
     * @param levels             The tree levels.
     * @param lmsTypeFirstLevel  The LMS parameters for the first level.
     * @param lmsTypeOtherLevels The LMS parameters for all other levels.
     * @param lmotsType          The LMOTS parameters.
     * @param filename           Where to store the private key on disk.
     * @return The HSS keypair.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     * @throws IOException              if storing the key to disk encountered a problem.
     */
    @Nonnull
    public static HSSKeyPair generateKeys(final int levels,
                                          @Nonnull final LMSType lmsTypeFirstLevel,
                                          @Nonnull final LMSType lmsTypeOtherLevels,
                                          @Nonnull final LMOTSType lmotsType,
                                          final String filename) throws NoSuchAlgorithmException, IOException {
        return generateKeys(levels, lmsTypeFirstLevel, lmsTypeOtherLevels, lmotsType, null, filename);
    }

    /**
     * Generates the HSS private/public key pair based on the given level, LMS, and LMOTS parameters.
     *
     * @param levels             The tree levels.
     * @param lmsTypeFirstLevel  The LMS parameters for the first level.
     * @param lmsTypeOtherLevels The LMS parameters for all other levels.
     * @param lmotsType          The LMOTS parameters.
     * @param seed               The seed for the RNG.
     * @param filename           Where to store the private key on disk.
     * @return The HSS keypair.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     * @throws IOException              if storing the key to disk encountered a problem.
     */
    @Nonnull
    public static HSSKeyPair generateKeys(final int levels,
                                          @Nonnull final LMSType lmsTypeFirstLevel,
                                          @Nonnull final LMSType lmsTypeOtherLevels,
                                          @Nonnull final LMOTSType lmotsType,
                                          final byte[] seed,
                                          final String filename) throws NoSuchAlgorithmException, IOException {
        requireNonNull(lmsTypeFirstLevel);
        requireNonNull(lmsTypeOtherLevels);
        requireNonNull(lmotsType);

        if (levels <= 0 || levels > 8) {
            throw new IllegalArgumentException("Incorrect number of levels");
        }

        final LMSPrivateKey[] privateKeys = new LMSPrivateKey[levels];
        final LMSPublicKey[] publicKeys = new LMSPublicKey[levels];
        final LMSSignature[] signatures = new LMSSignature[levels];

        LMSKeyPair lmsKeyPair = LMS.generateKeys(lmsTypeFirstLevel, lmotsType, seed);
        privateKeys[0] = lmsKeyPair.getPrivateKey();
        publicKeys[0] = lmsKeyPair.getPublicKey();

        //If we have more than one level we need to reserve just one key in the top level.
        if (levels > 1) {
            privateKeys[0].reserveKeys(1);
        } else {
            privateKeys[0].reserveKeys(DEFAULT_KEY_RESERVE_COUNT);
        }

        for (int i = 1; i < levels; i++) {
            lmsKeyPair = LMS.generateKeys(lmsTypeOtherLevels, lmotsType,
                    SecureRandom.getInstanceStrong().generateSeed(lmotsType.getN()));
            privateKeys[i] = lmsKeyPair.getPrivateKey();
            publicKeys[i] = lmsKeyPair.getPublicKey();

            final LMSPrivateKey lmsPrivateKey = privateKeys[i - 1];
            if (!lmsPrivateKey.hasReservedKey()) {
                lmsPrivateKey.reserveKeys(DEFAULT_KEY_RESERVE_COUNT);
            }
            signatures[i - 1] = LMS.generateSignature(publicKeys[i].getKey(), lmsPrivateKey);

            if (i == levels - 1 && !privateKeys[i].hasReservedKey()) {
                privateKeys[i].reserveKeys(DEFAULT_KEY_RESERVE_COUNT);
            }
        }

        final HSSPublicKey hssPublicKey = new HSSPublicKeyImpl(levels, publicKeys[0]);
        final HSSPrivateKey hssPrivateKey =
                new HSSPrivateKeyImpl(levels, privateKeys, publicKeys, signatures, filename);
        PersistenceUtil.storeKey(hssPrivateKey);
        return new HSSKeyPairImpl(hssPrivateKey, hssPublicKey);
    }

    /**
     * Generates a HSS signature for the given message with the given HSS private key.
     *
     * @param message    The original message.
     * @param privateKey The HSS private key.
     * @return The HSS signature.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     * @throws IOException              if storing the key to disk encountered a problem.
     */
    @Nonnull
    public static HSSSignature generateSignature(@Nonnull final String message,
                                                 @Nonnull final HSSPrivateKey privateKey)
            throws NoSuchAlgorithmException, IOException {
        requireNonNull(message);

        return generateSignature(message.getBytes(UTF_8), privateKey);
    }

    /**
     * Generates a HSS signature for the given message with the given HSS private key.
     *
     * @param message    The bytes of the original message.
     * @param privateKey The HSS private key.
     * @return The HSS signature.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     * @throws IOException              if storing the key to disk encountered a problem.
     */
    @Nonnull
    public static HSSSignature generateSignature(@Nonnull final byte[] message,
                                                 @Nonnull final HSSPrivateKey privateKey)
            throws NoSuchAlgorithmException, IOException {
        requireNonNull(message);
        requireNonNull(privateKey);

        final int level = privateKey.getLevels();
        int d = level;
        while (privateKey.getLmsPrivateKeys()[d - 1].getQIdentifier() == MathUtil
                .pow(privateKey.getLmsPrivateKeys()[d - 1].getLmsType().getH())) {
            d--;
            if (d == 0) {
                throw new IllegalStateException("Keys exceeded");
            }
        }
        while (d < level) {
            final LMSKeyPair lmsKeyPair = LMS.generateKeys(privateKey.getLmsPrivateKeys()[0].getLmsType(),
                    privateKey.getLmsPrivateKeys()[0].getLmotsType());
            privateKey.getLmsPrivateKeys()[d] = lmsKeyPair.getPrivateKey();
            privateKey.getLmsPublicKeys()[d] = lmsKeyPair.getPublicKey();

            final LMSPrivateKey lmsPrivateKey = privateKey.getLmsPrivateKeys()[d - 1];
            if (!lmsPrivateKey.hasReservedKey() && !lmsPrivateKey.isExhausted()) {
                lmsPrivateKey.reserveKeys(DEFAULT_KEY_RESERVE_COUNT);
                PersistenceUtil.storeKey(privateKey);
            }
            privateKey.getSignatures()[d - 1] =
                    LMS.generateSignature(privateKey.getLmsPublicKeys()[d].getKey(), lmsPrivateKey);
            d++;
        }

        final LMSPrivateKey lmsPrivateKey = privateKey.getLmsPrivateKeys()[level - 1];
        if (!lmsPrivateKey.hasReservedKey()) {
            lmsPrivateKey.reserveKeys(DEFAULT_KEY_RESERVE_COUNT);
            PersistenceUtil.storeKey(privateKey);
        }
        final LMSSignature messageSignature = LMS.generateSignature(message, lmsPrivateKey);
        privateKey.getSignatures()[level - 1] = messageSignature;

        final LMSSignature[] signatures = new LMSSignature[level];
        final LMSPublicKey[] publicKeys = new LMSPublicKey[level];

        for (int i = 0; i < level - 1; i++) {
            signatures[i] = privateKey.getSignatures()[i];
            publicKeys[i] = privateKey.getLmsPublicKeys()[i + 1];
        }
        signatures[level - 1] = messageSignature;
        return new HSSSignatureImpl(level - 1, signatures, publicKeys);
    }

    /**
     * Verifies the given HSS signature. Verifies all signatures in the signature chain.
     *
     * @param message   The original message.
     * @param signature The HSS signature of the message.
     * @param publicKey The HSS public key.
     * @return true/false if the given signature is valid.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     */
    public static boolean verifySignature(@Nonnull final String message,
                                          @Nonnull final HSSSignature signature,
                                          @Nonnull final HSSPublicKey publicKey)
            throws NoSuchAlgorithmException {
        requireNonNull(message);

        return verifySignature(message.getBytes(UTF_8), signature, publicKey);
    }

    /**
     * Verifies the given HSS signature. Verifies all signatures in the signature chain.
     *
     * @param message   The bytes of the original message.
     * @param signature The HSS signature of the message.
     * @param publicKey The HSS public key.
     * @return true/false if the given signature is valid.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     */
    public static boolean verifySignature(@Nonnull final byte[] message,
                                          @Nonnull final HSSSignature signature,
                                          @Nonnull final HSSPublicKey publicKey)
            throws NoSuchAlgorithmException {

        if (signature.getNumberOfSignedPublicKeys() + 1 != publicKey.getLevels() || publicKey.getLevels() <= 0) {
            throw new IllegalArgumentException("Incorrect number of signed private keys in signature");
        }

        LMSPublicKey pub = publicKey.getPublicKey();
        for (int i = 0; i < signature.getNumberOfSignedPublicKeys(); i++) {
            if (!LMS.verifySignature(signature.getLmsPublicKeys()[i].getKey(), signature.getSignatures()[i], pub)) {
                return false;
            }
            pub = signature.getLmsPublicKeys()[i];
        }

        return LMS.verifySignature(message, signature.getSignatures()[signature.getNumberOfSignedPublicKeys()], pub);
    }

    /**
     * Builds an HSS private key from a given byte array.
     *
     * @param inputStream The inputstream that provides the bytes of the key.
     * @param filename    The filename that contains the private key. After using the key it will be stored in this
     *                    file again.
     * @return the recreated HSSPrivateKey instance.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     * @throws IOException              if stream cannot be read.
     */
    @Nonnull
    public static HSSPrivateKey buildPrivateKey(@Nonnull final DataInputStream inputStream,
                                                final String filename)
            throws NoSuchAlgorithmException, IOException {
        return new HSSPrivateKeyImpl(inputStream, filename);
    }

    /**
     * Builds an HSS public key from a given byte array.
     *
     * @param inputStream The inputstream that provides the bytes of the key.
     * @return the recreated HSSPublicKey instance.
     * @throws IOException if stream cannot be read.
     */
    @Nonnull
    public static HSSPublicKey buildPublicKey(@Nonnull final DataInputStream inputStream) throws IOException {
        return new HSSPublicKeyImpl(inputStream);
    }

    /**
     * Builds an HSS signature from a given byte array.
     *
     * @param inputStream The inputstream that provides the bytes of the key.
     * @return the recreated HSSSignature instance.
     * @throws IOException if stream cannot be read.
     */
    @Nonnull
    public static HSSSignature buildSignature(@Nonnull final DataInputStream inputStream) throws IOException {
        return new HSSSignatureImpl(inputStream);
    }
}
