package at.andicover.lms.impl;

import at.andicover.digest.api.CustomMessageDigest;
import at.andicover.digest.impl.MessageDigestCache;
import at.andicover.lmots.api.LMOTSPrivateKey;
import at.andicover.lmots.api.LMOTSPublicKey;
import at.andicover.lmots.api.LMOTSSignature;
import at.andicover.lmots.api.LMOTSType;
import at.andicover.lmots.impl.LMOTS;
import at.andicover.lms.api.LMSKeyPair;
import at.andicover.lms.api.LMSPrivateKey;
import at.andicover.lms.api.LMSPublicKey;
import at.andicover.lms.api.LMSSignature;
import at.andicover.lms.api.LMSType;
import at.andicover.util.MathUtil;
import at.andicover.util.ThreadUtil;
import net.jcip.annotations.ThreadSafe;

import javax.annotation.Nonnull;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;

import static at.andicover.config.Defaults.RANDOM_NUMBER_ALGORITHM;
import static at.andicover.util.ByteUtil.intTo4ByteArray;
import static at.andicover.util.ByteUtil.merge;
import static at.andicover.util.SecurityString.getdIntr;
import static at.andicover.util.SecurityString.getdLeaf;
import static at.andicover.util.ThreadUtil.shutdownThreadExecutor;
import static java.util.Objects.requireNonNull;

/**
 * Utility class that provides methods to create private key, public key, sign a message and verify a signature
 * using the Leighton-Micali Signature schema.
 * <p>
 * To improve the performance of the large parameter sets on the first run you can perform a few warmup runs with a
 * smaller parameter set. This can save time of several minutes! e.g. before generating keys with
 * {@link LMSType#LMS_SHA256_M32_H25} you can generate 20 keys with {@link LMSType#LMS_SHA256_M32_H5}. With that you
 * will gain the bonus of Just-In-Time compilation and the cache will also be ready and those 10 calls will cost almost
 * no time compared to the savings later.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-5">RFC 8554 - LMS</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
@SuppressWarnings({"PMD.TooManyMethods", "PMD.ShortClassName", "PMD.UseVarargs"})
@ThreadSafe
public final class LMS {

    private LMS() {
    }

    /**
     * Generate an LMS private and public key pair.
     *
     * @param lmsType   the LMS parameter.
     * @param lmotsType the LMOTS parameter.
     * @return the LMS keypair.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     */
    @Nonnull
    public static LMSKeyPair generateKeys(@Nonnull final LMSType lmsType,
                                          @Nonnull final LMOTSType lmotsType) throws NoSuchAlgorithmException {
        return generateKeys(lmsType, lmotsType, null);
    }

    /**
     * Generate an LMS private and public key pair.
     *
     * @param lmsType   the LMS parameter.
     * @param lmotsType the LMOTS parameter.
     * @param seed      the seed for the RNG.
     * @return the LMS keypair.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     */
    @Nonnull
    public static LMSKeyPair generateKeys(@Nonnull final LMSType lmsType,
                                          @Nonnull final LMOTSType lmotsType,
                                          final byte[] seed) throws NoSuchAlgorithmException {
        requireNonNull(lmsType);
        requireNonNull(lmotsType);

        final int keys = MathUtil.pow(lmsType.getH());
        final LMOTSPrivateKey[] lmotsPrivateKeys = new LMOTSPrivateKey[keys];
        final LMOTSPublicKey[] lmotsPublicKeys = new LMOTSPublicKey[keys];
        final byte[] identifier = new byte[16];
        byte[] seedVolatile = seed;
        final SecureRandom secureRandom = SecureRandom.getInstance(RANDOM_NUMBER_ALGORITHM);
        final ExecutorService executorService = ThreadUtil.createNewThreadExecutor();

        // If we got no seed we generate one.
        if (seedVolatile == null) {
            seedVolatile = secureRandom.generateSeed(lmotsType.getN());
        }

        secureRandom.setSeed(seedVolatile);
        secureRandom.nextBytes(identifier);

        secureRandom.setSeed(seedVolatile);
        secureRandom.nextBytes(seedVolatile);
        final CustomMessageDigest digest =
                MessageDigestCache.getInstance().getMessageDigest(lmotsType.getHashAlgorithm());

        // Create all LM-OTS key pairs using threads.
        for (int q = 0; q < keys; q++) {
            final int finalQ = q;
            // We append the Q identifier to the seed and hash it to get a seed with uniform length again.
            // With this approach we have deterministic seeds for all keys and can fully utilize all cores because
            // we do not need to calculate the next seed for each task.
            final byte[] finalSeed = digest.digest(merge(seedVolatile, intTo4ByteArray(q)));
            executorService.execute(() -> {
                if (!Thread.currentThread().isInterrupted()) {
                    try {
                        final LMOTSPrivateKey lmotsPrivateKey =
                                LMOTS.generatePrivateKey(lmotsType, identifier, finalQ, finalSeed);
                        lmotsPrivateKeys[finalQ] = lmotsPrivateKey;
                        lmotsPublicKeys[finalQ] = LMOTS.generatePublicKey(lmotsPrivateKey);
                    } catch (NoSuchAlgorithmException ex) {
                        throw new IllegalStateException(ex);
                    }
                }
            });
        }
        shutdownThreadExecutor(executorService);

        final LMSPrivateKey privateKey = new LMSPrivateKeyImpl(lmsType, lmotsType, lmotsPrivateKeys, identifier);
        return new LMSKeyPairImpl(privateKey,
                new LMSPublicKeyImpl(privateKey, privateKey.calculateRoot(lmotsPublicKeys)));
    }

    /**
     * Generates a LMS public key from the given LMS private key.
     *
     * @param privateKey The LMS private key.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     */

    static void generatePublicKey(@Nonnull final LMSPrivateKey privateKey,
                                  @Nonnull final LMOTSPrivateKey[] lmotsPrivateKeys)
            throws NoSuchAlgorithmException {
        requireNonNull(privateKey);
        requireNonNull(lmotsPrivateKeys);

        final LMSType lmsType = privateKey.getLmsType();
        final int h = lmsType.getH();
        final int keys = MathUtil.pow(h);
        final LMOTSPublicKey[] lmotsPublicKeys = new LMOTSPublicKey[keys];
        final ExecutorService executorService = ThreadUtil.createNewThreadExecutor();

        // Create all LM-OTS public keys using threads.
        for (int i = 0; i < keys; i++) {
            final int finalI = i;
            executorService.execute(() -> {
                if (!Thread.currentThread().isInterrupted()) {
                    try {
                        lmotsPublicKeys[finalI] = LMOTS.generatePublicKey(lmotsPrivateKeys[finalI]);
                    } catch (NoSuchAlgorithmException ex) {
                        throw new IllegalStateException(ex);
                    }
                }
            });
        }
        shutdownThreadExecutor(executorService);
        privateKey.calculateRoot(lmotsPublicKeys);
    }

    /**
     * Generates a LMS signature for the given message with the given LMS private key.
     * Uses the next unused LMOTS private key to build an LMOTS signature.
     * This key and the path to the LMS root node are then used for the LMS signature.
     *
     * @param message    The original message.
     * @param privateKey The LMS private key.
     * @return The LMS signature.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     */
    @Nonnull
    public static LMSSignature generateSignature(@Nonnull final String message,
                                                 @Nonnull final LMSPrivateKey privateKey)
            throws NoSuchAlgorithmException {
        requireNonNull(message);

        return generateSignature(message.getBytes(StandardCharsets.UTF_8), privateKey);
    }

    /**
     * Generates a LMS signature for the given message with the given LMS private key.
     * Uses the next unused LMOTS private key to build an LMOTS signature.
     * This key and the path to the LMS root node are then used for the LMS signature.
     *
     * @param message    The bytes of the original message.
     * @param privateKey The LMS private key.
     * @return The LMS signature.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     */
    @Nonnull
    public static LMSSignature generateSignature(@Nonnull final byte[] message,
                                                 @Nonnull final LMSPrivateKey privateKey)
            throws NoSuchAlgorithmException {
        requireNonNull(message);
        requireNonNull(privateKey);

        final LMOTSPrivateKey lmotsPrivateKey = privateKey.getNextLmotsKey();
        final LMOTSSignature lmotsSignature = LMOTS.generateSignature(message, lmotsPrivateKey);

        final int pathNumber = lmotsPrivateKey.getQIdentifier() + MathUtil.pow(privateKey.getLmsType().getH());
        return new LMSSignatureImpl(privateKey.getLmsType(), lmotsSignature, lmotsPrivateKey.getQIdentifier(),
                privateKey.getPath(pathNumber));
    }

    /**
     * Generates a LMS public key candidate for the signature verification. Uses the given LMOTS public key and
     * the path to the root node of the LMS tree to build the LMS public key candidate.
     *
     * @param signature               The LMS signature.
     * @param identifier              The 16 byte identifier of the LMS public/private key pair.
     * @param generatedLmotsPublicKey The generated LMOTS public key candidate.
     * @return The generated LMS public key candidate.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     */
    @Nonnull
    public static LMSPublicKey generatePublicKey(@Nonnull final LMSSignature signature,
                                                 @Nonnull final byte[] identifier,
                                                 @Nonnull final LMOTSPublicKey generatedLmotsPublicKey)
            throws NoSuchAlgorithmException {
        requireNonNull(signature);
        requireNonNull(identifier);
        requireNonNull(generatedLmotsPublicKey);
        validateSignature(signature);

        final LMSType lmsType = signature.getLmsType();
        final CustomMessageDigest messageDigest =
                MessageDigestCache.getInstance().getMessageDigest(lmsType.getHashAlgorithm());
        int nodeNum = signature.getQIdentifier() + MathUtil.pow(lmsType.getH());
        byte[] tmp = messageDigest
                .digest(merge(identifier, intTo4ByteArray(nodeNum), getdLeaf(), generatedLmotsPublicKey.getKey()));

        int i = 0;
        while (nodeNum > 1) {
            if (nodeNum % 2 == 0) {
                tmp = messageDigest.digest(merge(identifier, intTo4ByteArray(nodeNum / 2), getdIntr(), tmp,
                        signature.getPath()[i]));
            } else {
                tmp = messageDigest
                        .digest(merge(identifier, intTo4ByteArray(nodeNum / 2), getdIntr(), signature.getPath()[i],
                                tmp));
            }
            nodeNum /= 2;
            i++;
        }
        return new LMSPublicKeyImpl(signature.getLmsType(), signature.getLmotsSignature().getLmotsType(), identifier,
                tmp);
    }

    /**
     * Verifies the given LMS signature. Generates an LMOTS public key candidate from the LMOTS signature
     * and uses this key and the path to the root node of the LMS tree to build the LMS public key candidate.
     * If the given public key and the calculated public key are equal then the signature is valid.
     *
     * @param message   The original message.
     * @param signature The LMS signature of the message.
     * @param publicKey The LMS public key.
     * @return true/false if the given signature is valid.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     */
    public static boolean verifySignature(@Nonnull final String message,
                                          @Nonnull final LMSSignature signature,
                                          @Nonnull final LMSPublicKey publicKey)
            throws NoSuchAlgorithmException {
        requireNonNull(message);

        return verifySignature(message.getBytes(StandardCharsets.UTF_8), signature, publicKey);
    }

    /**
     * Verifies the given LMS signature. Generates an LMOTS public key candidate from the LMOTS signature
     * and uses this key and the path to the root node of the LMS tree to build the LMS public key candidate.
     * If the given public key and the calculated public key are equal then the signature is valid.
     *
     * @param message   The bytes of the original message.
     * @param signature The LMS signature of the message.
     * @param publicKey The LMS public key.
     * @return true/false if the given signature is valid.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     */
    public static boolean verifySignature(@Nonnull final byte[] message,
                                          @Nonnull final LMSSignature signature,
                                          @Nonnull final LMSPublicKey publicKey)
            throws NoSuchAlgorithmException {
        requireNonNull(message);
        requireNonNull(signature);
        requireNonNull(publicKey);

        validatePublicKey(publicKey);
        validateSignature(signature);

        if (publicKey.getLmotsType() != signature.getLmotsSignature().getLmotsType()
                || publicKey.getLmsType() != signature.getLmsType()) {
            throw new IllegalArgumentException("Incompatible typecodes");
        }

        final int qIdentifier = signature.getQIdentifier();
        final byte[] identifier = publicKey.getIdentifier();
        final LMOTSPublicKey generatedLmotsPublicKey =
                LMOTS.generatePublicKey(message, signature.getLmotsSignature(), qIdentifier, identifier);
        final LMSPublicKey generatedLMSPublicKey =
                generatePublicKey(signature, publicKey.getIdentifier(), generatedLmotsPublicKey);
        return Arrays.equals(generatedLMSPublicKey.getKey(), publicKey.getKey());
    }

    private static void validatePublicKey(@Nonnull final LMSPublicKey publicKey) {
        final LMSType lmsType = publicKey.getLmsType();

        if (publicKey.getKey().length != lmsType.getM() || publicKey.getIdentifier().length != 16) {
            throw new IllegalArgumentException("Invalid public key length");
        }
    }

    private static void validateSignature(@Nonnull final LMSSignature signature) {
        final LMSType lmsType = signature.getLmsType();

        if (signature.getPath().length != lmsType.getH() || signature.getPath()[0].length != lmsType.getM()) {
            throw new IllegalArgumentException("Invalid signature length");
        }
    }

    /**
     * Builds an LMS private key from a given byte array.
     *
     * @param inputStream The inputstream that provides the bytes of the key.
     * @return the recreated LMSPrivateKey instance.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     * @throws IOException              if stream cannot be read.
     */
    @Nonnull
    public static LMSPrivateKey buildPrivateKey(@Nonnull final DataInputStream inputStream)
            throws NoSuchAlgorithmException, IOException {
        return new LMSPrivateKeyImpl(inputStream);
    }

    /**
     * Builds an LMS public key from a given byte array.
     *
     * @param inputStream The inputstream that provides the bytes of the key.
     * @return the recreated LMSPublicKey instance.
     * @throws IOException if stream cannot be read.
     */
    @Nonnull
    public static LMSPublicKey buildPublicKey(@Nonnull final DataInputStream inputStream) throws IOException {
        return new LMSPublicKeyImpl(inputStream);
    }

    /**
     * Builds an LMS signature from a given byte array.
     *
     * @param inputStream The inputstream that provides the bytes of the key.
     * @return the recreated LMSSignature instance.
     * @throws IOException if stream cannot be read.
     */
    @Nonnull
    public static LMSSignature buildSignature(@Nonnull final DataInputStream inputStream) throws IOException {
        return new LMSSignatureImpl(inputStream);
    }
}