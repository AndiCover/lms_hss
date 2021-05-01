package at.andicover.lmots.impl;

import at.andicover.digest.api.CustomMessageDigest;
import at.andicover.digest.impl.MessageDigestCache;
import at.andicover.lmots.api.LMOTSPrivateKey;
import at.andicover.lmots.api.LMOTSPublicKey;
import at.andicover.lmots.api.LMOTSSignature;
import at.andicover.lmots.api.LMOTSType;
import at.andicover.util.MathUtil;
import net.jcip.annotations.ThreadSafe;

import javax.annotation.Nonnull;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import static at.andicover.config.Defaults.RANDOM_NUMBER_ALGORITHM;
import static at.andicover.util.ByteUtil.intTo1ByteArray;
import static at.andicover.util.ByteUtil.intTo2ByteArray;
import static at.andicover.util.ByteUtil.intTo4ByteArray;
import static at.andicover.util.ByteUtil.merge;
import static at.andicover.util.SecurityString.getdMesg;
import static at.andicover.util.SecurityString.getdPblc;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

/**
 * Utility class that provides methods to create private keys, public keys, sign messages and verify signatures
 * using the Winternitz LMOTS schema.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-4">RFC 8554 - LM-OTS</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
@SuppressWarnings("PMD.TooManyMethods")
@ThreadSafe
public final class LMOTS {

    private LMOTS() {
    }

    /**
     * Generates the LMOTS private key based on the given LMOTS parameters.
     * Creates P random N-byte strings.
     *
     * @param parameters the LMOTS parameters.
     * @return the generated LMOTS private key.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     */
    @Nonnull
    public static LMOTSPrivateKey generatePrivateKey(@Nonnull final LMOTSType parameters)
            throws NoSuchAlgorithmException {
        requireNonNull(parameters);

        return generatePrivateKey(parameters, new byte[16], 0, null);
    }

    /**
     * Generates the LMOTS private key based on the given LMOTS parameters.
     * Creates P random N-byte strings.
     *
     * @param parameters  the LMOTS parameters.
     * @param identifier  the identifier.
     * @param qIdentifier the qIdentifier.
     * @return the generated LMOTS private key.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     */
    @Nonnull
    public static LMOTSPrivateKey generatePrivateKey(@Nonnull final LMOTSType parameters,
                                                     @Nonnull final byte[] identifier,
                                                     final int qIdentifier)
            throws NoSuchAlgorithmException {
        return generatePrivateKey(parameters, identifier, qIdentifier, null);
    }

    /**
     * Generates the LMOTS private key based on the given LMOTS parameters.
     * Creates P random N-byte strings.
     *
     * @param parameters  the LMOTS parameters.
     * @param identifier  the identifier.
     * @param qIdentifier the qIdentifier.
     * @param seed        the seed for the RNG.
     * @return the generated LMOTS private key.
     * @throws NoSuchAlgorithmException if the secure random algorithm does not exist.
     */
    @Nonnull
    public static LMOTSPrivateKey generatePrivateKey(@Nonnull final LMOTSType parameters,
                                                     @Nonnull final byte[] identifier,
                                                     final int qIdentifier,
                                                     final byte[] seed)
            throws NoSuchAlgorithmException {
        requireNonNull(parameters);
        requireNonNull(identifier);

        final byte[] finalSeed;
        if (seed != null) {
            finalSeed = seed;
        } else {
            final SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            finalSeed = secureRandom.generateSeed(parameters.getN());
        }

        return new LMOTSPrivateKeyImpl(parameters, identifier, qIdentifier, finalSeed);
    }

    /**
     * Generates the LMOTS public key for the given LMOTS private key.
     * Hashes each private key 2^w - 1 times to create the public key.
     *
     * @param privateKey the LMOTS private key.
     * @return the generated LMOTS public key.
     * @throws NoSuchAlgorithmException if the selected hash algorithm does not exist.
     */
    @Nonnull
    public static LMOTSPublicKey generatePublicKey(@Nonnull final LMOTSPrivateKey privateKey)
            throws NoSuchAlgorithmException {
        requireNonNull(privateKey);

        final byte[] identifier = privateKey.getIdentifier();
        final int qIdentifier = privateKey.getQIdentifier();
        final LMOTSType lmotsType = privateKey.getLmotsType();
        final int hashIterations = getHashIterations(lmotsType.getW());
        final CustomMessageDigest messageDigest =
                MessageDigestCache.getInstance().getMessageDigest(lmotsType.getHashAlgorithm());
        final byte[] y = new byte[lmotsType.getP() * lmotsType.getN()];

        final SecureRandom secureRandom = SecureRandom.getInstance(RANDOM_NUMBER_ALGORITHM);
        secureRandom.setSeed(privateKey.getSeed());

        byte[] tmp = new byte[lmotsType.getN()];
        for (int i = 0; i < lmotsType.getP(); i++) {
            secureRandom.nextBytes(tmp);
            for (int j = 0; j < hashIterations; j++) {
                tmp = messageDigest
                        .digest(merge(identifier, intTo4ByteArray(qIdentifier), intTo2ByteArray(i), intTo1ByteArray(j),
                                tmp));
            }
            System.arraycopy(tmp, 0, y, lmotsType.getN() * i, tmp.length);
        }
        return new LMOTSPublicKeyImpl(lmotsType, privateKey,
                messageDigest.digest(merge(identifier, intTo4ByteArray(qIdentifier), getdPblc(), y)));
    }

    /**
     * Generates a LMOTS signature for the given message.
     * Hashes the message with the given hash algorithm. Appends the calculated checksum to that hash.
     * The result is then hashed several times according to the result of coef(..).
     *
     * @param message    The bytes of the message to sign.
     * @param privateKey The private key.
     * @return The LMOTS signature.
     * @throws NoSuchAlgorithmException if the selected hash algorithm does not exist.
     */
    @Nonnull
    public static LMOTSSignature generateSignature(@Nonnull final String message,
                                                   @Nonnull final LMOTSPrivateKey privateKey)
            throws NoSuchAlgorithmException {
        requireNonNull(message);

        return generateSignature(message.getBytes(UTF_8), privateKey);
    }

    /**
     * Generates a LMOTS signature for the given message.
     * Hashes the message with the given hash algorithm. Appends the calculated checksum to that hash.
     * The result is then hashed several times according to the result of coef(..).
     *
     * @param message    The message to sign.
     * @param privateKey The private key.
     * @return The LMOTS signature.
     * @throws NoSuchAlgorithmException if the selected hash algorithm does not exist.
     */
    @Nonnull
    public static LMOTSSignature generateSignature(@Nonnull final byte[] message,
                                                   @Nonnull final LMOTSPrivateKey privateKey)
            throws NoSuchAlgorithmException {
        requireNonNull(message);
        requireNonNull(privateKey);

        final byte[] identifier = privateKey.getIdentifier();
        final int qIdentifier = privateKey.getQIdentifier();

        final LMOTSType lmotsType = privateKey.getLmotsType();
        final byte[] c = new byte[lmotsType.getN()];
        final CustomMessageDigest messageDigest =
                MessageDigestCache.getInstance().getMessageDigest(lmotsType.getHashAlgorithm());
        SecureRandom.getInstanceStrong().nextBytes(c);

        final byte[] q = messageDigest.digest(merge(identifier, intTo4ByteArray(qIdentifier), getdMesg(), c, message));
        final byte[] hashedMessageWithChecksum = merge(q, checksum(q, lmotsType));
        final byte[][] keys = new byte[lmotsType.getP()][lmotsType.getN()];

        final byte[][] privateKeys = privateKey.getKeys();
        final int hashIterations = getHashIterations(lmotsType.getW());
        for (int i = 0; i < lmotsType.getP(); i++) {
            final int a = coef(hashedMessageWithChecksum, i, lmotsType.getW(), hashIterations);
            byte[] tempKey = privateKeys[i];
            for (int j = 0; j < a; j++) {
                tempKey = messageDigest
                        .digest(merge(identifier, intTo4ByteArray(qIdentifier), intTo2ByteArray(i), intTo1ByteArray(j),
                                tempKey));
            }
            keys[i] = tempKey;
        }
        return new LMOTSSignatureImpl(privateKey.getLmotsType(), c, keys);
    }

    /**
     * Verifies the given signature for the given message and public key.
     * The signature is hashed several times according to the result of coef(..).
     * The result must be equal to the public key. If not the verification was not successful.
     *
     * @param message   The original message.
     * @param signature The message signature.
     * @param publicKey The public key.
     * @return true/false.
     * @throws NoSuchAlgorithmException if the selected hash algorithm does not exist.
     */
    public static boolean verifySignature(@Nonnull final String message,
                                          @Nonnull final LMOTSSignature signature,
                                          @Nonnull final LMOTSPublicKey publicKey)
            throws NoSuchAlgorithmException {
        requireNonNull(message);

        return verifySignature(message.getBytes(UTF_8), signature, publicKey);
    }

    /**
     * Verifies the given signature for the given message and public key.
     * The signature is hashed several times according to the result of coef(..).
     * The result must be equal to the public key. If not the verification was not successful.
     *
     * @param message   The bytes of the original message.
     * @param signature The message signature.
     * @param publicKey The public key.
     * @return true/false.
     * @throws NoSuchAlgorithmException if the selected hash algorithm does not exist.
     */
    public static boolean verifySignature(@Nonnull final byte[] message,
                                          @Nonnull final LMOTSSignature signature,
                                          @Nonnull final LMOTSPublicKey publicKey)
            throws NoSuchAlgorithmException {
        requireNonNull(message);
        requireNonNull(signature);
        requireNonNull(publicKey);

        validatePublicKey(publicKey);

        if (publicKey.getLmotsType() != signature.getLmotsType()) {
            throw new IllegalArgumentException("Incompatible typecodes");
        }

        final int qIdentifier = publicKey.getQIdentifier();
        final byte[] identifier = publicKey.getIdentifier();
        final LMOTSPublicKey generatedPublicKey = generatePublicKey(message, signature, qIdentifier, identifier);

        return Arrays.equals(generatedPublicKey.getKey(), publicKey.getKey());
    }

    /**
     * Generates an LMOTS public key candidate from the given message and signature for signature verification.
     *
     * @param message        The original message.
     * @param lmotsSignature The provided message signature.
     * @param qIdentifier    The leaf number q of the hash tree
     * @param identifier     The 16 byte identifier of the LMS public/private key pair.
     * @return the calculated LMOTS public key.
     * @throws NoSuchAlgorithmException if the selected hash algorithm does not exist.
     */
    @Nonnull
    public static LMOTSPublicKey generatePublicKey(@Nonnull final String message,
                                                   @Nonnull final LMOTSSignature lmotsSignature,
                                                   final int qIdentifier,
                                                   @Nonnull final byte[] identifier)
            throws NoSuchAlgorithmException {
        requireNonNull(message);

        return generatePublicKey(message.getBytes(UTF_8), lmotsSignature, qIdentifier, identifier);
    }

    /**
     * Generates an LMOTS public key candidate from the given message and signature for signature verification.
     *
     * @param message        The bytes of the original message.
     * @param lmotsSignature The provided message signature.
     * @param qIdentifier    The leaf number q of the hash tree
     * @param identifier     The 16 byte identifier of the LMS public/private key pair.
     * @return the calculated LMOTS public key.
     * @throws NoSuchAlgorithmException if the selected hash algorithm does not exist.
     */
    @Nonnull
    public static LMOTSPublicKey generatePublicKey(@Nonnull final byte[] message,
                                                   @Nonnull final LMOTSSignature lmotsSignature,
                                                   final int qIdentifier,
                                                   @Nonnull final byte[] identifier)
            throws NoSuchAlgorithmException {
        requireNonNull(message);
        requireNonNull(lmotsSignature);
        requireNonNull(identifier);
        validateSignature(lmotsSignature);

        final LMOTSType lmotsType = lmotsSignature.getLmotsType();
        final byte[] c = lmotsSignature.getC();
        final long iterations = getHashIterations(lmotsType.getW());
        final CustomMessageDigest messageDigest =
                MessageDigestCache.getInstance().getMessageDigest(lmotsType.getHashAlgorithm());
        byte[] z = new byte[0];

        final byte[] q = messageDigest.digest(merge(identifier, intTo4ByteArray(qIdentifier), getdMesg(), c, message));
        final byte[] hashedMessageWithChecksum = merge(q, checksum(q, lmotsType));

        final int hashIterations = getHashIterations(lmotsType.getW());
        for (int i = 0; i < lmotsType.getP(); i++) {
            final int a = coef(hashedMessageWithChecksum, i, lmotsType.getW(), hashIterations);
            byte[] tempKey = lmotsSignature.getKeys()[i];
            for (int j = a; j < iterations; j++) {
                tempKey = messageDigest
                        .digest(merge(identifier, intTo4ByteArray(qIdentifier), intTo2ByteArray(i), intTo1ByteArray(j),
                                tempKey));
            }
            z = merge(z, tempKey);
        }

        return new LMOTSPublicKeyImpl(lmotsType, identifier, qIdentifier,
                messageDigest.digest(merge(identifier, intTo4ByteArray(qIdentifier), getdPblc(), z)));
    }

    @Nonnull
    private static byte[] checksum(@Nonnull final byte[] hashedMessage, @Nonnull final LMOTSType parameters) {
        final byte[] result = new byte[2];
        int sum = 0;
        final int hashIterations = getHashIterations(parameters.getW());
        for (int i = 0; i < (parameters.getN() * 8 / parameters.getW()); i++) {
            sum += hashIterations - coef(hashedMessage, i, parameters.getW(), hashIterations);
        }
        sum = sum << parameters.getLs();
        result[1] = (byte) ((sum & 0x0000FF00) >> 8);
        result[0] = (byte) ((sum & 0x000000FF));
        return result;
    }

    private static int coef(@Nonnull final byte[] hashedMessage, final int i, final int w, final int hashIterations) {
        return hashIterations & (hashedMessage[(int) Math.floor(i * w / 8d)] >> (8 - (w * (i % (8 / w)) + w)));
    }

    /**
     * Calculates 2^w - 1.
     */
    private static int getHashIterations(final int w) {
        return MathUtil.pow(w) - 1;
    }

    private static void validatePublicKey(@Nonnull final LMOTSPublicKey publicKey) {
        final LMOTSType lmotsType = publicKey.getLmotsType();
        if (publicKey.getKey().length != lmotsType.getN() || publicKey.getIdentifier().length != 16) {
            throw new IllegalArgumentException("Invalid public key length");
        }
    }

    private static void validateSignature(@Nonnull final LMOTSSignature signature) {
        final LMOTSType lmotsType = signature.getLmotsType();
        if (signature.getC().length != lmotsType.getN() || signature.getKeys().length != lmotsType.getP()
                || signature.getKeys()[0].length != lmotsType.getN()) {
            throw new IllegalArgumentException("Invalid signature length");
        }
    }

    /**
     * Builds an LMOTS private key from a given byte array.
     *
     * @param inputStream The inputstream that provides the bytes of the key.
     * @return the recreated LMOTSPrivateKey instance.
     * @throws IOException if stream cannot be read.
     */
    @Nonnull
    public static LMOTSPrivateKey buildPrivateKey(@Nonnull final DataInputStream inputStream) throws IOException {
        return new LMOTSPrivateKeyImpl(inputStream);
    }

    /**
     * Builds an LMOTS public key from a given byte array.
     *
     * @param inputStream The inputstream that provides the bytes of the key.
     * @return the recreated LMOTSPublicKey instance.
     * @throws IOException if stream cannot be read.
     */
    @Nonnull
    public static LMOTSPublicKey buildPublicKey(@Nonnull final DataInputStream inputStream) throws IOException {
        return new LMOTSPublicKeyImpl(inputStream);
    }

    /**
     * Builds an LMOTS public key from a given byte array.
     *
     * @param inputStream The inputstream that provides the bytes of the key.
     * @return the recreated LMOTSPublicKey instance.
     * @throws IOException if stream cannot be read.
     */
    @Nonnull
    public static LMOTSSignature buildSignature(@Nonnull final DataInputStream inputStream) throws IOException {
        return new LMOTSSignatureImpl(inputStream);
    }
}
