package at.andicover.lmots.impl;

import at.andicover.lmots.api.LMOTSPrivateKey;
import at.andicover.lmots.api.LMOTSPublicKey;
import at.andicover.lmots.api.LMOTSSignature;
import at.andicover.lmots.api.LMOTSType;
import at.andicover.util.KeySizeUtil;
import at.andicover.util.PersistenceUtil;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W1;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W8;
import static at.andicover.util.TestUtil.getLmotsTypes;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings({"PMD.AvoidInstantiatingObjectsInLoops", "PMD.UseAssertEqualsInsteadOfAssertTrue", "PMD.AvoidInstantiatingObjectsInLoops"})
public final class LMOTSTest {

    @Test
    void generatePrivateKeyTest() throws NoSuchAlgorithmException {
        for (final LMOTSType parameters : getLmotsTypes()) {
            final LMOTSPrivateKey privateKey = LMOTS.generatePrivateKey(parameters);

            final byte[][] privateKeys = privateKey.getKeys();
            assertEquals(parameters.getP(), privateKeys.length);
            byte[] previousKey = null;
            for (int i = 0; i < parameters.getP(); i++) {
                final byte[] currentKey = privateKeys[i];
                assertEquals(parameters.getN(), currentKey.length);
                assertNotEquals(currentKey, previousKey);
                previousKey = currentKey;
            }
        }
    }

    @Test
    void generatePrivateKeyWithIdentifierTest() throws NoSuchAlgorithmException {
        for (final LMOTSType parameters : getLmotsTypes()) {
            for (int q = 0; q < 32; q++) {
                byte[] identifier;
                identifier = new byte[16];
                SecureRandom.getInstanceStrong().nextBytes(identifier);

                final LMOTSPrivateKey privateKey = LMOTS.generatePrivateKey(parameters, identifier, q);
                final byte[][] privateKeys = privateKey.getKeys();

                assertEquals(parameters.getP(), privateKeys.length);
                byte[] previousKey = null;
                for (int i = 0; i < parameters.getP(); i++) {
                    final byte[] currentKey = privateKeys[i];
                    assertEquals(parameters.getN(), currentKey.length);
                    assertNotEquals(currentKey, previousKey);
                    previousKey = currentKey;
                }
            }
        }
    }

    @Test
    void generatePublicKeyTest() throws NoSuchAlgorithmException {
        for (final LMOTSType parameters : getLmotsTypes()) {
            final LMOTSPrivateKey privateKey = LMOTS.generatePrivateKey(parameters);
            final LMOTSPublicKey publicKey = LMOTS.generatePublicKey(privateKey);

            assertTrue(Arrays.equals(publicKey.getIdentifier(), privateKey.getIdentifier()));
            assertEquals(publicKey.getQIdentifier(), privateKey.getQIdentifier());
            assertEquals(publicKey.getLmotsType(), privateKey.getLmotsType());
        }
    }

    @Test
    void generatePublicKeyWithIdentifierTest() throws NoSuchAlgorithmException {
        for (final LMOTSType parameters : getLmotsTypes()) {
            for (int q = 0; q < 32; q++) {
                byte[] identifier;
                identifier = new byte[16];
                SecureRandom.getInstanceStrong().nextBytes(identifier);

                final LMOTSPrivateKey privateKey = LMOTS.generatePrivateKey(parameters, identifier, q);
                final LMOTSPublicKey publicKey = LMOTS.generatePublicKey(privateKey);

                assertTrue(Arrays.equals(publicKey.getIdentifier(), privateKey.getIdentifier()));
                assertEquals(publicKey.getQIdentifier(), privateKey.getQIdentifier());
                assertEquals(publicKey.getLmotsType(), privateKey.getLmotsType());
            }
        }
    }

    @Test
    void generateSignatureAndValidateSignatureTest() throws NoSuchAlgorithmException {
        for (final LMOTSType parameters : getLmotsTypes()) {
            final LMOTSPrivateKey privateKey = LMOTS.generatePrivateKey(parameters);
            LMOTS.generateSignature("test", privateKey);
            final LMOTSPublicKey publicKey = LMOTS.generatePublicKey(privateKey);

            final String message = "test message";
            final LMOTSSignature signature = LMOTS.generateSignature(message, privateKey);

            assertEquals(KeySizeUtil.getOtsSignatureSize(parameters), signature.calculateSize());
            assertEquals(signature.getLmotsType(), privateKey.getLmotsType());

            assertTrue(LMOTS.verifySignature(message, signature, publicKey));
        }
    }

    @Test
    void generateSignatureAndValidateSignatureWithIdentifierTest() throws NoSuchAlgorithmException {
        for (final LMOTSType parameters : getLmotsTypes()) {
            for (int q = 0; q < parameters.getP(); q++) {
                byte[] identifier;
                identifier = new byte[16];
                SecureRandom.getInstanceStrong().nextBytes(identifier);

                final LMOTSPrivateKey privateKey = LMOTS.generatePrivateKey(parameters, identifier, q);
                LMOTS.generateSignature("test", privateKey);
                final LMOTSPublicKey publicKey = LMOTS.generatePublicKey(privateKey);

                final String message = "test message";
                final LMOTSSignature signature = LMOTS.generateSignature(message, privateKey);

                assertEquals(KeySizeUtil.getOtsSignatureSize(parameters), signature.calculateSize());
                assertEquals(signature.getLmotsType(), privateKey.getLmotsType());

                assertTrue(LMOTS.verifySignature(message, signature, publicKey));
            }
        }
    }

    @Test
    void validateEmptySignatureTest() throws NoSuchAlgorithmException {
        final LMOTSPrivateKey privateKey = LMOTS.generatePrivateKey(LMOTS_SHA256_N32_W8);
        final LMOTSPublicKey publicKey = LMOTS.generatePublicKey(privateKey);

        final String message = "test message";
        final LMOTSSignatureImpl signature =
                new LMOTSSignatureImpl(privateKey.getLmotsType(), new byte[32], new byte[34][32]);
        assertFalse(LMOTS.verifySignature(message, signature, publicKey));
    }

    @Test
    void signLongMessageTest() throws NoSuchAlgorithmException {
        for (final LMOTSType parameters : getLmotsTypes()) {
            final LMOTSPrivateKey privateKey = LMOTS.generatePrivateKey(parameters);
            LMOTS.generateSignature("test", privateKey);
            final LMOTSPublicKey publicKey = LMOTS.generatePublicKey(privateKey);

            final String message =
                    "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt "
                            + "ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et ju"
                            + "sto duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lore"
                            + "m ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed dia"
                            + "m nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam volupt"
                            + "ua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, "
                            + "no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, cons"
                            + "etetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magn"
                            + "a aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea re"
                            + "bum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. "
                            + "  \nDuis autem vel eum iriure dolor in hendrerit in vulputate velit esse molestie conseq"
                            + "uat, vel illum dolore eu feugiat nulla facilisis at vero eros et accumsan et iusto odio "
                            + "dignissim qui blandit praesent luptatum zzril delenit augue duis dolore te feugait nulla"
                            + " facilisi. Lorem ipsum dolor sit amet,";
            final LMOTSSignature signature = LMOTS.generateSignature(message, privateKey);

            assertEquals(KeySizeUtil.getOtsSignatureSize(parameters), signature.calculateSize());
            assertEquals(signature.getLmotsType(), privateKey.getLmotsType());

            assertTrue(LMOTS.verifySignature(message, signature, publicKey));
        }
    }

    @Test
    void verifySignatureInvalidTypecodes() throws NoSuchAlgorithmException {
        final LMOTSPrivateKey privateKey = LMOTS.generatePrivateKey(LMOTS_SHA256_N32_W8);
        final LMOTSPublicKey publicKey = LMOTS.generatePublicKey(privateKey);

        final String message = "my Message 1234d809s";
        final LMOTSPrivateKey privateKey2 = LMOTS.generatePrivateKey(LMOTS_SHA256_N32_W1);
        final LMOTSSignature signature = LMOTS.generateSignature(message, privateKey2);

        assertThrows(IllegalArgumentException.class, () -> LMOTS.verifySignature(message, signature, publicKey));
    }

    @Test
    void generatePublicKeyInvalidSignatureSize() throws NoSuchAlgorithmException {
        final LMOTSPrivateKey privateKey = LMOTS.generatePrivateKey(LMOTS_SHA256_N32_W8);
        final LMOTSPublicKey publicKey = LMOTS.generatePublicKey(privateKey);

        final String message = "my Message 1234d809s";
        final LMOTSSignature signature =
                new LMOTSSignatureImpl(privateKey.getLmotsType(), new byte[28], new byte[2][101]);

        assertThrows(IllegalArgumentException.class,
                () -> LMOTS
                        .generatePublicKey(message, signature, publicKey.getQIdentifier(), publicKey.getIdentifier()));
    }

    @Test
    void verifySignatureInvalidKeySize() throws NoSuchAlgorithmException {
        final LMOTSPrivateKey privateKey = LMOTS.generatePrivateKey(LMOTS_SHA256_N32_W8);
        final LMOTSPublicKey publicKey = new LMOTSPublicKeyImpl(LMOTS_SHA256_N32_W8, new byte[7], 17, new byte[72]);

        final String message = "my Message 1234d809s";
        final LMOTSSignature signature = LMOTS.generateSignature(message, privateKey);

        assertThrows(IllegalArgumentException.class, () -> LMOTS.verifySignature(message, signature, publicKey));
    }

    @Test
    void testPrivateKeyGetBytes() throws NoSuchAlgorithmException, IOException {
        final String filename = this.getClass().getName() + "_testPrivateKeyGetBytes.privkey";
        for (final LMOTSType lmotsType : getLmotsTypes()) {
            final byte[] identifier = new byte[16];
            SecureRandom.getInstanceStrong().nextBytes(identifier);
            final LMOTSPrivateKey privateKey = LMOTS.generatePrivateKey(lmotsType, identifier, 28);
            assertEquals(privateKey.calculateSize(), privateKey.getBytes().length);

            PersistenceUtil.storeKey(privateKey, filename);
            assertEquals(PersistenceUtil.loadKey(filename, LMOTSPrivateKey.class), privateKey);
        }
    }

    @Test
    void testPublicKeyLoadAndStore() throws NoSuchAlgorithmException, IOException {
        final String filename = this.getClass().getName() + "_testPublicKeyLoadAndStore.privkey";
        for (final LMOTSType lmotsType : getLmotsTypes()) {
            final byte[] identifier = new byte[16];
            SecureRandom.getInstanceStrong().nextBytes(identifier);
            final LMOTSPrivateKey privateKey = LMOTS.generatePrivateKey(lmotsType, identifier, 28);
            final LMOTSPublicKey publicKey = LMOTS.generatePublicKey(privateKey);
            assertEquals(publicKey.calculateSize(), publicKey.getBytes().length);

            PersistenceUtil.storeKey(publicKey, filename);
            assertEquals(PersistenceUtil.loadKey(filename, LMOTSPublicKey.class), publicKey);
        }
    }

    @Test
    void testSignatureStoreAndLoad() throws NoSuchAlgorithmException, IOException {
        final String filename = this.getClass().getName() + "_testSignatureStoreAndLoad.privkey";
        for (final LMOTSType lmotsType : getLmotsTypes()) {
            final byte[] identifier = new byte[16];
            SecureRandom.getInstanceStrong().nextBytes(identifier);
            final LMOTSPrivateKey privateKey = LMOTS.generatePrivateKey(lmotsType, identifier, 28);
            final LMOTSSignature signature = LMOTS.generateSignature("message", privateKey);
            assertEquals(signature.calculateSize(), signature.getBytes().length);

            PersistenceUtil.storeKey(signature, filename);
            assertEquals(PersistenceUtil.loadKey(filename, LMOTSSignature.class), signature);
        }
    }
}
