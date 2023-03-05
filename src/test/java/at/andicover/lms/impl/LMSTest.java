package at.andicover.lms.impl;

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
import at.andicover.util.KeySizeUtil;
import at.andicover.util.PersistenceUtil;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W2;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W8;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H10;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H5;
import static at.andicover.util.TestUtil.getLmotsTypes;
import static at.andicover.util.TestUtil.getLmsTypes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("PMD.UseAssertEqualsInsteadOfAssertTrue")
final class LMSTest {

    @Test
    void generatePrivateKeyTest() throws NoSuchAlgorithmException {
        for (final LMSType parameters : getLmsTypes()) {
            for (final LMOTSType lmotsType : getLmotsTypes()) {
                final LMSKeyPair keyPair = LMS.generateKeys(parameters, lmotsType);

                assertEquals(parameters, keyPair.getPrivateKey().getLmsType());
                assertEquals(lmotsType, keyPair.getPrivateKey().getLmotsType());
                assertEquals(0, keyPair.getPrivateKey().getQIdentifier());
                keyPair.getPrivateKey().reserveKeys(1);
                assertNotNull(keyPair.getPrivateKey().getNextLmotsKey());
                assertThrows(IllegalStateException.class, keyPair.getPrivateKey()::getNextLmotsKey);

                final int keys = (int) Math.pow(2, parameters.getH());
                keyPair.getPrivateKey().reserveKeys(keys);
                for (int i = 1; i < keys; i++) {
                    assertEquals(i, keyPair.getPrivateKey().getNextLmotsKey().getQIdentifier());
                }
            }
        }
    }

    @Test
    void generatePublicKeyTest() throws NoSuchAlgorithmException {
        for (final LMSType parameters : getLmsTypes()) {
            for (final LMOTSType lmotsType : getLmotsTypes()) {
                final LMSKeyPair keyPair = LMS.generateKeys(parameters, lmotsType);
                final LMSPrivateKey privateKey = keyPair.getPrivateKey();
                final LMSPublicKey publicKey = keyPair.getPublicKey();

                assertArrayEquals(publicKey.getIdentifier(), privateKey.getIdentifier());
                assertEquals(publicKey.getLmsType(), privateKey.getLmsType());
                assertEquals(publicKey.getLmotsType(), privateKey.getLmotsType());
            }
        }
    }

    @Test
    void generateSignatureAndValidateSignatureTest() throws NoSuchAlgorithmException {
        for (final LMSType parameters : getLmsTypes()) {
            for (final LMOTSType lmotsType : getLmotsTypes()) {
                final LMSKeyPair keyPair = LMS.generateKeys(parameters, lmotsType);
                final LMSPrivateKey privateKey = keyPair.getPrivateKey();
                final LMSPublicKey publicKey = keyPair.getPublicKey();

                final String message = "test message";
                privateKey.reserveKeys(1);
                final LMSSignature signature = LMS.generateSignature(message, privateKey);

                assertEquals(privateKey.getLmotsType(), signature.getLmotsSignature().getLmotsType());
                assertEquals(privateKey.getLmsType(), signature.getLmsType());
                assertEquals(0, signature.getQIdentifier());
                assertEquals(KeySizeUtil.getLmsSignatureSize(lmotsType, parameters), signature.calculateSize());
                assertEquals(signature.getQIdentifier(), privateKey.getQIdentifier() - 1);

                assertTrue(LMS.verifySignature(message, signature, publicKey));
            }
        }
    }

    @Test
    void validateEmptySignatureTest() throws NoSuchAlgorithmException {
        final LMSType lmsType = LMS_SHA256_M32_H5;
        final LMSKeyPair keyPair = LMS.generateKeys(lmsType, LMOTS_SHA256_N32_W8);
        final LMSPrivateKey privateKey = keyPair.getPrivateKey();
        final LMSPublicKey publicKey = keyPair.getPublicKey();
        privateKey.reserveKeys(2);

        final String message = "test message";
        final LMOTSPrivateKey lmotsPrivateKey = privateKey.getNextLmotsKey();
        final LMOTSSignature lmotsSignature = LMOTS.generateSignature(message, lmotsPrivateKey);
        final LMSSignature signature =
                new LMSSignatureImpl(privateKey.getLmsType(), lmotsSignature, lmotsPrivateKey.getQIdentifier(),
                        new byte[0][0]);
        assertThrows(IllegalArgumentException.class, () -> LMS.verifySignature(message, signature, publicKey));

        final LMSSignature newSignature =
                new LMSSignatureImpl(privateKey.getLmsType(), lmotsSignature, lmotsPrivateKey.getQIdentifier(),
                        new byte[lmsType.getH()][lmsType.getM()]);
        assertFalse(LMS.verifySignature(message, newSignature, publicKey));
    }

    @Test
    void allKeysUsedTest() throws NoSuchAlgorithmException {
        final LMSKeyPair keyPair = LMS.generateKeys(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8);
        final LMSPrivateKey privateKey = keyPair.getPrivateKey();
        final LMSPublicKey publicKey = keyPair.getPublicKey();
        privateKey.reserveKeys(32);

        for (int i = 0; i < 32; i++) {
            final String message = "test message " + i;
            final LMSSignature signature = LMS.generateSignature(message, privateKey);
            assertTrue(LMS.verifySignature(message, signature, publicKey));
        }
        assertTrue(privateKey.isExhausted());
        assertThrows(IllegalStateException.class, () -> LMS.generateSignature("some text", privateKey));
    }

    @Test
    void verifySignatureInvalidTypecodes() throws NoSuchAlgorithmException {
        final String message =
                "fjdkslajfsdoau89rfn34rhaesjfjasdkljfsdklöfu894trhjlsaöjfsklddklöfsfLÖFJKDKAS)rfh jkfdslö";
        final LMSKeyPair keyPair = LMS.generateKeys(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8);
        final LMSPrivateKey privateKey = keyPair.getPrivateKey();
        privateKey.reserveKeys(1);
        final LMSSignature signature = LMS.generateSignature(message, privateKey);
        final LMSKeyPair keyPair2 = LMS.generateKeys(LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W2);
        final LMSPublicKey publicKey = keyPair2.getPublicKey();

        assertThrows(IllegalArgumentException.class, () -> LMS.verifySignature(message, signature, publicKey));
    }

    @Test
    void verifySignatureInvalidKeySize() throws NoSuchAlgorithmException {
        final String message =
                "fjdkslajfsdoau89rfn34rhaesjfjasdkljfsdklöfu894trhjlsaöjfsklddklöfsfLÖFJKDKAS)rfh jkfdslö";
        final LMSKeyPair keyPair = LMS.generateKeys(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8);
        final LMSPrivateKey privateKey = keyPair.getPrivateKey();
        privateKey.reserveKeys(1);

        final LMSSignature signature = LMS.generateSignature(message, privateKey);
        final LMSPublicKey publicKey =
                new LMSPublicKeyImpl(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8, new byte[34], new byte[4]);

        assertThrows(IllegalArgumentException.class, () -> LMS.verifySignature(message, signature, publicKey));
    }

    @Test
    void verifyIncorrectTreeSize() throws NoSuchAlgorithmException {
        final LMSKeyPair keyPair = LMS.generateKeys(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8);
        assertThrows(IllegalArgumentException.class,
                () -> keyPair.getPrivateKey().calculateRoot(new LMOTSPublicKey[0]));
    }

    @Test
    void testPrivateKeyStoreAndLoad() throws NoSuchAlgorithmException, IOException {
        for (final LMSType lmsType : getLmsTypes()) {
            for (final LMOTSType lmotsType : getLmotsTypes()) {
                final LMSKeyPair keyPair = LMS.generateKeys(lmsType, lmotsType);
                final LMSPrivateKey privateKey = keyPair.getPrivateKey();
                assertEquals(privateKey.calculateSize(), privateKey.getBytes().length);


                final String filename = this.getClass().getName() + "_testPrivateKeyStoreAndLoad.privkey";
                PersistenceUtil.storeKey(privateKey, filename);
                assertEquals(PersistenceUtil.loadKey(filename, LMSPrivateKey.class), privateKey);
            }
        }
    }

    @Test
    void testPublicKeyStoreAndLoad() throws NoSuchAlgorithmException, IOException {
        for (final LMSType lmsType : getLmsTypes()) {
            for (final LMOTSType lmotsType : getLmotsTypes()) {
                final LMSKeyPair keyPair = LMS.generateKeys(lmsType, lmotsType);
                final LMSPublicKey publicKey = keyPair.getPublicKey();
                assertEquals(publicKey.calculateSize(), publicKey.getBytes().length);

                final String filename = this.getClass().getName() + "_testPublicKeyStoreAndLoad.privkey";
                PersistenceUtil.storeKey(publicKey, filename);
                assertEquals(PersistenceUtil.loadKey(filename, LMSPublicKey.class), publicKey);
            }
        }
    }

    @Test
    void testSignatureStoreAndLoad() throws NoSuchAlgorithmException, IOException {
        for (final LMSType lmsType : getLmsTypes()) {
            for (final LMOTSType lmotsType : getLmotsTypes()) {
                final LMSKeyPair keyPair = LMS.generateKeys(lmsType, lmotsType);
                final LMSPrivateKey privateKey = keyPair.getPrivateKey();
                privateKey.reserveKeys(1);

                final LMSSignature signature = LMS.generateSignature("mfdsakjf", privateKey);
                assertEquals(signature.calculateSize(), signature.getBytes().length);

                final String filename = this.getClass().getName() + "_testSignatureStoreAndLoad.privkey";
                PersistenceUtil.storeKey(signature, filename);
                assertEquals(PersistenceUtil.loadKey(filename, LMSSignature.class), signature);
            }
        }
    }

    @Test
    void testNoReservedKeys() throws NoSuchAlgorithmException {
        final LMSKeyPair keyPair = LMS.generateKeys(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8);
        assertThrows(IllegalStateException.class, keyPair.getPrivateKey()::getNextLmotsKey);
    }
}