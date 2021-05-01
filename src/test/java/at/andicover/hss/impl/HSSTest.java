package at.andicover.hss.impl;

import at.andicover.hss.api.HSSKeyPair;
import at.andicover.hss.api.HSSPrivateKey;
import at.andicover.hss.api.HSSPublicKey;
import at.andicover.hss.api.HSSSignature;
import at.andicover.lmots.api.LMOTSType;
import at.andicover.lms.api.LMSSignature;
import at.andicover.lms.api.LMSType;
import at.andicover.util.PersistenceUtil;
import at.andicover.util.TestUtil;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W1;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W2;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W8;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H10;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H15;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H5;
import static at.andicover.util.TestUtil.getLmotsTypes;
import static java.lang.Runtime.getRuntime;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings({"PMD.TooManyMethods", "PMD.UnusedLocalVariable"})
public final class HSSTest {

    @Test
    void generateKeysTest() throws NoSuchAlgorithmException, IOException {
        for (final LMOTSType lmotsType : getLmotsTypes()) {
            for (final LMSType lmsType : Arrays.asList(LMS_SHA256_M32_H5, LMS_SHA256_M32_H10)) {
                for (int i = 1; i <= 2; i++) {
                    final HSSKeyPair keyPair = HSS.generateKeys(i, lmsType, lmotsType, "generateKeysTest.privkey");
                    assertNotNull(keyPair.getPrivateKey());
                    assertNotNull(keyPair.getPublicKey());
                    assertEquals(i, keyPair.getPrivateKey().getLevels());
                    assertEquals(i, keyPair.getPublicKey().getLevels());
                    assertNotNull(keyPair.getPublicKey().getPublicKey());
                    assertEquals(i, keyPair.getPrivateKey().getLmsPrivateKeys().length);
                    assertEquals(i, keyPair.getPrivateKey().getSignatures().length);
                    assertEquals(i, keyPair.getPrivateKey().getLmsPublicKeys().length);
                }
            }
        }
    }

    @Test
    void generateSignatureAndValidateSignatureTest() throws NoSuchAlgorithmException, IOException {
        final String message =
                "jfdklsaj894wöahjrnfasöfkesdaö fklöfJKFHJPASDHFJKSjfösdökaljf(=)/$%§\")/U9asd7as98/D)A79poda98/()/&=)ZDAST§";
        for (final LMOTSType lmotsType : getLmotsTypes()) {
            for (int i = 1; i <= 8; i++) {
                final HSSKeyPair keyPair = HSS.generateKeys(i, LMS_SHA256_M32_H5, lmotsType,
                        "generateSignatureAndValidateSignatureTest.privkey");
                final HSSPrivateKey privateKey = keyPair.getPrivateKey();
                final HSSPublicKey publicKey = keyPair.getPublicKey();
                final HSSSignature signature = HSS.generateSignature(message, privateKey);
                assertTrue(HSS.verifySignature(message, signature, publicKey));
            }
        }
    }

    @Test
    void testInvalidLevels() {
        assertThrows(IllegalArgumentException.class,
                () -> HSS.generateKeys(0, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W1, "testInvalidLevels.privkey"));
        assertThrows(IllegalArgumentException.class,
                () -> HSS.generateKeys(9, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W1, "testInvalidLevels.privkey"));
    }

    @Test
    void testManySignatures() throws NoSuchAlgorithmException, IOException {
        final String message =
                "jfdklsaj894wöahjrnfasöfkesdaö fklöfJKFHJPASDHffdsaf32  FJKSjfösdökaljf(=)/$%§\")/U9asd7as98/D)A79poda98/()/&=)ZDAST§";
        final HSSKeyPair keyPair =
                HSS.generateKeys(1, LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8, "testManySignatures.privkey");
        final HSSPrivateKey privateKey = keyPair.getPrivateKey();
        final HSSPublicKey publicKey = keyPair.getPublicKey();

        for (int i = 0; i < 1024; i++) {
            final HSSSignature signature = HSS.generateSignature(message, privateKey);
            assertTrue(HSS.verifySignature(message, signature, publicKey));
        }
        assertThrows(IllegalStateException.class, () -> {
            final HSSSignature signature = HSS.generateSignature(message, privateKey);
        });
    }

    @Test
    void reserveKeysMultipleLevels() throws NoSuchAlgorithmException, IOException {
        final HSSKeyPair keyPair =
                HSS.generateKeys(2, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W2, "testManySignaturesThreads.privkey");
        keyPair.getPrivateKey().reserveKeys(32);
        assertEquals(32, keyPair.getPrivateKey().getReservedKeys());

        for (int j = 0; j < 31; j++) {
            for (int i = 0; i < 32; i++) {
                HSS.generateSignature("test", keyPair.getPrivateKey());
            }
            keyPair.getPrivateKey().reserveKeys(32);
            assertEquals(32, keyPair.getPrivateKey().getReservedKeys());
        }

        for (int i = 0; i < 32; i++) {
            HSS.generateSignature("test", keyPair.getPrivateKey());
        }
        assertEquals(0, keyPair.getPrivateKey().getReservedKeys());
        assertThrows(IllegalStateException.class, () -> keyPair.getPrivateKey().reserveKeys(32),
                "No unused LMOTS private key available");
    }

    @Test
    void testManySignaturesThreads() throws NoSuchAlgorithmException, IOException {
        final String message =
                "jfdklsaj894wöahjrnfasöfkesdaö fdsafg(=)/$%§\")/U9asd7as98sdfa/D)A79poda98/()/&=)ZDAST§";
        final HSSKeyPair keyPair =
                HSS.generateKeys(1, LMS_SHA256_M32_H15, LMOTS_SHA256_N32_W8, "testManySignaturesThreads.privkey");
        final HSSPrivateKey privateKey = keyPair.getPrivateKey();
        privateKey.reserveKeys(32_768);
        final HSSPublicKey publicKey = keyPair.getPublicKey();
        final ExecutorService executorService = Executors.newFixedThreadPool(getRuntime().availableProcessors());
        final List<Integer> qIdentifiers = new ArrayList<>();

        for (int i = 0; i < 32_768; i++) {
            final int finalI = i;
            executorService.execute(() -> {
                if (!Thread.currentThread().isInterrupted()) {
                    final HSSSignature signature;
                    try {
                        signature = HSS.generateSignature(message + finalI, privateKey);
                        assertFalse(qIdentifiers.contains(signature.getSignatures()[0].getQIdentifier()));
                        qIdentifiers.add(signature.getSignatures()[0].getQIdentifier());
                        assertTrue(HSS.verifySignature(message + finalI, signature, publicKey));
                    } catch (NoSuchAlgorithmException | IOException e) {
                        e.printStackTrace();
                    }
                }
            });
        }
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException ex) {
            ex.printStackTrace();
        }

        assertThrows(IllegalStateException.class, () -> {
            final HSSSignature signature = HSS.generateSignature(message, privateKey);
        });
    }

    @Test
    void testMultipeLevels() throws NoSuchAlgorithmException, IOException {
        final String message =
                "fdas fklöfJKFHJPASDHFJKSjfösdökaljf(=)/$%§\" 455)/U9asdgsdf 7as98/D)A79poda98/()/&=)ZDAST§";
        final HSSKeyPair keyPair =
                HSS.generateKeys(2, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8, "testMultipeLevels.privkey");
        final HSSPrivateKey privateKey = keyPair.getPrivateKey();
        final HSSPublicKey publicKey = keyPair.getPublicKey();

        final List<byte[]> usedSignatures = new ArrayList<>();
        for (int i = 0; i < 1024; i++) {
            final HSSSignature signature = HSS.generateSignature(message, privateKey);
            assertFalse(usedSignatures.contains(signature.getBytes()));
            usedSignatures.add(signature.getBytes());
            assertTrue(HSS.verifySignature(message, signature, publicKey));
        }
        assertThrows(IllegalStateException.class, () -> {
            final HSSSignature signature = HSS.generateSignature(message, privateKey);
        });
    }

    @Test
    void testInvalidPublicKey() throws NoSuchAlgorithmException, IOException {
        final String message =
                "jfdklsaj894wöahjrnfasöfkesdaö fk4dfs86löfJKFHJPASDHFJKSjfösdökaljf(=)/$%§\")/U9asd7as98/D)A79poda98/()/&=)ZDAST§";
        final HSSKeyPair keyPair =
                HSS.generateKeys(1, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8, "testInvalidPublicKey1.privkey");
        final HSSPrivateKey privateKey = keyPair.getPrivateKey();
        final HSSKeyPair keyPair2 =
                HSS.generateKeys(3, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8, "testInvalidPublicKey2.privkey");
        final HSSPublicKey publicKey2 = keyPair2.getPublicKey();

        final HSSSignature signature = HSS.generateSignature(message, privateKey);
        assertThrows(IllegalArgumentException.class, () -> HSS.verifySignature(message, signature, publicKey2));
    }

    @Test
    void testWrongPublicKey() throws NoSuchAlgorithmException, IOException {
        final String message =
                "jfdklsaj894wöahjrnfasöfkesdaö fklöfJKFHJPASD641sdf8a46fsdHFJKSjfösdökaljf(=)/$%§\")/U9asd7as98/D)A79poda98/()/&=)ZDAST§";
        final HSSKeyPair keyPair =
                HSS.generateKeys(1, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8, "testWrongPublicKey.privkey");
        final HSSPrivateKey privateKey = keyPair.getPrivateKey();
        final HSSPublicKey publicKey = keyPair.getPublicKey();
        final HSSSignature signature = HSS.generateSignature(message + message, privateKey);

        assertFalse(HSS.verifySignature(message, signature, publicKey));
    }

    @Test
    void testInvalidSignatureInChain() throws NoSuchAlgorithmException, IOException {
        final String message =
                "jfdklsaj894wöahjrnfasfd4sa64fsdöfkesdaö fklöfJKFHJPASDHFJKSjfösdökaljf(=)/$%§\")/U9asd7as98/D)A79poda98/()/&=)ZDAST§";
        final HSSKeyPair keyPair =
                HSS.generateKeys(4, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8, "testInvalidSignatureInChain.privkey");
        final HSSPrivateKey privateKey = keyPair.getPrivateKey();
        final HSSPublicKey publicKey = keyPair.getPublicKey();
        final LMSSignature[] signatures = privateKey.getSignatures();
        signatures[1] = signatures[2];
        final HSSSignature signature = new HSSSignatureImpl(3, signatures, privateKey.getLmsPublicKeys());

        assertFalse(HSS.verifySignature(message, signature, publicKey));
    }

    @Test
    void testPrivateKeyStoreAndLoad() throws NoSuchAlgorithmException, IOException {
        final String filename = this.getClass().getName() + "_testPrivateKeyStoreAndLoad.privkey";
        final LMSType lmsType = LMS_SHA256_M32_H5;
        for (final LMOTSType lmotsType : getLmotsTypes()) {
            for (int i = 1; i <= 2; i++) {
                final HSSKeyPair keyPair = HSS.generateKeys(i, lmsType, lmotsType, filename);
                assertEquals(keyPair.getPrivateKey().calculateSize(), keyPair.getPrivateKey().getBytes().length);

                PersistenceUtil.storeKey(keyPair.getPrivateKey(), filename);
                final HSSPrivateKey rebuiltPrivateKey =
                        (HSSPrivateKey) PersistenceUtil.loadKey(filename, HSSPrivateKey.class);
                assertNotNull(rebuiltPrivateKey);
                assertArrayEquals(rebuiltPrivateKey.getBytes(), keyPair.getPrivateKey().getBytes());
                assertArrayEquals(rebuiltPrivateKey.getSignatures(), keyPair.getPrivateKey().getSignatures());
                assertArrayEquals(rebuiltPrivateKey.getLmsPublicKeys(), keyPair.getPrivateKey().getLmsPublicKeys());
                assertEquals(rebuiltPrivateKey.getLevels(), keyPair.getPrivateKey().getLevels());

                for (int j = 0; j < Math.max(rebuiltPrivateKey.getLmsPrivateKeys().length,
                        keyPair.getPrivateKey().getLmsPrivateKeys().length); j++) {
                    assertEquals(rebuiltPrivateKey.getLmsPrivateKeys()[j].getLmsType(),
                            keyPair.getPrivateKey().getLmsPrivateKeys()[j].getLmsType());
                    assertArrayEquals(rebuiltPrivateKey.getLmsPrivateKeys()[j].getIdentifier(),
                            keyPair.getPrivateKey().getLmsPrivateKeys()[j].getIdentifier());
                    assertEquals(rebuiltPrivateKey.getLmsPrivateKeys()[j].getLmotsType(),
                            keyPair.getPrivateKey().getLmsPrivateKeys()[j].getLmotsType());
                }

            }
        }

        final HSSKeyPair keyPair = HSS.generateKeys(1, lmsType, LMOTS_SHA256_N32_W2, filename);
        HSS.generateSignature("fjsdaokljffios", keyPair.getPrivateKey());
        assertEquals(keyPair.getPrivateKey().calculateSize(), keyPair.getPrivateKey().getBytes().length);

        PersistenceUtil.storeKey(keyPair.getPrivateKey(), filename);
        final HSSPrivateKey rebuiltPrivateKey =
                (HSSPrivateKey) PersistenceUtil.loadKey(filename, HSSPrivateKey.class);
        assertNotNull(rebuiltPrivateKey);
        assertArrayEquals(rebuiltPrivateKey.getBytes(), keyPair.getPrivateKey().getBytes());
        assertArrayEquals(rebuiltPrivateKey.getSignatures(), keyPair.getPrivateKey().getSignatures());
        assertArrayEquals(rebuiltPrivateKey.getLmsPublicKeys(), keyPair.getPrivateKey().getLmsPublicKeys());
        assertEquals(rebuiltPrivateKey.getLevels(), keyPair.getPrivateKey().getLevels());

        for (int j = 0; j < Math.max(rebuiltPrivateKey.getLmsPrivateKeys().length,
                keyPair.getPrivateKey().getLmsPrivateKeys().length); j++) {
            assertEquals(rebuiltPrivateKey.getLmsPrivateKeys()[j].getLmsType(),
                    keyPair.getPrivateKey().getLmsPrivateKeys()[j].getLmsType());
            assertArrayEquals(rebuiltPrivateKey.getLmsPrivateKeys()[j].getIdentifier(),
                    keyPair.getPrivateKey().getLmsPrivateKeys()[j].getIdentifier());
            assertEquals(rebuiltPrivateKey.getLmsPrivateKeys()[j].getLmotsType(),
                    keyPair.getPrivateKey().getLmsPrivateKeys()[j].getLmotsType());
        }
    }

    @Test
    void testPublicKeyStoreAndLoad() throws NoSuchAlgorithmException, IOException {
        final String filename = this.getClass().getName() + "_testPublicKeyStoreAndLoad.privkey";
        for (final LMOTSType lmotsType : getLmotsTypes()) {
            for (int i = 1; i <= 2; i++) {
                final HSSKeyPair keyPair =
                        HSS.generateKeys(i, LMS_SHA256_M32_H5, lmotsType, filename);
                assertEquals(keyPair.getPublicKey().calculateSize(), keyPair.getPublicKey().getBytes().length);

                PersistenceUtil.storeKey(keyPair.getPublicKey(), filename);
                assertEquals(PersistenceUtil.loadKey(filename, HSSPublicKey.class), keyPair.getPublicKey());
            }
        }
    }

    @Test
    void testSignatureStoreAndLoad() throws NoSuchAlgorithmException, IOException {
        final String filename = this.getClass().getName() + "_testSignatureStoreAndLoad.privkey";
        for (final LMOTSType lmotsType : getLmotsTypes()) {
            for (int i = 1; i <= 2; i++) {
                final HSSKeyPair keyPair =
                        HSS.generateKeys(i, LMS_SHA256_M32_H5, lmotsType, filename);
                final HSSSignature signature = HSS.generateSignature("mfdsakjf", keyPair.getPrivateKey());

                assertEquals(signature.calculateSize(), signature.getBytes().length);

                PersistenceUtil.storeKey(signature, filename);
                assertEquals(PersistenceUtil.loadKey(filename, HSSSignature.class), signature);
            }
        }
    }

    @Test
    void testSeed() throws NoSuchAlgorithmException, IOException {
        final SecureRandom secureRandom = new SecureRandom();
        final byte[] seed = secureRandom.generateSeed(32);
        final HSSKeyPair keyPair =
                HSS.generateKeys(1, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W1, Arrays.copyOf(seed, seed.length));
        final HSSKeyPair keyPair2 =
                HSS.generateKeys(1, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W1, Arrays.copyOf(seed, seed.length));

        assertArrayEquals(keyPair.getPrivateKey().getLmsPrivateKeys()[0].getNextLmotsKey().getKeys(),
                keyPair2.getPrivateKey().getLmsPrivateKeys()[0].getNextLmotsKey().getKeys());
    }

    @Test
    @Disabled //Takes too long
    void testH20() throws NoSuchAlgorithmException, IOException {
        final HSSKeyPair hssKeyPair =
                HSS.generateKeys(1, LMSType.LMS_SHA256_M32_H20, LMOTS_SHA256_N32_W8, "testH20.privkey");
        assertNotNull(hssKeyPair.getPrivateKey());
        assertNotNull(hssKeyPair.getPublicKey());
        PersistenceUtil.storeKey(hssKeyPair.getPublicKey(), "testH20.pubkey");

        final String message = "some test message to sign with H20.";
        final HSSSignature hssSignature = HSS.generateSignature(message, hssKeyPair.getPrivateKey());
        assertTrue(HSS.verifySignature(message, hssSignature, hssKeyPair.getPublicKey()));
    }

    @Test
    @Disabled //Takes too long
    void testH25() throws NoSuchAlgorithmException, IOException {
        final HSSKeyPair hssKeyPair =
                HSS.generateKeys(1, LMSType.LMS_SHA256_M32_H25, LMOTS_SHA256_N32_W8, "testH25.privkey");
        assertNotNull(hssKeyPair.getPrivateKey());
        assertNotNull(hssKeyPair.getPublicKey());

        final String message = "some test message to sign with H25.";
        final HSSSignature hssSignature = HSS.generateSignature(message, hssKeyPair.getPrivateKey());
        assertTrue(HSS.verifySignature(message, hssSignature, hssKeyPair.getPublicKey()));
    }

    @Test
    @Disabled //Takes too long
    void testLoadLargeKeysAndVerifySignature() throws IOException, NoSuchAlgorithmException {
        final HSSPrivateKey privateKey = (HSSPrivateKey) PersistenceUtil
                .loadKey(TestUtil.getResourcePath("testH20.privkey"), HSSPrivateKey.class);
        final HSSPublicKey publicKey =
                (HSSPublicKey) PersistenceUtil.loadKey(TestUtil.getResourcePath("testH20.pubkey"), HSSPublicKey.class);

        assertNotNull(privateKey);
        assertNotNull(publicKey);

        final String message = "my test message";
        final HSSSignature signature = HSS.generateSignature(message, privateKey);
        assertTrue(HSS.verifySignature(message, signature, publicKey));
    }
}
