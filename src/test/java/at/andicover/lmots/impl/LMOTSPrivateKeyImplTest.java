package at.andicover.lmots.impl;

import at.andicover.lmots.api.LMOTSPrivateKey;
import at.andicover.lmots.api.LMOTSType;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@SuppressWarnings("PMD.SystemPrintln")
final class LMOTSPrivateKeyImplTest {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Test
    void testEqualsAndHashcode() {
        final LMOTSPrivateKey lmotsPrivateKey =
                new LMOTSPrivateKeyImpl(LMOTSType.LMOTS_SHA256_N32_W1, new byte[0], 2, new byte[0]);
        final LMOTSPrivateKey lmotsPrivateKey2 =
                new LMOTSPrivateKeyImpl(LMOTSType.LMOTS_SHA256_N32_W2, new byte[0], 2, new byte[0]);
        final LMOTSPrivateKey lmotsPrivateKey3 =
                new LMOTSPrivateKeyImpl(LMOTSType.LMOTS_SHA256_N32_W1, new byte[0], 2, new byte[0]);
        final LMOTSPrivateKey lmotsPrivateKey4 =
                new LMOTSPrivateKeyImpl(LMOTSType.LMOTS_SHA256_N32_W1, new byte[0], 3, new byte[0]);
        final LMOTSPrivateKey lmotsPrivateKey5 =
                new LMOTSPrivateKeyImpl(LMOTSType.LMOTS_SHA256_N32_W1, new byte[0], 2, new byte[]{0x12, 0x14});
        final LMOTSPrivateKey lmotsPrivateKey6 =
                new LMOTSPrivateKeyImpl(LMOTSType.LMOTS_SHA256_N32_W1, new byte[]{0x1, 0x17}, 2,
                        new byte[]{0x13, 0x15});

        assertNotEquals(lmotsPrivateKey, lmotsPrivateKey2);
        assertNotEquals(lmotsPrivateKey2.hashCode(), lmotsPrivateKey.hashCode());
        assertEquals(lmotsPrivateKey, lmotsPrivateKey3);
        assertEquals(lmotsPrivateKey3.hashCode(), lmotsPrivateKey.hashCode());
        assertEquals(lmotsPrivateKey, lmotsPrivateKey);
        assertNotEquals(lmotsPrivateKey, null);
        assertNotEquals(lmotsPrivateKey, new Object());
        assertNotEquals(lmotsPrivateKey, lmotsPrivateKey4);
        assertNotEquals(lmotsPrivateKey, lmotsPrivateKey5);
        assertNotEquals(lmotsPrivateKey, lmotsPrivateKey6);
        System.out.println(lmotsPrivateKey);
    }

    @Test
    void testSeed() throws NoSuchAlgorithmException {
        final LMOTSPrivateKey lmotsPrivateKey =
                new LMOTSPrivateKeyImpl(LMOTSType.LMOTS_SHA256_N32_W1, new byte[0], 2, SECURE_RANDOM.generateSeed(32));
        assertArrayEquals(lmotsPrivateKey.getKeys(), lmotsPrivateKey.getKeys());
    }
}