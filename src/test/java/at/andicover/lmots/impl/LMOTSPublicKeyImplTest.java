package at.andicover.lmots.impl;

import at.andicover.lmots.api.LMOTSPrivateKey;
import at.andicover.lmots.api.LMOTSPublicKey;
import at.andicover.lmots.api.LMOTSType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@SuppressWarnings("PMD.SystemPrintln")
final class LMOTSPublicKeyImplTest {

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
                new LMOTSPrivateKeyImpl(LMOTSType.LMOTS_SHA256_N32_W1, new byte[0], 2, new byte[]{0x13, 0x15});
        final LMOTSPrivateKey lmotsPrivateKey6 =
                new LMOTSPrivateKeyImpl(LMOTSType.LMOTS_SHA256_N32_W1, new byte[]{0x1, 0x17}, 2,
                        new byte[]{0x13, 0x15});

        final LMOTSPublicKey lmotsPublicKey =
                new LMOTSPublicKeyImpl(lmotsPrivateKey.getLmotsType(), lmotsPrivateKey, new byte[]{0x13, 0x15});
        final LMOTSPublicKey lmotsPublicKey2 =
                new LMOTSPublicKeyImpl(lmotsPrivateKey2.getLmotsType(), lmotsPrivateKey2, new byte[]{0x13, 0x15});
        final LMOTSPublicKey lmotsPublicKey3 =
                new LMOTSPublicKeyImpl(lmotsPrivateKey3.getLmotsType(), lmotsPrivateKey3, new byte[]{0x13, 0x15});
        final LMOTSPublicKey lmotsPublicKey4 =
                new LMOTSPublicKeyImpl(lmotsPrivateKey4.getLmotsType(), lmotsPrivateKey4, new byte[]{0x13, 0x15});
        final LMOTSPublicKey lmotsPublicKey5 =
                new LMOTSPublicKeyImpl(lmotsPrivateKey5.getLmotsType(), lmotsPrivateKey5, new byte[]{0x12, 0x14});
        final LMOTSPublicKey lmotsPublicKey6 =
                new LMOTSPublicKeyImpl(lmotsPrivateKey6.getLmotsType(), lmotsPrivateKey6, new byte[]{0x12, 0x14});

        assertNotEquals(lmotsPublicKey, lmotsPublicKey2);
        assertNotEquals(lmotsPublicKey2.hashCode(), lmotsPublicKey.hashCode());
        assertEquals(lmotsPublicKey, lmotsPublicKey3);
        assertEquals(lmotsPublicKey3.hashCode(), lmotsPublicKey.hashCode());
        assertEquals(lmotsPublicKey, lmotsPublicKey);
        assertNotEquals(lmotsPublicKey, null);
        assertNotEquals(lmotsPublicKey, new Object());
        assertNotEquals(lmotsPublicKey, lmotsPublicKey4);
        assertNotEquals(lmotsPublicKey, lmotsPublicKey5);
        assertNotEquals(lmotsPublicKey, lmotsPublicKey6);
        System.out.println(lmotsPublicKey);
    }
}