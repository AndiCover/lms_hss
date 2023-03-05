package at.andicover.lms.impl;

import at.andicover.lmots.api.LMOTSPrivateKey;
import at.andicover.lms.api.LMSPrivateKey;
import at.andicover.lms.api.LMSPublicKey;
import org.junit.jupiter.api.Test;

import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W1;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W2;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H10;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H5;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@SuppressWarnings("PMD.SystemPrintln")
final class LMSPublicKeyImplTest {

    @Test
    void testEqualsAndHashcode() {
        final LMSPrivateKey lmsPrivateKey =
                new LMSPrivateKeyImpl(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W1, new LMOTSPrivateKey[10], new byte[0]);
        final LMSPrivateKey lmsPrivateKey2 =
                new LMSPrivateKeyImpl(LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W1, new LMOTSPrivateKey[10], new byte[0]);
        final LMSPrivateKey lmsPrivateKey4 =
                new LMSPrivateKeyImpl(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W2, new LMOTSPrivateKey[10], new byte[0]);
        final LMSPrivateKey lmsPrivateKey5 =
                new LMSPrivateKeyImpl(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W1, new LMOTSPrivateKey[17], new byte[0]);
        final LMSPrivateKey lmsPrivateKey6 =
                new LMSPrivateKeyImpl(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W1, new LMOTSPrivateKey[10], new byte[8]);

        final LMSPublicKey lmsPublicKey = new LMSPublicKeyImpl(lmsPrivateKey, new byte[17]);
        final LMSPublicKey lmsPublicKey2 = new LMSPublicKeyImpl(lmsPrivateKey2, new byte[3]);
        final LMSPublicKey lmsPublicKey3 = new LMSPublicKeyImpl(lmsPrivateKey, new byte[17]);
        final LMSPublicKey lmsPublicKey4 = new LMSPublicKeyImpl(lmsPrivateKey4, new byte[17]);
        final LMSPublicKey lmsPublicKey5 = new LMSPublicKeyImpl(lmsPrivateKey5, new byte[22]);
        final LMSPublicKey lmsPublicKey6 = new LMSPublicKeyImpl(lmsPrivateKey6, new byte[17]);

        assertNotEquals(lmsPublicKey, lmsPublicKey2);
        assertNotEquals(lmsPublicKey2.hashCode(), lmsPublicKey.hashCode());
        assertEquals(lmsPublicKey, lmsPublicKey3);
        assertEquals(lmsPublicKey3.hashCode(), lmsPublicKey.hashCode());
        assertEquals(lmsPublicKey, lmsPublicKey);
        assertNotEquals(lmsPublicKey, null);
        assertNotEquals(lmsPublicKey, new Object());
        assertNotEquals(lmsPublicKey, lmsPublicKey4);
        assertNotEquals(lmsPublicKey, lmsPublicKey5);
        assertNotEquals(lmsPublicKey, lmsPublicKey6);
        System.out.println(lmsPublicKey);
    }
}