package at.andicover.lms.impl;

import at.andicover.lmots.api.LMOTSPrivateKey;
import at.andicover.lms.api.LMSPrivateKey;
import org.junit.jupiter.api.Test;

import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W1;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W2;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H10;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H5;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@SuppressWarnings("PMD.SystemPrintln")
public final class LMSPrivateKeyImplTest {

    @Test
    void testEqualsAndHashcode() {
        final LMSPrivateKey lmsPrivateKey =
                new LMSPrivateKeyImpl(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W1, new LMOTSPrivateKey[10], new byte[0]);
        final LMSPrivateKey lmsPrivateKey2 =
                new LMSPrivateKeyImpl(LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W1, new LMOTSPrivateKey[10], new byte[0]);
        final LMSPrivateKey lmsPrivateKey3 =
                new LMSPrivateKeyImpl(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W1, new LMOTSPrivateKey[10], new byte[0]);
        final LMSPrivateKey lmsPrivateKey4 =
                new LMSPrivateKeyImpl(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W2, new LMOTSPrivateKey[10], new byte[0]);
        final LMSPrivateKey lmsPrivateKey5 =
                new LMSPrivateKeyImpl(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W1, new LMOTSPrivateKey[17], new byte[0]);
        final LMSPrivateKey lmsPrivateKey6 =
                new LMSPrivateKeyImpl(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W1, new LMOTSPrivateKey[10], new byte[8]);

        assertNotEquals(lmsPrivateKey, lmsPrivateKey2);
        assertNotEquals(lmsPrivateKey2.hashCode(), lmsPrivateKey.hashCode());
        assertEquals(lmsPrivateKey, lmsPrivateKey3);
        assertEquals(lmsPrivateKey3.hashCode(), lmsPrivateKey.hashCode());
        assertEquals(lmsPrivateKey, lmsPrivateKey);
        assertNotEquals(lmsPrivateKey, null);
        assertNotEquals(lmsPrivateKey, new Object());
        assertNotEquals(lmsPrivateKey, lmsPrivateKey4);
        assertNotEquals(lmsPrivateKey, lmsPrivateKey5);
        assertNotEquals(lmsPrivateKey, lmsPrivateKey6);
        System.out.println(lmsPrivateKey);
    }
}
