package at.andicover.lms.impl;

import at.andicover.lmots.api.LMOTSSignature;
import at.andicover.lmots.impl.LMOTS;
import at.andicover.lms.api.LMSSignature;
import at.andicover.lms.api.LMSType;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W1;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W2;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@SuppressWarnings("PMD.SystemPrintln")
final class LMSSingatureImplTest {

    @Test
    void testEqualsAndHashcode() throws NoSuchAlgorithmException {
        final LMOTSSignature lmotsSignature =
                LMOTS.generateSignature("mesjfdsklajf", LMOTS.generatePrivateKey(LMOTS_SHA256_N32_W1));
        final LMOTSSignature lmotsSignature2 =
                LMOTS.generateSignature("mesjfdfdsafssklajf", LMOTS.generatePrivateKey(LMOTS_SHA256_N32_W2));

        final LMSSignature lmsSignature =
                new LMSSignatureImpl(LMSType.LMS_SHA256_M32_H5, lmotsSignature, 12, new byte[17][3]);
        final LMSSignature lmsSignature2 =
                new LMSSignatureImpl(LMSType.LMS_SHA256_M32_H10, lmotsSignature, 12, new byte[17][3]);
        final LMSSignature lmsSignature3 =
                new LMSSignatureImpl(LMSType.LMS_SHA256_M32_H5, lmotsSignature, 12, new byte[17][3]);
        final LMSSignature lmsSignature4 =
                new LMSSignatureImpl(LMSType.LMS_SHA256_M32_H5, lmotsSignature, 13, new byte[17][3]);
        final LMSSignature lmsSignature5 =
                new LMSSignatureImpl(LMSType.LMS_SHA256_M32_H5, lmotsSignature, 12, new byte[14][2]);
        final LMSSignature lmsSignature6 =
                new LMSSignatureImpl(LMSType.LMS_SHA256_M32_H5, lmotsSignature2, 12, new byte[17][3]);

        assertNotEquals(lmsSignature, lmsSignature2);
        assertNotEquals(lmsSignature2.hashCode(), lmsSignature.hashCode());
        assertEquals(lmsSignature, lmsSignature3);
        assertEquals(lmsSignature3.hashCode(), lmsSignature.hashCode());
        assertEquals(lmsSignature, lmsSignature);
        assertNotEquals(lmsSignature, null);
        assertNotEquals(lmsSignature, new Object());
        assertNotEquals(lmsSignature, lmsSignature4);
        assertNotEquals(lmsSignature, lmsSignature5);
        assertNotEquals(lmsSignature, lmsSignature6);
        System.out.println(lmsSignature);
    }
}