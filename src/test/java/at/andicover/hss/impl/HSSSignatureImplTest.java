package at.andicover.hss.impl;

import at.andicover.hss.api.HSSSignature;
import at.andicover.lmots.api.LMOTSType;
import at.andicover.lms.api.LMSKeyPair;
import at.andicover.lms.api.LMSPublicKey;
import at.andicover.lms.api.LMSSignature;
import at.andicover.lms.api.LMSType;
import at.andicover.lms.impl.LMS;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@SuppressWarnings("PMD.SystemPrintln")
public final class HSSSignatureImplTest {

    @Test
    void testEqualsAndHashcode() throws NoSuchAlgorithmException {
        final LMSKeyPair lmsKeyPair = LMS.generateKeys(LMSType.LMS_SHA256_M32_H5, LMOTSType.LMOTS_SHA256_N32_W1);
        lmsKeyPair.getPrivateKey().reserveKeys(1);
        final LMSKeyPair lmsKeyPair2 = LMS.generateKeys(LMSType.LMS_SHA256_M32_H5, LMOTSType.LMOTS_SHA256_N32_W4);
        lmsKeyPair2.getPrivateKey().reserveKeys(1);

        final LMSSignature lmsSignature = LMS.generateSignature("fjdkslj", lmsKeyPair.getPrivateKey());
        final LMSSignature lmsSignature2 = LMS.generateSignature("fjdkgfdgfsdg5sgrz5slj", lmsKeyPair2.getPrivateKey());
        final LMSSignature[] lmsSignatures = new LMSSignature[2];
        final LMSPublicKey[] lmsPublicKeys = new LMSPublicKey[2];
        lmsSignatures[0] = lmsSignature;
        lmsSignatures[1] = lmsSignature2;
        lmsPublicKeys[0] = lmsKeyPair.getPublicKey();
        lmsPublicKeys[1] = lmsKeyPair2.getPublicKey();

        final HSSSignature signature1 = new HSSSignatureImpl(1, lmsSignatures, lmsPublicKeys);
        final HSSSignature signature2 = new HSSSignatureImpl(2, lmsSignatures, lmsPublicKeys);
        final HSSSignature signature3 = new HSSSignatureImpl(1, lmsSignatures, lmsPublicKeys);
        final HSSSignature signature4 = new HSSSignatureImpl(1, new LMSSignature[1], lmsPublicKeys);
        final HSSSignature signature5 = new HSSSignatureImpl(1, lmsSignatures, new LMSPublicKey[2]);

        assertNotEquals(signature1, signature2);
        assertNotEquals(signature2.hashCode(), signature1.hashCode());
        assertEquals(signature1, signature3);
        assertEquals(signature3.hashCode(), signature1.hashCode());
        assertEquals(signature1, signature1);
        assertNotEquals(signature1, null);
        assertNotEquals(signature1, new Object());
        assertNotEquals(signature1, signature4);
        assertNotEquals(signature1, signature5);
        System.out.println(signature1);
    }
}
