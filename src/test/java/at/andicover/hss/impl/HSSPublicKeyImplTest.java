package at.andicover.hss.impl;

import at.andicover.hss.api.HSSPublicKey;
import at.andicover.lmots.api.LMOTSType;
import at.andicover.lms.api.LMSKeyPair;
import at.andicover.lms.api.LMSType;
import at.andicover.lms.impl.LMS;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@SuppressWarnings("PMD.SystemPrintln")
public final class HSSPublicKeyImplTest {

    @Test
    void testEqualsAndHashcode() throws NoSuchAlgorithmException {
        final LMSKeyPair lmsKeyPair = LMS.generateKeys(LMSType.LMS_SHA256_M32_H5, LMOTSType.LMOTS_SHA256_N32_W1);
        final LMSKeyPair lmsKeyPair2 = LMS.generateKeys(LMSType.LMS_SHA256_M32_H5, LMOTSType.LMOTS_SHA256_N32_W4);

        final HSSPublicKey publicKey = new HSSPublicKeyImpl(2, lmsKeyPair.getPublicKey());
        final HSSPublicKey publicKey2 = new HSSPublicKeyImpl(3, lmsKeyPair.getPublicKey());
        final HSSPublicKey publicKey3 = new HSSPublicKeyImpl(2, lmsKeyPair.getPublicKey());
        final HSSPublicKey publicKey4 = new HSSPublicKeyImpl(2, lmsKeyPair2.getPublicKey());

        assertNotEquals(publicKey, publicKey2);
        assertNotEquals(publicKey2.hashCode(), publicKey.hashCode());
        assertEquals(publicKey, publicKey3);
        assertEquals(publicKey3.hashCode(), publicKey.hashCode());
        assertEquals(publicKey, publicKey);
        assertNotEquals(publicKey, null);
        assertNotEquals(publicKey, new Object());
        assertNotEquals(publicKey, publicKey4);
        System.out.println(publicKey);
    }
}
