package at.andicover.lms.impl;

import at.andicover.lmots.api.LMOTSType;
import at.andicover.lms.api.LMSKeyPair;
import at.andicover.lms.api.LMSType;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class LMSKeyPairImplTest {

    @Test
    void testEqualsAndHashcode() throws NoSuchAlgorithmException {
        final LMSKeyPair keyPair =
                LMS.generateKeys(LMSType.LMS_SHA256_M32_H5, LMOTSType.LMOTS_SHA256_N32_W1);
        final LMSKeyPair keyPair2 =
                LMS.generateKeys(LMSType.LMS_SHA256_M32_H5, LMOTSType.LMOTS_SHA256_N32_W2);
        final LMSKeyPair keyPair3 = new LMSKeyPairImpl(keyPair.getPrivateKey(), keyPair.getPublicKey());
        final LMSKeyPair keyPair4 = new LMSKeyPairImpl(keyPair.getPrivateKey(), keyPair2.getPublicKey());

        assertNotEquals(keyPair, keyPair2);
        assertNotEquals(keyPair2.hashCode(), keyPair.hashCode());
        assertEquals(keyPair, keyPair3);
        assertEquals(keyPair3.hashCode(), keyPair.hashCode());
        assertEquals(keyPair, keyPair);
        assertNotEquals(keyPair, null);
        assertNotEquals(keyPair, keyPair4);
        assertNotEquals(keyPair, new Object());
    }
}