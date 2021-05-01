package at.andicover.hss.impl;

import at.andicover.hss.api.HSSKeyPair;
import at.andicover.hss.api.HSSPrivateKey;
import at.andicover.hss.api.HSSPublicKey;
import at.andicover.lmots.api.LMOTSType;
import at.andicover.lms.api.LMSKeyPair;
import at.andicover.lms.api.LMSPrivateKey;
import at.andicover.lms.api.LMSPublicKey;
import at.andicover.lms.api.LMSSignature;
import at.andicover.lms.api.LMSType;
import at.andicover.lms.impl.LMS;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public final class HSSKeyPairImplTest {

    @Test
    void testEqualsAndHashcode() throws NoSuchAlgorithmException {
        final LMSKeyPair lmsKeyPair = LMS.generateKeys(LMSType.LMS_SHA256_M32_H5, LMOTSType.LMOTS_SHA256_N32_W1);
        final LMSKeyPair lmsKeyPair2 = LMS.generateKeys(LMSType.LMS_SHA256_M32_H5, LMOTSType.LMOTS_SHA256_N32_W4);

        final HSSPrivateKey privateKey =
                new HSSPrivateKeyImpl(2, new LMSPrivateKey[1], new LMSPublicKey[2], new LMSSignature[3]);
        final HSSPrivateKey privateKey2 =
                new HSSPrivateKeyImpl(3, new LMSPrivateKey[3], new LMSPublicKey[4], new LMSSignature[3]);

        final HSSPublicKey publicKey = new HSSPublicKeyImpl(2, lmsKeyPair.getPublicKey());
        final HSSPublicKey publicKey2 = new HSSPublicKeyImpl(3, lmsKeyPair2.getPublicKey());

        final HSSKeyPair keyPair = new HSSKeyPairImpl(privateKey, publicKey);
        final HSSKeyPair keyPair2 = new HSSKeyPairImpl(privateKey2, publicKey2);
        final HSSKeyPair keyPair3 = new HSSKeyPairImpl(privateKey, publicKey);
        final HSSKeyPair keyPair4 = new HSSKeyPairImpl(privateKey, publicKey2);

        assertNotEquals(keyPair, keyPair2);
        assertNotEquals(keyPair2.hashCode(), keyPair.hashCode());
        assertEquals(keyPair, keyPair3);
        assertEquals(keyPair3.hashCode(), keyPair.hashCode());
        assertEquals(keyPair, keyPair);
        assertNotEquals(keyPair, null);
        assertNotEquals(keyPair, new Object());
        assertNotEquals(keyPair, keyPair4);
    }
}
