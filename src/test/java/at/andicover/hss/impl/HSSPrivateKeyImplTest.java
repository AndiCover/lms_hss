package at.andicover.hss.impl;

import at.andicover.hss.api.HSSPrivateKey;
import at.andicover.lms.api.LMSPrivateKey;
import at.andicover.lms.api.LMSPublicKey;
import at.andicover.lms.api.LMSSignature;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@SuppressWarnings("PMD.SystemPrintln")
public final class HSSPrivateKeyImplTest {

    @Test
    void testEqualsAndHashcode() {
        final HSSPrivateKey privateKey =
                new HSSPrivateKeyImpl(2, new LMSPrivateKey[1], new LMSPublicKey[2], new LMSSignature[3]);
        final HSSPrivateKey privateKey2 =
                new HSSPrivateKeyImpl(3, new LMSPrivateKey[1], new LMSPublicKey[2], new LMSSignature[3]);
        final HSSPrivateKey privateKey3 =
                new HSSPrivateKeyImpl(2, new LMSPrivateKey[1], new LMSPublicKey[2], new LMSSignature[3]);
        final HSSPrivateKey privateKey4 =
                new HSSPrivateKeyImpl(2, new LMSPrivateKey[2], new LMSPublicKey[2], new LMSSignature[3]);
        final HSSPrivateKey privateKey5 =
                new HSSPrivateKeyImpl(2, new LMSPrivateKey[1], new LMSPublicKey[4], new LMSSignature[3]);
        final HSSPrivateKey privateKey6 =
                new HSSPrivateKeyImpl(2, new LMSPrivateKey[1], new LMSPublicKey[2], new LMSSignature[5]);

        assertNotEquals(privateKey, privateKey2);
        assertNotEquals(privateKey2.hashCode(), privateKey.hashCode());
        assertEquals(privateKey, privateKey3);
        assertEquals(privateKey3.hashCode(), privateKey.hashCode());
        assertEquals(privateKey, privateKey);
        assertNotEquals(privateKey, null);
        assertNotEquals(privateKey, new Object());
        assertNotEquals(privateKey, privateKey4);
        assertNotEquals(privateKey, privateKey5);
        assertNotEquals(privateKey, privateKey6);
        System.out.println(privateKey);
    }
}
