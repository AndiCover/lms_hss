package at.andicover;

import at.andicover.hss.api.HSSKeyPair;
import at.andicover.hss.api.HSSSignature;
import at.andicover.hss.impl.HSS;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W8;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H5;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class ConsumerTest {

    @Test
    void consumerTest() throws IOException, NoSuchAlgorithmException {
        final String message = "One very important message that needs to be signed!";

        //Create an HSS keypair. 20 keys are already reserved.
        final HSSKeyPair hssKeyPair =
                HSS.generateKeys(2, LMS_SHA256_M32_H5, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8, "consumerTest.privkey");
        assertEquals(20, hssKeyPair.getPrivateKey().getReservedKeys());

        //Create a signature --> We have one reserved key less
        final HSSSignature signature = HSS.generateSignature(message, hssKeyPair.getPrivateKey());
        assertTrue(HSS.verifySignature(message, signature, hssKeyPair.getPublicKey()));

        //Reserve keys when IDLE
        hssKeyPair.getPrivateKey().reserveKeys(5);
        assertEquals(24, hssKeyPair.getPrivateKey().getReservedKeys());

        //Second party verifies the signature with the public key
        assertTrue(HSS.verifySignature(message, signature, hssKeyPair.getPublicKey()));
    }
}
