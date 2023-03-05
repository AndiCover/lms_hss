package at.andicover.lmots.impl;

import at.andicover.lmots.api.LMOTSSignature;
import at.andicover.lmots.api.LMOTSType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@SuppressWarnings("PMD.SystemPrintln")
final class LMOTSSignatureImplTest {

    @Test
    void testEqualsAndHashcode() {
        final LMOTSSignature lmotsSignature =
                new LMOTSSignatureImpl(LMOTSType.LMOTS_SHA256_N32_W1, new byte[2], new byte[4][34]);
        final LMOTSSignature lmotsSignature2 =
                new LMOTSSignatureImpl(LMOTSType.LMOTS_SHA256_N32_W2, new byte[2], new byte[4][34]);
        final LMOTSSignature lmotsSignature3 =
                new LMOTSSignatureImpl(LMOTSType.LMOTS_SHA256_N32_W1, new byte[2], new byte[4][34]);
        final LMOTSSignature lmotsSignature4 =
                new LMOTSSignatureImpl(LMOTSType.LMOTS_SHA256_N32_W1, new byte[4], new byte[4][34]);
        final LMOTSSignature lmotsSignature5 =
                new LMOTSSignatureImpl(LMOTSType.LMOTS_SHA256_N32_W1, new byte[2], new byte[2][12]);

        assertNotEquals(lmotsSignature, lmotsSignature2);
        assertNotEquals(lmotsSignature2.hashCode(), lmotsSignature.hashCode());
        assertEquals(lmotsSignature, lmotsSignature3);
        assertEquals(lmotsSignature3.hashCode(), lmotsSignature.hashCode());
        assertEquals(lmotsSignature, lmotsSignature);
        assertNotEquals(lmotsSignature, null);
        assertNotEquals(lmotsSignature, new Object());
        assertNotEquals(lmotsSignature, lmotsSignature4);
        assertNotEquals(lmotsSignature, lmotsSignature5);
        System.out.println(lmotsSignature);
    }
}