package at.andicover.lmots.impl;

import at.andicover.lmots.api.LMOTSType;
import org.junit.jupiter.api.Test;

import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N24_W1;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N24_W2;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N24_W4;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N24_W8;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W1;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W2;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W4;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W8;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHAKE_N24_W1;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHAKE_N24_W2;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHAKE_N24_W4;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHAKE_N24_W8;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHAKE_N32_W1;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHAKE_N32_W2;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHAKE_N32_W4;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHAKE_N32_W8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class LMOTSTypeTest {

    @Test
    void testLookup() {
        assertEquals(LMOTS_SHA256_N32_W1, LMOTSType.lookUp(1));
        assertEquals(LMOTS_SHA256_N32_W2, LMOTSType.lookUp(2));
        assertEquals(LMOTS_SHA256_N32_W4, LMOTSType.lookUp(3));
        assertEquals(LMOTS_SHA256_N32_W8, LMOTSType.lookUp(4));
        assertEquals(LMOTS_SHA256_N24_W1, LMOTSType.lookUp(5));
        assertEquals(LMOTS_SHA256_N24_W2, LMOTSType.lookUp(6));
        assertEquals(LMOTS_SHA256_N24_W4, LMOTSType.lookUp(7));
        assertEquals(LMOTS_SHA256_N24_W8, LMOTSType.lookUp(8));
        assertEquals(LMOTS_SHAKE_N32_W1, LMOTSType.lookUp(9));
        assertEquals(LMOTS_SHAKE_N32_W2, LMOTSType.lookUp(10));
        assertEquals(LMOTS_SHAKE_N32_W4, LMOTSType.lookUp(11));
        assertEquals(LMOTS_SHAKE_N32_W8, LMOTSType.lookUp(12));

        assertEquals(LMOTS_SHAKE_N24_W1, LMOTSType.lookUp(13));
        assertEquals(LMOTS_SHAKE_N24_W2, LMOTSType.lookUp(14));
        assertEquals(LMOTS_SHAKE_N24_W4, LMOTSType.lookUp(15));
        assertEquals(LMOTS_SHAKE_N24_W8, LMOTSType.lookUp(16));
        assertThrows(IllegalArgumentException.class, () -> LMOTSType.lookUp(0));
        assertThrows(IllegalArgumentException.class, () -> LMOTSType.lookUp(17));
    }
}