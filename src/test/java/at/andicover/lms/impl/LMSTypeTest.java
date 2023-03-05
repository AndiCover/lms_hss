package at.andicover.lms.impl;

import at.andicover.lms.api.LMSType;
import org.junit.jupiter.api.Test;

import static at.andicover.lms.api.LMSType.LMS_SHA256_M24_H10;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M24_H15;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M24_H20;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M24_H25;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M24_H5;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H10;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H15;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H20;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H25;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H5;
import static at.andicover.lms.api.LMSType.LMS_SHAKE_M24_H10;
import static at.andicover.lms.api.LMSType.LMS_SHAKE_M24_H15;
import static at.andicover.lms.api.LMSType.LMS_SHAKE_M24_H20;
import static at.andicover.lms.api.LMSType.LMS_SHAKE_M24_H25;
import static at.andicover.lms.api.LMSType.LMS_SHAKE_M24_H5;
import static at.andicover.lms.api.LMSType.LMS_SHAKE_M32_H10;
import static at.andicover.lms.api.LMSType.LMS_SHAKE_M32_H15;
import static at.andicover.lms.api.LMSType.LMS_SHAKE_M32_H20;
import static at.andicover.lms.api.LMSType.LMS_SHAKE_M32_H25;
import static at.andicover.lms.api.LMSType.LMS_SHAKE_M32_H5;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class LMSTypeTest {

    @Test
    void testLookup() {
        assertEquals(LMS_SHA256_M32_H5, LMSType.lookUp(5));
        assertEquals(LMS_SHA256_M32_H10, LMSType.lookUp(6));
        assertEquals(LMS_SHA256_M32_H15, LMSType.lookUp(7));
        assertEquals(LMS_SHA256_M32_H20, LMSType.lookUp(8));
        assertEquals(LMS_SHA256_M32_H25, LMSType.lookUp(9));

        assertEquals(LMS_SHA256_M24_H5, LMSType.lookUp(10));
        assertEquals(LMS_SHA256_M24_H10, LMSType.lookUp(11));
        assertEquals(LMS_SHA256_M24_H15, LMSType.lookUp(12));
        assertEquals(LMS_SHA256_M24_H20, LMSType.lookUp(13));
        assertEquals(LMS_SHA256_M24_H25, LMSType.lookUp(14));

        assertEquals(LMS_SHAKE_M32_H5, LMSType.lookUp(15));
        assertEquals(LMS_SHAKE_M32_H10, LMSType.lookUp(16));
        assertEquals(LMS_SHAKE_M32_H15, LMSType.lookUp(17));
        assertEquals(LMS_SHAKE_M32_H20, LMSType.lookUp(18));
        assertEquals(LMS_SHAKE_M32_H25, LMSType.lookUp(19));

        assertEquals(LMS_SHAKE_M24_H5, LMSType.lookUp(20));
        assertEquals(LMS_SHAKE_M24_H10, LMSType.lookUp(21));
        assertEquals(LMS_SHAKE_M24_H15, LMSType.lookUp(22));
        assertEquals(LMS_SHAKE_M24_H20, LMSType.lookUp(23));
        assertEquals(LMS_SHAKE_M24_H25, LMSType.lookUp(24));
        assertThrows(IllegalArgumentException.class, () -> LMSType.lookUp(3));
        assertThrows(IllegalArgumentException.class, () -> LMSType.lookUp(25));
    }
}