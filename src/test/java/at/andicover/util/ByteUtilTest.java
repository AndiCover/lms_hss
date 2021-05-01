package at.andicover.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public final class ByteUtilTest {

    @Test
    void testIntTo4ByteArray() {
        final int integer = Integer.MAX_VALUE;
        final byte[] bytes = ByteUtil.intTo4ByteArray(integer);
        assertEquals(integer, ByteUtil.byteArrayToInt(bytes, 0, bytes.length));
    }

    @Test
    void testIntTo2ByteArray() {
        final int integer = 65_535;
        final byte[] bytes = ByteUtil.intTo2ByteArray(integer);
        assertEquals(integer, ByteUtil.byteArrayToInt(bytes, 0, bytes.length));
    }

    @Test
    void testIntTo1ByteArray() {
        final int integer = 255;
        final byte[] bytes = ByteUtil.intTo1ByteArray(integer);
        assertEquals(integer, ByteUtil.byteArrayToInt(bytes, 0, bytes.length));
    }

    @Test
    void testInvalidLength() {
        final int integer = 20;
        final byte[] bytes = ByteUtil.intTo2ByteArray(integer);
        assertEquals(0, ByteUtil.byteArrayToInt(bytes, 0, 6));
        assertEquals(0, ByteUtil.byteArrayToInt(bytes, 0, -1));
    }
}