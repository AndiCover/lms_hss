package at.andicover.util;

import org.apache.commons.lang3.ArrayUtils;

import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;

/**
 * Utility class to build a byte array from an int value.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
public final class ByteUtil {

    private ByteUtil() {
    }

    /**
     * Creates a byte array with 4 bytes from the given integer.
     *
     * @param value the integer value.
     * @return the byte array with length 4.
     */
    @Nonnull
    public static byte[] intTo4ByteArray(final int value) {
        return new byte[]{
                (byte) (value >>> 24),
                (byte) (value >>> 16),
                (byte) (value >>> 8),
                (byte) value};
    }

    /**
     * Creates a byte array with 2 bytes from the given integer.
     *
     * @param value the integer value.
     * @return the byte array with length 2.
     */
    @Nonnull
    public static byte[] intTo2ByteArray(final int value) {
        return new byte[]{
                (byte) (value >>> 8),
                (byte) value};
    }

    /**
     * Create a byte array with 1 byte from the given integer.
     *
     * @param value the integer value.
     * @return the byte array with length 1.
     */
    @Nonnull
    public static byte[] intTo1ByteArray(final int value) {
        return new byte[]{
                (byte) value};
    }

    /**
     * Creates an integer from a given byte array. The given byte array can be much longer because the position of the
     * relevant bytes is defined by the parameters src and dst.
     *
     * <p>
     * Note: If dst - src is not 1, 2, or 4 this method will return 0!
     * </p>
     *
     * @param bytes the byte array.
     * @param src   the index of the first byte of the integer.
     * @param dst   the index of the last byte of the integer.
     * @return the resulting integer.
     */
    public static int byteArrayToInt(@Nonnull final byte[] bytes, final int src, final int dst) {
        final int length = dst - src;
        if (length == 4) {
            return bytes[src] << 24 | (bytes[src + 1] & 0xff) << 16 | (bytes[src + 2] & 0xff) << 8
                    | (bytes[src + 3] & 0xff);
        } else if (length == 2) {
            return (bytes[src] & 0xff) << 8 | (bytes[src + 1] & 0xff);
        } else if (length == 1) {
            return bytes[src] & 0xff;
        }
        return 0;
    }

    /**
     * Merges two byte arrays into one byte array.
     *
     * @param bytes  first byte array.
     * @param bytes2 second byte array.
     * @return resulting byte array with a total length of both input arrays combined.
     */
    @Nonnull
    public static byte[] merge(@Nonnull final byte[] bytes, @Nonnull final byte[] bytes2) {
        return ArrayUtils.addAll(bytes, bytes2);
    }

    /**
     * Merges four byte arrays into one byte array.
     *
     * @param bytes  first byte array.
     * @param bytes2 second byte array.
     * @param bytes3 third byte array.
     * @param bytes4 fourth byte array.
     * @return resulting byte array with a total length of all input arrays combined.
     */
    @Nonnull
    public static byte[] merge(@Nonnull final byte[] bytes, @Nonnull final byte[] bytes2, @Nonnull final byte[] bytes3,
                               @Nonnull final byte[] bytes4) {
        requireNonNull(bytes);
        requireNonNull(bytes2);
        requireNonNull(bytes3);
        requireNonNull(bytes4);

        final byte[] result = new byte[bytes.length + bytes2.length + bytes3.length + bytes4.length];
        int length = 0;
        System.arraycopy(bytes, 0, result, 0, bytes.length);
        length += bytes.length;
        System.arraycopy(bytes2, 0, result, length, bytes2.length);
        length += bytes2.length;
        System.arraycopy(bytes3, 0, result, length, bytes3.length);
        length += bytes3.length;
        System.arraycopy(bytes4, 0, result, length, bytes4.length);

        return result;
    }

    /**
     * Merges five byte arrays into one byte array.
     *
     * @param bytes  first byte array.
     * @param bytes2 second byte array.
     * @param bytes3 third byte array.
     * @param bytes4 fourth byte array.
     * @param bytes5 fifth byte array.
     * @return resulting byte array with a total length of all input arrays combined.
     */
    @Nonnull
    public static byte[] merge(@Nonnull final byte[] bytes, @Nonnull final byte[] bytes2, @Nonnull final byte[] bytes3,
                               @Nonnull final byte[] bytes4, @Nonnull final byte[] bytes5) {
        requireNonNull(bytes);
        requireNonNull(bytes2);
        requireNonNull(bytes3);
        requireNonNull(bytes4);
        requireNonNull(bytes5);

        final byte[] result = new byte[bytes.length + bytes2.length + bytes3.length + bytes4.length + bytes5.length];
        int length = 0;
        System.arraycopy(bytes, 0, result, 0, bytes.length);
        length += bytes.length;
        System.arraycopy(bytes2, 0, result, length, bytes2.length);
        length += bytes2.length;
        System.arraycopy(bytes3, 0, result, length, bytes3.length);
        length += bytes3.length;
        System.arraycopy(bytes4, 0, result, length, bytes4.length);
        length += bytes4.length;
        System.arraycopy(bytes5, 0, result, length, bytes5.length);

        return result;
    }
}
