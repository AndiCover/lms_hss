package at.andicover.util;

import javax.annotation.Nonnull;
import java.util.Arrays;

import static at.andicover.util.ByteUtil.intTo2ByteArray;

/**
 * Utility class with several predefined security strings.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-7.1">RFC 8554 - Security String</a>
 */
public final class SecurityString {

    private static final byte[] D_PBLC = intTo2ByteArray(Integer.decode("0x8080"));
    private static final byte[] D_MESG = intTo2ByteArray(Integer.decode("0x8181"));
    private static final byte[] D_LEAF = intTo2ByteArray(Integer.decode("0x8282"));
    private static final byte[] D_INTR = intTo2ByteArray(Integer.decode("0x8383"));

    private SecurityString() {
    }

    /**
     * @return D_PBLC as byte array.
     */
    @Nonnull
    public static byte[] getdPblc() {
        return Arrays.copyOf(D_PBLC, D_PBLC.length);
    }

    /**
     * @return D_MESG as byte array.
     */
    @Nonnull
    public static byte[] getdMesg() {
        return Arrays.copyOf(D_MESG, D_MESG.length);
    }

    /**
     * @return D_LEAF as byte array.
     */
    @Nonnull
    public static byte[] getdLeaf() {
        return Arrays.copyOf(D_LEAF, D_LEAF.length);
    }

    /**
     * @return D_INTR as byte array.
     */
    @Nonnull
    public static byte[] getdIntr() {
        return Arrays.copyOf(D_INTR, D_INTR.length);
    }
}
