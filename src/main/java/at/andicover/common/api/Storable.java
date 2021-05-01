package at.andicover.common.api;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.PipedOutputStream;

/**
 * Interface for storable key objects.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
public interface Storable {

    /**
     * Returns the key as byte array.
     * <p>
     * Note: Might throw an OutOfMemory exception. Use with care.
     * </p>
     *
     * @return the bytes of the object.
     */
    @Nonnull
    byte[] getBytes();

    /**
     * Writes the key to the given PipedOutputStream.
     *
     * @param outputStream The piped outputstream.
     * @throws IOException any possible IO exceptions.
     */
    void writeToPipedOutputStream(@Nonnull PipedOutputStream outputStream) throws IOException;
}
