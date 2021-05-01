package at.andicover.common.api;

/**
 * Interface for objects that can calculate their key size.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
public interface KeySize {

    /**
     * Calculates the key size and returns it.
     *
     * @return Key size in bytes.
     */
    int calculateSize();
}
