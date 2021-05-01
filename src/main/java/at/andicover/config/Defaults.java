package at.andicover.config;

/**
 * Class with some predefined defaults that are used in the application.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
public final class Defaults {

    /**
     * How many keys should be reserved by default. The consumer still needs to make sure that always enough keys are
     * reserved!
     */
    public static final int DEFAULT_KEY_RESERVE_COUNT = 20;

    /**
     * The algorithm used for generating random numbers. This algorithm must be able to give deterministic results if
     * an seed is used.
     */
    public static final String RANDOM_NUMBER_ALGORITHM = "SHA1PRNG";

    /**
     * The timeout of message digest instances in the cache in milliseconds.
     */
    public static final int CACHE_TIMEOUT = 60_000;

    /**
     * Number of max elements stored in the cache.
     *
     * <p>
     * Note: With the current implementation the cache will be cleared if we want to add another element to the full cache.
     * This is most likely faster than looping through the cache and removing all outdated elements.
     * In case the max entries are set too low this will make the cache useless and decrease performance!
     * </p>
     */
    public static final int MAX_CACHE_ENTRIES = 200;

    /**
     * Size of asynchronous buffer in byte. One thread writes to it another thread reads from it.
     */
    public static final int DEFAULT_OUTPUT_BUFFER = 16_384;

    /**
     * Number of top level nodes of the LMS tree we store in memory.
     * Does not include the root node. Current number are the first 15 levels of the tree which result
     * in about 2 MB additional space.
     */
    public static final int STORED_TOP_LEVEL_NODES = 65_535;

    /**
     * Number of threads in the thread pool.
     */
    public static final int THREAD_COUNT = 16;

    private Defaults() {
    }
}
