package at.andicover.util;

import javax.annotation.Nonnull;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import static at.andicover.config.Defaults.THREAD_COUNT;
import static java.util.Objects.requireNonNull;

/**
 * Utility class for common multithreading stuff.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
public final class ThreadUtil {

    private static final Logger LOGGER = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);


    private ThreadUtil() {
    }

    /**
     * Create a new thread pool with 16 threads.
     *
     * @return the newly created thread pool.
     */
    @Nonnull
    public static ExecutorService createNewThreadExecutor() {
        return new ThreadPoolExecutor(THREAD_COUNT, THREAD_COUNT, 1L, TimeUnit.MINUTES, new LinkedBlockingQueue<>());
    }

    /**
     * Shutdown the given Executor Service. Waits for its termination and handles all possible exceptions.
     * Running threads have enough time to finish their work.
     *
     * @param executorService The executor service to shutdown.
     */
    public static void shutdownThreadExecutor(@Nonnull final ExecutorService executorService) {
        requireNonNull(executorService);

        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS)) {
                executorService.shutdownNow();
                if (!executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS)) {
                    LOGGER.log(Level.SEVERE, "Thread executor did not terminate.");
                }
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }
}
