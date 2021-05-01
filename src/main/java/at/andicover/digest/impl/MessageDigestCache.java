package at.andicover.digest.impl;

import at.andicover.digest.api.CustomMessageDigest;

import javax.annotation.Nonnull;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static at.andicover.config.Defaults.CACHE_TIMEOUT;
import static at.andicover.config.Defaults.MAX_CACHE_ENTRIES;

/**
 * Simple cache that holds one {@link CustomMessageDigest} instance per thread and algorithm.
 * It aims to drastically reduce instance creations. Because most of the time each thread uses always the same
 * message digest we do not need to fetch the instance everytime and instead hold it in memory. Because this is done
 * for each thread independently we do not need to lock anything which would be relevant for {@link CustomShakeDigest}.
 * <p>
 * Everytime an instance is fetched from the cache its timeout is reset. With this we make sure to not timeout an
 * instance that is constantly being used. If the cache is full it will be cleared and all instances need to be created
 * again. Make sure that the max cache size is set high enough {@link at.andicover.config.Defaults#MAX_CACHE_ENTRIES}.
 *
 * <p>
 * Note: Does not improve anything if the algorithm changes for each call!
 * </p>
 *
 * @author andreas.schoengruber
 * @version %I%
 */
public final class MessageDigestCache {

    private final Map<Long, CacheValue> data = new ConcurrentHashMap<>();

    private static class InstanceHolder {
        public static final MessageDigestCache INSTANCE = new MessageDigestCache();
    }

    private MessageDigestCache() {
    }

    /**
     * @return the singleton instance of the cache.
     */
    public static MessageDigestCache getInstance() {
        return MessageDigestCache.InstanceHolder.INSTANCE;
    }

    /**
     * Retrieve the CustomMessageDigest from the cache. Creates a new instance and writes it to the
     * cache if no valid value exists.
     *
     * @param algorithm the string value of the hashing algorithm.
     * @return the value.
     * @throws NoSuchAlgorithmException if the hash algorithm was not found.
     */
    public CustomMessageDigest getMessageDigest(@Nonnull final String algorithm)
            throws NoSuchAlgorithmException {
        final long threadId = Thread.currentThread().getId();
        CacheValue cacheValue = data.get(threadId);
        if (cacheValue == null || cacheValue.isTimedOut() || !cacheValue.getAlgorithm().equals(algorithm)) {
            cacheValue = addToCache(algorithm, threadId);
        }
        return cacheValue.getMessageDigest();
    }

    @Nonnull
    private CacheValue addToCache(@Nonnull final String algorithm, final long threadId)
            throws NoSuchAlgorithmException {
        if (data.size() >= MAX_CACHE_ENTRIES) {
            cleanUp();
        }

        final CustomMessageDigest customMessageDigest = CustomMessageDigestFactory.getDigest(algorithm);
        final CacheValue cacheValue = new CacheValue(customMessageDigest, algorithm, CACHE_TIMEOUT);
        data.put(threadId, cacheValue);
        return cacheValue;
    }

    private void cleanUp() {
        data.clear();
    }
}
