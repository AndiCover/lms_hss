package at.andicover.digest.impl;

import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public final class MessageDigestCacheTest {

    @Test
    void testSimpleCache() throws NoSuchAlgorithmException {
        final MessageDigestCache cache = MessageDigestCache.getInstance();
        assertNotNull(cache.getMessageDigest("SHA-256"));
        assertNotNull(cache.getMessageDigest("SHA-256/192"));
        assertNotNull(cache.getMessageDigest("SHAKE256"));
        assertNotNull(cache.getMessageDigest("SHAKE256/192"));
    }
}
