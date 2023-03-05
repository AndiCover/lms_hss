package at.andicover.digest.impl;

import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class CustomMessageDigestFactoryTest {

    @Test
    void testValidAlgorithms() throws NoSuchAlgorithmException {
        assertNotNull(CustomMessageDigestFactory.getDigest("SHA-256"));
        assertNotNull(CustomMessageDigestFactory.getDigest("SHA-256/192"));
        assertNotNull(CustomMessageDigestFactory.getDigest("SHAKE256"));
        assertNotNull(CustomMessageDigestFactory.getDigest("SHAKE256/192"));
    }

    @Test
    void testInvalidAlgorithm() {
        assertThrows(NoSuchAlgorithmException.class, () -> CustomMessageDigestFactory.getDigest("dsaaddfas"));
    }
}