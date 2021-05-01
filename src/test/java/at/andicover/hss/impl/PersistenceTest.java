package at.andicover.hss.impl;

import at.andicover.hss.api.HSSKeyPair;
import at.andicover.hss.api.HSSPrivateKey;
import at.andicover.util.PersistenceUtil;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;

import static at.andicover.config.Defaults.DEFAULT_KEY_RESERVE_COUNT;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W1;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H5;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public final class PersistenceTest {

    private static final String KEY_FILENAME = "persistance_test.privkey";

    @Test
    void testKeyPersistance() throws IOException, NoSuchAlgorithmException {
        Files.deleteIfExists(Path.of(KEY_FILENAME));
        //We reserve all 32 keys when generating the key. The key is immediately stored to disk.
        final HSSKeyPair keyPair = HSS.generateKeys(1, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W1, KEY_FILENAME);
        final HSSPrivateKey privateKey = (HSSPrivateKey) PersistenceUtil.loadKey(KEY_FILENAME, HSSPrivateKey.class);

        // When reading the key again from disk we expect the current qIdentifier to be equal to the reserved key count --> 32.
        // Therefore no keys are available anymore.
        assertEquals(0, keyPair.getPrivateKey().getLmsPrivateKeys()[0].getQIdentifier());
        assertNotEquals(keyPair.getPrivateKey(), privateKey);
        assertNotNull(privateKey);
        assertFalse(privateKey.getLmsPrivateKeys()[0].hasReservedKey());
        assertEquals(DEFAULT_KEY_RESERVE_COUNT, privateKey.getLmsPrivateKeys()[0].getQIdentifier());
        assertThrows(IllegalStateException.class, () -> privateKey.getLmsPrivateKeys()[0].getNextLmotsKey());
    }
}
