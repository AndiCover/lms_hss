package at.andicover.util;

import at.andicover.hss.api.HSSPrivateKey;
import org.junit.jupiter.api.Test;

import java.io.UncheckedIOException;

import static org.junit.jupiter.api.Assertions.assertThrows;

final class PersistenceUtilTest {

    @Test
    void testLoadMissingFile() {
        assertThrows(UncheckedIOException.class, () -> PersistenceUtil.loadKey("missingFile_", HSSPrivateKey.class));
    }

    @Test
    void testInvalidKeyFile() {
        assertThrows(RuntimeException.class, () -> PersistenceUtil
                .loadKey("../../../src/test/resources/invalidKeyFile.privKey", HSSPrivateKey.class));
    }

    @Test
    void testEmptyKeyFile() {
        assertThrows(RuntimeException.class,
                () -> PersistenceUtil.loadKey("../../../src/test/resources/emptyKeyFile.privKey", HSSPrivateKey.class));
    }
}
