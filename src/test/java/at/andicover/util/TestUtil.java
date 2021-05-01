package at.andicover.util;

import at.andicover.lmots.api.LMOTSType;
import at.andicover.lms.api.LMSType;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import javax.annotation.Nonnull;
import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N24_W2;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W1;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHAKE_N24_W8;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHAKE_N32_W4;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M24_H10;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H5;
import static at.andicover.lms.api.LMSType.LMS_SHAKE_M24_H5;
import static at.andicover.lms.api.LMSType.LMS_SHAKE_M32_H5;

public final class TestUtil {

    private TestUtil() {
    }

    @Nonnull
    public static List<LMOTSType> getLmotsTypes() {
        return Arrays.asList(LMOTS_SHA256_N32_W1, LMOTS_SHA256_N24_W2, LMOTS_SHAKE_N32_W4, LMOTS_SHAKE_N24_W8);
    }

    @Nonnull
    public static List<LMSType> getLmsTypes() {
        return Arrays.asList(LMS_SHA256_M32_H5, LMS_SHA256_M24_H10, LMS_SHAKE_M32_H5, LMS_SHAKE_M24_H5);
    }

    @SuppressFBWarnings(value = "PATH_TRAVERSAL_IN", justification = "OK in unit test scenario.")
    @Nonnull
    public static String getResourcePath(@Nonnull final String resourceName) {
        final File file = new File(
                Objects.requireNonNull(Thread.currentThread().getContextClassLoader().getResource(resourceName))
                        .getFile());
        return file.getAbsolutePath();
    }
}
