package at.andicover.benchmarking.slow.signatureverification;

import at.andicover.hss.api.HSSKeyPair;
import at.andicover.hss.api.HSSPublicKey;
import at.andicover.hss.api.HSSSignature;
import at.andicover.hss.impl.HSS;
import at.andicover.lmots.api.LMOTSType;
import at.andicover.lms.api.LMSType;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Timeout;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 10, time = 20, timeUnit = TimeUnit.NANOSECONDS)
@Measurement(iterations = 5, time = 20, timeUnit = TimeUnit.NANOSECONDS)
@Fork(1)
@Timeout(time = 3, timeUnit = TimeUnit.HOURS)
public class HSSMultiLevelSignatureVerificationBenchmarkSlow {

    @Param({"LMOTS_SHA256_N32_W8"})
    private LMOTSType lmotsType;

    @Param({
            "LMS_SHA256_M32_H15",
            "LMS_SHA256_M32_H20",
            "LMS_SHA256_M32_H25"
    })
    private LMSType lmsTypeFirstLevel;

    @Param({
            "LMS_SHA256_M32_H10",
            "LMS_SHA256_M32_H15"
    })
    private LMSType lmsTypeSecondLevel;

    private HSSPublicKey publicKey;
    private HSSSignature signature;

    private static final String MESSAGE = "A short text that needs to be signed!";

    @Setup(Level.Trial)
    public void setUp() throws NoSuchAlgorithmException, IOException {
        final HSSKeyPair keyPair =
                HSS.generateKeys(1, lmsTypeFirstLevel, lmsTypeSecondLevel, lmotsType, null);
        keyPair.getPrivateKey().reserveKeys(10);
        publicKey = keyPair.getPublicKey();
        signature = HSS.generateSignature(MESSAGE, keyPair.getPrivateKey());

        System.out.println(
                "Benchmarking " + lmotsType.name() + " " + lmsTypeFirstLevel.name() + " " + lmsTypeSecondLevel.name());
    }

    @Benchmark
    public void testHSSSignatureVerification(@Nonnull final Blackhole blackhole) throws NoSuchAlgorithmException {
        blackhole.consume(HSS.verifySignature(MESSAGE, signature, publicKey));
    }
}
