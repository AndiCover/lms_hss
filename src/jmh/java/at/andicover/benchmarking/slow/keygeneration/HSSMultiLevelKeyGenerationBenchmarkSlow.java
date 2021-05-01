package at.andicover.benchmarking.slow.keygeneration;

import at.andicover.hss.api.HSSKeyPair;
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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 0, time = 20, timeUnit = TimeUnit.NANOSECONDS)
@Measurement(iterations = 1, time = 20, timeUnit = TimeUnit.NANOSECONDS)
@Fork(1)
@Timeout(time = 3, timeUnit = TimeUnit.HOURS)
public class HSSMultiLevelKeyGenerationBenchmarkSlow {

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

    @Setup(Level.Trial)
    public void setUp() throws NoSuchAlgorithmException, IOException {
        System.out.println(
                "Benchmarking " + lmotsType.name() + " " + lmsTypeFirstLevel.name() + " " + lmsTypeSecondLevel.name());

        //Warmup using faster parameter sets.
        for (int i = 0; i < 20; i++) {
            final HSSKeyPair keyPair = HSS.generateKeys(1, LMSType.LMS_SHA256_M32_H5, LMOTSType.LMOTS_SHA256_N24_W8);
        }
    }

    @Benchmark
    public void testHSSKeyGeneration() throws NoSuchAlgorithmException, IOException {
        final HSSKeyPair keyPair = HSS.generateKeys(2, lmsTypeFirstLevel, lmsTypeSecondLevel, lmotsType, null);
    }
}
