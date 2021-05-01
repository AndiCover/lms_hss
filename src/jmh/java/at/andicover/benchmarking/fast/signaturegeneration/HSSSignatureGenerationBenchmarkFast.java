package at.andicover.benchmarking.fast.signaturegeneration;

import at.andicover.hss.api.HSSKeyPair;
import at.andicover.hss.api.HSSPrivateKey;
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
public class HSSSignatureGenerationBenchmarkFast {

    @Param({
            "LMOTS_SHA256_N32_W8"
    })
    private LMOTSType lmotsType;

    @Param({
            "LMS_SHA256_M32_H5",
            "LMS_SHA256_M32_H10",
            "LMS_SHA256_M32_H15",
            "LMS_SHA256_M32_H20"
    })
    private LMSType lmsType;

    private HSSPrivateKey privateKey;

    @Setup(Level.Trial)
    public void setUp() throws NoSuchAlgorithmException, IOException {
        final HSSKeyPair keyPair = HSS.generateKeys(1, lmsType, lmotsType);
        privateKey = keyPair.getPrivateKey();
        privateKey.reserveKeys(100);

        System.out.println("Benchmarking " + lmotsType.name() + " " + lmsType.name());
    }

    @Benchmark
    public void testHSSSignatureGeneration()
            throws NoSuchAlgorithmException, IOException {
        final String message = "A short text that needs to be signed!";
        try {
            final HSSSignature signature = HSS.generateSignature(message, privateKey);
        } catch (IllegalStateException ex) {
            privateKey.reserveKeys(100);
        }
    }
}
