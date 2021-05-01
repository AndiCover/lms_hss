package at.andicover.benchmarking.fast.signaturegeneration;

import at.andicover.lmots.api.LMOTSPrivateKey;
import at.andicover.lmots.api.LMOTSSignature;
import at.andicover.lmots.api.LMOTSType;
import at.andicover.lmots.impl.LMOTS;
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
import org.openjdk.jmh.annotations.Warmup;

import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 10, time = 20, timeUnit = TimeUnit.NANOSECONDS)
@Measurement(iterations = 5, time = 20, timeUnit = TimeUnit.NANOSECONDS)
@Fork(1)
public class LMOTSSignatureGenerationBenchmarkFast {

    private LMOTSPrivateKey lmotsPrivateKey;

    @Param({
            "LMOTS_SHA256_N32_W1",
            "LMOTS_SHA256_N32_W2",
            "LMOTS_SHA256_N32_W4",
            "LMOTS_SHA256_N32_W8",
            "LMOTS_SHA256_N24_W1",
            "LMOTS_SHA256_N24_W2",
            "LMOTS_SHA256_N24_W4",
            "LMOTS_SHA256_N24_W8"
    })
    private LMOTSType lmotsType;

    @Setup(Level.Trial)
    public void setUp() throws NoSuchAlgorithmException {
        lmotsPrivateKey = LMOTS.generatePrivateKey(lmotsType);

        System.out.println("Benchmarking " + lmotsType.name());
    }

    @Benchmark
    public void testLMOTSSignatureGeneration() throws NoSuchAlgorithmException {
        final String message = "A short text that needs to be signed!";
        final LMOTSSignature signature = LMOTS.generateSignature(message, lmotsPrivateKey);
    }
}
