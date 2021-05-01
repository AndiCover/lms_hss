package at.andicover.benchmarking.fast.signatureverification;

import at.andicover.lmots.api.LMOTSPrivateKey;
import at.andicover.lmots.api.LMOTSPublicKey;
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
import org.openjdk.jmh.infra.Blackhole;

import javax.annotation.Nonnull;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 10, time = 20, timeUnit = TimeUnit.NANOSECONDS)
@Measurement(iterations = 5, time = 20, timeUnit = TimeUnit.NANOSECONDS)
@Fork(1)
public class LMOTSSignatureVerificationBenchmarkFast {

    private LMOTSPublicKey publicKey;
    private LMOTSSignature signature;
    private static final String MESSAGE = "A short text that needs to be signed!";

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
        final LMOTSPrivateKey privateKey = LMOTS.generatePrivateKey(lmotsType);
        publicKey = LMOTS.generatePublicKey(privateKey);
        signature = LMOTS.generateSignature(MESSAGE, privateKey);

        System.out.println("Benchmarking " + lmotsType.name());
    }

    @Benchmark
    public void testLMOTSSignatureVerification(@Nonnull final Blackhole blackhole) throws NoSuchAlgorithmException {
        blackhole.consume(LMOTS.verifySignature(MESSAGE, signature, publicKey));
    }
}
