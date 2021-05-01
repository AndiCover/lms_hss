package at.andicover.benchmarking.fast.signatureverification;

import at.andicover.lmots.api.LMOTSType;
import at.andicover.lms.api.LMSKeyPair;
import at.andicover.lms.api.LMSPublicKey;
import at.andicover.lms.api.LMSSignature;
import at.andicover.lms.api.LMSType;
import at.andicover.lms.impl.LMS;
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
public class LMSSignatureVerificationBenchmarkFast {

    @Param({
            "LMS_SHA256_M32_H5",
            "LMS_SHA256_M32_H10",
            "LMS_SHA256_M32_H15",
            "LMS_SHA256_M32_H20"
    })
    private LMSType lmsType;

    @Param({
            "LMOTS_SHA256_N32_W1",
            "LMOTS_SHA256_N32_W2",
            "LMOTS_SHA256_N32_W4",
            "LMOTS_SHA256_N32_W8"
    })
    private LMOTSType lmotsType;

    private LMSPublicKey publicKey;
    private LMSSignature signature;

    private static final String MESSAGE = "A short text that needs to be signed!";

    @Setup(Level.Trial)
    public void setUp() throws NoSuchAlgorithmException {
        final LMSKeyPair keyPair = LMS.generateKeys(lmsType, lmotsType);
        publicKey = keyPair.getPublicKey();
        keyPair.getPrivateKey().reserveKeys(10);
        signature = LMS.generateSignature(MESSAGE, keyPair.getPrivateKey());

        System.out.println("Benchmarking " + lmotsType.name() + " " + lmsType.name());
    }

    @Benchmark
    public void testLMSSignatureVerification(@Nonnull final Blackhole blackhole) throws NoSuchAlgorithmException {
        blackhole.consume(LMS.verifySignature(MESSAGE, signature, publicKey));
    }
}
