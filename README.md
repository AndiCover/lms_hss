# Efficient implementation of hash-based signature schemes - LMS and HSS

This is an efficient implementation of the hash-based signature scheme Leighton-Micali-Signature (LMS) and its multi
tree variant Hierarchical Signature System (HSS).

The main intend of this implementation is for academic use. Although it is faster in most cases than the reference
implementation in [RFC 8554](https://tools.ietf.org/html/rfc8554), it consumes much more memory.

Example:
An LMS tree with height 25 has 2^25 key pairs. Therefore, we need 2 * 2^25 objects. In Java, we have an object overhead
of 16 bytes which then results in a total overhead of 16 * 2 * 2^25 bytes ~ 1.07 GB!

[![Java CI with Gradle](https://github.com/AndiCover/lms_hss/actions/workflows/gradle.yml/badge.svg)](https://github.com/AndiCover/lms_hss/actions/workflows/gradle.yml)

## Getting Started

### Prerequisites

* JDK 14
* IntelliJ IDEA recommended
* Enough RAM 12+ GB (16 GB recommended, smaller parameter sets can work with less than 512 MB. Larger parameter sets (
  H20 and H25) and benchmarking require more memory)

### Installing

Clone the repository to you local disk and open it with any IDE you want. IntellJ IDEA is recommended to use. After
refreshing the Gradle project to download all dependencies, the project should be setup and ready to use. You can then
create a Jar file if you want to run it without an IDE.

### Running the tests

Running the Gradle test task will execute all unit tests of this project. You can either start it from your IDE or using
the Gradle command directly:

`./gradlew test`

The report can be found in `build/reports/tests`. Note: Because the tests are executed in parallel the duration shown
there is not correct and typically shows a much higher duration. This task will also create the Jacoco test coverage
report. It can be found in `build/jacocoHtml/index.html`.

Note: 3 very long-running tests are disabled. They might take several hours.

### Running checkstyle

Running the Gradle checkstyle task will execute checkstyle checks of main, test, and jmh of this project. You can either
start it from your IDE or using the Gradle command directly:

`./gradlew checkstyle`

The report can be found in `build/reports/checkstyle`.

### Running CPD check

Running the Gradle cpdCheck task will execute CPD checks of this project. It will detect duplicate code. You can either
start it from your IDE or using the Gradle command directly:

`./gradlew cpdCheck`

The report can be found in `build/reports/cpd`.

### Running PMD

Running the Gradle pmd task will execute the PMD checks of this project. You can either start it from your IDE or using
the Gradle command directly:

`./gradlew pmd`

The report can be found in `build/reports/pmd`.

### Running Spotbugs

Running the Gradle spotbugs task will execute the Spotbugs checks of this project. You can either start it from your IDE
or using the Gradle command directly:

`./gradlew spotbugs`

The report can be found in `build/reports/spotbugs`.

### Generating javadoc

Running the Gradle javadoc task will generate the javadoc report. You can either start it from your IDE or using the
Gradle command directly:

`./gradlew javadoc`

The generated documentation can be found in `build/docs/javadoc/index.html`.

## Benchmarks

## Running benchmarks

Benchmarks can be executed with the Gradle jmh task. You can either start if from your IDE or using the Gradle command
directly:

`./gradlew jmh`

The benchmark results can be found in `build/reports/jmh`. Note: Those benchmarks will take several hours. Faster
benchmarks are performed multiple times to warmup the JVM. Slower benchmarks are run once. In this case several runs
with fast parameter sets are used to warmup the JVM.

## Benchmark results

Used CPU: **AMD Ryzen 7 3700X**

The results are compared with the reference C implementation.

Note: the Java implementation consumes much more memory than the C implementation.

### Key generation

In almost all cases the Java implementation is faster than the C implementation. The difference increases with larger parameter sets. This is most likely because of Java's Just-in-time-Compiler which performs better
with more iterations. Important are the JVM warmup runs. In a real-life scenario it would also make sense to create a
few keys with a small parameter set (takes a few milliseconds) to save significantly time for the large parameter sets.

One interesting result is that in both implementations, parameter sets with W2 perform better than with W1,
although W1 requires fewer computations. This is probably because the thread overhead is too much for that few
computations.

### Signature generation

With smaller parameter sets both implementation perform similarly. With larger parameter sets the C implementation is
faster. This is because it uses some kind of Fractal Merkle Tree Traversal. In my Java implementation only the top 15
levels of an LMS tree are stored in memory. Therefore, it needs to calculate the remaining levels to build the path for
the signature.

### Signature verification

Both implementation perform similarly. All signatures are verified in <2 ms. Invalid signatures would be even faster.

## Usage

The usage of this application should be pretty straight forward. All methods that are not relevant to the user should be
inaccessible. It is possible to use HSS, LMS, and also LM-OTS. Below are examples for HSS.

### Key generation

`HSSKeyPair hssKeyPair = HSS.generateKeys(2, LMS_SHA256_M32_H5, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8, "myKey.privkey");`

By default, 20 keys are already reserved.

### Reserve keys

The consumer needs to make sure to not run out of reserved keys.

Retrieve the current available keys: `hssKeyPair.getPrivateKey().getReservedKeys()`

Reserve new keys: `hssKeyPair.getPrivateKey().reserveKeys(10);`

### Signature generation

`HSSSignature signature = HSS.generateSignature("My test message", hssKeyPair.getPrivateKey());`

### Signature verification

`HSS.verifySignature("My test message", signature, hssKeyPair.getPublicKey())`

## Built With

* [Gradle](https://gradle.org/)
* [Open JDK 14](https://openjdk.java.net/projects/jdk/14/)
* [IntelliJ IDEA](https://www.jetbrains.com/idea/)
* [Checkstyle](https://checkstyle.sourceforge.io/)
* [CPD Check](https://pmd.github.io/latest/pmd_userdocs_cpd.html)
* [PMD](https://pmd.github.io/)
* [Spotbugs](https://spotbugs.github.io/)
* [JMH](https://github.com/openjdk/jmh)
* [Jacoco](https://www.eclemma.org/jacoco/)

## Authors

* Andreas Schöngruber
