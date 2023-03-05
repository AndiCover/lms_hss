package at.andicover.util;

import at.andicover.common.api.Storable;
import at.andicover.hss.api.HSSPrivateKey;
import at.andicover.hss.api.HSSPublicKey;
import at.andicover.hss.api.HSSSignature;
import at.andicover.hss.impl.HSS;
import at.andicover.lmots.api.LMOTSPrivateKey;
import at.andicover.lmots.api.LMOTSPublicKey;
import at.andicover.lmots.api.LMOTSSignature;
import at.andicover.lmots.impl.LMOTS;
import at.andicover.lms.api.LMSPrivateKey;
import at.andicover.lms.api.LMSPublicKey;
import at.andicover.lms.api.LMSSignature;
import at.andicover.lms.impl.LMS;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.io.FilenameUtils;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static at.andicover.config.Defaults.DEFAULT_OUTPUT_BUFFER;
import static at.andicover.util.ThreadUtil.shutdownThreadExecutor;
import static java.nio.file.StandardOpenOption.APPEND;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.util.Objects.requireNonNull;

/**
 * Utility class to store and load keys from disk. An HSS private key must be saved to non volatile memory
 * after reserving keys.
 *
 * @author andreas.schoengruber
 * @version %I%
 */
public final class PersistenceUtil {

    private PersistenceUtil() {
    }

    /**
     * Stores the given private key in the file defined in the private key.
     * <p>
     * Note: Deletes the file before writing to it. Make sure it is not used by another process.
     * </p>
     *
     * @param privateKey the HSS private key to store.
     * @throws IOException if writing to the file does not work or the file cannot be deleted because it is used by
     *                     another process.
     */
    public static void storeKey(@Nonnull final HSSPrivateKey privateKey) throws IOException {
        requireNonNull(privateKey);
        if (privateKey.getFilename() == null) {
            return;
        }

        final Path outputfile = Path.of(FilenameUtils.getFullPath(privateKey.getFilename())
                + FilenameUtils.getName(privateKey.getFilename()));

        Files.deleteIfExists(outputfile);
        writeToFile(privateKey, outputfile);
    }

    /**
     * Stores a storable object in the given file.
     * <p>
     * Note: Deletes the file before writing to it. Make sure it is not used by another process.
     * </p>
     *
     * @param storable the storable object to store.
     * @param filename the destination filename.
     * @throws IOException if writing to the file does not work or the file cannot be deleted because it is used by
     *                     another process.
     */
    public static void storeKey(@Nonnull final Storable storable, @Nonnull final String filename)
            throws IOException {
        requireNonNull(storable);
        requireNonNull(filename);

        final Path outputfile = Path.of(FilenameUtils.getFullPath(filename) + FilenameUtils.getName(filename));
        Files.deleteIfExists(outputfile);
        writeToFile(storable, outputfile);
    }

    /**
     * Loads a storable object from disk. One thread reads the file chunk by chunk and writes the content into a small
     * buffer which is concurrently read by a second thread which constructs the object. This approach is used to
     * decrease the memory used when loading a complete file in the memory. Reading the file once and then creating
     * objects would require at least twice the memory of the file which can get pretty large (2GB+).
     *
     * @param filename the source filename.
     * @param clazz    The clazz of the stored key we want to return.
     * @return the created object.
     */
    @CheckForNull
    @SuppressFBWarnings(value = "PATH_TRAVERSAL_IN", justification = "Consumer should know what he is doing.")
    @SuppressWarnings({"PMD.AvoidFileStream", "PMD.CognitiveComplexity"})
    public static Storable loadKey(@Nonnull final String filename, @Nonnull final Class<?> clazz) {
        try (PipedOutputStream outputStream = new PipedOutputStream();
             FileInputStream in = new FileInputStream(
                     FilenameUtils.getFullPath(filename) + FilenameUtils.getName(filename));
             PipedInputStream pipedInputStream = new PipedInputStream(outputStream, DEFAULT_OUTPUT_BUFFER);
             DataInputStream inputStream = new DataInputStream(pipedInputStream)) {

            final ExecutorService executor = Executors.newCachedThreadPool();
            //First thread reads the file to the buffer.
            executor.execute(() -> {
                try {
                    int read;
                    final byte[] data = new byte[DEFAULT_OUTPUT_BUFFER];
                    while ((read = in.read(data)) != -1) {
                        outputStream.write(data, 0, read);
                    }
                    outputStream.close();
                } catch (IOException ex) {
                    throw new UncheckedIOException(ex);
                }
            });

            //Second thread builds the object from the buffer.
            final Future<Storable> storableFuture = executor.submit(() -> {
                if (clazz == LMOTSPrivateKey.class) {
                    return LMOTS.buildPrivateKey(inputStream);
                } else if (clazz == LMOTSPublicKey.class) {
                    return LMOTS.buildPublicKey(inputStream);
                } else if (clazz == LMOTSSignature.class) {
                    return LMOTS.buildSignature(inputStream);
                } else if (clazz == LMSPrivateKey.class) {
                    return LMS.buildPrivateKey(inputStream);
                } else if (clazz == LMSPublicKey.class) {
                    return LMS.buildPublicKey(inputStream);
                } else if (clazz == LMSSignature.class) {
                    return LMS.buildSignature(inputStream);
                } else if (clazz == HSSPrivateKey.class) {
                    return HSS.buildPrivateKey(inputStream, filename);
                } else if (clazz == HSSPublicKey.class) {
                    return HSS.buildPublicKey(inputStream);
                } else if (clazz == HSSSignature.class) {
                    return HSS.buildSignature(inputStream);
                } else {
                    throw new IllegalArgumentException("Invalid type");
                }
            });

            try {
                return storableFuture.get();
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            } catch (ExecutionException ex) {
                throw new IllegalStateException(ex);
            }
            shutdownThreadExecutor(executor);

        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        return null;
    }

    /**
     * Writes a storable object to the given file. One thread reads the bytes of the object to the buffer and
     * the second thread writes the content of this buffer to the file. This approach is used to
     * decrease the memory used when storing an object to a file. Building one big byte array of the object
     * would result in twice the required memory.
     *
     * @param storable   the object to store.
     * @param outputfile the destination file.
     * @throws IOException if writing to the file does not work.
     */
    private static void writeToFile(@Nonnull final Storable storable, @Nonnull final Path outputfile)
            throws IOException {
        requireNonNull(storable);
        requireNonNull(outputfile);

        try (PipedOutputStream outputStream = new PipedOutputStream();
             PipedInputStream inputStream = new PipedInputStream(outputStream, DEFAULT_OUTPUT_BUFFER)) {

            final ExecutorService executor = Executors.newCachedThreadPool();
            executor.execute(() -> {
                try {
                    storable.writeToPipedOutputStream(outputStream);
                    outputStream.close();
                } catch (IOException ex) {
                    throw new UncheckedIOException(ex);
                }
            });

            executor.execute(() -> {
                int read;
                final byte[] data = new byte[DEFAULT_OUTPUT_BUFFER];
                try {
                    while ((read = inputStream.read(data)) != -1) {
                        Files.write(outputfile, Arrays.copyOfRange(data, 0, read), CREATE, APPEND);
                    }
                    inputStream.close();
                } catch (IOException ex) {
                    throw new UncheckedIOException(ex);
                }
            });

            shutdownThreadExecutor(executor);
        }
    }
}