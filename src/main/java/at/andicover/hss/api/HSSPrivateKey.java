package at.andicover.hss.api;

import at.andicover.common.api.KeySize;
import at.andicover.common.api.Storable;
import at.andicover.lms.api.LMSPrivateKey;
import at.andicover.lms.api.LMSPublicKey;
import at.andicover.lms.api.LMSSignature;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

/**
 * Interface for the HSS private key.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-6.1">RFC 8554 - HSS Key Generation</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
public interface HSSPrivateKey extends Storable, KeySize {

    /**
     * @return the LMS levels.
     */
    int getLevels();

    /**
     * @return the list of LMS private keys.
     */
    @Nonnull
    LMSPrivateKey[] getLmsPrivateKeys();

    /**
     * @return the list of LMS public keys.
     */
    @Nonnull
    LMSPublicKey[] getLmsPublicKeys();

    /**
     * @return the list of LMS signatures.
     */
    @Nonnull
    LMSSignature[] getSignatures();

    /**
     * @return where to store the private key.
     */
    @CheckForNull
    String getFilename();

    /**
     * Allows reserving several keys. The future state is saved on disk. If the application crashes all
     * reserved keys that weren't used are lost.
     *
     * @param numberOfKeys how many keys should be reserved.
     * @throws NoSuchAlgorithmException if the given hashing algorithm does not exist.
     * @throws IOException              if the key cannot be stored to disk.
     */
    void reserveKeys(int numberOfKeys) throws NoSuchAlgorithmException, IOException;

    /**
     * @return number of reserved keys that were not used.
     */
    int getReservedKeys();
}
