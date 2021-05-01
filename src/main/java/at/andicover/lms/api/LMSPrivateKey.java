package at.andicover.lms.api;

import at.andicover.common.api.KeySize;
import at.andicover.common.api.Storable;
import at.andicover.lmots.api.LMOTSPrivateKey;
import at.andicover.lmots.api.LMOTSPublicKey;
import at.andicover.lmots.api.LMOTSType;

import javax.annotation.Nonnull;
import java.security.NoSuchAlgorithmException;

/**
 * Interface for the Leighton-Micali-Signature private key.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-5.2">RFC 8554 - LMS Private Key</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
@SuppressWarnings("PMD.UseVarargs")
public interface LMSPrivateKey extends Storable, KeySize {

    /**
     * @return the typecode of the used LMS parameter set.
     */
    @Nonnull
    LMSType getLmsType();

    /**
     * @return the typecode of the used LMOTS parameter set.
     */
    @Nonnull
    LMOTSType getLmotsType();

    /**
     * @return the 16 byte identifier for the LMS public/private key pair.
     */
    @Nonnull
    byte[] getIdentifier();

    /**
     * @return the leaf number q of the hash tree.
     */
    int getQIdentifier();

    /**
     * @return the next unused LMOTS private key.
     * @throws IllegalStateException if all keys were used.
     */
    LMOTSPrivateKey getNextLmotsKey() throws IllegalStateException;

    /**
     * Calculates the path for the LMS signature.
     *
     * @param nodenumber the nodenumber of the used LM-OTS private key.
     * @return the path to the root of the tree.
     * @throws NoSuchAlgorithmException if the given hashing algorithm does not exist.
     */
    @Nonnull
    byte[][] getPath(int nodenumber) throws NoSuchAlgorithmException;

    /**
     * @return if all keys were used.
     */
    boolean isExhausted();

    /**
     * Allows reserving several keys. The future state is saved on disk. If the application crashes all
     * reserved keys that weren't used are lost.
     *
     * @param numberOfKeys how many keys should be reserved.
     */
    void reserveKeys(int numberOfKeys);

    /**
     * @return number of reserved keys that were not used.
     */
    int getReservedKeys();

    /**
     * @return if there are reserved keys available.
     */
    boolean hasReservedKey();

    /**
     * Calculate the root key without storing intermediate nodes. Stores the hashes of the leaf nodes in the private key.
     *
     * @param lmotsPublicKeys All LMOTS public keys.
     * @return The root key.
     * @throws NoSuchAlgorithmException if the hashing algorithm was not found.
     */
    byte[] calculateRoot(LMOTSPublicKey[] lmotsPublicKeys) throws NoSuchAlgorithmException;
}
