package at.andicover.lmots.api;

import at.andicover.common.api.KeySize;
import at.andicover.common.api.Storable;

import javax.annotation.Nonnull;
import java.security.NoSuchAlgorithmException;

/**
 * Interface for the Winternitz LMOTS private key. Holds the private keys.
 *
 * @author andreas.schoengruber
 * @version %I%
 * @see <a href="https://tools.ietf.org/html/rfc8554#section-4.2">RFC 8554 - LM-OTS Private Key</a>
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final">Recommendation for Stateful
 * Hash-Based Signature Schemes</a>
 */
public interface LMOTSPrivateKey extends Storable, KeySize {

    /**
     * @return All keys of the private key.
     * @throws NoSuchAlgorithmException if the given hashing algorithm does not exist.
     */
    @Nonnull
    byte[][] getKeys() throws NoSuchAlgorithmException;

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
     * @return the seed for the RNG.
     */
    byte[] getSeed();

    /**
     * @return the typecode of the used LMOTS parameter set.
     */
    @Nonnull
    LMOTSType getLmotsType();
}
