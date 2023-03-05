package at.andicover.util;

import at.andicover.hss.api.HSSKeyPair;
import at.andicover.hss.api.HSSSignature;
import at.andicover.hss.impl.HSS;
import at.andicover.lmots.api.LMOTSPrivateKey;
import at.andicover.lmots.api.LMOTSType;
import at.andicover.lmots.impl.LMOTS;
import at.andicover.lms.api.LMSKeyPair;
import at.andicover.lms.api.LMSPrivateKey;
import at.andicover.lms.api.LMSType;
import at.andicover.lms.impl.LMS;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W1;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W2;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W4;
import static at.andicover.lmots.api.LMOTSType.LMOTS_SHA256_N32_W8;
import static at.andicover.lms.api.LMSType.LMS_SHA256_M32_H5;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings({"PMD.NcssCount", "PMD.UnusedAssignment", "PMD.SystemPrintln", "PMD.JUnitTestsShouldIncludeAssert",
        "PMD.ExcessiveMethodLength"})
final class KeySizeUtilTest {

    private static final String MESSAGE =
            "The six episodes of the first season of Parks and Recreation originally aired in the United States on"
                    + " the NBC television networks on Thursdays between April 9 and May 14, 2009. The comedy series"
                    + " was created by Greg Daniels and Michael Schur,";

    @Test
    void testLmotsKeySizes() throws NoSuchAlgorithmException {
        LMOTSType lmotsType = LMOTS_SHA256_N32_W8;
        LMOTSPrivateKey lmotsPrivateKey = LMOTS.generatePrivateKey(lmotsType);
        assertEquals(56, lmotsPrivateKey.calculateSize());
        assertEquals(56, KeySizeUtil.getOtsPrivateKeySize(lmotsType));
        assertEquals(56, LMOTS.generatePublicKey(lmotsPrivateKey).calculateSize());
        assertEquals(56, KeySizeUtil.getOtsPublicKeySize(lmotsType));
        assertEquals(1124, LMOTS.generateSignature(MESSAGE, lmotsPrivateKey).calculateSize());
        assertEquals(1124, KeySizeUtil.getOtsSignatureSize(lmotsType));

        lmotsType = LMOTS_SHA256_N32_W4;
        lmotsPrivateKey = LMOTS.generatePrivateKey(lmotsType);
        assertEquals(56, lmotsPrivateKey.calculateSize());
        assertEquals(56, KeySizeUtil.getOtsPrivateKeySize(lmotsType));
        assertEquals(56, LMOTS.generatePublicKey(lmotsPrivateKey).calculateSize());
        assertEquals(56, KeySizeUtil.getOtsPublicKeySize(lmotsType));
        assertEquals(2180, LMOTS.generateSignature(MESSAGE, lmotsPrivateKey).calculateSize());
        assertEquals(2180, KeySizeUtil.getOtsSignatureSize(lmotsType));

        lmotsType = LMOTS_SHA256_N32_W2;
        lmotsPrivateKey = LMOTS.generatePrivateKey(lmotsType);
        assertEquals(56, lmotsPrivateKey.calculateSize());
        assertEquals(56, KeySizeUtil.getOtsPrivateKeySize(lmotsType));
        assertEquals(56, LMOTS.generatePublicKey(lmotsPrivateKey).calculateSize());
        assertEquals(56, KeySizeUtil.getOtsPublicKeySize(lmotsType));
        assertEquals(4292, LMOTS.generateSignature(MESSAGE, lmotsPrivateKey).calculateSize());
        assertEquals(4292, KeySizeUtil.getOtsSignatureSize(lmotsType));

        lmotsType = LMOTS_SHA256_N32_W1;
        lmotsPrivateKey = LMOTS.generatePrivateKey(LMOTS_SHA256_N32_W1);
        assertEquals(56, lmotsPrivateKey.calculateSize());
        assertEquals(56, KeySizeUtil.getOtsPrivateKeySize(lmotsType));
        assertEquals(56, LMOTS.generatePublicKey(lmotsPrivateKey).calculateSize());
        assertEquals(56, KeySizeUtil.getOtsPublicKeySize(lmotsType));
        assertEquals(8516, LMOTS.generateSignature(MESSAGE, lmotsPrivateKey).calculateSize());
        assertEquals(8516, KeySizeUtil.getOtsSignatureSize(lmotsType));
    }

    @Test
    void testLmsKeySizes() throws NoSuchAlgorithmException {
        LMOTSType lmotsType = LMOTS_SHA256_N32_W8;
        final LMSType lmsType = LMS_SHA256_M32_H5;
        LMSKeyPair keyPair = LMS.generateKeys(lmsType, lmotsType);
        LMSPrivateKey lmsPrivateKey = keyPair.getPrivateKey();
        lmsPrivateKey.reserveKeys(1);
        assertEquals(1820, lmsPrivateKey.calculateSize());
        assertEquals(1820, KeySizeUtil.getLmsPrivateKeySize(lmotsType, lmsType));
        assertEquals(56, keyPair.getPublicKey().calculateSize());
        assertEquals(56, KeySizeUtil.getLmsPublicKeySize(lmotsType, lmsType));
        assertEquals(1292, LMS.generateSignature(MESSAGE, lmsPrivateKey).calculateSize());
        assertEquals(1292, KeySizeUtil.getLmsSignatureSize(lmotsType, lmsType));

        lmotsType = LMOTS_SHA256_N32_W4;
        keyPair = LMS.generateKeys(lmsType, lmotsType);
        lmsPrivateKey = keyPair.getPrivateKey();
        lmsPrivateKey.reserveKeys(1);
        assertEquals(1820, lmsPrivateKey.calculateSize());
        assertEquals(1820, KeySizeUtil.getLmsPrivateKeySize(lmotsType, lmsType));
        assertEquals(56, keyPair.getPublicKey().calculateSize());
        assertEquals(56, KeySizeUtil.getLmsPublicKeySize(lmotsType, lmsType));
        assertEquals(2348, LMS.generateSignature(MESSAGE, lmsPrivateKey).calculateSize());
        assertEquals(2348, KeySizeUtil.getLmsSignatureSize(lmotsType, lmsType));

        lmotsType = LMOTS_SHA256_N32_W2;
        keyPair = LMS.generateKeys(lmsType, lmotsType);
        lmsPrivateKey = keyPair.getPrivateKey();
        lmsPrivateKey.reserveKeys(1);
        assertEquals(1820, lmsPrivateKey.calculateSize());
        assertEquals(1820, KeySizeUtil.getLmsPrivateKeySize(lmotsType, lmsType));
        assertEquals(56, keyPair.getPublicKey().calculateSize());
        assertEquals(56, KeySizeUtil.getLmsPublicKeySize(lmotsType, lmsType));
        assertEquals(4460, LMS.generateSignature(MESSAGE, lmsPrivateKey).calculateSize());
        assertEquals(4460, KeySizeUtil.getLmsSignatureSize(lmotsType, lmsType));

        lmotsType = LMOTS_SHA256_N32_W1;
        keyPair = LMS.generateKeys(lmsType, lmotsType);
        lmsPrivateKey = keyPair.getPrivateKey();
        lmsPrivateKey.reserveKeys(1);
        assertEquals(1820, lmsPrivateKey.calculateSize());
        assertEquals(1820, KeySizeUtil.getLmsPrivateKeySize(lmotsType, lmsType));
        assertEquals(56, keyPair.getPublicKey().calculateSize());
        assertEquals(56, KeySizeUtil.getLmsPublicKeySize(lmotsType, lmsType));
        assertEquals(8684, LMS.generateSignature(MESSAGE, lmsPrivateKey).calculateSize());
        assertEquals(8684, KeySizeUtil.getLmsSignatureSize(lmotsType, lmsType));
    }

    @Test
    void testEmptyArray() {
        final byte[][] array = new byte[0][0];
        assertEquals(0, KeySizeUtil.getByteArraySize(array));
    }

    @Test
    void testHssKeySizes() throws NoSuchAlgorithmException, IOException {
        LMOTSType lmotsType = LMOTS_SHA256_N32_W8;
        final LMSType lmsType = LMS_SHA256_M32_H5;
        int level = 1;
        HSSKeyPair hssKeyPair = HSS.generateKeys(level, lmsType, lmotsType,
                KeySizeUtil.class.getName() + "_L1_H5_W8.privkey");
        //signature generation updates private key
        HSSSignature signature = HSS.generateSignature(MESSAGE, hssKeyPair.getPrivateKey());
        assertEquals(3172, hssKeyPair.getPrivateKey().calculateSize());
        assertEquals(3172, KeySizeUtil.getHssPrivateKeySize(lmotsType, lmsType, level));
        assertEquals(60, hssKeyPair.getPublicKey().calculateSize());
        assertEquals(60, KeySizeUtil.getHssPublicKeySize(lmotsType, lmsType, level));
        assertEquals(1296, signature.calculateSize());
        assertEquals(1296, KeySizeUtil.getHssSignatureSize(lmotsType, lmsType, level));

        lmotsType = LMOTS_SHA256_N32_W4;
        hssKeyPair = HSS.generateKeys(level, lmsType, lmotsType,
                KeySizeUtil.class.getName() + "_L1_H5_W4.privkey");
        signature = HSS.generateSignature(MESSAGE, hssKeyPair.getPrivateKey());
        assertEquals(4228, hssKeyPair.getPrivateKey().calculateSize());
        assertEquals(4228, KeySizeUtil.getHssPrivateKeySize(lmotsType, lmsType, level));
        assertEquals(60, hssKeyPair.getPublicKey().calculateSize());
        assertEquals(60, KeySizeUtil.getHssPublicKeySize(lmotsType, lmsType, level));
        assertEquals(2352, signature.calculateSize());
        assertEquals(2352, KeySizeUtil.getHssSignatureSize(lmotsType, lmsType, level));

        lmotsType = LMOTS_SHA256_N32_W2;
        hssKeyPair = HSS.generateKeys(level, lmsType, lmotsType,
                KeySizeUtil.class.getName() + "_L1_H5_W2.privkey");
        signature = HSS.generateSignature(MESSAGE, hssKeyPair.getPrivateKey());
        assertEquals(6340, hssKeyPair.getPrivateKey().calculateSize());
        assertEquals(6340, KeySizeUtil.getHssPrivateKeySize(lmotsType, lmsType, level));
        assertEquals(60, hssKeyPair.getPublicKey().calculateSize());
        assertEquals(60, KeySizeUtil.getHssPublicKeySize(lmotsType, lmsType, level));
        assertEquals(4464, signature.calculateSize());
        assertEquals(4464, KeySizeUtil.getHssSignatureSize(lmotsType, lmsType, level));

        lmotsType = LMOTS_SHA256_N32_W1;
        hssKeyPair = HSS.generateKeys(level, lmsType, lmotsType,
                KeySizeUtil.class.getName() + "_L1_H5_W1.privkey");
        signature = HSS.generateSignature(MESSAGE, hssKeyPair.getPrivateKey());
        assertEquals(10_564, hssKeyPair.getPrivateKey().calculateSize());
        assertEquals(10_564, KeySizeUtil.getHssPrivateKeySize(lmotsType, lmsType, level));
        assertEquals(60, hssKeyPair.getPublicKey().calculateSize());
        assertEquals(60, KeySizeUtil.getHssPublicKeySize(lmotsType, lmsType, level));
        assertEquals(8688, signature.calculateSize());
        assertEquals(8688, KeySizeUtil.getHssSignatureSize(lmotsType, lmsType, level));

        level = 2;
        lmotsType = LMOTS_SHA256_N32_W8;
        hssKeyPair = HSS.generateKeys(level, lmsType, lmotsType,
                KeySizeUtil.class.getName() + "_L2_H5_W8.privkey");
        signature = HSS.generateSignature(MESSAGE, hssKeyPair.getPrivateKey());
        assertEquals(6340, hssKeyPair.getPrivateKey().calculateSize());
        assertEquals(6340, KeySizeUtil.getHssPrivateKeySize(lmotsType, lmsType, level));
        assertEquals(60, hssKeyPair.getPublicKey().calculateSize());
        assertEquals(60, KeySizeUtil.getHssPublicKeySize(lmotsType, lmsType, level));
        assertEquals(2644, signature.calculateSize());
        assertEquals(2644, KeySizeUtil.getHssSignatureSize(lmotsType, lmsType, level));

        lmotsType = LMOTS_SHA256_N32_W4;
        hssKeyPair = HSS.generateKeys(level, lmsType, lmotsType,
                KeySizeUtil.class.getName() + "_L2_H5_W4.privkey");
        signature = HSS.generateSignature(MESSAGE, hssKeyPair.getPrivateKey());
        assertEquals(8452, hssKeyPair.getPrivateKey().calculateSize());
        assertEquals(8452, KeySizeUtil.getHssPrivateKeySize(lmotsType, lmsType, level));
        assertEquals(60, hssKeyPair.getPublicKey().calculateSize());
        assertEquals(60, KeySizeUtil.getHssPublicKeySize(lmotsType, lmsType, level));
        assertEquals(4756, signature.calculateSize());
        assertEquals(4756, KeySizeUtil.getHssSignatureSize(lmotsType, lmsType, level));

        lmotsType = LMOTS_SHA256_N32_W2;
        hssKeyPair = HSS.generateKeys(level, lmsType, lmotsType,
                KeySizeUtil.class.getName() + "_L2_H5_W2.privkey");
        signature = HSS.generateSignature(MESSAGE, hssKeyPair.getPrivateKey());
        assertEquals(12_676, hssKeyPair.getPrivateKey().calculateSize());
        assertEquals(12_676, KeySizeUtil.getHssPrivateKeySize(lmotsType, lmsType, level));
        assertEquals(60, hssKeyPair.getPublicKey().calculateSize());
        assertEquals(60, KeySizeUtil.getHssPublicKeySize(lmotsType, lmsType, level));
        assertEquals(8980, signature.calculateSize());
        assertEquals(8980, KeySizeUtil.getHssSignatureSize(lmotsType, lmsType, level));

        lmotsType = LMOTS_SHA256_N32_W1;
        hssKeyPair = HSS.generateKeys(level, lmsType, lmotsType,
                KeySizeUtil.class.getName() + "_L2_H5_W1.privkey");
        signature = HSS.generateSignature(MESSAGE, hssKeyPair.getPrivateKey());
        assertEquals(21_124, hssKeyPair.getPrivateKey().calculateSize());
        assertEquals(21_124, KeySizeUtil.getHssPrivateKeySize(lmotsType, lmsType, level));
        assertEquals(60, hssKeyPair.getPublicKey().calculateSize());
        assertEquals(60, KeySizeUtil.getHssPublicKeySize(lmotsType, lmsType, level));
        assertEquals(17_428, signature.calculateSize());
        assertEquals(17_428, KeySizeUtil.getHssSignatureSize(lmotsType, lmsType, level));

        level = 8;
        lmotsType = LMOTS_SHA256_N32_W8;
        hssKeyPair = HSS.generateKeys(level, lmsType, lmotsType,
                KeySizeUtil.class.getName() + "_L8_H5_W8.privkey");
        signature = HSS.generateSignature(MESSAGE, hssKeyPair.getPrivateKey());
        assertEquals(25_348, hssKeyPair.getPrivateKey().calculateSize());
        assertEquals(25_348, KeySizeUtil.getHssPrivateKeySize(lmotsType, lmsType, level));
        assertEquals(60, hssKeyPair.getPublicKey().calculateSize());
        assertEquals(60, KeySizeUtil.getHssPublicKeySize(lmotsType, lmsType, level));
        assertEquals(10_732, signature.calculateSize());
        assertEquals(10_732, KeySizeUtil.getHssSignatureSize(lmotsType, lmsType, level));

        lmotsType = LMOTS_SHA256_N32_W4;
        hssKeyPair = HSS.generateKeys(level, lmsType, lmotsType,
                KeySizeUtil.class.getName() + "_L8_H5_W4.privkey");
        signature = HSS.generateSignature(MESSAGE, hssKeyPair.getPrivateKey());
        assertEquals(33_796, hssKeyPair.getPrivateKey().calculateSize());
        assertEquals(33_796, KeySizeUtil.getHssPrivateKeySize(lmotsType, lmsType, level));
        assertEquals(60, hssKeyPair.getPublicKey().calculateSize());
        assertEquals(60, KeySizeUtil.getHssPublicKeySize(lmotsType, lmsType, level));
        assertEquals(19_180, signature.calculateSize());
        assertEquals(19_180, KeySizeUtil.getHssSignatureSize(lmotsType, lmsType, level));

        lmotsType = LMOTS_SHA256_N32_W2;
        hssKeyPair = HSS.generateKeys(level, lmsType, lmotsType,
                KeySizeUtil.class.getName() + "_L8_H5_W2.privkey");
        signature = HSS.generateSignature(MESSAGE, hssKeyPair.getPrivateKey());
        assertEquals(50_692, hssKeyPair.getPrivateKey().calculateSize());
        assertEquals(50_692, KeySizeUtil.getHssPrivateKeySize(lmotsType, lmsType, level));
        assertEquals(60, hssKeyPair.getPublicKey().calculateSize());
        assertEquals(60, KeySizeUtil.getHssPublicKeySize(lmotsType, lmsType, level));
        assertEquals(36_076, signature.calculateSize());
        assertEquals(36_076, KeySizeUtil.getHssSignatureSize(lmotsType, lmsType, level));

        lmotsType = LMOTS_SHA256_N32_W1;
        hssKeyPair = HSS.generateKeys(level, lmsType, lmotsType,
                KeySizeUtil.class.getName() + "_L8_H5_W1.privkey");
        signature = HSS.generateSignature(MESSAGE, hssKeyPair.getPrivateKey());
        assertEquals(84_484, hssKeyPair.getPrivateKey().calculateSize());
        assertEquals(84_484, KeySizeUtil.getHssPrivateKeySize(lmotsType, lmsType, level));
        assertEquals(60, hssKeyPair.getPublicKey().calculateSize());
        assertEquals(60, KeySizeUtil.getHssPublicKeySize(lmotsType, lmsType, level));
        assertEquals(69_868, signature.calculateSize());
        assertEquals(69_868, KeySizeUtil.getHssSignatureSize(lmotsType, lmsType, level));
    }

    @Test
    void printLmotsKeySizes() {
        for (final LMOTSType lmotsType : LMOTSType.values()) {
            System.out.println("#######################################");
            System.out.println("Parameter: " + lmotsType);
            System.out.println("Private key: " + KeySizeUtil.getOtsPrivateKeySize(lmotsType));
            System.out.println("Public key: " + KeySizeUtil.getOtsPublicKeySize(lmotsType));
            System.out.println("Signature: " + KeySizeUtil.getOtsSignatureSize(lmotsType));
        }
    }

    @Test
    void printLmsKeySizes() {
        for (final LMSType lmsType : LMSType.values()) {
            for (final LMOTSType lmotsType : LMOTSType.values()) {
                System.out.println("#######################################");
                System.out.println("Parameter: " + lmsType + " " + lmotsType);
                System.out.println("Private key: " + KeySizeUtil.getLmsPrivateKeySize(lmotsType, lmsType));
                System.out.println("Public key: " + KeySizeUtil.getLmsPublicKeySize(lmotsType, lmsType));
                System.out.println("Signature: " + KeySizeUtil.getLmsSignatureSize(lmotsType, lmsType));
            }
        }
    }

    @Test
    void printHssKeySizes() {
        for (int i = 1; i <= 8; i++) {
            for (final LMSType lmsType : LMSType.values()) {
                for (final LMOTSType lmotsType : LMOTSType.values()) {
                    System.out.println("#######################################");
                    System.out.println("Parameter: level: " + i + " " + lmsType + " " + lmotsType);
                    System.out.println("Private key: " + KeySizeUtil.getHssPrivateKeySize(lmotsType, lmsType, i));
                    System.out.println("Public key: " + KeySizeUtil.getHssPublicKeySize(lmotsType, lmsType, i));
                    System.out.println("Signature: " + KeySizeUtil.getHssSignatureSize(lmotsType, lmsType, i));
                }
            }
        }
    }
}