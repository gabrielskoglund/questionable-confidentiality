package qconf.ciphers.aes128;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

abstract class AES128BlockModeTest {

    /** Return an instance of this particular AES mode */
    abstract AES128BlockMode getCipher(Key key);

    /** See {@link #encryptionOfOneBlockGivesExpectedResult} for details on key and plaintext*/
    abstract byte[] getCiphertextForOneBlock();

    /** See {@link #encryptionOfSeveralBlocksGivesExpectedResult} for details on key and plaintext*/
    abstract byte[] getCiphertextForSeveralBlocks();

    @Test
    void encryptionWithInvalidMessageLengthThrowsException() throws Key.InvalidKeyException {
        Key k = new Key(HexFormat.of().parseHex("2b7e151628aed2a6abf7158809cf4f3c"));
        assertThrows(AES128BlockMode.InvalidInputLengthException.class, () -> getCipher(k).encrypt(new byte[]{1, 2, 3}));
    }

    @Test
    void decryptionWithInvalidMessageLengthThrowsException() throws Key.InvalidKeyException {
        Key key = new Key(HexFormat.of().parseHex("2b7e151628aed2a6abf7158809cf4f3c"));
        assertThrows(AES128BlockMode.InvalidInputLengthException.class, () -> getCipher(key).decrypt(new byte[]{1, 2, 3}));
    }

    @Test
    void encryptionOfOneBlockGivesExpectedResult()
            throws Key.InvalidKeyException, AES128BlockMode.InvalidInputLengthException {
        byte[] plaintext = HexFormat.of().parseHex("3243f6a8885a308d313198a2e0370734");
        byte[] key = HexFormat.of().parseHex("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] expected = getCiphertextForOneBlock();
        assertArrayEquals(expected, getCipher(new Key(key)).encrypt(plaintext));
    }

    @Test
    void encryptionOfSeveralBlocksGivesExpectedResult()
            throws Key.InvalidKeyException, AES128BlockMode.InvalidInputLengthException {
        byte[] plaintext = ("The llama (Lama glama) is a domesticated South American camelid, widely used as a meat and " +
                "pack animal by Andean cultures since the Pre-Columbian era. Llamas are social animals and live with " +
                "others as a herd.").getBytes(StandardCharsets.US_ASCII);
        byte[] key = "Be a happy llama".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = getCiphertextForSeveralBlocks();
        assertArrayEquals(expected, getCipher(new Key(key)).encrypt(plaintext));
    }

    @Test
    void decryptionOfOneBlockGivesExpectedResult() throws Key.InvalidKeyException, AES128BlockMode.InvalidInputLengthException {
        byte[] ciphertext = getCiphertextForOneBlock();
        byte[] key = HexFormat.of().parseHex("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] expected = HexFormat.of().parseHex("3243f6a8885a308d313198a2e0370734");
        assertArrayEquals(expected, getCipher(new Key(key)).decrypt(ciphertext));
    }

    @Test
    void decryptionOfSeveralBlocksGivesExpectedResult()
            throws Key.InvalidKeyException, AES128BlockMode.InvalidInputLengthException {
        byte[] ciphertext = getCiphertextForSeveralBlocks();
        byte[] key = "Be a happy llama".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = ("The llama (Lama glama) is a domesticated South American camelid, widely used as a meat and " +
                "pack animal by Andean cultures since the Pre-Columbian era. Llamas are social animals and live with " +
                "others as a herd.").getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(expected, getCipher(new Key(key)).decrypt(ciphertext));
    }
}
