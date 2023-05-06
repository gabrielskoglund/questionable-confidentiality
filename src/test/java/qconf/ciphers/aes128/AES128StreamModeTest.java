package qconf.ciphers.aes128;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

abstract class AES128StreamModeTest {

    /** Return an instance of this particular AES mode */
    abstract AES128StreamMode getCipher(Key key);

    /** See {@link #encryptionOfOneByteGivesExpectedResult} for details on key and plaintext */
    abstract byte[] getCiphertextForOneByte();

    /** See {@link #encryptionOfOneBlockGivesExpectedResult} for details on key and plaintext*/
    abstract byte[] getCiphertextForOneBlock();

    /** See {@link #encryptionOfThirtyBytesGivesExpectedResult} for details on key and plaintext*/
    abstract byte[] getCiphertextForThirtyBytes();

    /** See {@link #encryptionOfSeveralBlocksGivesExpectedResult} for details on key and plaintext*/
    abstract byte[] getCiphertextForSeveralBlocks();

    @Test
    void encryptionOfOneByteGivesExpectedResult() throws Key.InvalidKeyException {
        byte[] plaintext = "x".getBytes(StandardCharsets.US_ASCII);
        byte[] key = HexFormat.of().parseHex("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] expected = getCiphertextForOneByte();
        assertArrayEquals(expected, getCipher(new Key(key)).encrypt(plaintext));
    }

    @Test
    void encryptionOfOneBlockGivesExpectedResult() throws Key.InvalidKeyException {
        byte[] plaintext = HexFormat.of().parseHex("3243f6a8885a308d313198a2e0370734");
        byte[] key = HexFormat.of().parseHex("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] expected = getCiphertextForOneBlock();
        assertArrayEquals(expected, getCipher(new Key(key)).encrypt(plaintext));
    }

    @Test
    public void encryptionOfThirtyBytesGivesExpectedResult() throws Key.InvalidKeyException {
        byte[] plaintext = "It's peanut butter jelly time!".getBytes(StandardCharsets.US_ASCII);
        byte[] key = HexFormat.of().parseHex("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] expected = getCiphertextForThirtyBytes();
        assertArrayEquals(expected, getCipher(new Key(key)).encrypt(plaintext));
    }

    @Test
    void encryptionOfSeveralBlocksGivesExpectedResult() throws Key.InvalidKeyException {
        byte[] plaintext = ("The llama (Lama glama) is a domesticated South American camelid, widely used as a meat and " +
                "pack animal by Andean cultures since the Pre-Columbian era. Llamas are social animals and live with " +
                "others as a herd.").getBytes(StandardCharsets.US_ASCII);
        byte[] key = "Be a happy llama".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = getCiphertextForSeveralBlocks();
        assertArrayEquals(expected, getCipher(new Key(key)).encrypt(plaintext));
    }

    @Test
    void decryptionOfOneByteGivesExpectedResult() throws Key.InvalidKeyException {
        byte[] ciphertext = getCiphertextForOneByte();
        byte[] key = HexFormat.of().parseHex("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] expected = "x".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(expected, getCipher(new Key(key)).decrypt(ciphertext));
    }

    @Test
    void decryptionOfOneBlockGivesExpectedResult() throws Key.InvalidKeyException {
        byte[] ciphertext = getCiphertextForOneBlock();
        byte[] key = HexFormat.of().parseHex("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] expected = HexFormat.of().parseHex("3243f6a8885a308d313198a2e0370734");
        assertArrayEquals(expected, getCipher(new Key(key)).decrypt(ciphertext));
    }

    @Test
    public void decryptionOfTwentyBytesGivesExpectedResult() throws Key.InvalidKeyException {
        byte[] ciphertext = getCiphertextForThirtyBytes();
        byte[] key = HexFormat.of().parseHex("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] expected = "It's peanut butter jelly time!".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(expected, getCipher(new Key(key)).decrypt(ciphertext));
    }

    @Test
    void decryptionOfSeveralBlocksGivesExpectedResult() throws Key.InvalidKeyException {
        byte[] ciphertext = getCiphertextForSeveralBlocks();
        byte[] key = "Be a happy llama".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = ("The llama (Lama glama) is a domesticated South American camelid, widely used as a meat and " +
                "pack animal by Andean cultures since the Pre-Columbian era. Llamas are social animals and live with " +
                "others as a herd.").getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(expected, getCipher(new Key(key)).decrypt(ciphertext));
    }
}
