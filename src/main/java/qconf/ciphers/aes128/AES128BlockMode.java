package qconf.ciphers.aes128;

/**
 * Class representing AES block modes of operations.
 *
 * @author Gabriel Skoglund
 */
public abstract class AES128BlockMode extends AES128 {

    AES128BlockMode(Key key) {
        super(key);
    }

    /**
     * @param plaintext the plaintext to be encrypted.
     * @return a byte array containing the encrypted form of the plaintext.
     * @throws InvalidInputLengthException if the plaintext is not a multiple of the block size (16 bytes).
     */
    public abstract byte[] encrypt(byte[] plaintext) throws AES128BlockMode.InvalidInputLengthException;

    /**
     * @param ciphertext the ciphertext to be decrypted.
     * @return a byte array containing the decrypted form of the ciphertext.
     * @throws InvalidInputLengthException if the ciphertext is not a multiple of the block size (16 bytes).
     */
    public abstract byte[] decrypt(byte[] ciphertext) throws AES128BlockMode.InvalidInputLengthException;

    /**
     * AES-128 block modes of operations require the input to be a multiple of 16 bytes.
     */
    public static class InvalidInputLengthException extends Exception {
        public InvalidInputLengthException(int inputLength) {
            super("The AES128 input must be a multiple of " + BLOCK_SZ + " bytes, but the input was " +
                  inputLength + " bytes long");
        }
    }
}
