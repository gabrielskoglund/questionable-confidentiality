package qconf.ciphers.aes128;

/**
 * Class representing AES stream modes of operations.
 *
 * @author Gabriel Skoglund
 */
public abstract class AES128StreamMode extends AES128 {
    AES128StreamMode(Key key) { super(key); }

    /**
     * @param plaintext the plaintext to be encrypted.
     * @return a byte array containing the encrypted form of the plaintext.
     */
    public abstract byte[] encrypt(byte[] plaintext);

    /**
     * @param ciphertext the ciphertext to be decrypted.
     * @return a byte array containing the decrypted form of the ciphertext.
     */
    public abstract byte[] decrypt(byte[] ciphertext);
}
