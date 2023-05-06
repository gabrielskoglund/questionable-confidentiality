package qconf.ciphers.aes128;

import java.util.Arrays;

/**
 * AES-128 CBC (Cipher Block Chaining) mode of operation, where each block is XORed with the previous block before
 * being encrypted to ensure that equivalent plaintext blocks will not hash to equivalent ciphertext blocks.
 *
 * @author Gabriel Skoglund
 */
public class AES128CBC extends AES128BlockMode {

    private State iv;

    /**
     * Create a new AES-128 CBC cipher instance with the given key.
     *
     * @param key                  the 16 byte key to use for encryption/decryption.
     * @param initializationVector the IV that will be used for the first step of the CBC decryption/encryption.
     *                             Note that reusing an IV with the same key will leak the length of any shared prefix
     *                             of encrypted messages. It is recommended to set a new IV for each message.
     * @throws InvalidInitializationVectorLengthException if the IV provided is not exactly 16 bytes.
     */
    public AES128CBC(Key key, byte[] initializationVector) throws InvalidInitializationVectorLengthException {
        super(key);
        if (initializationVector.length != BLOCK_SZ)
            throw new InvalidInitializationVectorLengthException(initializationVector.length);
        iv = new State(initializationVector);
    }

    @Override
    public byte[] encrypt(byte[] plaintext) throws InvalidInputLengthException {
        checkInputLength(plaintext);

        byte[] output = new byte[plaintext.length];
        State currentState = iv;
        for (int i = 0; i < plaintext.length; i += BLOCK_SZ) {
            currentState = new State(xorBlocks(Arrays.copyOfRange(plaintext, i, i + BLOCK_SZ), currentState.state));
            encrypt(currentState);
            System.arraycopy(currentState.state, 0, output, i, BLOCK_SZ);
        }

        return output;
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) throws InvalidInputLengthException {
        checkInputLength(ciphertext);

        byte[] output = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i += BLOCK_SZ) {
            State currentState = new State(Arrays.copyOfRange(ciphertext, i, i + BLOCK_SZ));
            decrypt(currentState);
            byte[] prevBlock = (i == 0) ? iv.state : Arrays.copyOfRange(ciphertext, i - BLOCK_SZ, i);
            System.arraycopy(xorBlocks(currentState.state, prevBlock), 0, output, i, BLOCK_SZ);
        }

        return output;
    }

    private byte[] xorBlocks(byte[] target, byte[] other) {
        byte[] result = new byte[BLOCK_SZ];
        for (int i = 0; i < BLOCK_SZ; i++)
            result[i] = (byte) (target[i] ^ other[i]);
        return result;
    }

    /**
     * @param initializationVector the new IV to use.
     * @return a reference to this AES128CBC object.
     * @throws InvalidInitializationVectorLengthException if the IV provided is not exactly 16 bytes.
     */
    public AES128CBC setInitializationVector(byte[] initializationVector)
            throws InvalidInitializationVectorLengthException {
        if (initializationVector.length != BLOCK_SZ)
            throw new InvalidInitializationVectorLengthException(initializationVector.length);
        iv = new State(initializationVector);
        return this;
    }

    /**
     * @return the currently set IV of this cipher.
     */
    public byte[] getInitializationVector() {
        return iv.state;
    }

    public static class InvalidInitializationVectorLengthException extends Exception {
        public InvalidInitializationVectorLengthException(int providedLength) {
            super("The provided initialization vector must be exactly " + BLOCK_SZ + " bytes. " +
                    "Provided length: " + providedLength + "bytes.");
        }
    }
}
