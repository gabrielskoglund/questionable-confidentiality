package qconf.ciphers.aes128;

import java.util.Arrays;
import java.util.function.Consumer;

/**
 * AES-128 ECB (Electronic Codebook) mode of operation, applying the AES cipher on each block in turn, with no
 * interaction between blocks. Please note that this is an inherently less secure mode, as identical plaintext blocks
 * will be encrypted to identical ciphertext blocks. For this reason, consider using a more secure mode such as CBC.
 *
 * @author Gabriel Skoglund
 */
public class AES128ECB extends AES128BlockMode {

    /**
     * Create a new AES-128 ECB cipher instance with the given key.
     * @param key the 16 byte key to use for encryption/decryption.
     */
    public AES128ECB(Key key) {
        super(key);
    }

    @Override
    public byte[] encrypt(byte[] plaintext) throws InvalidInputLengthException {
        return performECB(plaintext, super::encrypt);
    }
    @Override
    public byte[] decrypt(byte[] ciphertext) throws InvalidInputLengthException {
        return performECB(ciphertext, super::decrypt);
    }

    protected byte[] performECB(byte[] input, Consumer<State> operation) throws InvalidInputLengthException {
        checkInputLength(input);

        byte[] output = new byte[input.length];
        for (int i = 0; i < input.length; i += BLOCK_SZ) {
            State state = new State(Arrays.copyOfRange(input, i, i + BLOCK_SZ));
            operation.accept(state);
            System.arraycopy(state.state, 0, output, i, BLOCK_SZ);
        }
        return output;
    }
}
