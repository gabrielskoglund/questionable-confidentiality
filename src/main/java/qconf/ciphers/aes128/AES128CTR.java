package qconf.ciphers.aes128;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * AES-128 CTR (Counter) mode of operation, where the input is XORed with encrypted value of a counter which
 * is incremented for each block. This is a stream mode of operation and does not place any constraints on the
 * length of the input.
 *
 * @author Gabriel Skoglund
 */
public class AES128CTR extends AES128StreamMode {

    private final Counter counter;

    /**
     * Create a new AES-128 CBC cipher instance with the given key.
     *
     * @param key the 16 byte key to use for encryption/decryption.
     * @param counter the initial counter value to use when encrypting/decrypting.
     *                <b>Important note:</b> The security of this mode relies on never reusing the same
     *                counter value/key combination. When creating a new cipher instance, it is recommended
     *                to create a new (securely) random initial counter value.
     */
    public AES128CTR(Key key, Counter counter) {
        super(key);
        this.counter = counter;
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        byte[] output = new byte[plaintext.length];
        for (int i = 0; ; i += BLOCK_SZ) {
            State ctr = new State(counter.getValue());
            encrypt(ctr);
            int j = i;
            for (; j < i + BLOCK_SZ && j < plaintext.length; j++)
                output[j] = (byte) (ctr.state[j - i] ^ plaintext[j]);
            counter.increment();
            if (j == plaintext.length)
                break;
        }
        return output;
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) {
        // Note: CTR encryption and decryption use the same operations
        return encrypt(ciphertext);
    }

    /**
     * Counter used for encryption/decryption.
     */
    public static class Counter {
        private BigInteger counter;

        /**
         * The maximum value of the counter before wrapping around (when extracting the lowest 128 bits)
         * will be 2^128 - 1
         */
        private static final BigInteger MAX_VALUE = new BigInteger("340282366920938463463374607431768211455");

        /**
         * @param initialValue The initial value of this counter.
         */
        public Counter(BigInteger initialValue) {
            counter = initialValue.mod(MAX_VALUE);
        }

        /** Extract the lowest 16 bytes of the counter */
        private byte[] getValue() {
            byte[] val = counter.toByteArray();
            return Arrays.copyOfRange(val, val.length - 16, val.length);
        }

        private void increment() {
            counter = counter.add(BigInteger.ONE);
        }
    }
}
