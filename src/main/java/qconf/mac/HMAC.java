package qconf.mac;

import qconf.hashes.Digest;
import qconf.hashes.HashFunction;

import java.util.Arrays;
import java.util.function.Supplier;

/**
 * HMAC as specified by RFC 2104. Can be used with any block-based hash algorithm to provide a message authentication
 * code. The security of the MAC will be related of the security of the underlying hash function, but HMAC is not
 * susceptible to message extension attacks.
 *
 * @param <H> a class implementing the {@link HashFunction} interface.
 *
 * @author Gabriel Skoglund
 */
public class HMAC<H extends HashFunction> {

    private final H hashFunction;
    private static final byte INNER_PAD_BYTE = 0x36;
    private static final byte OUTER_PAD_BYTE = 0x5c;

    /**
     * Create a new HMAC instance based on the given hash function.
     * @param hashFunctionSupplier a {@link Supplier} that provides an instance of the desired hash function.
     */
    public HMAC(Supplier<H> hashFunctionSupplier) {
        this.hashFunction = hashFunctionSupplier.get();
    }

    /**
     * Create a hash based message digest using the given key and input.
     * @param key the HMAC key to use. In order to ensure security, the key length should be at least equal to the
     *            digest size of the underlying hash function.
     * @param input the message for which to compute the MAC.
     * @return a HMAC {@link Digest}.
     */
    public Digest digest(byte[] key, byte[] input) {
        key = makeKeyBlockSized(key);

        byte[] inner = new byte[hashFunction.blockSize() + input.length];
        byte[] innerKey = xorKey(key, INNER_PAD_BYTE);
        System.arraycopy(innerKey, 0, inner, 0, hashFunction.blockSize());
        System.arraycopy(input, 0, inner, hashFunction.blockSize(), input.length);
        inner = hashFunction.digest(inner).asBytes();

        byte[] outer = new byte[hashFunction.blockSize() + hashFunction.digestSize()];
        byte[] outerKey = xorKey(key, OUTER_PAD_BYTE);
        System.arraycopy(outerKey, 0, outer, 0, hashFunction.blockSize());
        System.arraycopy(inner, 0, outer, hashFunction.blockSize(), inner.length);

        return hashFunction.digest(outer);
    }

    /** Ensure that the key is the same size as the block size of the hash algorithm */
    private byte[] makeKeyBlockSized(byte[] key) {
        if (key.length > hashFunction.blockSize())
            key = hashFunction.digest(key).asBytes();
        if (key.length < hashFunction.blockSize())
            return Arrays.copyOf(key, hashFunction.blockSize());
        return key;
    }

    /** Generate an inner/outer key by XORing a specific byte into the given key */
    private byte[] xorKey(byte[] key, byte padByte) {
        byte[] xoredKey = new byte[key.length];
        for (int i = 0; i < xoredKey.length; i++)
            xoredKey[i] = (byte) (key[i] ^ padByte);

        return xoredKey;
    }
}
