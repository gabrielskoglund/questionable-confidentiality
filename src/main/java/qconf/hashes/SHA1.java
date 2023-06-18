package qconf.hashes;

import java.util.Arrays;

/**
 * The SHA-1 hash function as defined in NIST FIPS 180-4.
 * The function turns byte input of any length into message digests of 160-bits.
 * By specification, SHA-1 can take input of any length less than 2^64 bits
 * (2^61 bytes). However, the maximum input size of this implementation is
 * bounded by the maximum size of arrays in java (2^31 - 1 elements).
 * <p>
 * Please note that SHA-1 is no longer considered to be a secure hash function,
 * and either SHA-2 or SHA-3 should be used for sensitive applications.
 *
 * @author Gabriel Skoglund
 */
public class SHA1 implements HashFunction {

    /** Length of the message digest in bytes. */
    public static final int DIGEST_LENGTH = 20;

    /** Block size in bytes */
    private static final int BLOCK_SZ = 64;

    /** Word length in bytes. */
    private static final int WORD_LEN = 4;

    /** Initial hash value */
    private static final int[] H_0 = new int[]{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};

    /** Number of rounds for each message block */
    public static final int NUM_ROUNDS = 80;

    /**
     * Digest the given input bytes and produce a {@value #DIGEST_LENGTH} byte long digest.
     * @param input the input byte array to be hashed.
     * @return a {@value #DIGEST_LENGTH} byte {@link Digest}.
     */
    @Override
    public Digest digest(byte[] input) {
        input = Util.pad(input);
        int[] hash = Arrays.copyOf(H_0, H_0.length);

        for (int block = 0; block < input.length; block += BLOCK_SZ) {
            // Initialize the message schedule W_t
            int[] w = new int[NUM_ROUNDS];
            for (int t = 0; t < 16; t++)
                w[t] = Util.bytesToInt(input[block + WORD_LEN * t], input[block + WORD_LEN * t + 1],
                                       input[block + WORD_LEN * t + 2], input[block + WORD_LEN * t + 3]);
            for (int t = 16; t < 80; t++)
                w[t] = Integer.rotateLeft(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);

            // Initialize working variables
            int a = hash[0], b = hash[1], c = hash[2], d = hash[3], e = hash[4];

            // Perform rounds
            for (int t = 0; t < 80; t++) {
                int tmp = Integer.rotateLeft(a, 5) + roundFunction(b, c, d, t) + e + roundConstant(t) + w[t];
                e = d;
                d = c;
                c = Integer.rotateLeft(b, 30);
                b = a;
                a = tmp;
            }

            // Calculate intermediate hash values
            hash[0] = a + hash[0];
            hash[1] = b + hash[1];
            hash[2] = c + hash[2];
            hash[3] = d + hash[3];
            hash[4] = e + hash[4];
        }

        // Turn hash words back into bytes
        return Util.getDigest(hash, DIGEST_LENGTH, WORD_LEN);
    }

    /**
     * Calculate the SHA-1 round function f_t
     */
    private int roundFunction(int x, int y, int z, int t) {
        if (t < 20)
            return (x & y) ^ (~x & z);
        else if (t < 40 || t >= 60)
            return x ^ y ^ z;
        else
            return (x & y) ^ (x & z) ^ (y & z);
    }

    /**
     * Get the SHA-1 round constant K_t
     */
    private int roundConstant(int t) {
        if (t < 20)
            return 0x5a827999;
        else if (t < 40)
            return 0x6ed9eba1;
        else if (t < 60)
            return 0x8f1bbcdc;
        else
            return 0xca62c1d6;
    }
}
