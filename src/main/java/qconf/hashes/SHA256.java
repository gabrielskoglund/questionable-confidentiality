package qconf.hashes;

import java.util.Arrays;

/**
 * The SHA-256 hash function as defined in NIST FIPS 180-4.
 * The function turns byte input of any length into message digests of 256-bits.
 * By specification, SHA-256 can take input of any length less than 2^64 bits
 * (2^61 bytes). However, the maximum input size of this implementation is
 * bounded by the maximum size of arrays in java (2^31 - 1 elements).
 *
 * @author Gabriel Skoglund
 */
public class SHA256 implements HashFunction {

    /** Length of the message digest in bytes. */
    public static final int DIGEST_LENGTH = 32;

    /** Block size in bytes */
    private static final int BLOCK_SZ = 64;

    /** Word length in bytes. */
    private static final int WORD_LEN = 4;

    /** Number of rounds for each message block */
    public static final int NUM_ROUNDS = 64;

    /** Initial hash value */
    private static final int[] H_0 = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    public static final int[] ROUND_CONSTANTS = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    @Override
    public Digest digest(byte[] input) {
        input = Util.pad(input);
        int[] hash = Arrays.copyOf(H_0, H_0.length);

        for (int block = 0; block < input.length; block += BLOCK_SZ) {
            // Prepare the message schedule W_t
            int[] w = new int[NUM_ROUNDS];
            for (int t = 0; t < 16; t++)
                w[t] = Util.bytesToInt(input[block + t * WORD_LEN], input[block + t * WORD_LEN + 1],
                                       input[block + t * WORD_LEN + 2], input[block + t * WORD_LEN + 3]);
            for (int t = 16; t < NUM_ROUNDS; t++)
                w[t] = smallSigmaOne(w[t - 2]) + w[t - 7] + smallSigmaZero(w[t - 15]) + w[t - 16];

            // Set up working variables
            int a = hash[0], b = hash[1], c = hash[2], d = hash[3], e = hash[4], f = hash[5], g = hash[6], h = hash[7];

            // Perform rounds
            for (int t = 0; t < NUM_ROUNDS; t++) {
                int tOne = h + bigSigmaOne(e) + ch(e, f, g) + ROUND_CONSTANTS[t] + w[t];
                int tTwo = bigSigmaZero(a) + maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + tOne;
                d = c;
                c = b;
                b = a;
                a = tOne + tTwo;
            }

            // Calculate immediate hash values
            hash[0] += a;
            hash[1] += b;
            hash[2] += c;
            hash[3] += d;
            hash[4] += e;
            hash[5] += f;
            hash[6] += g;
            hash[7] += h;
        }

        // Turn hash back into bytes
        return Util.getDigest(hash, DIGEST_LENGTH, WORD_LEN);
    }

    /** SHA-256 Ch function */
    private static int ch(int x, int y, int z)  {
        return (x & y) ^ (~x & z);
    }

    /** SHA-256 Maj function */
    private static int maj(int x, int y, int z)  {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    /** SHA-256 \Sigma_0 function */
    private static int bigSigmaZero(int x) {
        return Integer.rotateRight(x, 2) ^ Integer.rotateRight(x, 13) ^ Integer.rotateRight(x, 22);
    }

    /** SHA-256 \Sigma_1 function */
    private static int bigSigmaOne(int x) {
        return Integer.rotateRight(x, 6) ^ Integer.rotateRight(x, 11) ^ Integer.rotateRight(x, 25);
    }

    /** SHA-256 \sigma_0 function */
    private static int smallSigmaZero(int x) {
        return Integer.rotateRight(x, 7) ^ Integer.rotateRight(x, 18) ^ (x >>> 3);
    }

    /** SHA-256 \sigma_1 function */
    private static int smallSigmaOne(int x) {
        return Integer.rotateRight(x, 17) ^ Integer.rotateRight(x, 19) ^ (x >>> 10);
    }
}
