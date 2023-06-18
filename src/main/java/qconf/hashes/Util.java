package qconf.hashes;

import java.util.Arrays;

/**
 * Various hash function utilities.
 *
 * @author Gabriel Skoglund
 */
class Util {

    /**
     * Pad an input byte array. The output will have the bit pattern
     * [input] + 1 + 0^k + [original length encoded as a 64-bit number]
     * where k is the smallest positive number satisfying: input length + 1 + k = 448 mod 512
     */
    static byte[] pad(byte[] input) {
        long bitLen = input.length * 8L;
        int k = (int) (448 - (bitLen + 1) % 512);
        if (k < 0)
            k += 512;
        int outputLen = input.length + (k + 1) / 8 + 8;
        byte[] output = Arrays.copyOf(input, outputLen);
        output[input.length] = (byte) (1 << 7);
        for (int i = 7; i >= 0; i--)
            output[outputLen - i - 1] = (byte) (bitLen >> (i * 8));
        return output;
    }

    /** Convert 4 bytes in big endian format into a 32-bit integer */
    static int bytesToInt(byte a, byte b, byte c, byte d) {
        return ((a & 0xff) << 24) | ((b & 0xff) << 16) | ((c & 0xff) << 8) | (d & 0xff);
    }

    /** Convert a hash consisting of an array of integers to a message digest */
    static Digest getDigest(int[] hash, int digestLength, int wordLength) {
        byte[] digest = new byte[digestLength];
        for (int i = 0; i < digestLength; i += wordLength) {
            for (int j = 0; j < wordLength; j++)
                digest[i + j] = (byte) (hash[i / wordLength] >>> ((wordLength - j - 1) * Byte.SIZE));
        }
        return new Digest(digest);
    }
}
