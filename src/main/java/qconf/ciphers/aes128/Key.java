package qconf.ciphers.aes128;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Class representing a key for the 128-bit version of AES.
 *
 * @author Gabriel Skoglund
 */
public class Key {

    /** The number of bytes this key consists of. */
    public static final short LENGTH = 16;

    protected byte[] key;

    /**
     * @param key a byte array containing the key material.
     * @throws InvalidKeyException if the length of the provided key is not exactly 16 bytes.
     */
    public Key(byte[] key) throws InvalidKeyException {
        if (key.length != LENGTH)
            throw new InvalidKeyException();
        this.key = key;
    }

    /**
     * Exception for keys that are not exactly 128 bits (16 bytes) long.
     */
    public static class InvalidKeyException extends Exception {
        public InvalidKeyException() { super("Key length must be exactly " + LENGTH + " bytes"); }
    }

    /** Expand this key into round keys */
    List<Key> expand() {
        // We store the generated keys in a continuous array
        byte[] keys = new byte[Key.LENGTH * (AES128.NUM_ROUNDS + 1)];
        System.arraycopy(key, 0, keys, 0, Key.LENGTH);

        // rCon is a list of round constants
        byte[][] rCon = {
                { 0x01, 0x00, 0x00, 0x00},
                { 0x02, 0x00, 0x00, 0x00},
                { 0x04, 0x00, 0x00, 0x00},
                { 0x08, 0x00, 0x00, 0x00},
                { 0x10, 0x00, 0x00, 0x00},
                { 0x20, 0x00, 0x00, 0x00},
                { 0x40, 0x00, 0x00, 0x00},
                {-0x80, 0x00, 0x00, 0x00},
                { 0x1B, 0x00, 0x00, 0x00},
                { 0x36, 0x00, 0x00, 0x00}
        };

        int bytesPerWord = 4;
        for (int i = Key.LENGTH; i < Key.LENGTH * (AES128.NUM_ROUNDS + 1); i += bytesPerWord) {
            // The word is a 4 byte section of a key
            byte[] word = Arrays.copyOfRange(keys, i - bytesPerWord, i);
            if (i % Key.LENGTH == 0) {
                rotWord(word);
                subWord(word);
                xorWord(word, rCon[i / Key.LENGTH - 1]);
            }
            xorWord(word, Arrays.copyOfRange(keys, i - Key.LENGTH, i - Key.LENGTH + bytesPerWord));
            System.arraycopy(word, 0, keys, i, bytesPerWord);
        }

        // Create key objects from sections of the key array
        List<Key> ret = new ArrayList<>();
        for (int i = 0; i < keys.length; i += Key.LENGTH) {
            try {
                ret.add(new Key(Arrays.copyOfRange(keys, i, i + Key.LENGTH)));
            } catch (Key.InvalidKeyException e) {
                // This really shouldn't happen
                throw new RuntimeException(e);
            }
        }
        return ret;
    }

    /** Rotate a 4 byte word left by 1 byte */
    private static void rotWord(byte[] word) {
        byte first = word[0];
        for (int i = 0; i < word.length - 1; i++)
            word[i] = word[i + 1];
        word[word.length - 1] = first;
    }

    /** Apply the AES S-Box to a 4 byte word */
    private static void subWord(byte[] word) {
        for (int i = 0; i < word.length; i++)
            word[i] = (byte) AES128.SBOX[word[i] & 0xff];
    }

    /** XOR one 4 byte word into another */
    private static void xorWord(byte[] word, byte[] other) {
        for (int i = 0; i < word.length; i++)
            word[i] ^= other[i];
    }
}
