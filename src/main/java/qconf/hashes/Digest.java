package qconf.hashes;

import java.util.HexFormat;

/**
 * A message digest, created as a result of the application of a hash function.
 *
 * @author Gabriel Skoglund
 */
public class Digest {

    private final byte[] digest;

    Digest(byte[] digest) {
        this.digest = digest;
    }

    /**
     * @return this digest as a byte array.
     */
    public byte[] asBytes() {
        return digest;
    }

    /**
     * @return this digest as a hexadecimal string.
     */
    public String asHex() {
        return HexFormat.of().formatHex(digest);
    }

    /**
     * @return The number of bytes that this digest consists of.
     */
    public int numberOfBytes() {
        return digest.length;
    }
}
