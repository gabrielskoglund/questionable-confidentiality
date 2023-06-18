package qconf.hashes;

/**
 *  A function taking an input of variable length to a digest of fixed size.
 *  These functions are intended to be cryptographically secure, guaranteeing
 *  collision resistance and fist/second preimage resistance. However, actual
 *  security properties will vary based on the concrete implementation.
 *
 * @author Gabriel Skoglund
 */
public interface HashFunction {

    /**
     * @param input An array of bytes to be hashed.
     * @return a hash {@link Digest} of the input bytes.
     */
    Digest digest(byte[] input);
}
