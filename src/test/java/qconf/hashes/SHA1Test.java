package qconf.hashes;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class SHA1Test {

    @Test
    public void emptyInputGivesExpectedResult() {
        String expected = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        String actual = new SHA1().digest(new byte[0]).asHex();
        assertEquals(expected, actual);
    }

    @Test
    public void oneBlockInputGivesExpectedResult() {
        String expected = "a9993e364706816aba3e25717850c26c9cd0d89d";
        String actual = new SHA1().digest("abc".getBytes(StandardCharsets.US_ASCII)).asHex();
        assertEquals(expected, actual);
    }

    @Test
    public void twoBlockInputGivesExpectedResult() {
        String expected = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";
        String actual = new SHA1()
                .digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes(StandardCharsets.US_ASCII))
                .asHex();
        assertEquals(expected, actual);
    }

    @Test
    public void inputOfSizeBlockSizeMinusOneGivesExpectedResult() {
        byte[] input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .getBytes(StandardCharsets.US_ASCII);
        String expected = "03f09f5b158a7a8cdad920bddc29b81c18a551f5";
        String actual = new SHA1().digest(input).asHex();
        assertEquals(expected, actual);
    }

    @Test
    public void inputOfSizeExactlyOneBlockGivesExpectedResult() {
        byte[] input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .getBytes(StandardCharsets.US_ASCII);
        String expected = "0098ba824b5c16427bd7a1122a5a442a25ec644d";
        String actual = new SHA1().digest(input).asHex();
        assertEquals(expected, actual);
    }
}
