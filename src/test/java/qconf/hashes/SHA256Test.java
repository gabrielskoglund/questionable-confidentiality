package qconf.hashes;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SHA256Test {

    @Test
    public void emptyInputGivesExpectedResult() {
        String expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        String actual = new SHA256().digest(new byte[0]).asHex();
        assertEquals(expected, actual);
    }

    @Test
    public void oneBlockInputGivesExpectedResult() {
        String expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        String actual = new SHA256().digest("abc".getBytes(StandardCharsets.US_ASCII)).asHex();
        assertEquals(expected, actual);
    }

    @Test
    public void twoBlockInputGivesExpectedResult() {
        String expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        String actual = new SHA256()
                .digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes(StandardCharsets.US_ASCII))
                .asHex();
        assertEquals(expected, actual);
    }

    @Test
    public void inputOfSizeBlockSizeMinusOneGivesExpectedResult() {
        byte[] input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .getBytes(StandardCharsets.US_ASCII);
        String expected = "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34";
        String actual = new SHA256().digest(input).asHex();
        assertEquals(expected, actual);
    }

    @Test
    public void inputOfSizeExactlyOneBlockGivesExpectedResult() {
        byte[] input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .getBytes(StandardCharsets.US_ASCII);
        String expected = "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb";
        String actual = new SHA256().digest(input).asHex();
        assertEquals(expected, actual);
    }
}
