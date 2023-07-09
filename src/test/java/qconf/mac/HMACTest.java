package qconf.mac;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import qconf.hashes.SHA256;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HMACTest {

    private static HMAC<SHA256> hmacSha256;

    @BeforeAll
    static void setUp() {
        hmacSha256 = new HMAC<>(SHA256::new);
    }

    @Test
    void HMACSHA256GivesExpectedResult() {
        byte[] key = HexFormat.of().parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] data = "Hi There".getBytes(StandardCharsets.US_ASCII);
        String expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        assertEquals(expected, hmacSha256.digest(key, data).asHex());
    }

    @Test
    void HMACSHA256WithKeyOfLengthShorterThanDigestSizeGivesExpectedResult() {
        byte[] key = "Jefe".getBytes(StandardCharsets.US_ASCII);
        byte[] data = "what do ya want for nothing?".getBytes(StandardCharsets.US_ASCII);
        String expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        assertEquals(expected, hmacSha256.digest(key, data).asHex());
    }

    @Test
    void HMACSHA256WithKeyAndMessageCombinedLongerThanBlockSizeGivesExpectedResult() {
        byte[] key = HexFormat.of().parseHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        byte[] data = HexFormat.of().parseHex("dddddddddddddddddddddddddddddddddddddddddddddddddd" +
                "dddddddddddddddddddddddddddddddddddddddddddddddddd");
        String expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";
        assertEquals(expected, hmacSha256.digest(key, data).asHex());
    }

    @Test
    void HMACSHA256WithKeyLongerThanBlockSizeGivesExpectedResult() {
        byte[] key = HexFormat.of().parseHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaa");
        byte[] data = "Test Using Larger Than Block-Size Key - Hash Key First".getBytes(StandardCharsets.US_ASCII);
        String expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";
        assertEquals(expected, hmacSha256.digest(key, data).asHex());
    }

    @Test
    void HMACSHA256WithBothKeyAndMessageLongerThanBlockSizeGivesExpectedResult() {
        byte[] key = HexFormat.of().parseHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaa");
        byte[] data = ("This is a test using a larger than block-size key and a larger than block-size data. The key" +
                " needs to be hashed before being used by the HMAC algorithm.").getBytes(StandardCharsets.US_ASCII);
        String expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";
        assertEquals(expected, hmacSha256.digest(key, data).asHex());
    }
}
