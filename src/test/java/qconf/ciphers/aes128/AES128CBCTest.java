package qconf.ciphers.aes128;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HexFormat;

public class AES128CBCTest extends AES128BlockModeTest {

    private static final byte[] iv = HexFormat.of().parseHex("0123456789abcdef0123456789abcdef");

    @Test
    public void badIVLengthThrowsException() throws Key.InvalidKeyException {
        Key key = new Key(HexFormat.of().parseHex("00000000000000000000000000000000"));
        assertThrows(AES128CBC.InvalidInitializationVectorLengthException.class,
                     () -> new AES128CBC(key, new byte[]{1}));
    }

    @Override
    AES128BlockMode getCipher(Key key) {
        try {
            return new AES128CBC(key, iv);
        } catch (AES128CBC.InvalidInitializationVectorLengthException e) {
            throw new RuntimeException(e); // This should not happen
        }
    }

    @Override
    byte[] getCiphertextForOneBlock() {
        return HexFormat.of().parseHex("6af84ce5aaa86deb0dfe2d3a772ca014");
    }

    @Override
    byte[] getCiphertextForSeveralBlocks() {
        return HexFormat.of().parseHex("47cf74f3b438b44e0c94bf11385ca542ea5f6b5916833aa67fe14ee9212e3b1265d09" +
                "493f4d660b323236f6ddd04d16719e6ffd71b21ca2968d83971aca855267fa4b7d4593f433bb362244768a673d50f16564" +
                "f5fb577613bfd1f4f33558246711c7ddad941810f9afca2f64873bd5116fadefcfd112757d9ee15f2ec2d18d567a34d3de" +
                "79dce10aeafff4112ca32f5d872701e78d578668d6968a768001fc25c314b2730b99b671ed7ac6a0aa6b36902a597c57cf" +
                "642ace77b215e256d6b236d74755ed770554412d8045dff879cc4");
    }
}
