package qconf.ciphers.aes128;

import java.math.BigInteger;
import java.util.HexFormat;

public class AES128CTRTest extends AES128StreamModeTest {

    private final BigInteger initialCounterValue =
            new BigInteger(HexFormat.of().parseHex("0123456789abcdef0123456789abcdef"));

    @Override
    AES128StreamMode getCipher(Key key) {
        return new AES128CTR(key, new AES128CTR.Counter(initialCounterValue));
    }

    @Override
    byte[] getCiphertextForOneByte() {
        return HexFormat.of().parseHex("ac");
    }

    @Override
    byte[] getCiphertextForOneBlock() {
        return HexFormat.of().parseHex("e60cfdd1a789874c339298f2fd8d0fa8");
    }

    @Override
    byte[] getCiphertextForThirtyBytes() {
        return HexFormat.of().parseHex("9d3b2c0a0fa3d2a06cd674707fcf7ce8c245d2cd4513f7cf6127f2d7f4f8");
    }

    @Override
    byte[] getCiphertextForSeveralBlocks() {
        return HexFormat.of().parseHex("acf1e2c8930e96f6fe005f3d78231e1cae68fc8fb4128b417876a25495c09db53" +
                "49bc718b6c36429f44a50bfee487b4ecb70a84f9e506e590d49785508529a3cb14355002e48557c4b04016d810f9e9" +
                "cac27bce1ea68450585750370039f3129862268e1acc01b7463da4d6374c19e886b21a032bcac0fd7ec317bcb80f16" +
                "0a99921affe52533c04dd7d3ad9e2856633cd1e88b95c3c76fcf0568be78c952c3e6e9c3dd87feaa03e4555151c713" +
                "a119b348ddac6b2c4e2dc598bc1c1e8d806602cf1a01ce781387e187c92744261a9db");
    }
}
