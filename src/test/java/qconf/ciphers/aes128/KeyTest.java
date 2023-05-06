package qconf.ciphers.aes128;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeyTest {

    @Test
    void emptyKeyGivesInvalidKeyException() {
        assertThrows(Key.InvalidKeyException.class, () -> new Key(new byte[]{}));
    }

    @Test
    void tooShortKeyGivesInvalidKeyException() {
        assertThrows(Key.InvalidKeyException.class, () -> new Key(new byte[]{0,1,2}));
    }

    @Test
    void tooLongKeyGivesInvalidKeyException() {
        assertThrows(Key.InvalidKeyException.class,
                     () -> new Key(new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}));
    }

    @Test
    void keyExpansionGivesExpectedResult() throws Key.InvalidKeyException {
        var expected = List.of(
                HexFormat.of().parseHex("00000000000000000000000000000000"),
                HexFormat.of().parseHex("62636363626363636263636362636363"),
                HexFormat.of().parseHex("9b9898c9f9fbfbaa9b9898c9f9fbfbaa"),
                HexFormat.of().parseHex("90973450696ccffaf2f457330b0fac99"),
                HexFormat.of().parseHex("ee06da7b876a1581759e42b27e91ee2b"),
                HexFormat.of().parseHex("7f2e2b88f8443e098dda7cbbf34b9290"),
                HexFormat.of().parseHex("ec614b851425758c99ff09376ab49ba7"),
                HexFormat.of().parseHex("217517873550620bacaf6b3cc61bf09b"),
                HexFormat.of().parseHex("0ef903333ba9613897060a04511dfa9f"),
                HexFormat.of().parseHex("b1d4d8e28a7db9da1d7bb3de4c664941"),
                HexFormat.of().parseHex("b4ef5bcb3e92e21123e951cf6f8f188e")
        );
        List<Key> keys = new Key(HexFormat.of().parseHex("00000000000000000000000000000000")).expand();
        for (int i = 0; i < expected.size(); i++)
            assertArrayEquals(expected.get(i), keys.get(i).key);
    }
}
