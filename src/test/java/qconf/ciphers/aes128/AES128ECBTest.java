package qconf.ciphers.aes128;

import java.util.HexFormat;

class AES128ECBTest extends AES128BlockModeTest {

    @Override
    AES128BlockMode getCipher(Key key) {
        return new AES128ECB(key);
    }

    @Override
    byte[] getCiphertextForOneBlock() {
        return HexFormat.of().parseHex("3925841d02dc09fbdc118597196a0b32");
    }

    @Override
    byte[] getCiphertextForSeveralBlocks() {
        return HexFormat.of().parseHex("19ada7e9f9d878a63c9c3035a6a37925129873d2298b06fe6a5ef3a8" +
                "f2d7310af03cd24cedb75f986a7df956c71f8324b28acd941a86d767fd280e2eb03378844f294e047d35a27152bebad4" +
                "8129ff15f79799e5682510dd226cd233cd4f2d47a413ddf5d260c32d94bbdc56676a5935cc77c01c80946d8d978acebf" +
                "b682ccaebaedb968fac94bcf4b68b959acbe6c5b5c906fd21bfd3ba315b9b153b449fa6fd440a75ac6b7f121f8dfcea6" +
                "6e3de2a52e9be2597fb8d843bb587e38926d7f8a5d9fe7d3dc4c9b7ebd9e1741a1422de8");
    }
}
