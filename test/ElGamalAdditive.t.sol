// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/ElGamalAdditive.sol";
import "../src/BigNum.sol";

contract ElGamalAdditiveTest is Test {
    ElGamalAdditive public elgamal;

    // Small prime parameters
    bytes public smallPrime = abi.encodePacked(uint256(23));
    bytes public xSmall = abi.encodePacked(uint256(10));
    bytes public g = abi.encodePacked(uint256(2));
    bytes public hSmall;

    // Large prime parameters
    bytes public largePrime =
        abi.encodePacked(uint256(115792089237316195423570985008687907853269984665640564039457584007913129639747));
    bytes public x = abi.encodePacked(uint256(12345678901234567890));
    bytes public hLarge;

    function setUp() public {
        elgamal = new ElGamalAdditive();

        // For small prime, use xSmall
        {
            BigNumber memory bn_g = BigNumber(g, false, BigNum.bitLength(g));
            BigNumber memory bn_xSmall = BigNum.init(xSmall, false);
            BigNumber memory bn_p_small = BigNumber(smallPrime, false, BigNum.bitLength(smallPrime));
            hSmall = BigNum.modexp(bn_g, bn_xSmall, bn_p_small).val;
        }

        // For large prime, use x
        {
            BigNumber memory bn_g = BigNumber(g, false, BigNum.bitLength(g));
            BigNumber memory bn_x = BigNum.init(x, false);
            BigNumber memory bn_p_large = BigNumber(largePrime, false, BigNum.bitLength(largePrime));
            hLarge = BigNum.modexp(bn_g, bn_x, bn_p_large).val;
        }
    }

    function testEncryptDecryptSmallPrime() public {
        PublicKey memory pk = PublicKey(smallPrime, g, hSmall);
        bytes memory r = abi.encodePacked(uint256(3));
        uint256 m = 4;

        // Compute expected values:
        BigNumber memory bn_g = BigNumber(pk.g, false, BigNum.bitLength(pk.g));
        BigNumber memory bn_r = BigNumber(r, false, BigNum.bitLength(r));
        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));
        BigNumber memory bn_m = BigNum.init(abi.encodePacked(m), false);
        BigNumber memory g_m = BigNum.modexp(bn_g, bn_m, bn_p);
        BigNumber memory h_r = BigNum.modexp(BigNumber(pk.h, false, BigNum.bitLength(pk.h)), bn_r, bn_p);

        (BigNumber memory c1, BigNumber memory c2) = elgamal.encrypt(abi.encodePacked(m), r, pk);
        assertEq(c1.val, BigNum.modexp(bn_g, bn_r, bn_p).val, "c1 mismatch");
        assertEq(c2.val, BigNum.modmul(g_m, h_r, bn_p).val, "c2 should be g^m * h^r mod p");
    }

    function testEncryptDecryptLargePrime() public {
        PublicKey memory pk = PublicKey(largePrime, g, hLarge);
        bytes memory r = abi.encodePacked(uint256(98765432109876543210));
        uint256 m = 42;

        BigNumber memory bn_g = BigNumber(pk.g, false, BigNum.bitLength(pk.g));
        BigNumber memory bn_r = BigNumber(r, false, BigNum.bitLength(r));
        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));

        BigNumber memory bn_m = BigNumber(abi.encodePacked(m), false, BigNum.bitLength(abi.encodePacked(m)));
        BigNumber memory g_m = BigNum.modexp(bn_g, bn_m, bn_p);
        BigNumber memory h_r = BigNum.modexp(BigNumber(pk.h, false, BigNum.bitLength(pk.h)), bn_r, bn_p);

        (BigNumber memory c1, BigNumber memory c2) = elgamal.encrypt(abi.encodePacked(m), r, pk);
        assertEq(c1.val, BigNum.modexp(bn_g, bn_r, bn_p).val, "c1 mismatch");
        assertEq(c2.val, BigNum.modmul(g_m, h_r, bn_p).val, "c2 should be g^m * h^r mod p");
    }

    function testDecryptAdditiveSmallPrime() public {
        PublicKey memory pk = PublicKey(smallPrime, g, hSmall);
        bytes memory decryptionKey = xSmall;
        bytes memory r = abi.encodePacked(uint256(3));
        uint256 m = 4;

        (BigNumber memory c1, BigNumber memory c2) = elgamal.encrypt(abi.encodePacked(m), r, pk);

        uint256 decrypted = elgamal.decrypt(Ciphertext(c1.val, c2.val), decryptionKey, pk);
        assertEq(decrypted, m, "Additive decryption did not recover m");
    }

    function testHomomorphicAdditionSmallPrime() public {
        PublicKey memory pk = PublicKey(smallPrime, g, hSmall);
        bytes memory r1 = abi.encodePacked(uint256(3));
        bytes memory r2 = abi.encodePacked(uint256(4));
        uint256 m1 = 4;
        uint256 m2 = 5;

        (BigNumber memory c1_1, BigNumber memory c2_1) = elgamal.encrypt(abi.encodePacked(m1), r1, pk);
        (BigNumber memory c1_2, BigNumber memory c2_2) = elgamal.encrypt(abi.encodePacked(m2), r2, pk);
        (BigNumber memory newC1, BigNumber memory newC2) =
            elgamal.homomorphicAddition(Ciphertext(c1_1.val, c2_1.val), Ciphertext(c1_2.val, c2_2.val), pk);

        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));

        assertEq(newC1.val, BigNum.modmul(c1_1, c1_2, bn_p).val, "newC1 mismatch");
        assertEq(newC2.val, BigNum.modmul(c2_1, c2_2, bn_p).val, "newC2 mismatch");
    }

    function testHomomorphicAdditionLargePrime() public {
        PublicKey memory pk = PublicKey(largePrime, g, hLarge);
        bytes memory r1 = abi.encodePacked(uint256(12345678901234567890));
        bytes memory r2 = abi.encodePacked(uint256(98765432109876543210));
        uint256 m1 = 42;
        uint256 m2 = 17;

        (BigNumber memory c1_1, BigNumber memory c2_1) = elgamal.encrypt(abi.encodePacked(m1), r1, pk);
        (BigNumber memory c1_2, BigNumber memory c2_2) = elgamal.encrypt(abi.encodePacked(m2), r2, pk);
        (BigNumber memory newC1, BigNumber memory newC2) =
            elgamal.homomorphicAddition(Ciphertext(c1_1.val, c2_1.val), Ciphertext(c1_2.val, c2_2.val), pk);

        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));
        BigNumber memory expectedNewC1 = BigNum.modmul(c1_1, c1_2, bn_p);
        BigNumber memory expectedNewC2 = BigNum.modmul(c2_1, c2_2, bn_p);

        assertEq(newC1.val, expectedNewC1.val, "newC1 mismatch");
        assertEq(newC2.val, expectedNewC2.val, "newC2 mismatch");
    }

    function testHomomorphicSubtractionSmallPrime() public {
        PublicKey memory pk = PublicKey(smallPrime, g, hSmall);
        bytes memory r1 = abi.encodePacked(uint256(3));
        bytes memory r2 = abi.encodePacked(uint256(4));
        uint256 m1 = 7;
        uint256 m2 = 3;

        (BigNumber memory c1_1, BigNumber memory c2_1) = elgamal.encrypt(abi.encodePacked(m1), r1, pk);
        (BigNumber memory c1_2, BigNumber memory c2_2) = elgamal.encrypt(abi.encodePacked(m2), r2, pk);
        (BigNumber memory newC1, BigNumber memory newC2) =
            elgamal.homomorphicSubtraction(Ciphertext(c1_1.val, c2_1.val), Ciphertext(c1_2.val, c2_2.val), pk);

        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));
        BigNumber memory invC1 = BigNum.modexp(c1_2, BigNum.sub(bn_p, BigNum.one()), bn_p);
        BigNumber memory invC2 = BigNum.modexp(c2_2, BigNum.sub(bn_p, BigNum.one()), bn_p);
        BigNumber memory expectedNewC1 = BigNum.modmul(c1_1, invC1, bn_p);
        BigNumber memory expectedNewC2 = BigNum.modmul(c2_1, invC2, bn_p);

        assertEq(newC1.val, expectedNewC1.val, "newC1 mismatch");
        assertEq(newC2.val, expectedNewC2.val, "newC2 mismatch");
    }

    function testHomomorphicSubtractionLargePrime() public {
        PublicKey memory pk = PublicKey(largePrime, g, hLarge);
        bytes memory r1 = abi.encodePacked(uint256(12345678901234567890));
        bytes memory r2 = abi.encodePacked(uint256(98765432109876543210));
        uint256 m1 = 42;
        uint256 m2 = 17;

        (BigNumber memory c1_1, BigNumber memory c2_1) = elgamal.encrypt(abi.encodePacked(m1), r1, pk);
        (BigNumber memory c1_2, BigNumber memory c2_2) = elgamal.encrypt(abi.encodePacked(m2), r2, pk);
        (BigNumber memory newC1, BigNumber memory newC2) =
            elgamal.homomorphicSubtraction(Ciphertext(c1_1.val, c2_1.val), Ciphertext(c1_2.val, c2_2.val), pk);

        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));
        BigNumber memory invC1 = BigNum.modexp(c1_2, BigNum.sub(bn_p, BigNum.one()), bn_p);
        BigNumber memory invC2 = BigNum.modexp(c2_2, BigNum.sub(bn_p, BigNum.one()), bn_p);
        BigNumber memory expectedNewC1 = BigNum.modmul(c1_1, invC1, bn_p);
        BigNumber memory expectedNewC2 = BigNum.modmul(c2_1, invC2, bn_p);

        assertEq(newC1.val, expectedNewC1.val, "newC1 mismatch");
        assertEq(newC2.val, expectedNewC2.val, "newC2 mismatch");
    }
}
