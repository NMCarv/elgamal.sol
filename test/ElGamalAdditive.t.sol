// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import 'forge-std/Test.sol';
import '../src/ElGamalAdditive.sol';
import '../src/BigNum.sol';

contract ElGamalAdditiveTest is Test {
    ElGamalAdditive public elgamal;
    bytes public smallPrime = abi.encodePacked(uint256(23));
    bytes public largePrime =
        abi.encodePacked(uint256(2 ** 256 - 2 ** 32 - 977)); // Example 256-bit prime
    bytes public g = abi.encodePacked(uint256(2)); // Generator
    bytes public x = abi.encodePacked(uint256(5)); // Private key
    bytes public h; // Public key h = g^x mod p

    function setUp() public {
        elgamal = new ElGamalAdditive();
        // Compute h = g^x mod p for small prime
        BigNumber memory bn_g = BigNumber(g, false, BigNum.bitLength(g));
        BigNumber memory bn_x = BigNumber(x, false, BigNum.bitLength(x));
        BigNumber memory bn_p = BigNumber(
            smallPrime,
            false,
            BigNum.bitLength(smallPrime)
        );
        h = BigNum.modexp(bn_g, bn_x, bn_p).val;
    }

    // Test encryption and decryption with small prime
    function testEncryptDecryptSmallPrime() public {
        PublicKey memory pk = PublicKey(smallPrime, g, h);
        bytes memory r = abi.encodePacked(uint256(3)); // Randomness
        uint256 m = 4;
        (BigNumber memory c1, BigNumber memory c2) = elgamal.encrypt(
            abi.encodePacked(uint256(m)),
            r,
            pk
        );

        // Since decryption is typically off-chain, we’d verify manually or mock it.
        // For small prime 23, g=2, x=5, h=2^5 mod 23 = 9, r=3:
        // c1 = g^r mod p = 2^3 mod 23 = 8
        // c2 = g^m * h^r mod p = 2^4 * 9^3 mod 23 = 16 * 729 mod 23 = 3
        assertEq(uint256(bytes32(c1.val)), 8, 'c1 should be g^r mod p');
        assertEq(uint256(bytes32(c2.val)), 3, 'c2 should be g^m * h^r mod p');
    }

    // Test homomorphic addition with small prime
    function testHomomorphicAdditionSmallPrime() public {
        PublicKey memory pk = PublicKey(smallPrime, g, h);
        bytes memory r1 = abi.encodePacked(uint256(3));
        bytes memory r2 = abi.encodePacked(uint256(4));
        uint256 m1 = 4;
        uint256 m2 = 5;

        (BigNumber memory c1_1, BigNumber memory c2_1) = elgamal.encrypt(
            abi.encodePacked(uint256(m1)),
            r1,
            pk
        );
        (BigNumber memory c1_2, BigNumber memory c2_2) = elgamal.encrypt(
            abi.encodePacked(uint256(m2)),
            r2,
            pk
        );

        (BigNumber memory newC1, BigNumber memory newC2) = elgamal
            .homomorphicAddition(
                Ciphertext(c1_1.val, c2_1.val),
                Ciphertext(c1_2.val, c2_2.val),
                pk
            );

        // newC1 = c1_1 * c1_2 mod p, newC2 = c2_1 * c2_2 mod p
        // Decrypt manually: should equal m1 + m2 = 9
    }

    // Test homomorphic subtraction with small prime
    function testHomomorphicSubtractionSmallPrime() public {
        PublicKey memory pk = PublicKey(smallPrime, g, h);

        // Randomness for encryption
        bytes memory r1 = abi.encodePacked(uint256(3));
        bytes memory r2 = abi.encodePacked(uint256(4));

        // Plaintexts
        uint256 m1 = 7;
        uint256 m2 = 3;

        // Encrypt m1 and m2
        (BigNumber memory c1_1, BigNumber memory c2_1) = elgamal.encrypt(
            abi.encodePacked(uint256(m1)),
            r1,
            pk
        );
        (BigNumber memory c1_2, BigNumber memory c2_2) = elgamal.encrypt(
            abi.encodePacked(uint256(m2)),
            r2,
            pk
        );

        // Perform homomorphic subtraction
        (BigNumber memory newC1, BigNumber memory newC2) = elgamal
            .homomorphicSubtraction(
                Ciphertext(c1_1.val, c2_1.val),
                Ciphertext(c1_2.val, c2_2.val),
                pk
            );
    }

    // Test with large prime
    function testEncryptDecryptLargePrime() public {
        // Recompute h for large prime
        BigNumber memory bn_g = BigNumber(g, false, BigNum.bitLength(g));
        BigNumber memory bn_x = BigNumber(x, false, BigNum.bitLength(x));
        BigNumber memory bn_p = BigNumber(
            largePrime,
            false,
            BigNum.bitLength(largePrime)
        );
        h = BigNum.modexp(bn_g, bn_x, bn_p).val;

        PublicKey memory pk = PublicKey(largePrime, g, h);
        bytes memory r = abi.encodePacked(uint256(3));
        uint256 m = 4;
        (BigNumber memory c1, BigNumber memory c2) = elgamal.encrypt(
            abi.encodePacked(uint256(m)),
            r,
            pk
        );
    }
}
