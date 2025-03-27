// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import 'forge-std/Test.sol';
import '../src/ElGamalMultiplicative.sol';
import '../src/BigNum.sol';

contract ElGamalMultiplicativeTest is Test {
    ElGamalMultiplicative public elgamal;
    bytes public smallPrime = abi.encodePacked(uint256(23));
    bytes public largePrime =
        abi.encodePacked(uint256(2 ** 256 - 2 ** 32 - 977)); // Example 256-bit prime
    bytes public g = abi.encodePacked(uint256(2)); // Generator
    bytes public x = abi.encodePacked(uint256(5)); // Private key
    bytes public h; // Public key h = g^x mod p

    function setUp() public {
        elgamal = new ElGamalMultiplicative();
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
        bytes memory r = abi.encodePacked(uint256(3));
        uint256 m = 4;
        (BigNumber memory c1, BigNumber memory c2) = elgamal.encrypt(
            abi.encodePacked(uint256(m)),
            r,
            pk
        );

        // For p=23, g=2, x=5, h=9, r=3:
        // c1 = g^r mod p = 2^3 mod 23 = 8
        // c2 = h^r * m mod p = 9^3 * 4 mod 23 = 18
        assertEq(uint256(bytes32(c1.val)), 8, 'c1 should be g^r mod p');
        assertEq(uint256(bytes32(c2.val)), 18, 'c2 should be h^r * m mod p');
    }

    // Test homomorphic multiplication with small prime
    function testHomomorphicMultiplicationSmallPrime() public {
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
            .homomorphicMultiplication(
                Ciphertext(c1_1.val, c2_1.val),
                Ciphertext(c1_2.val, c2_2.val),
                pk
            );
        // newC1 = c1_1 * c1_2 mod p, newC2 = c2_1 * c2_2 mod p
        // Decrypt manually: should equal m1 * m2 = 20
    }

    function testHomomorphicDivisionSmallPrime() public {
        // Set up public key with a small prime (p), generator (g), and public key (h)
        PublicKey memory pk = PublicKey(smallPrime, g, h);

        // Randomness for encryption
        bytes memory r1 = abi.encodePacked(uint256(3));
        bytes memory r2 = abi.encodePacked(uint256(4));

        // Plaintexts
        uint256 m1 = 8;
        uint256 m2 = 4; // Must have inverse mod p

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

        // Perform homomorphic division
        (BigNumber memory newC1, BigNumber memory newC2) = elgamal
            .homomorphicDivision(
                Ciphertext(c1_1.val, c2_1.val),
                Ciphertext(c1_2.val, c2_2.val),
                pk
            );
    }

    // Test with large prime
    function testEncryptDecryptLargePrime() public {
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
        // Verify gas usage and correctness with large numbers
    }
}
