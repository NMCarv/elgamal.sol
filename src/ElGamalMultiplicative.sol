// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import './BigNum.sol';

/// @title Ciphertext Struct
/// @notice Represents a multiplicative ElGamal ciphertext with two components (c1, c2)
struct Ciphertext {
    bytes c1; // g^r mod p
    bytes c2; // m * h^r mod p
}

/// @title PublicKey Struct
/// @notice Represents an ElGamal public key
struct PublicKey {
    bytes p; // Prime modulus
    bytes g; // Generator
    bytes h; // Public key (g^x mod p)
}

/// @title ElGamal Multiplicative Cryptosystem Implementation
/// @notice Provides homomorphic operations for multiplicative ElGamal
/// @dev Uses BigNum library for large number operations
contract ElGamalMultiplicative {
    using BigNum for *;

    /// @notice Event emitted after a homomorphic operation
    /// @param c1 The first component of the resulting ciphertext
    /// @param c2 The second component of the resulting ciphertext
    event OperationResult(bytes c1, bytes c2);

    /// @notice Multiplies two encrypted values homomorphically
    /// @dev For multiplicative ElGamal: (c1, c2) * (c1', c2') = (c1 * c1' mod p, c2 * c2' mod p)
    /// @param ct1 First ciphertext
    /// @param ct2 Second ciphertext
    /// @param pk Public key
    /// @return newC1 The first component of the resulting ciphertext
    /// @return newC2 The second component of the resulting ciphertext
    function homomorphicMultiplication(
        Ciphertext calldata ct1,
        Ciphertext calldata ct2,
        PublicKey calldata pk
    ) external view returns (BigNumber memory newC1, BigNumber memory newC2) {
        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));

        newC1 = BigNum.modmul(
            BigNumber(ct1.c1, false, BigNum.bitLength(ct1.c1)),
            BigNumber(ct2.c1, false, BigNum.bitLength(ct2.c1)),
            bn_p
        );
        newC2 = BigNum.modmul(
            BigNumber(ct1.c2, false, BigNum.bitLength(ct1.c2)),
            BigNumber(ct2.c2, false, BigNum.bitLength(ct2.c2)),
            bn_p
        );
    }

    /// @notice Divides one encrypted value by another homomorphically
    /// @param ct1 Numerator ciphertext (c1, c2)
    /// @param ct2 Denominator ciphertext (c1', c2')
    /// @param pk Public key (p, g, h)
    /// @return newC1 The first component of the resulting ciphertext
    /// @return newC2 The second component of the resulting ciphertext
    function homomorphicDivision(
        Ciphertext calldata ct1,
        Ciphertext calldata ct2,
        PublicKey calldata pk
    ) external view returns (BigNumber memory newC1, BigNumber memory newC2) {
        require(
            !BigNum.isZero(BigNumber(ct2.c1, false, BigNum.bitLength(ct2.c1))),
            'Cannot divide by zero ciphertext c1'
        );
        require(
            !BigNum.isZero(BigNumber(ct2.c2, false, BigNum.bitLength(ct2.c2))),
            'Cannot divide by zero ciphertext c2'
        );

        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));
        BigNumber memory bn_2 = BigNumber(
            abi.encodePacked(uint256(2)),
            false,
            BigNum.bitLength(abi.encodePacked(uint256(2)))
        );

        // Compute inverse of ct2.c1: (c1')^{p-2} mod p
        BigNumber memory invC1 = BigNum.modexp(
            BigNumber(ct2.c1, false, BigNum.bitLength(ct2.c1)),
            BigNum.sub(bn_p, bn_2),
            bn_p
        );

        // Compute inverse of ct2.c2: (c2')^{p-2} mod p
        BigNumber memory invC2 = BigNum.modexp(
            BigNumber(ct2.c2, false, BigNum.bitLength(ct2.c2)),
            BigNum.sub(bn_p, bn_2),
            bn_p
        );

        // Compute newC1 = c1 * (c1')^{-1} mod p
        newC1 = BigNum.modmul(
            BigNumber(ct1.c1, false, BigNum.bitLength(ct1.c1)),
            invC1,
            bn_p
        );

        // Compute newC2 = c2 * (c2')^{-1} mod p
        newC2 = BigNum.modmul(
            BigNumber(ct1.c2, false, BigNum.bitLength(ct1.c2)),
            invC2,
            bn_p
        );
    }

    /// @notice Encrypts a plaintext value using the public key
    /// @dev Computes c1 = g^r mod p, c2 = m * h^r mod p
    /// @param m Plaintext value to encrypt
    /// @param r Randomness as bytes
    /// @param pk Public key
    /// @return c1 The first component of the encrypted ciphertext
    /// @return c2 The second component of the encrypted ciphertext
    function encrypt(
        bytes memory m,
        bytes memory r,
        PublicKey calldata pk
    ) external view returns (BigNumber memory c1, BigNumber memory c2) {
        BigNumber memory bn_r = BigNumber(r, false, BigNum.bitLength(r));
        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));

        // c1 = g^r mod p
        c1 = BigNum.modexp(
            BigNumber(pk.g, false, BigNum.bitLength(pk.g)),
            bn_r,
            bn_p
        );

        // c2 = m * h^r mod p
        BigNumber memory h_r = BigNum.modexp(
            BigNumber(pk.h, false, BigNum.bitLength(pk.h)),
            bn_r,
            bn_p
        );
        c2 = BigNum.modmul(BigNumber(m, false, BigNum.bitLength(m)), h_r, bn_p);
    }

    /// @notice Decrypts a ciphertext using the private key x.
    /// @dev Only works correctly for small primes where all numbers fit in 256 bits.
    /// @param ct The ciphertext to decrypt.
    /// @param x The private key as bytes.
    /// @param pk The public key.
    /// @return m The decrypted plaintext as a BigNumber.
    function decrypt(
        Ciphertext calldata ct,
        bytes calldata x,
        PublicKey calldata pk
    ) external view returns (BigNumber memory m) {
        // Prepare modulus and private key as BigNumber.
        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));
        BigNumber memory bn_x = BigNum.init(x, false);

        // Compute h_r = (c1)^x mod p.
        BigNumber memory h_r = BigNum.modexp(
            BigNumber(ct.c1, false, BigNum.bitLength(ct.c1)),
            bn_x,
            bn_p
        );
        // Compute inverse of h_r using Fermat's little theorem (since p is prime):
        // h_r^{-1} = h_r^(p-2) mod p.
        BigNumber memory inv_h_r = BigNum.modexp(
            h_r,
            BigNum.sub(bn_p, BigNum.two()),
            bn_p
        );
        // Then, m = c2 * inv_h_r mod p.
        m = BigNum.modmul(
            BigNumber(ct.c2, false, BigNum.bitLength(ct.c2)),
            inv_h_r,
            bn_p
        );
    }
}
