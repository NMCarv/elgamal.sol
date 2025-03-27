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

/// @title ElGamal Additive Homomorphic Encryption
/// @dev Supports additive homomorphism with scalar multiplication/division
contract ElGamalAdditive {
    using BigNum for *;

    /// @notice Encrypts a plaintext value using the public key
    /// @dev Computes c1 = g^r mod p, c2 = g^m * h^r mod p
    /// @param m Plaintext value to encrypt
    /// @param r Randomness as bytes
    /// @param pk Public key
    /// @return c1 The encrypted ciphertext first component
    /// @return c2 The encrypted ciphertext second component
    function encrypt(
        uint256 m,
        bytes memory r,
        PublicKey calldata pk
    ) external view returns (BigNumber memory c1, BigNumber memory c2) {
        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));

        BigNumber memory bn_r = BigNumber(r, false, BigNum.bitLength(r));
        BigNumber memory bn_m = BigNumber(
            abi.encodePacked(m),
            false,
            BigNum.bitLength(m)
        );

        // c1 = g^r mod p
        c1 = BigNum.modexp(
            BigNumber(pk.g, false, BigNum.bitLength(pk.g)),
            bn_r,
            bn_p
        );

        // c2 = g^m * h^r mod p
        BigNumber memory g_m = BigNum.modexp(
            BigNumber(pk.g, false, BigNum.bitLength(pk.g)),
            bn_m,
            bn_p
        );
        BigNumber memory h_r = BigNum.modexp(
            BigNumber(pk.h, false, BigNum.bitLength(pk.h)),
            bn_r,
            bn_p
        );
        c2 = BigNum.modmul(g_m, h_r, bn_p);
    }

    /// @notice Adds two encrypted values homomorphically
    /// @dev For additive ElGamal: (c1, c2) + (c1', c2') = (c1 * c1' mod p, c2 * c2' mod p)
    /// @param ct1 First ciphertext
    /// @param ct2 Second ciphertext
    /// @param pk Public key
    /// @return newC1 The resulting ciphertext first component
    /// @return newC2 The resulting ciphertext second component
    function homomorphicAddition(
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

    /// @notice Subtracts one encrypted value from another homomorphically
    /// @dev For additive ElGamal: (c1, c2) - (c1', c2') = (c1 / c1' mod p, c2 / c2' mod p)
    /// @param ct1 First ciphertext (minuend)
    /// @param ct2 Second ciphertext (subtrahend)
    /// @param pk Public key
    /// @return newC1 The resulting ciphertext first component
    /// @return newC2 The resulting ciphertext second component
    function homomorphicSubtraction(
        Ciphertext calldata ct1,
        Ciphertext calldata ct2,
        PublicKey calldata pk
    ) external view returns (BigNumber memory newC1, BigNumber memory newC2) {
        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));

        // Compute inverse of ct2.c1 and ct2.c2 modulo p
        BigNumber memory invC1 = BigNum.modexp(
            BigNumber(ct2.c1, false, BigNum.bitLength(ct2.c1)),
            BigNum.sub(bn_p, BigNum.one()),
            bn_p
        );
        BigNumber memory invC2 = BigNum.modexp(
            BigNumber(ct2.c2, false, BigNum.bitLength(ct2.c2)),
            BigNum.sub(bn_p, BigNum.one()),
            bn_p
        );

        // Compute newC1 = c1 * invC1' mod p
        newC1 = BigNum.modmul(
            BigNumber(ct1.c1, false, BigNum.bitLength(ct1.c1)),
            invC1,
            bn_p
        );

        // Compute newC2 = c2 * invC2' mod p
        newC2 = BigNum.modmul(
            BigNumber(ct1.c2, false, BigNum.bitLength(ct1.c2)),
            invC2,
            bn_p
        );
    }

    /// @notice Multiplies an encrypted value by a scalar
    /// @dev For additive ElGamal: k * (c1, c2) = (c1^k mod p, c2^k mod p)
    /// @param ct Ciphertext to scale
    /// @param k Scalar multiplier (as bytes)
    /// @param pk Public key
    /// @return newC1 The resulting ciphertext first component
    /// @return newC2 The resulting ciphertext second component
    function scalarMultiply(
        Ciphertext calldata ct,
        bytes memory k,
        PublicKey calldata pk
    ) external view returns (BigNumber memory newC1, BigNumber memory newC2) {
        BigNumber memory bn_k = BigNum.init(k, false);

        // Compute newC1 = c1^k mod p
        newC1 = BigNum.modexp(
            BigNumber(ct.c1, false, BigNum.bitLength(ct.c1)),
            bn_k,
            BigNumber(pk.p, false, BigNum.bitLength(pk.p))
        );

        // Compute newC2 = c2^k mod p
        newC2 = BigNum.modexp(
            BigNumber(ct.c2, false, BigNum.bitLength(ct.c2)),
            bn_k,
            BigNumber(pk.p, false, BigNum.bitLength(pk.p))
        );
    }

    /// @notice Divides an encrypted value by a scalar (approximate)
    /// @dev Computes ct^{1/k} which requires k^{-1} mod (p-1)
    /// @param ct Ciphertext to divide
    /// @param k Scalar divisor (as bytes)
    /// @param pk Public key
    /// @return newC1 The resulting ciphertext first component
    /// @return newC2 The resulting ciphertext second component
    function scalarDivide(
        Ciphertext calldata ct,
        bytes memory k,
        PublicKey calldata pk
    ) external view returns (BigNumber memory newC1, BigNumber memory newC2) {
        BigNumber memory bn_k = BigNum.init(k, false);

        // Compute k^{-1} mod (p-1)
        BigNumber memory p_minus_one = BigNum.sub(
            BigNumber(pk.p, false, BigNum.bitLength(pk.p)),
            BigNum.one()
        );
        BigNumber memory inv_k = BigNum.modexp(
            bn_k,
            BigNum.sub(p_minus_one, BigNum.one()),
            p_minus_one
        );

        // Compute newC1 = c1^{inv_k} mod p
        newC1 = BigNum.modexp(
            BigNumber(ct.c1, false, BigNum.bitLength(ct.c1)),
            inv_k,
            BigNumber(pk.p, false, BigNum.bitLength(pk.p))
        );

        // Compute newC2 = c2^{inv_k} mod p
        newC2 = BigNum.modexp(
            BigNumber(ct.c2, false, BigNum.bitLength(ct.c2)),
            inv_k,
            BigNumber(pk.p, false, BigNum.bitLength(pk.p))
        );
    }
}
