// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BigNum.sol";

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

    /// @notice Adds two encrypted values homomorphically
    /// @dev For additive ElGamal: (c1, c2) + (c1', c2') = (c1 * c1' mod p, c2 * c2' mod p)
    /// @param ct1 First ciphertext
    /// @param ct2 Second ciphertext
    /// @param pk Public key
    /// @return newC1 The resulting ciphertext first component
    /// @return newC2 The resulting ciphertext second component
    function homomorphicAddition(Ciphertext calldata ct1, Ciphertext calldata ct2, PublicKey calldata pk)
        external
        view
        returns (BigNumber memory newC1, BigNumber memory newC2)
    {
        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));

        newC1 = BigNum.modmul(
            BigNumber(ct1.c1, false, BigNum.bitLength(ct1.c1)), BigNumber(ct2.c1, false, BigNum.bitLength(ct2.c1)), bn_p
        );
        newC2 = BigNum.modmul(
            BigNumber(ct1.c2, false, BigNum.bitLength(ct1.c2)), BigNumber(ct2.c2, false, BigNum.bitLength(ct2.c2)), bn_p
        );
    }

    /// @notice Subtracts one encrypted value from another homomorphically
    /// @dev For additive ElGamal: (c1, c2) - (c1', c2') = (c1 / c1' mod p, c2 / c2' mod p)
    /// @param ct1 First ciphertext (minuend)
    /// @param ct2 Second ciphertext (subtrahend)
    /// @param pk Public key
    /// @return newC1 The resulting ciphertext first component
    /// @return newC2 The resulting ciphertext second component
    function homomorphicSubtraction(Ciphertext calldata ct1, Ciphertext calldata ct2, PublicKey calldata pk)
        external
        view
        returns (BigNumber memory newC1, BigNumber memory newC2)
    {
        require(
            !BigNum.isZero(BigNumber(ct2.c1, false, BigNum.bitLength(ct2.c1))), "Cannot subtract zero ciphertext c1"
        );
        require(
            !BigNum.isZero(BigNumber(ct2.c2, false, BigNum.bitLength(ct2.c2))), "Cannot subtract zero ciphertext c2"
        );

        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));

        // Compute inverse of ct2.c1 and ct2.c2 modulo p
        BigNumber memory invC1 =
            BigNum.modexp(BigNumber(ct2.c1, false, BigNum.bitLength(ct2.c1)), BigNum.sub(bn_p, BigNum.one()), bn_p);
        BigNumber memory invC2 =
            BigNum.modexp(BigNumber(ct2.c2, false, BigNum.bitLength(ct2.c2)), BigNum.sub(bn_p, BigNum.one()), bn_p);

        // Compute newC1 = c1 * invC1' mod p
        newC1 = BigNum.modmul(BigNumber(ct1.c1, false, BigNum.bitLength(ct1.c1)), invC1, bn_p);

        // Compute newC2 = c2 * invC2' mod p
        newC2 = BigNum.modmul(BigNumber(ct1.c2, false, BigNum.bitLength(ct1.c2)), invC2, bn_p);
    }

    /// @notice Multiplies an encrypted value by a scalar
    /// @dev For additive ElGamal: k * (c1, c2) = (c1^k mod p, c2^k mod p)
    /// @param ct Ciphertext to scale
    /// @param k Scalar multiplier (as bytes)
    /// @param pk Public key
    /// @return newC1 The resulting ciphertext first component
    /// @return newC2 The resulting ciphertext second component
    function scalarMultiply(Ciphertext calldata ct, bytes memory k, PublicKey calldata pk)
        external
        view
        returns (BigNumber memory newC1, BigNumber memory newC2)
    {
        BigNumber memory bn_k = BigNum.init(k, false);
        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));

        // Compute newC1 = c1^k mod p
        newC1 = BigNum.modexp(BigNumber(ct.c1, false, BigNum.bitLength(ct.c1)), bn_k, bn_p);

        // Compute newC2 = c2^k mod p
        newC2 = BigNum.modexp(BigNumber(ct.c2, false, BigNum.bitLength(ct.c2)), bn_k, bn_p);
    }

    /// @notice Divides an encrypted value by a scalar (approximate)
    /// @dev Computes ct^{1/k} which requires k^{-1} mod (p-1)
    /// @param ct Ciphertext to divide
    /// @param k Scalar divisor (as bytes)
    /// @param pk Public key
    /// @return newC1 The resulting ciphertext first component
    /// @return newC2 The resulting ciphertext second component
    function scalarDivide(Ciphertext calldata ct, bytes memory k, PublicKey calldata pk)
        external
        view
        returns (BigNumber memory newC1, BigNumber memory newC2)
    {
        BigNumber memory bn_k = BigNum.init(k, false);
        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));

        // Compute k^{-1} mod (p-1)
        BigNumber memory p_minus_one = BigNum.sub(bn_p, BigNum.one());

        // Ensure divisor is coprime with (p-1)
        require(gcd(bn_k, p_minus_one).eq(BigNum.one()), "k must be coprime with p-1");

        BigNumber memory inv_k = BigNum.modexp(bn_k, BigNum.sub(p_minus_one, BigNum.one()), p_minus_one);

        // Compute newC1 = c1^{inv_k} mod p
        newC1 = BigNum.modexp(BigNumber(ct.c1, false, BigNum.bitLength(ct.c1)), inv_k, bn_p);

        // Compute newC2 = c2^{inv_k} mod p
        newC2 = BigNum.modexp(BigNumber(ct.c2, false, BigNum.bitLength(ct.c2)), inv_k, bn_p);
    }

    /// @notice Encrypts a plaintext value using the public key
    /// @dev Computes c1 = g^r mod p, c2 = g^m * h^r mod p
    /// @param m Plaintext value to encrypt
    /// @param r Randomness as bytes
    /// @param pk Public key
    /// @return c1 The encrypted ciphertext first component
    /// @return c2 The encrypted ciphertext second component
    function encrypt(bytes memory m, bytes memory r, PublicKey calldata pk)
        external
        view
        returns (BigNumber memory c1, BigNumber memory c2)
    {
        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));

        BigNumber memory bn_r = BigNumber(r, false, BigNum.bitLength(r));
        BigNumber memory bn_m = BigNumber(m, false, BigNum.bitLength(m));

        // c1 = g^r mod p
        c1 = BigNum.modexp(BigNumber(pk.g, false, BigNum.bitLength(pk.g)), bn_r, bn_p);

        // c2 = g^m * h^r mod p
        BigNumber memory g_m = BigNum.modexp(BigNumber(pk.g, false, BigNum.bitLength(pk.g)), bn_m, bn_p);
        BigNumber memory h_r = BigNum.modexp(BigNumber(pk.h, false, BigNum.bitLength(pk.h)), bn_r, bn_p);
        c2 = BigNum.modmul(g_m, h_r, bn_p);
    }

    /// @notice Decrypts a ciphertext using the private key x.
    /// @dev This implementation uses a brute-force discrete log search and is only suitable for small primes.
    /// @param ct The ciphertext to decrypt.
    /// @param x The private key as bytes.
    /// @param pk The public key.
    /// @return m The decrypted plaintext as a uint256.
    function decrypt(Ciphertext calldata ct, bytes calldata x, PublicKey calldata pk)
        external
        view
        returns (uint256 m)
    {
        // Prepare modulus and private key as BigNumber.
        BigNumber memory bn_p = BigNumber(pk.p, false, BigNum.bitLength(pk.p));
        BigNumber memory bn_x = BigNum.init(x, false);

        // Compute h_r = (c1)^x mod p.
        BigNumber memory h_r = BigNum.modexp(BigNumber(ct.c1, false, BigNum.bitLength(ct.c1)), bn_x, bn_p);
        // Compute the inverse of h_r: inv_h_r = h_r^(p-2) mod p.
        BigNumber memory inv_h_r = BigNum.modexp(h_r, BigNum.sub(bn_p, BigNum.two()), bn_p);
        // Compute g^m = c2 * inv_h_r mod p.
        BigNumber memory g_m = BigNum.modmul(BigNumber(ct.c2, false, BigNum.bitLength(ct.c2)), inv_h_r, bn_p);

        // For small primes, we can solve the discrete log by brute force.
        uint256 p_val = uint256(bytes32(bn_p.val));

        // Get the generator g as a uint256.
        BigNumber memory bn_g = BigNumber(pk.g, false, BigNum.bitLength(pk.g));
        uint256 g_val = uint256(bytes32(bn_g.val));
        uint256 target = uint256(bytes32(g_m.val));

        // Try all exponents from 0 up to p_val-1.
        for (uint256 i = 0; i < p_val; i++) {
            if (modExp(g_val, i, p_val) == target) {
                return i;
            }
        }
        revert("Discrete log not found");
    }

    /// @notice Helper function to compute (base^exponent) mod modulus for uint256 numbers.
    function modExp(uint256 base, uint256 exponent, uint256 modulus) internal pure returns (uint256 result) {
        result = 1;
        base = base % modulus;
        while (exponent > 0) {
            if (exponent & 1 == 1) {
                result = mulmod(result, base, modulus);
            }
            exponent = exponent >> 1;
            base = mulmod(base, base, modulus);
        }
    }

    /// @notice Helper function to compute the greatest common divisor of two BigNumbers.
    function gcd(BigNumber memory a, BigNumber memory b) internal view returns (BigNumber memory) {
        while (!b.isZero()) {
            BigNumber memory temp = b;
            b = BigNum.mod(a, b);
            a = temp;
        }
        return a;
    }
}
