// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev A point on the elliptic curve
struct ECPoint {
    uint256 x;
    uint256 y;
}

/// @dev The ciphertext is a pair of EC points: (C1, C2)
struct Ciphertext {
    ECPoint c1;
    ECPoint c2;
}

/// @dev The public key consists of a single EC point Q = x*G.
struct PublicKey {
    ECPoint Q;
}

/// @title Elliptic Curve ElGamal on BN256 using precompiles
/// @notice Supports encryption, decryption, homomorphic addition, and subtraction
contract ECCElGamal {
    // BN256 curve field prime
    uint256 private immutable FIELD_MODULUS =
        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    /// @notice Performs elliptic curve point addition using the BN256 precompile (address 0x06)
    /// @param p1 The first EC point
    /// @param p2 The second EC point
    /// @return r The resulting EC point (p1 + p2)
    function ecAdd(
        ECPoint memory p1,
        ECPoint memory p2
    ) internal view returns (ECPoint memory r) {
        uint256[4] memory input;
        input[0] = p1.x;
        input[1] = p1.y;
        input[2] = p2.x;
        input[3] = p2.y;
        uint256[2] memory output;
        bool success;
        assembly {
            // BN256 addition precompile at address 0x06; input size 128 bytes, output size 64 bytes
            success := staticcall(gas(), 0x06, input, 0x80, output, 0x40)
        }
        require(success, 'EC addition failed');
        r.x = output[0];
        r.y = output[1];
    }

    /// @notice Performs elliptic curve scalar multiplication using the BN256 precompile (address 0x07)
    /// @param p The EC point to multiply
    /// @param scalar The scalar multiplier
    /// @return r The resulting EC point (scalar * p)
    function ecMul(
        ECPoint memory p,
        uint256 scalar
    ) internal view returns (ECPoint memory r) {
        uint256[3] memory input;
        input[0] = p.x;
        input[1] = p.y;
        input[2] = scalar;
        uint256[2] memory output;
        bool success;
        assembly {
            // BN256 scalar multiplication precompile at address 0x07; input size 96 bytes, output size 64 bytes
            success := staticcall(gas(), 0x07, input, 0x60, output, 0x40)
        }
        require(success, 'EC scalar multiplication failed');
        r.x = output[0];
        r.y = output[1];
    }

    /// @notice Returns the negation of an EC point. For a point (x, y), the negative is (x, p - y).
    /// @param p The point to negate
    /// @return r The negated point
    function ecNeg(ECPoint memory p) internal pure returns (ECPoint memory r) {
        r.x = p.x;
        if (p.y == 0) {
            r.y = 0;
        } else {
            r.y = FIELD_MODULUS - p.y;
        }
    }

    /// @notice Homomorphically adds two ciphertexts.
    /// @dev (C1, C2) + (C1', C2') = (C1 + C1', C2 + C2')
    /// @param ct1 First ciphertext
    /// @param ct2 Second ciphertext
    /// @return result The resulting ciphertext after addition
    function homomorphicAddition(
        Ciphertext calldata ct1,
        Ciphertext calldata ct2
    ) public view returns (Ciphertext memory result) {
        result.c1 = ecAdd(ct1.c1, ct2.c1);
        result.c2 = ecAdd(ct1.c2, ct2.c2);
    }

    /// @notice Homomorphically subtracts one ciphertext from another.
    /// @dev (C1, C2) - (C1', C2') = (C1 + (-C1'), C2 + (-C2'))
    /// @param ct1 First ciphertext (minuend)
    /// @param ct2 Second ciphertext (subtrahend)
    /// @return result The resulting ciphertext after subtraction
    function homomorphicSubtraction(
        Ciphertext calldata ct1,
        Ciphertext calldata ct2
    ) public view returns (Ciphertext memory result) {
        ECPoint memory negC1 = ecNeg(ct2.c1);
        ECPoint memory negC2 = ecNeg(ct2.c2);
        result.c1 = ecAdd(ct1.c1, negC1);
        result.c2 = ecAdd(ct1.c2, negC2);
    }

    /// @notice Homomorphically adds a scalar to the ciphertext.
    /// @dev Assumes the plaintext is encoded as M = m * G.
    ///      The operation is: C2' = C2 + (k * G), leaving C1 unchanged.
    /// @param ct The original ciphertext.
    /// @param k The scalar to add.
    /// @return result The resulting ciphertext after scalar addition.
    function scalarAddition(
        Ciphertext calldata ct,
        uint256 k
    ) public view returns (Ciphertext memory result) {
        // BN256 generator G = (1,2)
        ECPoint memory G = ECPoint(1, 2);
        ECPoint memory kG = ecMul(G, k);
        result.c1 = ct.c1; // C1 remains the same
        result.c2 = ecAdd(ct.c2, kG); // C2 + k*G
    }

    /// @notice Homomorphically subtracts a scalar from the ciphertext.
    /// @dev Assumes the plaintext is encoded as M = m * G.
    ///      The operation is: C2' = C2 - (k * G), leaving C1 unchanged.
    /// @param ct The original ciphertext.
    /// @param k The scalar to subtract.
    /// @return result The resulting ciphertext after scalar subtraction.
    function scalarSubtraction(
        Ciphertext calldata ct,
        uint256 k
    ) public view returns (Ciphertext memory result) {
        // BN256 generator G = (1,2)
        ECPoint memory G = ECPoint(1, 2);
        ECPoint memory kG = ecMul(G, k);
        result.c1 = ct.c1; // C1 remains the same
        result.c2 = ecAdd(ct.c2, ecNeg(kG)); // C2 - k*G
    }

    /// @notice Encrypts a plaintext EC point using the public key and randomness.
    /// @dev Encryption: C1 = r * G, C2 = M + r * Q, where G is the generator.
    /// @param M The plaintext message (as an EC point)
    /// @param r The random scalar (ensure it is uniformly random and secret)
    /// @param pk The public key (with Q = x * G)
    /// @return ct The resulting ciphertext
    function encrypt(
        ECPoint calldata M,
        uint256 r,
        PublicKey calldata pk
    ) public view returns (Ciphertext memory ct) {
        // The generator for BN256 is (1,2)
        ECPoint memory G = ECPoint(1, 2);
        ct.c1 = ecMul(G, r); // C1 = r * G
        ECPoint memory rQ = ecMul(pk.Q, r); // r * Q
        ct.c2 = ecAdd(M, rQ); // C2 = M + r * Q
    }

    /// @notice Decrypts a ciphertext using the private key.
    /// @dev Decryption: M = C2 - x * C1
    /// @param ct The ciphertext to decrypt
    /// @param x The private key
    /// @return M The decrypted EC point representing the plaintext
    function decrypt(
        Ciphertext calldata ct,
        uint256 x
    ) public view returns (ECPoint memory M) {
        ECPoint memory xC1 = ecMul(ct.c1, x); // x * C1
        ECPoint memory neg_xC1 = ecNeg(xC1); // -(x * C1)
        M = ecAdd(ct.c2, neg_xC1); // M = C2 - x * C1
    }
}
