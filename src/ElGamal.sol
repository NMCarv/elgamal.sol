// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import './BigNum.sol';
using BigNum for BigNumber;

struct ElGamalCiphertext {
    BigNumber c1; // g^r mod p
    BigNumber c2; // (m * h^r) mod p or (g^m * h^r) mod p
}

struct ElGamalPublicKey {
    BigNumber p;
    BigNumber g;
    BigNumber h;
}

struct ElGamalPrivateKey {
    BigNumber x;
}

/// @title ElGamal Cryptosystem Implementation
/// @notice Provides operations for both multiplicative and additive ElGamal encryption.
/// @dev All heavy arithmetic uses BigNum which leverages Ethereum’s precompile for modexp.
contract ElGamal {
    /// @notice Helper: modular exponentiation (base^exponent mod modulus)
    /// @param base The base value as a BigNumber.
    /// @param exponent The exponent as uint256.
    /// @param modulus The prime modulus.
    /// @return The result of (base^exponent) mod modulus.
    function modExp(
        BigNumber memory base,
        uint256 exponent,
        BigNumber memory modulus
    ) internal view returns (BigNumber memory) {
        return BigNum.mod(BigNum.pow(base, exponent), modulus);
    }

    /// @notice Helper: calculates the modular inverse using Fermat's Little Theorem.
    /// @param a The number to invert.
    /// @param modulus The prime modulus.
    /// @return The modular inverse of a mod modulus.
    function calculateModInverse(
        BigNumber memory a,
        BigNumber memory modulus
    ) internal view returns (BigNumber memory) {
        require(!BigNum.isZero(a), 'Cannot invert zero');
        require(BigNum.lt(a, modulus), 'Value must be less than modulus');
        // Using Fermat's Little Theorem: a^(p-2) mod p
        BigNumber memory two = BigNum.two();
        BigNumber memory modMinus2 = BigNum.sub(modulus, two);
        return modExp(a, BigNum.toUint(modMinus2), modulus);
    }

    /// @notice Helper: multiplies a by the modular inverse of b modulo modulus.
    /// @param a The number to multiply.
    /// @param b The number to invert and multiply.
    /// @param modulus The prime modulus.
    /// @return The result of (a * b^(-1)) mod modulus.
    function modInverseAndMultiply(
        BigNumber memory a,
        BigNumber memory b,
        BigNumber memory modulus
    ) internal view returns (BigNumber memory) {
        BigNumber memory inv = calculateModInverse(b, modulus);
        return BigNum.modmul(a, inv, modulus);
    }

    /// @notice Encrypts a message using standard (multiplicative) ElGamal encryption.
    /// @dev Encryption: c1 = g^r mod p, c2 = m * h^r mod p.
    /// @param message The message to encrypt (as a group element).
    /// @param ephemeralKey The random ephemeral key r.
    /// @param publicKey The ElGamal public key.
    /// @return ciphertext The resulting ciphertext.
    function encrypt(
        BigNumber memory message,
        BigNumber memory ephemeralKey,
        ElGamalPublicKey calldata publicKey
    ) public view returns (ElGamalCiphertext memory) {
        require(!BigNum.isZero(publicKey.p), 'Invalid modulus');
        require(!BigNum.isZero(ephemeralKey), 'Invalid ephemeral key');
        require(
            BigNum.lt(ephemeralKey, publicKey.p),
            'Ephemeral key too large'
        );
        require(BigNum.lt(message, publicKey.p), 'Message too large');

        // c1 = g^r mod p
        BigNumber memory c1 = modExp(
            publicKey.g,
            BigNum.toUint(ephemeralKey),
            publicKey.p
        );
        // hr = h^r mod p
        BigNumber memory hr = modExp(
            publicKey.h,
            BigNum.toUint(ephemeralKey),
            publicKey.p
        );
        // c2 = m * hr mod p
        BigNumber memory c2 = BigNum.modmul(message, hr, publicKey.p);

        return ElGamalCiphertext(c1, c2);
    }

    /// @notice Encrypts a message using additive ElGamal encryption (message-in-exponent).
    /// @dev Encryption: c1 = g^r mod p, c2 = g^m * h^r mod p.
    /// @param message The message to encrypt (as a uint256, encoded as g^message).
    /// @param ephemeralKey The random ephemeral key r.
    /// @param publicKey The ElGamal public key.
    /// @return ciphertext The resulting ciphertext.
    function encryptForAddition(
        uint256 message,
        BigNumber memory ephemeralKey,
        ElGamalPublicKey calldata publicKey
    ) public view returns (ElGamalCiphertext memory) {
        // c1 = g^r mod p
        BigNumber memory c1 = modExp(
            publicKey.g,
            BigNum.toUint(ephemeralKey),
            publicKey.p
        );
        // gm = g^m mod p
        BigNumber memory gm = modExp(publicKey.g, message, publicKey.p);
        // hr = h^r mod p
        BigNumber memory hr = modExp(
            publicKey.h,
            BigNum.toUint(ephemeralKey),
            publicKey.p
        );
        // c2 = g^m * h^r mod p
        BigNumber memory c2 = BigNum.modmul(gm, hr, publicKey.p);

        return ElGamalCiphertext(c1, c2);
    }

    /// @notice Performs homomorphic addition of two ciphertexts.
    /// @dev Computes (c1_1 * c1_2 mod p, c2_1 * c2_2 mod p).
    /// @param a First ciphertext.
    /// @param b Second ciphertext.
    /// @param publicKey The ElGamal public key.
    /// @return result The encrypted sum.
    function homomorphicAdd(
        ElGamalCiphertext calldata a,
        ElGamalCiphertext calldata b,
        ElGamalPublicKey calldata publicKey
    ) public view returns (ElGamalCiphertext memory) {
        BigNumber memory newC1 = BigNum.modmul(a.c1, b.c1, publicKey.p);
        BigNumber memory newC2 = BigNum.modmul(a.c2, b.c2, publicKey.p);

        return ElGamalCiphertext(newC1, newC2);
    }

    /// @notice Performs homomorphic subtraction of two ciphertexts.
    /// @dev Computes (c1_1 * inv(c1_2) mod p, c2_1 * inv(c2_2) mod p).
    /// @param a First ciphertext.
    /// @param b Second ciphertext (to be subtracted).
    /// @param publicKey The ElGamal public key.
    /// @return result The encrypted difference.
    function homomorphicSubtract(
        ElGamalCiphertext calldata a,
        ElGamalCiphertext calldata b,
        ElGamalPublicKey calldata publicKey
    ) public view returns (ElGamalCiphertext memory) {
        // Use modInverseAndMultiply to avoid duplicating inversion logic.
        BigNumber memory newC1 = modInverseAndMultiply(a.c1, b.c1, publicKey.p);
        BigNumber memory newC2 = modInverseAndMultiply(a.c2, b.c2, publicKey.p);

        return ElGamalCiphertext(newC1, newC2);
    }

    /// @notice Performs scalar multiplication on a ciphertext.
    /// @dev Computes (c1^scalar mod p, c2^scalar mod p).
    /// @param a The ciphertext.
    /// @param scalar The scalar multiplier.
    /// @param publicKey The ElGamal public key.
    /// @return result The resulting ciphertext.
    function scalarMultiply(
        ElGamalCiphertext calldata a,
        uint256 scalar,
        ElGamalPublicKey calldata publicKey
    ) public view returns (ElGamalCiphertext memory) {
        BigNumber memory newC1 = modExp(a.c1, scalar, publicKey.p);
        BigNumber memory newC2 = modExp(a.c2, scalar, publicKey.p);
        return ElGamalCiphertext(newC1, newC2);
    }

    /// @notice Performs homomorphic multiplication of two ciphertexts.
    /// @dev Computes (c1_1 * c1_2 mod p, c2_1 * c2_2 mod p).
    /// @param a First ciphertext.
    /// @param b Second ciphertext.
    /// @param publicKey The ElGamal public key.
    /// @return result The encrypted product.
    function homomorphicMultiply(
        ElGamalCiphertext calldata a,
        ElGamalCiphertext calldata b,
        ElGamalPublicKey calldata publicKey
    ) public view returns (ElGamalCiphertext memory) {
        BigNumber memory newC1 = BigNum.modmul(a.c1, b.c1, publicKey.p);
        BigNumber memory newC2 = BigNum.modmul(a.c2, b.c2, publicKey.p);
        return ElGamalCiphertext(newC1, newC2);
    }

    /// @notice Performs homomorphic division of two ciphertexts.
    /// @dev Computes a new ciphertext that decrypts to the division of the plaintexts.
    /// @param a Numerator ciphertext.
    /// @param b Denominator ciphertext.
    /// @param publicKey The ElGamal public key.
    /// @return result The encrypted quotient.
    function homomorphicDivide(
        ElGamalCiphertext calldata a,
        ElGamalCiphertext calldata b,
        ElGamalPublicKey calldata publicKey
    ) public view returns (ElGamalCiphertext memory) {
        BigNumber memory newC1 = modInverseAndMultiply(a.c1, b.c1, publicKey.p);
        BigNumber memory newC2 = modInverseAndMultiply(a.c2, b.c2, publicKey.p);
        return ElGamalCiphertext(newC1, newC2);
    }

    /// @notice Adds a constant to an encrypted value.
    /// @dev For ciphertext (c1, c2) and constant k, computes (c1, c2 * g^k mod p).
    /// @param a The ciphertext.
    /// @param k The constant to add.
    /// @param publicKey The ElGamal public key.
    /// @return result The new ciphertext.
    function addConstant(
        ElGamalCiphertext calldata a,
        uint256 k,
        ElGamalPublicKey calldata publicKey
    ) public view returns (ElGamalCiphertext memory) {
        BigNumber memory gk = modExp(publicKey.g, k, publicKey.p);
        BigNumber memory newC2 = BigNum.modmul(a.c2, gk, publicKey.p);
        return ElGamalCiphertext(a.c1, newC2);
    }

    /// @notice Subtracts a constant from an encrypted value.
    /// @dev For ciphertext (c1, c2) and constant k, computes (c1, c2 * inv(g^k) mod p).
    /// @param a The ciphertext.
    /// @param k The constant to subtract.
    /// @param publicKey The ElGamal public key.
    /// @return result The new ciphertext.
    function subtractConstant(
        ElGamalCiphertext calldata a,
        uint256 k,
        ElGamalPublicKey calldata publicKey
    ) public view returns (ElGamalCiphertext memory) {
        BigNumber memory gk = modExp(publicKey.g, k, publicKey.p);
        BigNumber memory newC2 = modInverseAndMultiply(a.c2, gk, publicKey.p);
        return ElGamalCiphertext(a.c1, newC2);
    }

    /// @notice Re-randomizes an encrypted value without changing its plaintext.
    /// @dev Multiplies the ciphertext by an encryption of 1 (i.e. re-encrypts 1 with a new ephemeral key).
    /// @param a The ciphertext to re-randomize.
    /// @param newEphemeralKey A new random ephemeral key.
    /// @param publicKey The ElGamal public key.
    /// @return result The re-randomized ciphertext.
    function reRandomize(
        ElGamalCiphertext calldata a,
        BigNumber memory newEphemeralKey,
        ElGamalPublicKey calldata publicKey
    ) public view returns (ElGamalCiphertext memory) {
        // Encryption of 1: (g^r, h^r)
        BigNumber memory randC1 = modExp(
            publicKey.g,
            BigNum.toUint(newEphemeralKey),
            publicKey.p
        );
        BigNumber memory randC2 = modExp(
            publicKey.h,
            BigNum.toUint(newEphemeralKey),
            publicKey.p
        );
        // Multiply the original ciphertext by the encryption of 1
        BigNumber memory newC1 = BigNum.modmul(a.c1, randC1, publicKey.p);
        BigNumber memory newC2 = BigNum.modmul(a.c2, randC2, publicKey.p);
        return ElGamalCiphertext(newC1, newC2);
    }

    /// @notice Decrypts an ElGamal ciphertext using the private key.
    /// @dev Decryption: m = c2 * (c1^x)^(-1) mod p.
    /// @param ciphertext The ciphertext to decrypt.
    /// @param privateKey The ElGamal private key.
    /// @param publicKey The ElGamal public key.
    /// @return message The decrypted message (for additive encryption, note that this returns g^m).
    function decrypt(
        ElGamalCiphertext calldata ciphertext,
        ElGamalPrivateKey calldata privateKey,
        ElGamalPublicKey calldata publicKey
    ) public view returns (BigNumber memory) {
        // Compute s = c1^x mod p
        BigNumber memory s = modExp(
            ciphertext.c1,
            BigNum.toUint(privateKey.x),
            publicKey.p
        );
        // Compute m = c2 * s^(-1) mod p
        return modInverseAndMultiply(ciphertext.c2, s, publicKey.p);
    }

    /// @notice Generates a random ephemeral key suitable for ElGamal encryption.
    /// @dev Combines on-chain entropy sources. For higher security, consider a VRF or off-chain randomness.
    /// @param p The prime modulus.
    /// @return ephemeralKey The generated ephemeral key in the range [1, p-2].
    function generateEphemeralKey(
        BigNumber memory p
    ) public view returns (BigNumber memory) {
        bytes32 randomBytes = keccak256(
            abi.encodePacked(
                block.timestamp,
                block.prevrandao,
                msg.sender,
                blockhash(block.number - 1)
            )
        );
        BigNumber memory rand = BigNum.init(
            abi.encodePacked(randomBytes),
            false
        );
        BigNumber memory two = BigNum.two();
        BigNumber memory pMinus2 = BigNum.sub(p, two);
        // Reduce to range [0, p-3]
        BigNumber memory reduced = BigNum.mod(rand, pMinus2);
        BigNumber memory one = BigNum.one();
        // Shift to range [1, p-2]
        return BigNum.add(reduced, one);
    }
}
