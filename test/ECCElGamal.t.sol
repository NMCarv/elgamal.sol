// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import 'forge-std/Test.sol';
import '../src/ECCElGamal.sol';

/// @dev A helper contract that exposes internal BN256 operations for testing.
contract TestECCElGamal is ECCElGamal {
    function publicEcMul(
        ECPoint memory p,
        uint256 scalar
    ) public view returns (ECPoint memory) {
        return ecMul(p, scalar);
    }
    function publicEcAdd(
        ECPoint memory p1,
        ECPoint memory p2
    ) public view returns (ECPoint memory) {
        return ecAdd(p1, p2);
    }
    function publicEcNeg(
        ECPoint memory p
    ) public pure returns (ECPoint memory) {
        return ecNeg(p);
    }
}

contract ECCElGamalTest is Test {
    TestECCElGamal public ecc;

    // BN256 generator G = (1,2)
    ECPoint public G = ECPoint(1, 2);
    // Choose a private key x and compute public key Q = x * G.
    uint256 public x = 7;
    PublicKey public pk;

    function setUp() public {
        ecc = new TestECCElGamal();
        ECPoint memory Q = ecc.publicEcMul(G, x);
        pk = PublicKey(Q);
    }

    /// @dev Compares two EC points by checking their x and y coordinates.
    function assertPointEqual(
        ECPoint memory p1,
        ECPoint memory p2
    ) internal pure {
        assertEq(p1.x, p2.x, 'X coordinate mismatch');
        assertEq(p1.y, p2.y, 'Y coordinate mismatch');
    }

    /// @notice Test that encrypting and then decrypting a message recovers the original point.
    function testEncryptDecrypt() public view {
        // Encode message m = 3 as M = 3 * G.
        uint256 m = 3;
        ECPoint memory M = ecc.publicEcMul(G, m);
        // Choose a random scalar r, e.g. 5.
        uint256 r = 5;
        Ciphertext memory ct = ecc.encrypt(M, r, pk);
        ECPoint memory decrypted = ecc.decrypt(ct, x);
        // The decrypted point should equal M.
        assertPointEqual(decrypted, M);
    }

    /// @notice Test homomorphic addition: encrypt two messages and add their ciphertexts.
    function testHomomorphicAddition() public view {
        // Encrypt messages m1 = 2 and m2 = 4.
        uint256 m1 = 2;
        uint256 m2 = 4;
        ECPoint memory M1 = ecc.publicEcMul(G, m1);
        ECPoint memory M2 = ecc.publicEcMul(G, m2);
        uint256 r1 = 3;
        uint256 r2 = 6;
        Ciphertext memory ct1 = ecc.encrypt(M1, r1, pk);
        Ciphertext memory ct2 = ecc.encrypt(M2, r2, pk);
        // Homomorphically add ciphertexts.
        Ciphertext memory ctAdd = ecc.homomorphicAddition(ct1, ct2);
        // Decrypt the sum: should equal M1 + M2.
        ECPoint memory decrypted = ecc.decrypt(ctAdd, x);
        ECPoint memory expected = ecc.publicEcAdd(M1, M2);
        assertPointEqual(decrypted, expected);
    }

    /// @notice Test homomorphic subtraction: encrypt two messages and subtract their ciphertexts.
    function testHomomorphicSubtraction() public view {
        // Encrypt messages m1 = 5 and m2 = 2.
        uint256 m1 = 5;
        uint256 m2 = 2;
        ECPoint memory M1 = ecc.publicEcMul(G, m1);
        ECPoint memory M2 = ecc.publicEcMul(G, m2);
        uint256 r1 = 4;
        uint256 r2 = 3;
        Ciphertext memory ct1 = ecc.encrypt(M1, r1, pk);
        Ciphertext memory ct2 = ecc.encrypt(M2, r2, pk);
        // Homomorphically subtract ciphertexts.
        Ciphertext memory ctSub = ecc.homomorphicSubtraction(ct1, ct2);
        // Decrypt: should equal M1 - M2 = M1 + (-M2).
        ECPoint memory decrypted = ecc.decrypt(ctSub, x);
        ECPoint memory negM2 = ecc.publicEcNeg(M2);
        ECPoint memory expected = ecc.publicEcAdd(M1, negM2);
        assertPointEqual(decrypted, expected);
    }

    /// @notice Test scalar addition on a ciphertext.
    /// Adding a scalar k means adding k*G to the plaintext.
    function testScalarAddition() public view {
        // Encrypt message m = 3, i.e. M = 3 * G.
        uint256 m = 3;
        ECPoint memory M = ecc.publicEcMul(G, m);
        uint256 r = 5;
        Ciphertext memory ct = ecc.encrypt(M, r, pk);
        // Scalar addition: add k = 4, so expected message is M + 4*G.
        uint256 k = 4;
        Ciphertext memory ctScalarAdd = ecc.scalarAddition(ct, k);
        ECPoint memory decrypted = ecc.decrypt(ctScalarAdd, x);
        ECPoint memory kG = ecc.publicEcMul(G, k);
        ECPoint memory expected = ecc.publicEcAdd(M, kG);
        assertPointEqual(decrypted, expected);
    }

    /// @notice Test scalar subtraction on a ciphertext.
    /// Subtracting a scalar k means subtracting k*G from the plaintext.
    function testScalarSubtraction() public view {
        // Encrypt message m = 6, i.e. M = 6 * G.
        uint256 m = 6;
        ECPoint memory M = ecc.publicEcMul(G, m);
        uint256 r = 7;
        Ciphertext memory ct = ecc.encrypt(M, r, pk);
        // Scalar subtraction: subtract k = 2, so expected message is M - 2*G.
        uint256 k = 2;
        Ciphertext memory ctScalarSub = ecc.scalarSubtraction(ct, k);
        ECPoint memory decrypted = ecc.decrypt(ctScalarSub, x);
        ECPoint memory kG = ecc.publicEcMul(G, k);
        ECPoint memory neg_kG = ecc.publicEcNeg(kG);
        ECPoint memory expected = ecc.publicEcAdd(M, neg_kG);
        assertPointEqual(decrypted, expected);
    }
}
