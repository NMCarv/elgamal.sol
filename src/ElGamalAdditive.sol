// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ElGamal Additive Homomorphic Encryption
/// @dev Supports additive homomorphism with scalar multiplication/division
contract ElGamalAdditive {
    struct Ciphertext {
        uint256 c1; // g^r mod p
        uint256 c2; // (g^m * h^r) mod p
    }

    uint256 public immutable p;
    uint256 public immutable g;
    uint256 public immutable h;
    address public immutable owner;

    mapping(address => Ciphertext) public encryptedBalances;

    event EncryptedValueStored(address indexed user, uint256 c1, uint256 c2);
    event HomomorphicAddition(address indexed user, uint256 c1, uint256 c2);
    event HomomorphicSubtraction(address indexed user, uint256 c1, uint256 c2);
    event ScalarMultiplication(address indexed user, uint256 c1, uint256 c2);
    event ScalarDivision(address indexed user, uint256 c1, uint256 c2);

    constructor(uint256 _p, uint256 _g, uint256 _h) {
        require(_p > 0 && _g > 0 && _h > 0, 'Invalid parameters');
        p = _p;
        g = _g;
        h = _h;
        owner = msg.sender;
    }

    function storeEncryptedValue(uint256 c1, uint256 c2) external {
        require(c1 > 0 && c2 > 0, 'Invalid ciphertext');
        encryptedBalances[msg.sender] = Ciphertext(c1, c2);
        emit EncryptedValueStored(msg.sender, c1, c2);
    }

    /// @notice Get encrypted balance for a user
    function getEncryptedBalance(
        address user
    ) external view returns (uint256, uint256) {
        Ciphertext memory ct = encryptedBalances[user];
        return (ct.c1, ct.c2);
    }

    function homomorphicAddition(address user1, address user2) external {
        Ciphertext memory ct1 = encryptedBalances[user1];
        Ciphertext memory ct2 = encryptedBalances[user2];

        require(ct1.c1 != 0 && ct1.c2 != 0, 'User1 has no encrypted value');
        require(ct2.c1 != 0 && ct2.c2 != 0, 'User2 has no encrypted value');

        uint256 newC1 = (ct1.c1 * ct2.c1) % p;
        uint256 newC2 = (ct1.c2 * ct2.c2) % p;
        encryptedBalances[msg.sender] = Ciphertext(newC1, newC2);
        emit HomomorphicAddition(msg.sender, newC1, newC2);
    }

    /// @notice Homomorphic Subtraction: (c1 / c1') % p, (c2 / c2') % p
    function homomorphicSubtraction(address user1, address user2) external {
        Ciphertext memory ct1 = encryptedBalances[user1];
        Ciphertext memory ct2 = encryptedBalances[user2];

        require(ct1.c1 != 0 && ct1.c2 != 0, 'User1 has no encrypted value');
        require(ct2.c1 != 0 && ct2.c2 != 0, 'User2 has no encrypted value');

        // Compute modular inverse of c1' and c2'
        uint256 invC1 = modInverse(ct2.c1, p);
        uint256 invC2 = modInverse(ct2.c2, p);

        uint256 newC1 = (ct1.c1 * invC1) % p;
        uint256 newC2 = (ct1.c2 * invC2) % p;

        encryptedBalances[msg.sender] = Ciphertext(newC1, newC2);
        emit HomomorphicSubtraction(msg.sender, newC1, newC2);
    }

    /// @notice Mixes multiplication and addition: (C_1^k * C_2) % p
    function scalarMultiply(
        address user1,
        uint256 multiplier,
        address user2
    ) external {
        Ciphertext memory ct1 = encryptedBalances[user1];
        Ciphertext memory ct2 = encryptedBalances[user2];

        require(ct1.c1 != 0 && ct1.c2 != 0, 'User1 has no encrypted value');
        require(ct2.c1 != 0 && ct2.c2 != 0, 'User2 has no encrypted value');
        require(multiplier > 0, 'Multiplier must be nonzero');

        uint256 scaledC1 = modExp(ct1.c1, multiplier, p);
        uint256 scaledC2 = modExp(ct1.c2, multiplier, p);

        uint256 newC1 = (scaledC1 * ct2.c1) % p;
        uint256 newC2 = (scaledC2 * ct2.c2) % p;

        encryptedBalances[msg.sender] = Ciphertext(newC1, newC2);
        emit ScalarMultiplication(msg.sender, newC1, newC2);
    }

    /// @notice Mixes multiplication, addition, and scalar division
    /// @dev Computes (C_1^k * C_2)^(1/d) mod p
    function scalarDivide(
        address user1,
        uint256 multiplier,
        address user2,
        uint256 divisor
    ) external {
        Ciphertext memory ct1 = encryptedBalances[user1];
        Ciphertext memory ct2 = encryptedBalances[user2];

        require(ct1.c1 != 0 && ct1.c2 != 0, 'User1 has no encrypted value');
        require(ct2.c1 != 0 && ct2.c2 != 0, 'User2 has no encrypted value');
        require(multiplier > 0, 'Multiplier must be nonzero');
        require(divisor > 0, 'Divisor must be nonzero');

        // Ensure divisor is coprime with (p-1)
        require(gcd(divisor, p - 1) == 1, 'Divisor must be coprime with (p-1)');

        uint256 scaledC1 = modExp(ct1.c1, multiplier, p);
        uint256 scaledC2 = modExp(ct1.c2, multiplier, p);

        uint256 addedC1 = (scaledC1 * ct2.c1) % p;
        uint256 addedC2 = (scaledC2 * ct2.c2) % p;

        uint256 divisorInv = modInverse(divisor, p - 1);
        uint256 newC1 = modExp(addedC1, divisorInv, p);
        uint256 newC2 = modExp(addedC2, divisorInv, p);

        encryptedBalances[msg.sender] = Ciphertext(newC1, newC2);
        emit ScalarDivision(msg.sender, newC1, newC2);
    }

    /// @notice Compute Greatest Common Divisor (GCD) using Euclidean algorithm
    function gcd(uint256 a, uint256 b) internal pure returns (uint256) {
        while (b != 0) {
            uint256 temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    function modExp(
        uint256 base,
        uint256 exp,
        uint256 mod
    ) internal view returns (uint256) {
        (bool success, bytes memory result) = address(0x05).staticcall(
            abi.encode(base, exp, mod)
        );
        require(success, 'ModExp failed');
        return abi.decode(result, (uint256));
    }

    /// @notice Computes modular inverse using extended Euclidean algorithm
    function modInverse(
        uint256 a,
        uint256 mod
    ) internal pure returns (uint256) {
        int256 t = 0;
        int256 newT = 1;
        int256 r = int256(mod);
        int256 newR = int256(a);

        while (newR != 0) {
            int256 quotient = r / newR;
            (t, newT) = (newT, t - quotient * newT);
            (r, newR) = (newR, r - quotient * newR);
        }

        require(r == 1, 'No modular inverse');
        return uint256(t < 0 ? t + int256(mod) : t);
    }
}
