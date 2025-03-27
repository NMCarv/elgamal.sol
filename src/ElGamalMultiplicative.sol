// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ElGamal Multiplicative Homomorphic Encryption
/// @dev Supports multiplicative homomorphism with scalar addition/subtraction
contract ElGamalMultiplicative {
    struct Ciphertext {
        uint256 c1; // g^r mod p
        uint256 c2; // (m * h^r) mod p
    }

    uint256 public immutable p;
    uint256 public immutable g;
    uint256 public immutable h;
    address public immutable owner;

    mapping(address => Ciphertext) public encryptedBalances;

    event EncryptedValueStored(address indexed user, uint256 c1, uint256 c2);
    event HomomorphicMultiplication(
        address indexed user,
        uint256 c1,
        uint256 c2
    );
    event HomomorphicDivision(address indexed user, uint256 c1, uint256 c2);
    event ScalarExponentiation(address indexed user, uint256 c1, uint256 c2);

    modifier onlyOwner() {
        require(msg.sender == owner, 'Not authorized');
        _;
    }

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

    /// @notice Scalar Exponentiation: (c1^scalar, c2^scalar)
    function scalarExponentiation(address user, uint256 scalar) external {
        Ciphertext memory ct = encryptedBalances[user];
        require(ct.c1 != 0 && ct.c2 != 0, 'User has no encrypted value');

        uint256 newC1 = modExp(ct.c1, scalar, p);
        uint256 newC2 = modExp(ct.c2, scalar, p);

        encryptedBalances[msg.sender] = Ciphertext(newC1, newC2);
        emit ScalarExponentiation(msg.sender, newC1, newC2);
    }

    /// @notice Homomorphic Multiplication: (c1 * c1', c2 * c2')
    function homomorphicMultiplication(address user1, address user2) external {
        Ciphertext memory ct1 = encryptedBalances[user1];
        Ciphertext memory ct2 = encryptedBalances[user2];
        require(ct1.c1 != 0 && ct1.c2 != 0, 'User1 has no value');
        require(ct2.c1 != 0 && ct2.c2 != 0, 'User2 has no value');
        uint256 newC1 = (ct1.c1 * ct2.c1) % p;
        uint256 newC2 = (ct1.c2 * ct2.c2) % p;
        encryptedBalances[msg.sender] = Ciphertext(newC1, newC2);
        emit HomomorphicMultiplication(msg.sender, newC1, newC2);
    }

    /// @notice Homomorphic Division: (c1^(1/scalar), c2^(1/scalar))
    function homomorphicDivision(address user, uint256 scalar) external {
        Ciphertext memory ct = encryptedBalances[user];
        require(ct.c1 != 0 && ct.c2 != 0, 'User has no encrypted value');

        uint256 scalarInv = modInverse(scalar, p - 1);
        uint256 newC1 = modExp(ct.c1, scalarInv, p);
        uint256 newC2 = modExp(ct.c2, scalarInv, p);

        encryptedBalances[msg.sender] = Ciphertext(newC1, newC2);
        emit HomomorphicDivision(msg.sender, newC1, newC2);
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
