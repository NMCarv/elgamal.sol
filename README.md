# 🔐 ElGamal Cryptosystem in Solidity with Big Number Support

This project provides a fully on-chain implementation of the **ElGamal cryptosystem** in **Solidity**, supporting both **additive** and **multiplicative** homomorphic encryption. It includes:

- ✅ Big number arithmetic using a custom `BigNum` library
- ✅ ElGamal encryption (additive & multiplicative variants)
- ✅ Homomorphic operations: addition, subtraction, multiplication, division
- ✅ Unit tests with [Foundry](https://book.getfoundry.sh/)
- ✅ Decryption for small prime moduli

## ✨ Features

### 🧠 Cryptographic Schemes

| Variant        | Ciphertext Form               | Decryption Method                          |
| -------------- | ----------------------------- | ------------------------------------------ |
| Multiplicative | `(c1, c2) = (g^r, m * h^r)`   | `m = c2 * (c1^x)^(-1) mod p`               |
| Additive       | `(c1, c2) = (g^r, g^m * h^r)` | `g^m = c2 * (c1^x)^(-1) mod p` + brute log |

Both variants support secure homomorphic operations.

### 🔢 Big Number Arithmetic

This repo includes a standalone `BigNum.sol` library for:

- Modular exponentiation, multiplication, inversion
- Comparison, equality, shifting
- Encoding/decoding between bytes and integers

Used to support 256+ bit arithmetic for cryptographic ops on-chain.

## 🧪 Tests

We use **Foundry** to test all core functionality, including:

- Encryption and decryption for small and large primes
- Homomorphic addition, subtraction, multiplication, division
- Byte-level BigNumber correctness
- Edge cases in modular math

### 🟢 Example Output

```bash
forge test
```

```
[PASS] testEncryptDecryptSmallPrime()
[PASS] testDecryptMultiplicativeSmallPrime()
[PASS] testDecryptAdditiveSmallPrime()
[PASS] testHomomorphicAdditionLargePrime()
[PASS] testHomomorphicMultiplicationSmallPrime()
...
```

## 📁 Repository Structure

```
├── src/
│   ├── BigNum.sol                  # Core bignum arithmetic library
│   ├── ElGamalAdditive.sol         # Additive ElGamal encryption
│   ├── ElGamalMultiplicative.sol   # Multiplicative ElGamal encryption
│
├── test/
│   ├── ElGamalAdditive.t.sol       # Unit tests for additive variant
│   ├── ElGamalMultiplicative.t.sol # Unit tests for multiplicative variant
│
├── foundry.toml
├── README.md
```

## 🛠️ Usage

### 1. Build

```bash
forge build
```

### 2. Run Tests

```bash
forge test -vvv
```

### 3. Format Code

```bash
forge fmt
```

## 🔍 Testing Decryption

To ensure correctness, we include **decryption logic for small primes** directly in Solidity, both for additive and multiplicative ElGamal.

Multiplicative decryption:

```solidity
m = c2 * (c1^x)^(-1) mod p
```

Additive decryption (small primes only):

```solidity
g^m = c2 * (c1^x)^(-1) mod p
m = bruteForceDiscreteLog(g^m, g, p)
```

> Note: Discrete log computation is infeasible for large primes. Decryption for large primes is **not implemented**, by design.

## ⚠️ Limitations

- Decryption only implemented for **small primes**
- No private key generation on-chain
- Not optimized for gas (this is a reference implementation)
- No zero-knowledge or proof systems (yet 😉)

## 📌 Goals

This project is educational, research-oriented, and intended for those studying:

- Cryptography on-chain
- Secure multiparty computation (SMPC)
- Homomorphic encryption
- Solidity for systems programming

## 📚 References

- ElGamal cryptosystem: [Wikipedia](https://en.wikipedia.org/wiki/ElGamal_encryption)
- Homomorphic encryption: [Wikipedia](https://en.wikipedia.org/wiki/Homomorphic_encryption)

## 🪪 License

MIT — free to use, study, remix, or build on. Commercial use at your discretion.
