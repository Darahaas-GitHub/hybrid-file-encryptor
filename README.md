# Hybrid Post-Quantum File Encryptor (Go)

A high-performance command-line utility built in Go that protects data-at-rest using a **Hybrid Cryptographic Architecture**. By fusing battle-tested classical elliptic curve cryptography with NIST-standardized Post-Quantum Cryptography (PQC), this tool ensures your protected files remain completely secure against both traditional attacks and future quantum computing capabilities ("Harvest Now, Decrypt Later").

---

## 🛡️ Cryptographic Architecture

This utility employs an asymmetric envelope encryption strategy. Instead of utilizing a pre-shared password, it encrypts data for a recipient's specific public cryptographic profile using a layered "Dual-Lock" mechanism. An adversary must mathematically compromise *both* X25519 and ML-KEM-768 simultaneously to read the underlying data.

### Phase 1: Encryption Flow
This phase starts with plaintext and the recipient's public keys, producing a combined ciphertext payload. The main entry point is `EncryptData`.

1. **Key Encapsulation:** `EncryptData` handles key encapsulation to generate the hybrid shared secret and key encapsulation components.
   * **Classical KEM (X25519):** An ephemeral X25519 key pair is generated. The ephemeral public key becomes the ciphertext component `ctX25519`. An ECDH operation is performed with the recipient's public key to establish a classical secret (`x25519Secret`).
   * **Post-Quantum KEM (ML-KEM-768):** The ML-KEM scheme encapsulates a secret against the recipient's ML-KEM public key, producing `ctMLKEM` and a post-quantum secret (`mlkemSecret`).
2. **Deriving the Shared Secret:** Both secrets are passed to `DeriveAESKey` (which utilizes HKDF-SHA256 internally) to safely mix and smooth the entropy from both classical and post-quantum methods into a single `combinedSecret`.
3. **Symmetric Encryption:** Back in `EncryptData`, the `combinedSecret` is used to initialize an AES-GCM cipher block.
   * A random 12-byte initialization vector (nonce) is generated.
   * The plaintext is encrypted using AES-GCM to produce the `encryptedPayload`.
4. **Assembly:** The final output byte array is packed in this sequence: 

$$\text{Output} = \text{ctX25519 (32 bytes)} \parallel \text{ctMLKEM (1088 bytes)} \parallel \text{nonce (12 bytes)} \parallel \text{encryptedPayload}$$

---

### Phase 2: Decryption Flow
This phase takes the packed ciphertext and the recipient's private keys, recovering the original plaintext. The entry point is `DecryptData`.

1. **Unpacking the Payload:** `DecryptData` slices the input ciphertext to separate the components:
   * `ctX25519` (first 32 bytes)
   * `ctMLKEM` (next 1088 bytes)
   * `nonce` (next 12 bytes)
   * `encryptedPayload` (the remaining bytes)
2. **Key Decapsulation:** `DecryptData` handles decapsulation with the recipient's private keys and the extracted ciphertext KEM components.
   * **Classical KEM (X25519):** Computes the shared classical secret using the recipient's X25519 private key and the ephemeral public key `ctX25519`.
   * **Post-Quantum KEM (ML-KEM-768):** Decapsulates `ctMLKEM` using the recipient's ML-KEM private key to recover the post-quantum secret.
3. **Re-deriving the Shared Secret:** Like encryption, it calls the key derivation logic to hash both recovered secrets together with SHA-256 to reconstruct the exact same `combinedSecret`.
4. **Symmetric Decryption:** Using the recovered `combinedSecret`, `DecryptData` initializes the AES-GCM cipher block. It decrypts and verifies the integrity of the `encryptedPayload` using the `nonce` via `gcm.Open`. If the authentication check succeeds, the original plaintext is returned.

---

## 📦 Binary File Format Specification

When a file is encrypted, the utility prepends a custom structural layout header containing the public deployment configuration keys to the payload. This adds a minimal overhead of only ~1.1 KB to the file size:
┌─────────────────────────┬─────────────────────────┬───────────────────┬────────────────────────┐
│  X25519 Ephemeral Pub   │   ML-KEM Ciphertext     │  AES-GCM Nonce    │ Encrypted File Data    │
│       (32 Bytes)        │      (1088 Bytes)       │    (12 Bytes)     │ (Variable Size)        │
└─────────────────────────┴─────────────────────────┴───────────────────┴────────────────────────┘
---

## 🚀 Getting Started

### Prerequisites
* Go compiler toolchain (**v1.21** or higher)

### Installation
Clone the repository locally and sync module dependencies:
```bash
git clone [https://github.com/YOUR_GITHUB_USERNAME/hybrid-file-encryptor.git](https://github.com/YOUR_GITHUB_USERNAME/hybrid-file-encryptor.git)
cd hybrid-file-encryptor
go mod tidy
Usage & CLI Command Routing
The application exposes three primary subcommand routers within the terminal flags interface:

1. Key Generation
Generate a fresh, persistent hybrid identity key pair for testing or distribution:

Bash
go run . gen-keys
2. Encrypting a File
To encrypt a targeted local file, call the encrypt subcommand. The application will output an encrypted .enc asset payload file, alongside a companion demo .key asset tracking private vectors:

Bash
go run . encrypt -file message.txt
Output: message.txt.enc and message.txt.key

3. Decrypting a File
To unlock the encrypted container back into clean plaintext file formats, execute the decrypt path flag routing command:

Bash
go run . decrypt -file message.txt.enc
The program automatically locates the associated .key module, decapsulates the multi-layered hybrid shared secrets, executes structural tamper-checks, and writes the recovered output.

🛠️ Built Using
Go Standard Library (crypto/aes, crypto/cipher, crypto/ecdh)

Go Extended Cryptography Suite (golang.org/x/crypto/mlkem, golang.org/x/crypto/hkdf)


---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

README CREATED USING GOOGLE GEMINI