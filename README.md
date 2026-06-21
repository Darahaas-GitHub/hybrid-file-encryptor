# Hybrid Post-Quantum File Encryptor (Demo Project)

A Go command-line tool for streaming file encryption with a hybrid classical and post-quantum envelope:

- X25519 ephemeral ECDH for the classical shared secret
- ML-KEM-768 for the post-quantum shared secret
- HKDF-SHA-256 to derive one AES-256 key from both secrets
- AES-256-GCM for authenticated chunked file encryption

The sender encrypts to a recipient public key file. Only the matching private key can decrypt.

## Security Model

This project does not embed credentials, private keys, passwords, `.env` files, or hard-coded secret material. Generated private keys are local user secrets and must not be committed.

Private key files are written with `0600` permissions. For stronger at-rest protection, set a passphrase in an environment variable before generating keys:

```bash
export HYBRID_ENCRYPTOR_PASSPHRASE="use-a-long-random-passphrase"
go run . gen-keys
```

On Windows PowerShell:

```powershell
$env:HYBRID_ENCRYPTOR_PASSPHRASE = "use-a-long-random-passphrase"
go run . gen-keys
```

The passphrase is not stored by the tool. For production use, load that environment variable from your operating-system secret store or vault workflow.

## Installation

```bash
git clone https://github.com/Darahaas-GitHub/hybrid-file-encryptor.git
cd hybrid-file-encryptor
go mod download
```

## Usage

Generate a recipient key pair:

```bash
go run . gen-keys -out-dir . -name id_hybrid
```

This creates:

- `id_hybrid`: private key
- `id_hybrid.pub`: public key

Encrypt a file to the recipient public key:

```bash
go run . encrypt -file message.txt -pubkey id_hybrid.pub
```

Decrypt with the matching private key:

```bash
go run . decrypt -file message.txt.enc -privkey id_hybrid
```

If the private key is passphrase-protected, set the same passphrase environment variable before decrypting.

## Encrypted File Format

Encrypted files use a versioned binary format:

```text
magic        6 bytes   "HPQENC"
version      1 byte
suite        1 byte    X25519 + ML-KEM-768 + AES-256-GCM
chunk size   4 bytes
x25519 len   2 bytes
mlkem len    2 bytes
nonce len    1 byte
ctX25519     variable
ctMLKEM      variable
base nonce   variable
chunks       repeated [uint32 length][AES-GCM ciphertext+tag]
```

Every encrypted chunk authenticates the full header as AES-GCM additional authenticated data, plus a chunk role marker for continuation or final chunk.

## Key File Format

Key files use a separate `HPQKEY` magic header with a version, key type, and protection mode. Public keys are unencrypted. Private keys can be either local-permission protected or passphrase-protected with Argon2id plus AES-GCM.

## Development Checks

```bash
go test ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

The GitHub Actions workflow runs tests and `govulncheck` on push and pull request.

## Repository Hygiene

The `.gitignore` excludes generated keys, encrypted outputs, decrypted outputs, `.env` files, and local binaries. Do not commit private keys, passphrases, decrypted files, or generated executables.

## License

MIT. See [LICENSE](LICENSE).

README.md done using Google Gemini and OpenAI ChatGPT.
