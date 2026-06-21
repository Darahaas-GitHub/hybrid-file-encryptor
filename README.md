# hybrid-file-encryptor

A command-line tool for hybrid post-quantum file encryption. It combines X25519 (classical elliptic-curve Diffie–Hellman) with ML-KEM-768 (NIST's post-quantum key encapsulation mechanism) so that an attacker must break *both* schemes to recover the plaintext. The threat model is simple: a sender encrypts a file to a recipient's public key, and only the holder of the corresponding private key can decrypt it. This protects data at rest against a future adversary with a cryptographically relevant quantum computer, while retaining classical security today.

## Cryptographic Architecture

1. **Key Generation**: The recipient generates an X25519 keypair and an ML-KEM-768 keypair. Both public keys are stored together in `id_hybrid.pub`; both private keys in `id_hybrid`.

2. **Encryption** (performed by the sender):
   - An ephemeral X25519 keypair is generated. The sender performs ECDH with the recipient's X25519 public key to derive a classical shared secret.
   - ML-KEM-768 encapsulation produces a post-quantum shared secret and a ciphertext.
   - The two shared secrets are concatenated and fed into **HKDF-SHA256** (no salt, info string `hybrid-pqc-file-encryptor-v1`) to derive a single 32-byte AES-256 key.
   - The file is encrypted in 64 KB streaming chunks using **AES-256-GCM**. Each chunk gets a unique nonce derived by XOR-ing a random 12-byte base nonce with a zero-padded big-endian uint64 chunk counter. Each chunk's GCM additional authenticated data (AAD) is `"cont"` for non-final chunks and `"last"` for the final chunk, which prevents silent truncation.

3. **Decryption** (performed by the recipient):
   - The recipient reads the magic header and key-exchange ciphertexts from the file header.
   - X25519 ECDH and ML-KEM decapsulation recover the two shared secrets; HKDF derives the same AES key.
   - Chunks are decrypted in sequence. The AAD is verified to detect truncation or reordering.

## Encrypted File Format (`.enc`)

```
Offset  Length   Field
──────  ──────   ─────
0       6        Magic header: ASCII "HFPQV1"
6       32       Ephemeral X25519 public key (ctX25519)
38      1088     ML-KEM-768 ciphertext (ctMLKEM)
1126    12       Base nonce (random)
1138    ...      Chunked ciphertext stream
```

Each chunk in the stream:

```
[uint32 BE: length of sealed_data][sealed_data]
```

`sealed_data` = AES-GCM ciphertext + 16-byte authentication tag. AAD is `"cont"` or `"last"`.

## Key File Format

Both `id_hybrid` (private) and `id_hybrid.pub` (public) use the same container format:

```
[6 bytes: "HFPQV1"]
[uint16 BE: key1_length][key1_bytes]
[uint16 BE: key2_length][key2_bytes]
```

- **Public file** (`id_hybrid.pub`): key1 = X25519 public key (32 bytes), key2 = ML-KEM-768 public key.
- **Private file** (`id_hybrid`): key1 = X25519 private key (32 bytes), key2 = ML-KEM-768 private key.

## CLI Usage

### Generate a keypair

```
hybrid-encryptor gen-keys
```

Writes `id_hybrid` (private, mode 0600) and `id_hybrid.pub` (public, mode 0644) in the current directory.

### Encrypt a file

```
hybrid-encryptor encrypt -file document.txt -pubkey id_hybrid.pub
```

Produces `document.txt.enc` (mode 0600). The private key is never touched during encryption.

### Decrypt a file

```
hybrid-encryptor decrypt -file document.txt.enc -privkey id_hybrid
```

Produces `document.txt` (the `.enc` suffix is stripped). If the input doesn't end in `.enc`, the output gets a `.dec` suffix.

## Limitations & Known Gaps

- **Memory per chunk**: Each 64 KB chunk is fully buffered in memory during encryption and decryption. The tool streams across chunks, but individual chunks are not sub-streamed. This is adequate for normal file sizes but is not a true constant-memory streaming cipher.
- **No key revocation**: There is no mechanism to revoke a compromised keypair. If your private key leaks, all files encrypted to it are compromised.
- **No authenticated sender identity**: The encryption is anonymous. The recipient cannot verify *who* encrypted the file — only that someone with their public key did.
- **No cross-platform key portability guarantees**: The key file format is a simple binary encoding. Byte-order is fixed (big-endian), but no versioning beyond the magic header exists. Future format changes would need a new magic string or version byte.
- **No key derivation from passwords**: Keys are raw cryptographic keys, not derived from passphrases. There is no KDF-based key wrapping for the private key file.
- **Chunk counter overflow**: The nonce derivation uses a uint64 counter. At 64 KB per chunk, this overflows after 2^64 chunks (~10^20 bytes), which is not a practical concern.

## Build & Test

Requires Go 1.21+ (tested with Go 1.26).

```bash
# Build
go build -o hybrid-encryptor .

# Run tests
go test -v -count=1 ./...

# Quick smoke test
./hybrid-encryptor gen-keys
echo "hello world" > test.txt
./hybrid-encryptor encrypt -file test.txt -pubkey id_hybrid.pub
./hybrid-encryptor decrypt -file test.txt.enc -privkey id_hybrid
cat test.txt  # should print "hello world"
```

## Dependencies

- [cloudflare/circl](https://github.com/cloudflare/circl) — ML-KEM-768 implementation
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) — HKDF-SHA256
- Go standard library — AES-GCM, X25519, SHA-256