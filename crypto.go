// crypto.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/hkdf"
)

const (
	// fileMagic is prepended to encrypted files for format identification.
	fileMagic                           = "HPQENC"
	fileVersion                         = byte(1)
	fileSuiteHybridX25519MLKEM768AESGCM = byte(1)
	// chunkSize is the plaintext chunk size for streaming encryption (64 KB).
	chunkSize = 64 * 1024
	// x25519CtLen is the byte length of an X25519 ephemeral public key.
	x25519CtLen = 32
	// nonceLen is the byte length of an AES-GCM nonce.
	nonceLen = 12
	// maxEncryptedChunkLen limits allocation from untrusted ciphertext lengths.
	maxEncryptedChunkLen = chunkSize + 16
)

const (
	chunkAADContinuation = "cont"
	chunkAADFinal        = "last"
)

// HybridKeyPair holds both classical and post-quantum public/private keys.
type HybridKeyPair struct {
	X25519Private *ecdh.PrivateKey
	X25519Public  *ecdh.PublicKey
	MLKEMPrivate  *mlkem768.PrivateKey
	MLKEMPublic   *mlkem768.PublicKey
}

// GenerateHybridKeyPair creates a new pair of X25519 and ML-KEM-768 keys.
func GenerateHybridKeyPair() (*HybridKeyPair, error) {
	// X25519 (classical ECDH)
	x25519Priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 key: %w", err)
	}

	// ML-KEM-768 (post-quantum KEM, security ≈ AES-192)
	mlkemPub, mlkemPriv, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-KEM key: %w", err)
	}

	return &HybridKeyPair{
		X25519Private: x25519Priv,
		X25519Public:  x25519Priv.PublicKey(),
		MLKEMPrivate:  mlkemPriv,
		MLKEMPublic:   mlkemPub,
	}, nil
}

// CombineSecrets derives a 32-byte symmetric key from the X25519 and ML-KEM
// shared secrets using HKDF-SHA256 with domain separation.
func CombineSecrets(x25519Secret, mlkemSecret []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(x25519Secret)+len(mlkemSecret))
	ikm = append(ikm, x25519Secret...)
	ikm = append(ikm, mlkemSecret...)

	info := []byte("HPQENC-v1-X25519-MLKEM768-AES256GCM")
	reader := hkdf.New(sha256.New, ikm, nil, info)

	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}
	return key, nil
}

func buildFileHeader(ctX25519, ctMLKEM, baseNonce []byte) ([]byte, error) {
	if len(ctX25519) != x25519CtLen {
		return nil, fmt.Errorf("invalid X25519 ciphertext length: got %d, want %d", len(ctX25519), x25519CtLen)
	}
	if len(ctMLKEM) != mlkem768.Scheme().CiphertextSize() {
		return nil, fmt.Errorf("invalid ML-KEM ciphertext length: got %d, want %d", len(ctMLKEM), mlkem768.Scheme().CiphertextSize())
	}
	if len(baseNonce) != nonceLen {
		return nil, fmt.Errorf("invalid nonce length: got %d, want %d", len(baseNonce), nonceLen)
	}
	if len(ctX25519) > math.MaxUint16 || len(ctMLKEM) > math.MaxUint16 {
		return nil, fmt.Errorf("ciphertext component too large")
	}

	header := make([]byte, 0, len(fileMagic)+1+1+4+2+2+1+len(ctX25519)+len(ctMLKEM)+len(baseNonce))
	header = append(header, []byte(fileMagic)...)
	header = append(header, fileVersion, fileSuiteHybridX25519MLKEM768AESGCM)
	header = binary.BigEndian.AppendUint32(header, chunkSize)
	header = binary.BigEndian.AppendUint16(header, uint16(len(ctX25519)))
	header = binary.BigEndian.AppendUint16(header, uint16(len(ctMLKEM)))
	header = append(header, byte(len(baseNonce)))
	header = append(header, ctX25519...)
	header = append(header, ctMLKEM...)
	header = append(header, baseNonce...)
	return header, nil
}

func readFileHeader(r io.Reader) (header, ctX25519, ctMLKEM, baseNonce []byte, err error) {
	prefixLen := len(fileMagic) + 1 + 1 + 4 + 2 + 2 + 1
	prefix := make([]byte, prefixLen)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("invalid file: missing or truncated header")
	}
	if string(prefix[:len(fileMagic)]) != fileMagic {
		return nil, nil, nil, nil, fmt.Errorf("invalid file: missing or incorrect magic header")
	}

	offset := len(fileMagic)
	version := prefix[offset]
	offset++
	if version != fileVersion {
		return nil, nil, nil, nil, fmt.Errorf("unsupported encrypted file version: %d", version)
	}
	suite := prefix[offset]
	offset++
	if suite != fileSuiteHybridX25519MLKEM768AESGCM {
		return nil, nil, nil, nil, fmt.Errorf("unsupported cryptographic suite: %d", suite)
	}
	encodedChunkSize := binary.BigEndian.Uint32(prefix[offset:])
	offset += 4
	if encodedChunkSize != chunkSize {
		return nil, nil, nil, nil, fmt.Errorf("unsupported chunk size: %d", encodedChunkSize)
	}
	xLen := int(binary.BigEndian.Uint16(prefix[offset:]))
	offset += 2
	mlkemLen := int(binary.BigEndian.Uint16(prefix[offset:]))
	offset += 2
	nLen := int(prefix[offset])

	if xLen != x25519CtLen {
		return nil, nil, nil, nil, fmt.Errorf("invalid X25519 ciphertext length: %d", xLen)
	}
	if mlkemLen != mlkem768.Scheme().CiphertextSize() {
		return nil, nil, nil, nil, fmt.Errorf("invalid ML-KEM ciphertext length: %d", mlkemLen)
	}
	if nLen != nonceLen {
		return nil, nil, nil, nil, fmt.Errorf("invalid nonce length: %d", nLen)
	}

	components := make([]byte, xLen+mlkemLen+nLen)
	if _, err := io.ReadFull(r, components); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read encrypted file header components: %w", err)
	}

	header = make([]byte, 0, len(prefix)+len(components))
	header = append(header, prefix...)
	header = append(header, components...)
	ctX25519 = components[:xLen]
	ctMLKEM = components[xLen : xLen+mlkemLen]
	baseNonce = components[xLen+mlkemLen:]
	return header, ctX25519, ctMLKEM, baseNonce, nil
}

func chunkAAD(header []byte, role string) []byte {
	aad := make([]byte, 0, len(header)+len(role))
	aad = append(aad, header...)
	aad = append(aad, role...)
	return aad
}

// Encapsulate performs hybrid key encapsulation against the recipient's public
// keys. Returns the X25519 ephemeral public key, ML-KEM ciphertext, and a
// derived 32-byte symmetric key.
func Encapsulate(recipX25519Pub *ecdh.PublicKey, recipMLKEMPub kem.PublicKey) (ctX25519 []byte, ctMLKEM []byte, combinedSecret []byte, err error) {
	// Ephemeral X25519 key for this encryption
	ephemeralPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate ephemeral X25519 key: %w", err)
	}
	ctX25519 = ephemeralPriv.PublicKey().Bytes()

	// X25519 shared secret
	x25519Secret, err := ephemeralPriv.ECDH(recipX25519Pub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compute X25519 secret: %w", err)
	}

	// ML-KEM-768 encapsulation
	scheme := mlkem768.Scheme()
	ctMLKEM, mlkemSecret, err := scheme.Encapsulate(recipMLKEMPub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encapsulate ML-KEM secret: %w", err)
	}

	combinedSecret, err = CombineSecrets(x25519Secret, mlkemSecret)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to derive combined key: %w", err)
	}
	return ctX25519, ctMLKEM, combinedSecret, nil
}

// Decapsulate recovers the hybrid shared secret using the recipient's private keys.
func Decapsulate(recipX25519Priv *ecdh.PrivateKey, recipMLKEMPriv kem.PrivateKey, ctX25519 []byte, ctMLKEM []byte) ([]byte, error) {
	ephemeralPub, err := ecdh.X25519().NewPublicKey(ctX25519)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral X25519 public key: %w", err)
	}

	x25519Secret, err := recipX25519Priv.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute X25519 secret: %w", err)
	}

	scheme := mlkem768.Scheme()
	mlkemSecret, err := scheme.Decapsulate(recipMLKEMPriv, ctMLKEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate ML-KEM secret: %w", err)
	}

	return CombineSecrets(x25519Secret, mlkemSecret)
}

// deriveChunkNonce produces a per-chunk nonce by XOR-ing the base nonce with
// a big-endian uint64 chunk counter zero-padded to 12 bytes.
func deriveChunkNonce(baseNonce []byte, counter uint64) []byte {
	nonce := make([]byte, nonceLen)
	copy(nonce, baseNonce)
	var counterBuf [12]byte
	binary.BigEndian.PutUint64(counterBuf[4:], counter)
	for i := 0; i < nonceLen; i++ {
		nonce[i] ^= counterBuf[i]
	}
	return nonce
}

// EncryptData encrypts data from r and writes the encrypted output to w using
// hybrid key exchange (X25519 + ML-KEM-768) and AES-256-GCM.
//
// Output format:
//
//	"HPQENC"   (6 bytes magic header)
//	version    (1 byte)
//	suite      (1 byte)
//	chunkSize  (4 bytes)
//	lengths    (X25519, ML-KEM, nonce)
//	ctX25519   (ephemeral X25519 public key)
//	ctMLKEM    (ML-KEM-768 ciphertext)
//	baseNonce  (random)
//	[chunks...]:
//	  [uint32 BE chunk_ciphertext_len][chunk_ciphertext + GCM tag]
//	  AAD = header || "cont" for non-final chunks, header || "last" for final
func EncryptData(recipientMLKEMPub kem.PublicKey, recipientX25519Pub *ecdh.PublicKey, r io.Reader, w io.Writer) error {
	// 1. Encapsulate to derive hybrid shared secret
	ctX25519, ctMLKEM, combinedSecret, err := Encapsulate(recipientX25519Pub, recipientMLKEMPub)
	if err != nil {
		return fmt.Errorf("failed to encapsulate secrets: %w", err)
	}

	// 2. Set up AES-256-GCM
	block, err := aes.NewCipher(combinedSecret)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// 3. Generate base nonce (12 random bytes)
	baseNonce := make([]byte, nonceLen)
	if _, err := rand.Read(baseNonce); err != nil {
		return fmt.Errorf("failed to generate random nonce: %w", err)
	}

	// 4. Write authenticated, versioned header.
	header, err := buildFileHeader(ctX25519, ctMLKEM, baseNonce)
	if err != nil {
		return fmt.Errorf("failed to build encrypted file header: %w", err)
	}
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// 5. Stream plaintext in 64 KB chunks
	buf := make([]byte, chunkSize)
	var counter uint64
	var lenBuf [4]byte

	for {
		n, readErr := io.ReadFull(r, buf)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return fmt.Errorf("failed to read input: %w", readErr)
		}

		isLast := readErr == io.EOF || readErr == io.ErrUnexpectedEOF

		aadRole := chunkAADContinuation
		if isLast {
			aadRole = chunkAADFinal
		}

		chunkNonce := deriveChunkNonce(baseNonce, counter)
		sealed := gcm.Seal(nil, chunkNonce, buf[:n], chunkAAD(header, aadRole))

		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(sealed)))
		if _, err := w.Write(lenBuf[:]); err != nil {
			return fmt.Errorf("failed to write chunk length: %w", err)
		}
		if _, err := w.Write(sealed); err != nil {
			return fmt.Errorf("failed to write chunk data: %w", err)
		}

		counter++
		if isLast {
			break
		}
	}

	return nil
}

// DecryptData decrypts data from r and writes the plaintext to w using the
// recipient's private keys.
func DecryptData(recipientX25519Priv *ecdh.PrivateKey, recipientMLKEMPriv kem.PrivateKey, r io.Reader, w io.Writer) error {
	// 1. Read and verify encrypted file header.
	header, ctX25519, ctMLKEM, baseNonce, err := readFileHeader(r)
	if err != nil {
		return err
	}

	// 2. Decapsulate to recover combined secret.
	combinedSecret, err := Decapsulate(recipientX25519Priv, recipientMLKEMPriv, ctX25519, ctMLKEM)
	if err != nil {
		return fmt.Errorf("failed to decapsulate shared secret: %w", err)
	}

	// 3. Set up AES-256-GCM.
	block, err := aes.NewCipher(combinedSecret)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// 4. Decrypt chunks.
	var counter uint64
	var lenBuf [4]byte

	for {
		// Read chunk length
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return fmt.Errorf("unexpected end of file: missing final chunk")
			}
			return fmt.Errorf("failed to read chunk length: %w", err)
		}

		chunkLen := binary.BigEndian.Uint32(lenBuf[:])
		if chunkLen == 0 || chunkLen > maxEncryptedChunkLen {
			return fmt.Errorf("invalid encrypted chunk length: %d", chunkLen)
		}
		chunkData := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, chunkData); err != nil {
			return fmt.Errorf("failed to read chunk data: %w", err)
		}

		chunkNonce := deriveChunkNonce(baseNonce, counter)

		// Try decrypting as a continuation chunk first.
		plaintext, err := gcm.Open(nil, chunkNonce, chunkData, chunkAAD(header, chunkAADContinuation))
		if err != nil {
			// Try as the final chunk.
			plaintext, err = gcm.Open(nil, chunkNonce, chunkData, chunkAAD(header, chunkAADFinal))
			if err != nil {
				return fmt.Errorf("failed to decrypt chunk %d: authentication failed", counter)
			}
			// Final chunk — write plaintext and verify no trailing data
			if len(plaintext) > 0 {
				if _, err := w.Write(plaintext); err != nil {
					return fmt.Errorf("failed to write plaintext: %w", err)
				}
			}
			// Check that nothing follows the final chunk
			trailing := make([]byte, 1)
			n, _ := r.Read(trailing)
			if n > 0 {
				return fmt.Errorf("unexpected data after final chunk")
			}
			return nil
		}

		// Non-final chunk
		if len(plaintext) > 0 {
			if _, err := w.Write(plaintext); err != nil {
				return fmt.Errorf("failed to write plaintext: %w", err)
			}
		}
		counter++
	}
}
