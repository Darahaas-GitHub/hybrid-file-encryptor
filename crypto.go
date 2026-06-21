// crypto.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"crypto/ecdh"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// HybridKeyPair holds both classical and post-quantum public/private keys
type HybridKeyPair struct {
	X25519Private *ecdh.PrivateKey
	X25519Public  *ecdh.PublicKey
	MLKEMPrivate  *mlkem768.PrivateKey
	MLKEMPublic   *mlkem768.PublicKey
}

// EncryptData encrypts the plaintext using hybrid key exchange with the recipient's public keys.
// the output format is: ctX25519 (32 bytes) || ctMLKEM (1088 bytes) || nonce (12 bytes) || aesGcmCiphertext
func EncryptData(recipientMLKEMPub kem.PublicKey, recipientX25519Pub *ecdh.PublicKey, plaintext []byte) ([]byte, error) {
	// 1. Perform encapsulation to get the hybrid shared secret and ciphertexts
	ctX25519, ctMLKEM, combinedSecret, err := Encapsulate(recipientX25519Pub, recipientMLKEMPub)
	if err != nil {
		return nil, fmt.Errorf("failed to encapsulate secrets: %w", err)
	}

	//AES-GCM cipher
	block, err := aes.NewCipher(combinedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM block: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	encryptedPayload := gcm.Seal(nil, nonce, plaintext, nil)

	//final output: ctX25519 || ctMLKEM || nonce || encryptedPayload
	out := make([]byte, 0, len(ctX25519)+len(ctMLKEM)+len(nonce)+len(encryptedPayload))
	out = append(out, ctX25519...)
	out = append(out, ctMLKEM...)
	out = append(out, nonce...)
	out = append(out, encryptedPayload...)

	return out, nil
}

// GenerateHybridKeyPair creates a new pair of X25519 and ML-KEM-768 keys
func GenerateHybridKeyPair() (*HybridKeyPair, error) {
	//X25519 Keys (Classical)
	x25519Priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 key: %w", err)
	}

	// ML-KEM-768 Keys (Post-Quantum)
	// mlkem768 equivalent to AES-192
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

// Generate a hybrid shared secret for the receiver's public keys.
func Encapsulate(recipX25519Pub *ecdh.PublicKey, recipMLKEMPub kem.PublicKey) (ctX25519 []byte, ctMLKEM []byte, combinedSecret []byte, err error) {
	// ephemeral X25519 keys
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

	//ML-KEM secret
	scheme := mlkem768.Scheme()
	ctMLKEM, mlkemSecret, err := scheme.Encapsulate(recipMLKEMPub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encapsulate ML-KEM secret: %w", err)
	}
	combinedSecret = CombineSecrets(x25519Secret, mlkemSecret)
	return ctX25519, ctMLKEM, combinedSecret, nil
}

// CombineSecrets mixes the classical and post-quantum secrets using SHA-256
func CombineSecrets(x25519Secret, mlkemSecret []byte) []byte {
	hasher := sha256.New()
	hasher.Write(x25519Secret)
	hasher.Write(mlkemSecret)
	return hasher.Sum(nil)
}

// DecryptData decrypts a hybrid encrypted ciphertext using the recipient's private keys.
func DecryptData(recipientX25519Priv *ecdh.PrivateKey, recipientMLKEMPriv kem.PrivateKey, ciphertext []byte) ([]byte, error) {
	const (
		x25519CtLen = 32
		mlkemCtLen  = 1088
		nonceLen    = 12
		headerLen   = x25519CtLen + mlkemCtLen + nonceLen
	)

	if len(ciphertext) < headerLen {
		return nil, fmt.Errorf("ciphertext too short (must be at least %d bytes)", headerLen)
	}

	ctX25519 := ciphertext[:x25519CtLen]
	ctMLKEM := ciphertext[x25519CtLen : x25519CtLen+mlkemCtLen]
	nonce := ciphertext[x25519CtLen+mlkemCtLen : headerLen]
	encryptedPayload := ciphertext[headerLen:]

	//decapsulation to recover the combined shared secret
	combinedSecret, err := Decapsulate(recipientX25519Priv, recipientMLKEMPriv, ctX25519, ctMLKEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate shared secret: %w", err)
	}
	//AES-GCM with the combined secret
	block, err := aes.NewCipher(combinedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM block: %w", err)
	}

	//Decrypt the payload

	plaintext, err := gcm.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload (auth tag mismatch): %w", err)
	}

	return plaintext, nil
}

// Decapsulate reconstructs the hybrid shared secret key
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
	return CombineSecrets(x25519Secret, mlkemSecret), nil
}
