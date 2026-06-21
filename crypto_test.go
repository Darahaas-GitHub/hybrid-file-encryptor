// crypto_test.go
package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	keys, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	plaintext := []byte("The quick brown fox jumps over the lazy dog.")

	var cipherBuf bytes.Buffer
	err = EncryptData(keys.MLKEMPublic, keys.X25519Public, bytes.NewReader(plaintext), &cipherBuf)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	var plainBuf bytes.Buffer
	err = DecryptData(keys.X25519Private, keys.MLKEMPrivate, bytes.NewReader(cipherBuf.Bytes()), &plainBuf)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(plainBuf.Bytes(), plaintext) {
		t.Fatalf("plaintext mismatch:\ngot:  %q\nwant: %q", plainBuf.Bytes(), plaintext)
	}
}

func TestTamperDetection(t *testing.T) {
	keys, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	plaintext := []byte("Sensitive data that must not be tampered with.")

	var cipherBuf bytes.Buffer
	err = EncryptData(keys.MLKEMPublic, keys.X25519Public, bytes.NewReader(plaintext), &cipherBuf)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Copy ciphertext and flip a byte in the first encrypted chunk.
	tampered := make([]byte, cipherBuf.Len())
	copy(tampered, cipherBuf.Bytes())
	headerLen := len(fileMagic) + 1 + 1 + 4 + 2 + 2 + 1 + x25519CtLen + mlkem768.Scheme().CiphertextSize() + nonceLen
	tamperOffset := headerLen + 4
	if len(tampered) > tamperOffset {
		tampered[tamperOffset] ^= 0xFF
	} else {
		t.Fatal("ciphertext unexpectedly short")
	}

	var plainBuf bytes.Buffer
	err = DecryptData(keys.X25519Private, keys.MLKEMPrivate, bytes.NewReader(tampered), &plainBuf)
	if err == nil {
		t.Fatal("expected decryption to fail on tampered ciphertext, but it succeeded")
	}
}

func TestMagicHeaderValidation(t *testing.T) {
	keys, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	// Data that does not start with the HFPQV1 magic header.
	badData := bytes.Repeat([]byte{0x00}, 2000)

	var plainBuf bytes.Buffer
	err = DecryptData(keys.X25519Private, keys.MLKEMPrivate, bytes.NewReader(badData), &plainBuf)
	if err == nil {
		t.Fatal("expected error for missing magic header, but got nil")
	}
	if !strings.Contains(err.Error(), "magic header") {
		t.Fatalf("expected error mentioning 'magic header', got: %v", err)
	}
}

func TestHeaderTamperDetection(t *testing.T) {
	keys, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	var cipherBuf bytes.Buffer
	err = EncryptData(keys.MLKEMPublic, keys.X25519Public, bytes.NewReader([]byte("header-bound data")), &cipherBuf)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	tampered := append([]byte(nil), cipherBuf.Bytes()...)
	tampered[len(fileMagic)+1] ^= 0x01 // suite byte

	var plainBuf bytes.Buffer
	err = DecryptData(keys.X25519Private, keys.MLKEMPrivate, bytes.NewReader(tampered), &plainBuf)
	if err == nil {
		t.Fatal("expected header tampering to fail")
	}
}

func TestWrongPrivateKeyFails(t *testing.T) {
	recipient, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("recipient key generation failed: %v", err)
	}
	wrongRecipient, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("wrong key generation failed: %v", err)
	}

	var cipherBuf bytes.Buffer
	err = EncryptData(recipient.MLKEMPublic, recipient.X25519Public, bytes.NewReader([]byte("secret")), &cipherBuf)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	var plainBuf bytes.Buffer
	err = DecryptData(wrongRecipient.X25519Private, wrongRecipient.MLKEMPrivate, bytes.NewReader(cipherBuf.Bytes()), &plainBuf)
	if err == nil {
		t.Fatal("expected decryption with the wrong private key to fail")
	}
}

func TestLargeFileRoundTrip(t *testing.T) {
	keys, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	// 5 MB of random data — exercises multiple 64 KB chunks.
	plaintext := make([]byte, 5*1024*1024)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	var cipherBuf bytes.Buffer
	err = EncryptData(keys.MLKEMPublic, keys.X25519Public, bytes.NewReader(plaintext), &cipherBuf)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	var plainBuf bytes.Buffer
	err = DecryptData(keys.X25519Private, keys.MLKEMPrivate, bytes.NewReader(cipherBuf.Bytes()), &plainBuf)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(plainBuf.Bytes(), plaintext) {
		t.Fatalf("plaintext mismatch: got %d bytes, want %d bytes", plainBuf.Len(), len(plaintext))
	}
}

func TestKeyFileRejectsWrongKindAndTrailingData(t *testing.T) {
	publicFile, err := serializePlainKeyFile(keyKindPublic, bytes.Repeat([]byte{0x01}, x25519CtLen), bytes.Repeat([]byte{0x02}, mlkem768.Scheme().CiphertextSize()))
	if err != nil {
		t.Fatalf("failed to serialize public key: %v", err)
	}
	if _, _, err := parseKeyFile(publicFile, keyKindPrivate, defaultPassphraseEnv); err == nil {
		t.Fatal("expected public key parsed as private key to fail")
	}

	trailing := append(append([]byte(nil), publicFile...), 0x00)
	if _, _, err := parseKeyFile(trailing, keyKindPublic, defaultPassphraseEnv); err == nil {
		t.Fatal("expected trailing key data to fail")
	}
}

func TestEncryptedPrivateKeyRequiresPassphrase(t *testing.T) {
	const envName = "HYBRID_ENCRYPTOR_TEST_PASSPHRASE"
	t.Setenv(envName, "correct horse battery staple")

	privateFile, err := serializeEncryptedPrivateKeyFile(bytes.Repeat([]byte{0x01}, x25519CtLen), bytes.Repeat([]byte{0x02}, mlkem768.Scheme().CiphertextSize()), os.Getenv(envName))
	if err != nil {
		t.Fatalf("failed to serialize encrypted private key: %v", err)
	}
	x25519Bytes, mlkemBytes, err := parseKeyFile(privateFile, keyKindPrivate, envName)
	if err != nil {
		t.Fatalf("failed to parse encrypted private key: %v", err)
	}
	if len(x25519Bytes) != x25519CtLen || len(mlkemBytes) != mlkem768.Scheme().CiphertextSize() {
		t.Fatal("unexpected encrypted private key material lengths")
	}

	t.Setenv(envName, "wrong passphrase")
	if _, _, err := parseKeyFile(privateFile, keyKindPrivate, envName); err == nil {
		t.Fatal("expected wrong passphrase to fail")
	}
}
