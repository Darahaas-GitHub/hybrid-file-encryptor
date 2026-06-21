// crypto_test.go
package main

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
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

	// Copy ciphertext and flip a byte in the encrypted chunk payload.
	// Header layout: magic(6) + ctX25519(32) + ctMLKEM(1088) + nonce(12) + chunkLen(4) = 1142
	// Byte 1150 is well inside the first chunk's ciphertext data.
	tampered := make([]byte, cipherBuf.Len())
	copy(tampered, cipherBuf.Bytes())
	if len(tampered) > 1150 {
		tampered[1150] ^= 0xFF
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
