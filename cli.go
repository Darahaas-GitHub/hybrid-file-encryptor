// cli.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/argon2"
)

const (
	// keyFileMagic identifies hybrid key files. It is intentionally distinct
	// from encrypted data files to prevent accidental parser confusion.
	keyFileMagic   = "HPQKEY"
	keyFileVersion = byte(1)
	keyKindPublic  = byte(1)
	keyKindPrivate = byte(2)

	keyProtectionNone       = byte(0)
	keyProtectionPassphrase = byte(1)
	keyKDFArgon2id          = byte(1)

	defaultKeyName       = "id_hybrid"
	defaultPassphraseEnv = "HYBRID_ENCRYPTOR_PASSPHRASE"

	argon2Time            = uint32(3)
	argon2Memory          = uint32(64 * 1024)
	argon2Threads         = uint8(4)
	argon2KeyLen          = uint32(32)
	argon2SaltLen         = 16
	keyEncryptionNonceLen = 12
)

// RunCLI parses command-line arguments and routes them to the correct handlers.
func RunCLI() {
	encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	genKeysCmd := flag.NewFlagSet("gen-keys", flag.ExitOnError)

	keyOutDirFlag := genKeysCmd.String("out-dir", ".", "Directory for generated key files")
	keyNameFlag := genKeysCmd.String("name", defaultKeyName, "Base name for generated key files")
	keyPassEnvFlag := genKeysCmd.String("passphrase-env", defaultPassphraseEnv, "Environment variable containing a private-key passphrase")

	encFileFlag := encryptCmd.String("file", "", "Path to the file to encrypt")
	encPubkeyFlag := encryptCmd.String("pubkey", "", "Path to the recipient's public key file (.pub)")

	decFileFlag := decryptCmd.String("file", "", "Path to the .enc file to decrypt")
	decPrivkeyFlag := decryptCmd.String("privkey", "", "Path to the private key file")
	decPassEnvFlag := decryptCmd.String("passphrase-env", defaultPassphraseEnv, "Environment variable containing the private-key passphrase")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "gen-keys":
		genKeysCmd.Parse(os.Args[2:])
		handleKeyGeneration(*keyOutDirFlag, *keyNameFlag, *keyPassEnvFlag)

	case "encrypt":
		encryptCmd.Parse(os.Args[2:])
		if *encFileFlag == "" || *encPubkeyFlag == "" {
			fmt.Println("Error: both -file and -pubkey flags are required.")
			encryptCmd.Usage()
			os.Exit(1)
		}
		handleEncryption(*encFileFlag, *encPubkeyFlag)

	case "decrypt":
		decryptCmd.Parse(os.Args[2:])
		if *decFileFlag == "" || *decPrivkeyFlag == "" {
			fmt.Println("Error: both -file and -privkey flags are required.")
			decryptCmd.Usage()
			os.Exit(1)
		}
		handleDecryption(*decFileFlag, *decPrivkeyFlag, *decPassEnvFlag)

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: hybrid-encryptor <command> [arguments]")
	fmt.Println()
	fmt.Println("Available Commands:")
	fmt.Println("  gen-keys   Generate a hybrid X25519 + ML-KEM-768 keypair")
	fmt.Println("  encrypt    Encrypt a file using a recipient's public key")
	fmt.Println("  decrypt    Decrypt a .enc file using your private key")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  hybrid-encryptor gen-keys")
	fmt.Println("  hybrid-encryptor encrypt -file document.txt -pubkey id_hybrid.pub")
	fmt.Println("  hybrid-encryptor decrypt -file document.txt.enc -privkey id_hybrid")
}

func serializeKeyMaterial(key1, key2 []byte) ([]byte, error) {
	if len(key1) > 0xffff || len(key2) > 0xffff {
		return nil, fmt.Errorf("key component too large")
	}
	buf := make([]byte, 0, 2+len(key1)+2+len(key2))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(key1)))
	buf = append(buf, key1...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(key2)))
	buf = append(buf, key2...)
	return buf, nil
}

func parseKeyMaterial(data []byte) (key1, key2 []byte, err error) {
	if len(data) < 2 {
		return nil, nil, fmt.Errorf("key file truncated: missing X25519 length")
	}
	key1Len := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]

	if len(data) < key1Len {
		return nil, nil, fmt.Errorf("key file truncated: X25519 data")
	}
	key1 = data[:key1Len]
	data = data[key1Len:]

	if len(data) < 2 {
		return nil, nil, fmt.Errorf("key file truncated: missing ML-KEM length")
	}
	key2Len := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]

	if len(data) < key2Len {
		return nil, nil, fmt.Errorf("key file truncated: ML-KEM data")
	}
	key2 = data[:key2Len]
	data = data[key2Len:]
	if len(data) != 0 {
		return nil, nil, fmt.Errorf("key file has trailing data")
	}

	return key1, key2, nil
}

func serializePlainKeyFile(kind byte, key1, key2 []byte) ([]byte, error) {
	material, err := serializeKeyMaterial(key1, key2)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(keyFileMagic)+3+len(material))
	buf = append(buf, []byte(keyFileMagic)...)
	buf = append(buf, keyFileVersion, kind, keyProtectionNone)
	buf = append(buf, material...)
	return buf, nil
}

func serializeEncryptedPrivateKeyFile(key1, key2 []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("passphrase must not be empty")
	}
	material, err := serializeKeyMaterial(key1, key2)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate key-encryption salt: %w", err)
	}
	key := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create key-encryption cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create key-encryption GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate key-encryption nonce: %w", err)
	}

	aad := make([]byte, 0, len(keyFileMagic)+3+1+4+4+1+1+len(salt)+1+len(nonce)+4)
	aad = append(aad, []byte(keyFileMagic)...)
	aad = append(aad, keyFileVersion, keyKindPrivate, keyProtectionPassphrase)
	aad = append(aad, keyKDFArgon2id)
	aad = binary.BigEndian.AppendUint32(aad, argon2Time)
	aad = binary.BigEndian.AppendUint32(aad, argon2Memory)
	aad = append(aad, argon2Threads, byte(len(salt)))
	aad = append(aad, salt...)
	aad = append(aad, byte(len(nonce)))
	aad = append(aad, nonce...)
	aad = binary.BigEndian.AppendUint32(aad, uint32(len(material)+gcm.Overhead()))

	ciphertext := gcm.Seal(nil, nonce, material, aad)
	return append(aad, ciphertext...), nil
}

func parseKeyFile(data []byte, wantKind byte, passphraseEnv string) (key1, key2 []byte, err error) {
	if len(data) < len(keyFileMagic)+3 {
		return nil, nil, fmt.Errorf("key file too short")
	}
	if string(data[:len(keyFileMagic)]) != keyFileMagic {
		return nil, nil, fmt.Errorf("invalid key file: bad magic header")
	}

	offset := len(keyFileMagic)
	version, kind, protection := data[offset], data[offset+1], data[offset+2]
	offset += 3
	if version != keyFileVersion {
		return nil, nil, fmt.Errorf("unsupported key file version: %d", version)
	}
	if kind != wantKind {
		return nil, nil, fmt.Errorf("wrong key file type")
	}
	if protection == keyProtectionNone {
		return parseKeyMaterial(data[offset:])
	}
	if protection != keyProtectionPassphrase {
		return nil, nil, fmt.Errorf("unsupported key protection mode: %d", protection)
	}
	if wantKind != keyKindPrivate {
		return nil, nil, fmt.Errorf("encrypted public keys are not supported")
	}
	if len(data[offset:]) < 1+4+4+1+1 {
		return nil, nil, fmt.Errorf("encrypted key file truncated")
	}

	if data[offset] != keyKDFArgon2id {
		return nil, nil, fmt.Errorf("unsupported key KDF: %d", data[offset])
	}
	offset++
	time := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	memory := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	threads := data[offset]
	offset++
	if time != argon2Time || memory != argon2Memory || threads != argon2Threads {
		return nil, nil, fmt.Errorf("unsupported Argon2id parameters")
	}
	saltLen := int(data[offset])
	offset++
	if saltLen != argon2SaltLen {
		return nil, nil, fmt.Errorf("unsupported Argon2id salt length")
	}
	if len(data[offset:]) < saltLen+1 {
		return nil, nil, fmt.Errorf("encrypted key file truncated: salt")
	}
	salt := data[offset : offset+saltLen]
	offset += saltLen
	nonceLen := int(data[offset])
	offset++
	if nonceLen != keyEncryptionNonceLen {
		return nil, nil, fmt.Errorf("unsupported key-encryption nonce length")
	}
	if len(data[offset:]) < nonceLen+4 {
		return nil, nil, fmt.Errorf("encrypted key file truncated: nonce")
	}
	nonce := data[offset : offset+nonceLen]
	offset += nonceLen
	ciphertextLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	if len(data[offset:]) != ciphertextLen {
		return nil, nil, fmt.Errorf("encrypted key file truncated or has trailing data")
	}

	passphrase := os.Getenv(passphraseEnv)
	if passphrase == "" {
		return nil, nil, fmt.Errorf("private key is passphrase-protected; set %s", passphraseEnv)
	}
	key := argon2.IDKey([]byte(passphrase), salt, time, memory, threads, argon2KeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create key-decryption cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create key-decryption GCM: %w", err)
	}
	material, err := gcm.Open(nil, nonce, data[offset:], data[:offset])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt private key: authentication failed")
	}
	return parseKeyMaterial(material)
}

func handleKeyGeneration(outDir, keyName, passphraseEnv string) {
	fmt.Println("Generating hybrid keypair...")

	if keyName == "" {
		fmt.Println("Key name must not be empty")
		os.Exit(1)
	}
	if passphraseEnv == "" {
		fmt.Println("Passphrase environment variable name must not be empty")
		os.Exit(1)
	}
	if err := os.MkdirAll(outDir, 0700); err != nil {
		fmt.Printf("Failed to create key output directory: %v\n", err)
		os.Exit(1)
	}

	keys, err := GenerateHybridKeyPair()
	if err != nil {
		fmt.Printf("Failed to generate keys: %v\n", err)
		os.Exit(1)
	}

	mlkemPubBytes, err := keys.MLKEMPublic.MarshalBinary()
	if err != nil {
		fmt.Printf("Failed to marshal ML-KEM public key: %v\n", err)
		os.Exit(1)
	}
	mlkemPrivBytes, err := keys.MLKEMPrivate.MarshalBinary()
	if err != nil {
		fmt.Printf("Failed to marshal ML-KEM private key: %v\n", err)
		os.Exit(1)
	}

	privPath := filepath.Join(outDir, keyName)
	pubPath := privPath + ".pub"

	pubData, err := serializePlainKeyFile(keyKindPublic, keys.X25519Public.Bytes(), mlkemPubBytes)
	if err != nil {
		fmt.Printf("Failed to serialize public key: %v\n", err)
		os.Exit(1)
	}
	if err := writeNewFile(pubPath, pubData, 0644); err != nil {
		fmt.Printf("Failed to write public key file: %v\n", err)
		os.Exit(1)
	}

	passphrase := os.Getenv(passphraseEnv)
	var privData []byte
	if passphrase == "" {
		privData, err = serializePlainKeyFile(keyKindPrivate, keys.X25519Private.Bytes(), mlkemPrivBytes)
	} else {
		privData, err = serializeEncryptedPrivateKeyFile(keys.X25519Private.Bytes(), mlkemPrivBytes, passphrase)
	}
	if err != nil {
		fmt.Printf("Failed to serialize private key: %v\n", err)
		os.Exit(1)
	}
	if err := writeNewFile(privPath, privData, 0600); err != nil {
		fmt.Printf("Failed to write private key file: %v\n", err)
		os.Exit(1)
	}

	if passphrase == "" {
		fmt.Printf("Keypair written to %s (private) and %s (public). Set %s before gen-keys to encrypt the private key at rest.\n", privPath, pubPath, passphraseEnv)
		return
	}
	fmt.Printf("Passphrase-protected keypair written to %s (private) and %s (public)\n", privPath, pubPath)
}

func handleEncryption(filePath, pubkeyPath string) {
	fmt.Printf("Encrypting %s...\n", filePath)

	pubData, err := os.ReadFile(pubkeyPath)
	if err != nil {
		fmt.Printf("Failed to read public key file: %v\n", err)
		os.Exit(1)
	}
	x25519PubBytes, mlkemPubBytes, err := parseKeyFile(pubData, keyKindPublic, "")
	if err != nil {
		fmt.Printf("Invalid public key file: %v\n", err)
		os.Exit(1)
	}

	x25519Pub, err := ecdh.X25519().NewPublicKey(x25519PubBytes)
	if err != nil {
		fmt.Printf("Failed to parse X25519 public key: %v\n", err)
		os.Exit(1)
	}
	mlkemPub, err := mlkem768.Scheme().UnmarshalBinaryPublicKey(mlkemPubBytes)
	if err != nil {
		fmt.Printf("Failed to parse ML-KEM public key: %v\n", err)
		os.Exit(1)
	}

	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Failed to open input file: %v\n", err)
		os.Exit(1)
	}
	defer inFile.Close()

	outPath := filePath + ".enc"
	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("Failed to create output file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	if err := EncryptData(mlkemPub, x25519Pub, inFile, outFile); err != nil {
		fmt.Printf("Encryption failed: %v\n", err)
		_ = os.Remove(outPath)
		os.Exit(1)
	}

	fmt.Printf("Encrypted file written to: %s\n", outPath)
}

func handleDecryption(filePath, privkeyPath, passphraseEnv string) {
	fmt.Printf("Decrypting %s...\n", filePath)

	privData, err := os.ReadFile(privkeyPath)
	if err != nil {
		fmt.Printf("Failed to read private key file: %v\n", err)
		os.Exit(1)
	}
	x25519PrivBytes, mlkemPrivBytes, err := parseKeyFile(privData, keyKindPrivate, passphraseEnv)
	if err != nil {
		fmt.Printf("Invalid private key file: %v\n", err)
		os.Exit(1)
	}

	x25519Priv, err := ecdh.X25519().NewPrivateKey(x25519PrivBytes)
	if err != nil {
		fmt.Printf("Failed to parse X25519 private key: %v\n", err)
		os.Exit(1)
	}
	mlkemPriv, err := mlkem768.Scheme().UnmarshalBinaryPrivateKey(mlkemPrivBytes)
	if err != nil {
		fmt.Printf("Failed to parse ML-KEM private key: %v\n", err)
		os.Exit(1)
	}

	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Failed to open encrypted file: %v\n", err)
		os.Exit(1)
	}
	defer inFile.Close()

	outPath := strings.TrimSuffix(filePath, ".enc")
	if outPath == filePath {
		outPath = filePath + ".dec"
	}

	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("Failed to create output file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	if err := DecryptData(x25519Priv, mlkemPriv, inFile, outFile); err != nil {
		fmt.Printf("Decryption failed: %v\n", err)
		_ = os.Remove(outPath)
		os.Exit(1)
	}

	fmt.Printf("Decrypted file written to: %s\n", outPath)
}

func writeNewFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}
