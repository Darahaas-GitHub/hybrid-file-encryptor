// cli.go
package main

import (
	"crypto/ecdh"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// keyFileMagic identifies hybrid key files.
const keyFileMagic = "HFPQV1"

// RunCLI parses command-line arguments and routes them to the correct handlers.
func RunCLI() {
	encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	genKeysCmd := flag.NewFlagSet("gen-keys", flag.ExitOnError)

	// Encrypt flags
	encFileFlag := encryptCmd.String("file", "", "Path to the file to encrypt")
	encPubkeyFlag := encryptCmd.String("pubkey", "", "Path to the recipient's public key file (.pub)")

	// Decrypt flags
	decFileFlag := decryptCmd.String("file", "", "Path to the .enc file to decrypt")
	decPrivkeyFlag := decryptCmd.String("privkey", "", "Path to the private key file")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "gen-keys":
		genKeysCmd.Parse(os.Args[2:])
		handleKeyGeneration()

	case "encrypt":
		encryptCmd.Parse(os.Args[2:])
		if *encFileFlag == "" || *encPubkeyFlag == "" {
			fmt.Println("Error: Both -file and -pubkey flags are required.")
			encryptCmd.Usage()
			os.Exit(1)
		}
		handleEncryption(*encFileFlag, *encPubkeyFlag)

	case "decrypt":
		decryptCmd.Parse(os.Args[2:])
		if *decFileFlag == "" || *decPrivkeyFlag == "" {
			fmt.Println("Error: Both -file and -privkey flags are required.")
			decryptCmd.Usage()
			os.Exit(1)
		}
		handleDecryption(*decFileFlag, *decPrivkeyFlag)

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: hybrid-encryptor <command> [arguments]")
	fmt.Println("\nAvailable Commands:")
	fmt.Println("  gen-keys   Generate a hybrid X25519 + ML-KEM-768 keypair")
	fmt.Println("  encrypt    Encrypt a file using a recipient's public key")
	fmt.Println("  decrypt    Decrypt a .enc file using your private key")
	fmt.Println("\nExamples:")
	fmt.Println("  hybrid-encryptor gen-keys")
	fmt.Println("  hybrid-encryptor encrypt -file document.txt -pubkey id_hybrid.pub")
	fmt.Println("  hybrid-encryptor decrypt -file document.txt.enc -privkey id_hybrid")
}

// serializeKeyFile encodes two key components into the binary key file format:
//
//	[6-byte magic "HFPQV1"][uint16 BE key1_len][key1_bytes][uint16 BE key2_len][key2_bytes]
func serializeKeyFile(key1, key2 []byte) []byte {
	buf := make([]byte, 0, len(keyFileMagic)+2+len(key1)+2+len(key2))
	buf = append(buf, []byte(keyFileMagic)...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(key1)))
	buf = append(buf, key1...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(key2)))
	buf = append(buf, key2...)
	return buf
}

// parseKeyFile reads two key components from the binary key file format.
func parseKeyFile(data []byte) (key1, key2 []byte, err error) {
	if len(data) < len(keyFileMagic) {
		return nil, nil, fmt.Errorf("key file too short")
	}
	if string(data[:len(keyFileMagic)]) != keyFileMagic {
		return nil, nil, fmt.Errorf("invalid key file: bad magic header")
	}
	data = data[len(keyFileMagic):]

	if len(data) < 2 {
		return nil, nil, fmt.Errorf("key file truncated: missing key1 length")
	}
	key1Len := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]

	if len(data) < key1Len {
		return nil, nil, fmt.Errorf("key file truncated: key1 data")
	}
	key1 = data[:key1Len]
	data = data[key1Len:]

	if len(data) < 2 {
		return nil, nil, fmt.Errorf("key file truncated: missing key2 length")
	}
	key2Len := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]

	if len(data) < key2Len {
		return nil, nil, fmt.Errorf("key file truncated: key2 data")
	}
	key2 = data[:key2Len]

	return key1, key2, nil
}

func handleKeyGeneration() {
	fmt.Println("Generating hybrid keypair...")

	keys, err := GenerateHybridKeyPair()
	if err != nil {
		fmt.Printf("Failed to generate keys: %v\n", err)
		os.Exit(1)
	}

	// Marshal ML-KEM keys to binary
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

	// Write public key: id_hybrid.pub (0644)
	pubData := serializeKeyFile(keys.X25519Public.Bytes(), mlkemPubBytes)
	if err := os.WriteFile("id_hybrid.pub", pubData, 0644); err != nil {
		fmt.Printf("Failed to write public key file: %v\n", err)
		os.Exit(1)
	}

	// Write private key: id_hybrid (0600)
	privData := serializeKeyFile(keys.X25519Private.Bytes(), mlkemPrivBytes)
	if err := os.WriteFile("id_hybrid", privData, 0600); err != nil {
		fmt.Printf("Failed to write private key file: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Keypair written to id_hybrid (private) and id_hybrid.pub (public)")
}

func handleEncryption(filePath, pubkeyPath string) {
	fmt.Printf("Encrypting %s...\n", filePath)

	// Read recipient's public key file
	pubData, err := os.ReadFile(pubkeyPath)
	if err != nil {
		fmt.Printf("Failed to read public key file: %v\n", err)
		os.Exit(1)
	}
	x25519PubBytes, mlkemPubBytes, err := parseKeyFile(pubData)
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

	// Open input file for reading
	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Failed to open input file: %v\n", err)
		os.Exit(1)
	}
	defer inFile.Close()

	// Create output file with restricted permissions (0600)
	outPath := filePath + ".enc"
	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Printf("Failed to create output file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	// Stream-encrypt into the output file
	if err := EncryptData(mlkemPub, x25519Pub, inFile, outFile); err != nil {
		fmt.Printf("Encryption failed: %v\n", err)
		os.Remove(outPath)
		os.Exit(1)
	}

	fmt.Printf("🔒 Encrypted file written to: %s\n", outPath)
}

func handleDecryption(filePath, privkeyPath string) {
	fmt.Printf("Decrypting %s...\n", filePath)

	// Read private key file
	privData, err := os.ReadFile(privkeyPath)
	if err != nil {
		fmt.Printf("Failed to read private key file: %v\n", err)
		os.Exit(1)
	}
	x25519PrivBytes, mlkemPrivBytes, err := parseKeyFile(privData)
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

	// Open encrypted file for reading
	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Failed to open encrypted file: %v\n", err)
		os.Exit(1)
	}
	defer inFile.Close()

	// Determine output path: strip .enc suffix, or append .dec
	outPath := strings.TrimSuffix(filePath, ".enc")
	if outPath == filePath {
		outPath = filePath + ".dec"
	}

	// Create output file
	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Printf("Failed to create output file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	// Stream-decrypt into the output file
	if err := DecryptData(x25519Priv, mlkemPriv, inFile, outFile); err != nil {
		fmt.Printf("Decryption failed: %v\n", err)
		os.Remove(outPath)
		os.Exit(1)
	}

	fmt.Printf("🔓 Decrypted file written to: %s\n", outPath)
}
