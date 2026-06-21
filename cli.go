// cli.go
package main

import (
	"crypto/ecdh"
	"flag"
	"fmt"
	"os"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// RunCLI parses command-line arguments and routes them to the correct crypto actions
func RunCLI() {
	// Define CLI modes
	encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	genKeysCmd := flag.NewFlagSet("gen-keys", flag.ExitOnError)

	// Flags for encryption mode
	encFileFlag := encryptCmd.String("file", "", "Path to the file you want to encrypt")

	// Flags for decryption mode
	decFileFlag := decryptCmd.String("file", "", "Path to the .enc file you want to decrypt")

	// Check if the user provided a subcommand
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
		if *encFileFlag == "" {
			fmt.Println("Error: Please provide a file path using the -file flag.")
			encryptCmd.Usage()
			os.Exit(1)
		}
		handleEncryption(*encFileFlag)

	case "decrypt":
		decryptCmd.Parse(os.Args[2:])
		if *decFileFlag == "" {
			fmt.Println("Error: Please provide a file path using the -file flag.")
			decryptCmd.Usage()
			os.Exit(1)
		}
		handleDecryption(*decFileFlag)

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: hybrid-encryptor <command> [arguments]")
	fmt.Println("\nAvailable Commands:")
	fmt.Println("  gen-keys   Generate a fresh pair of local hybrid public/private keys")
	fmt.Println("  encrypt    Encrypt a local file using post-quantum hybrid math")
	fmt.Println("  decrypt    Decrypt a protected .enc file")
	fmt.Println("\nExample:")
	fmt.Println("  go run . encrypt -file document.txt")
}

// Stub handlers for files - we will link these with your crypto functions in main.go
func handleKeyGeneration() {
	fmt.Println("Generating your persistent hybrid keypair...")
	keys, err := GenerateHybridKeyPair()
	if err != nil {
		fmt.Printf("Failed to generate keys: %v\n", err)
		return
	}

	// For testing the CLI, we'll write down that we made them.
	// In a full app, you would save these to files like 'id_hybrid' and 'id_hybrid.pub'
	fmt.Printf("✓ Success! Generated X25519 and ML-KEM keys.\n")
	fmt.Printf("Public keys are ready to receive encrypted assets!\n")
	_ = keys // Keep compiler happy
}

func handleEncryption(filePath string) {
	fmt.Printf("Reading %s for encryption...\n", filePath)

	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Failed to read file: %v\n", err)
		return
	}

	// We generate an on-the-fly recipient keypair just to simulate encrypting for yourself
	mockRecipient, err := GenerateHybridKeyPair()
	if err != nil {
		fmt.Printf("Crypto initialization failure: %v\n", err)
		return
	}

	// Call our crypto package logic from Step 3
	ciphertext, err := EncryptData(mockRecipient.MLKEMPublic, mockRecipient.X25519Public, plaintext)
	if err != nil {
		fmt.Printf("Encryption failed: %v\n", err)
		return
	}

	outPath := filePath + ".enc"
	err = os.WriteFile(outPath, ciphertext, 0644)
	if err != nil {
		fmt.Printf("Failed to save encrypted file: %v\n", err)
		return
	}

	fmt.Printf("🔒 Secure file created successfully at: %s\n", outPath)

	// Temporary: For this demo, let's save the private key so you can immediately test decryption
	// We append '.key' to simulate possessing the private key package.
	mlkemPrivBytes, err := mockRecipient.MLKEMPrivate.MarshalBinary()
	if err != nil {
		fmt.Printf("Failed to marshal ML-KEM private key: %v\n", err)
		return
	}

	mockPrivBytes := append(mockRecipient.X25519Private.Bytes(), mlkemPrivBytes...)
	err = os.WriteFile(filePath+".key", mockPrivBytes, 0600)
	if err != nil {
		fmt.Printf("Failed to save private key file: %v\n", err)
		return
	}
	fmt.Println("👉 (Demo Mode Key saved to disk so you can run the decrypt command next!)")
}

func handleDecryption(filePath string) {
	fmt.Printf("Opening protected file: %s...\n", filePath)
	
	ciphertext, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Failed to read file: %v\n", err)
		return
	}

	// Determine key file path
	keyPath := filePath
	if len(filePath) > 4 && filePath[len(filePath)-4:] == ".enc" {
		keyPath = filePath[:len(filePath)-4] + ".key"
	} else {
		keyPath = filePath + ".key"
	}

	fmt.Printf("Loading private keys from %s...\n", keyPath)
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Printf("Failed to read key file: %v\n", err)
		return
	}

	if len(keyBytes) < 32 {
		fmt.Printf("Error: Key file is too small or corrupted\n")
		return
	}

	x25519PrivBytes := keyBytes[:32]
	mlkemPrivBytes := keyBytes[32:]

	// 1. Reconstruct X25519 Private Key
	x25519Priv, err := ecdh.X25519().NewPrivateKey(x25519PrivBytes)
	if err != nil {
		fmt.Printf("Failed to parse X25519 private key: %v\n", err)
		return
	}

	// 2. Reconstruct ML-KEM Private Key
	mlkemPriv, err := mlkem768.Scheme().UnmarshalBinaryPrivateKey(mlkemPrivBytes)
	if err != nil {
		fmt.Printf("Failed to parse ML-KEM private key: %v\n", err)
		return
	}

	fmt.Println("🔓 Processing cryptographic header bytes and decapsulating...")
	
	// 3. Decrypt the data using our crypto package logic
	plaintext, err := DecryptData(x25519Priv, mlkemPriv, ciphertext)
	if err != nil {
		fmt.Printf("Decryption failed: %v\n", err)
		return
	}

	// Save the decrypted file by removing ".enc" or appending ".dec"
	outPath := filePath
	if len(filePath) > 4 && filePath[len(filePath)-4:] == ".enc" {
		outPath = filePath[:len(filePath)-4]
	} else {
		outPath = filePath + ".dec"
	}

	err = os.WriteFile(outPath, plaintext, 0644)
	if err != nil {
		fmt.Printf("Failed to save decrypted file: %v\n", err)
		return
	}

	fmt.Printf("🔓 Decrypted file successfully created at: %s\n", outPath)
	fmt.Printf("Decrypted plaintext content:\n---\n%s---\n", string(plaintext))
}
