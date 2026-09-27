package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run encrypt_config.go <options.yml>")
		os.Exit(1)
	}

	plaintext, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	passphrase := "YourSuperSecretPassphraseChangeMeNow!@#2026"

	key := sha256.Sum256([]byte(passphrase))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	err = os.WriteFile("cmd/options.enc", []byte(encoded), 0644)
	if err != nil {
		panic(err)
	}

	fmt.Println("[+] Encrypted config written to cmd/options.enc")
}
