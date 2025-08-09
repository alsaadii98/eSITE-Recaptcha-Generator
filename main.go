package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
)

var (
	aesKey, _ = base64.StdEncoding.DecodeString("szqC6Qw5k7o2ztNcJsiDBbT+bKqHRF8kUCSVbjw3QKA=")
)

func pkcs5Padding(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

func encryptAES(plaintext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	padded := pkcs5Padding(plaintext, block.BlockSize())

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	finalData := append(iv, ciphertext...)
	return base64.StdEncoding.EncodeToString(finalData), nil
}

func main() {
	data := map[string]interface{}{
		"id":               "UE1A." + time.Now().Format("060102.150405"), // dynamic id with date-time
		"type":             "user",
		"brand":            "ali",
		"model":            "sdk_gphone64_x86_64",
		"nonce":            uuid.New().String(), // new UUID each run
		"device":           "emu64xa",
		"display":          "UE1A." + time.Now().Format("060102.150405"),
		"product":          "sdk_gphone64_x86_64",
		"platform":         "android",
		"timestamp":        fmt.Sprintf("%d", time.Now().UnixMilli()), // current timestamp in ms
		"manufacturer":     "Google",
		"serialNumber":     "unknown",
		"version.baseOS":   "",
		"isPhysicalDevice": true,
		"version.codename": "REL",
	}

	prettyJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		panic(err)
	}

	encrypted, err := encryptAES(prettyJSON, aesKey)
	if err != nil {
		panic(err)
	}

	fmt.Println("──────────────────────────────────────────────")
	fmt.Println("Encrypted Data (Base64):")
	fmt.Println("──────────────────────────────────────────────")
	fmt.Println(encrypted)
	fmt.Println("──────────────────────────────────────────────")
	fmt.Println("Copy the above Base64 string for use.")
	fmt.Println("──────────────────────────────────────────────")
}
