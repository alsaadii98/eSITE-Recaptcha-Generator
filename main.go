package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	// AES key (decoded from Java Base64 string)
	aesKey, _ = base64.StdEncoding.DecodeString("szqC6Qw5k7o2ztNcJsiDBbT+bKqHRF8kUCSVbjw3QKA=")
	// IV (decoded from Java Base64 string)
	iv, _ = base64.StdEncoding.DecodeString("+u2aDBSnkxq7ESAcy433JA==")
)

func pkcs5Padding(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

func encryptAES(plaintext []byte, key []byte, iv []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	padded := pkcs5Padding(plaintext, block.BlockSize())

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func main() {
	data := map[string]interface{}{
		"id":               "UE1A.230829.036.A4",
		"type":             "user",
		"brand":            "Google Pixel",
		"model":            "sdk_gphone64_x86_64",
		"nonce":            uuid.New().String(),
		"device":           "emu64xa",
		"display":          "UE1A.230829.036.A4",
		"product":          "sdk_gphone64_x86_64",
		"platform":         "android",
		"timestamp":        fmt.Sprintf("%d", time.Now().UnixMilli()),
		"manufacturer":     "Google",
		"serialNumber":     "unknown",
		"version.baseOS":   "",
		"isPhysicalDevice": true,
		"version.codename": "REL",
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	// Encrypt
	encrypted, err := encryptAES(jsonData, aesKey, iv)
	if err != nil {
		panic(err)
	}

	fmt.Println("──────────────────────────────────────────────")
	fmt.Println("Encrypted Data (Base64):")
	fmt.Println("This value is generated to bypass the reCAPTCHA in the 'eSITE-Authentication-MicroService'")
	fmt.Println("──────────────────────────────────────────────")
	fmt.Println(encrypted)
	fmt.Println("──────────────────────────────────────────────")
}
