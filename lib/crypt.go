package lib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// GenerateHash takes a string and hashType. Based on hashType calls the
// respected function or returns an error that the hashType isn't supported
func GenerateHash(s []byte, hashType string) (string, error) {
	switch hashType {
	case "sha512":
		return GenerateSHA512(s), nil
	default:
		return "", fmt.Errorf("[!] GenerateHash: %s not supported", hashType)
	}
}

// GenerateSHA512 takes a string, generates a SHA512 hash
// and sends back as hex string
func GenerateSHA512(s []byte) string {
	sha := sha512.New()
	sha.Write(s)

	return hex.EncodeToString(sha.Sum(nil))
}

// AESEncrypt https://golang.org/src/crypto/cipher/example_test.go
// Returns base64 encoded ciphertext and base64 encoded IV
// Not returning both (iv:ciphertext) as includes too much js/vbs to detach
func AESEncrypt(key, text []byte) (string, string, error) {
	plaintext, err := pkcs7Pad(text)
	if err != nil {
		return "", "", err
	}

	if len(plaintext)%aes.BlockSize != 0 {
		return "", "", fmt.Errorf("[!] AESEncrypt: plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return Base64Encode(ciphertext[aes.BlockSize:]), Base64Encode(iv), nil
}

// https://github.com/go-web/tokenizer/blob/master/pkcs7.go
func pkcs7Pad(b []byte) ([]byte, error) {
	if aes.BlockSize <= 0 {
		return nil, fmt.Errorf("[!] pkcs7Pad: invalid blocksize")
	}
	if b == nil || len(b) == 0 {
		return nil, fmt.Errorf("[!] pkcs7Pad: invalid PKCS7 data (empty or not padded)")
	}
	n := aes.BlockSize - (len(b) % aes.BlockSize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

// Base64Encode basic wrapper around base64 encoding
func Base64Encode(data []byte) string {
	sEnc := base64.StdEncoding.EncodeToString(data)
	return sEnc
}
