package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

var (
	encryptionKey []byte
	ErrKeyNotSet  = errors.New("encryption key not set")
)

func SetEncryptionKey(key string) error {
	if key == "" {
		return errors.New("encryption key cannot be empty")
	}
	if len(key) < 32 {
		return errors.New("encryption key must be at least 32 characters")
	}
	sum := sha256.Sum256([]byte(key))
	encryptionKey = sum[:]
	return nil
}

func IsKeySet() bool {
	return encryptionKey != nil
}

func EncryptSecret(plaintext string) (string, error) {
	if encryptionKey == nil {
		return "", ErrKeyNotSet
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptSecret(ciphertext string) (string, error) {
	if encryptionKey == nil {
		return "", ErrKeyNotSet
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, cipherData := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
