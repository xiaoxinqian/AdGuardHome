package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	KeySize     = 32
	NonceSize   = 12
	KeyFileName = "security.key"
)

var (
	ErrInvalidKeySize   = errors.New("invalid key size: must be 32 bytes")
	ErrInvalidCipher    = errors.New("invalid ciphertext: too short")
	ErrDecryptionFailed = errors.New("decryption failed")
)

type EncryptedStore struct {
	key     []byte
	keyPath string
}

func NewEncryptedStore(dataDir string) (*EncryptedStore, error) {
	keyPath := filepath.Join(dataDir, KeyFileName)

	key, err := loadOrGenerateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading or generating key: %w", err)
	}

	return &EncryptedStore{
		key:     key,
		keyPath: keyPath,
	}, nil
}

func loadOrGenerateKey(keyPath string) ([]byte, error) {
	if keyData, err := os.ReadFile(keyPath); err == nil {
		key, err := base64.StdEncoding.DecodeString(string(keyData))
		if err != nil {
			return nil, fmt.Errorf("decoding key: %w", err)
		}
		if len(key) != KeySize {
			return nil, ErrInvalidKeySize
		}
		return key, nil
	}

	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	keyData := base64.StdEncoding.EncodeToString(key)
	if err := os.WriteFile(keyPath, []byte(keyData), 0600); err != nil {
		return nil, fmt.Errorf("writing key file: %w", err)
	}

	return key, nil
}

func (es *EncryptedStore) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(es.key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (es *EncryptedStore) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(es.key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidCipher
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

func (es *EncryptedStore) EncryptString(plaintext string) (string, error) {
	ciphertext, err := es.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (es *EncryptedStore) DecryptString(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decoding base64: %w", err)
	}
	plaintext, err := es.Decrypt(data)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (es *EncryptedStore) Store(path string, data []byte) error {
	encrypted, err := es.Encrypt(data)
	if err != nil {
		return fmt.Errorf("encrypting data: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	if err := os.WriteFile(path, encrypted, 0600); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	return nil
}

func (es *EncryptedStore) Load(path string) ([]byte, error) {
	encrypted, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	data, err := es.Decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypting data: %w", err)
	}

	return data, nil
}

func (es *EncryptedStore) KeyPath() string {
	return es.keyPath
}
