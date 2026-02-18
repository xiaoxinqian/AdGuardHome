package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestNewEncryptedStore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := NewEncryptedStore(tmpDir)
	if err != nil {
		t.Fatalf("NewEncryptedStore: %v", err)
	}

	if store == nil {
		t.Fatal("store is nil")
	}

	if len(store.key) != KeySize {
		t.Errorf("key size = %d, want %d", len(store.key), KeySize)
	}

	keyPath := filepath.Join(tmpDir, KeyFileName)
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("key file was not created")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := NewEncryptedStore(tmpDir)
	if err != nil {
		t.Fatalf("NewEncryptedStore: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"single byte", []byte{0x00}},
		{"short", []byte("hello")},
		{"medium", []byte("The quick brown fox jumps over the lazy dog")},
		{"binary", []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}},
		{"long", make([]byte, 1024)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := store.Encrypt(tt.data)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			if bytes.Equal(tt.data, encrypted) {
				t.Error("encrypted data is same as plaintext")
			}

			decrypted, err := store.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if !bytes.Equal(tt.data, decrypted) {
				t.Errorf("decrypted data mismatch\ngot:  %v\nwant: %v", decrypted, tt.data)
			}
		})
	}
}

func TestEncryptDecryptString(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := NewEncryptedStore(tmpDir)
	if err != nil {
		t.Fatalf("NewEncryptedStore: %v", err)
	}

	plaintext := "my-secret-totp-key"
	encrypted, err := store.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	if plaintext == encrypted {
		t.Error("encrypted string is same as plaintext")
	}

	decrypted, err := store.DecryptString(encrypted)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("decrypted string = %q, want %q", decrypted, plaintext)
	}
}

func TestStoreAndLoad(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := NewEncryptedStore(tmpDir)
	if err != nil {
		t.Fatalf("NewEncryptedStore: %v", err)
	}

	data := []byte("sensitive configuration data")
	storePath := filepath.Join(tmpDir, "secrets", "config.enc")

	if err := store.Store(storePath, data); err != nil {
		t.Fatalf("Store: %v", err)
	}

	loaded, err := store.Load(storePath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !bytes.Equal(data, loaded) {
		t.Errorf("loaded data mismatch\ngot:  %s\nwant: %s", loaded, data)
	}
}

func TestDecryptInvalidData(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := NewEncryptedStore(tmpDir)
	if err != nil {
		t.Fatalf("NewEncryptedStore: %v", err)
	}

	_, err = store.Decrypt([]byte("too short"))
	if err != ErrInvalidCipher {
		t.Errorf("Decrypt error = %v, want %v", err, ErrInvalidCipher)
	}

	_, err = store.Decrypt([]byte("this is definitely not valid encrypted data for sure"))
	if err == nil {
		t.Error("Decrypt should fail with invalid data")
	}
}

func TestKeyReuse(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store1, err := NewEncryptedStore(tmpDir)
	if err != nil {
		t.Fatalf("NewEncryptedStore (1): %v", err)
	}

	encrypted, err := store1.Encrypt([]byte("test data"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	store2, err := NewEncryptedStore(tmpDir)
	if err != nil {
		t.Fatalf("NewEncryptedStore (2): %v", err)
	}

	decrypted, err := store2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if string(decrypted) != "test data" {
		t.Errorf("decrypted = %q, want %q", decrypted, "test data")
	}
}

func TestDifferentKeys(t *testing.T) {
	tmpDir1, err := os.MkdirTemp("", "crypto-test-1")
	if err != nil {
		t.Fatalf("creating temp dir 1: %v", err)
	}
	defer os.RemoveAll(tmpDir1)

	tmpDir2, err := os.MkdirTemp("", "crypto-test-2")
	if err != nil {
		t.Fatalf("creating temp dir 2: %v", err)
	}
	defer os.RemoveAll(tmpDir2)

	store1, err := NewEncryptedStore(tmpDir1)
	if err != nil {
		t.Fatalf("NewEncryptedStore (1): %v", err)
	}

	store2, err := NewEncryptedStore(tmpDir2)
	if err != nil {
		t.Fatalf("NewEncryptedStore (2): %v", err)
	}

	encrypted, err := store1.Encrypt([]byte("test data"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = store2.Decrypt(encrypted)
	if err == nil {
		t.Error("Decrypt should fail with different key")
	}
}
