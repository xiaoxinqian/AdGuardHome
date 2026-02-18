package home

import (
	"os"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/crypto"
)

func TestTOTPGenerateSecret(t *testing.T) {
	svc := NewTOTPService(&TOTPServiceConfig{
		Issuer: "AdGuardHome",
	})

	secret, err := svc.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	if len(secret) != 32 {
		t.Errorf("secret length = %d, want 32", len(secret))
	}
}

func TestTOTPValidate(t *testing.T) {
	svc := NewTOTPService(&TOTPServiceConfig{
		Issuer: "AdGuardHome",
	})

	secret, err := svc.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	if err := svc.SetSecret(secret); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	if !svc.IsEnabled() {
		t.Error("IsEnabled should return true after setting secret")
	}
}

func TestTOTPGenerateQRCode(t *testing.T) {
	svc := NewTOTPService(&TOTPServiceConfig{
		Issuer: "AdGuardHome",
	})

	secret, err := svc.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	if err := svc.SetSecret(secret); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	qrCode, err := svc.GenerateQRCode("admin")
	if err != nil {
		t.Fatalf("GenerateQRCode: %v", err)
	}

	if len(qrCode) == 0 {
		t.Error("QR code is empty")
	}
}

func TestTOTPEncryptedSecret(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "totp-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	encryptor, err := NewTestEncryptor(tmpDir)
	if err != nil {
		t.Fatalf("NewTestEncryptor: %v", err)
	}

	svc := NewTOTPService(&TOTPServiceConfig{
		Issuer:    "AdGuardHome",
		Encryptor: encryptor,
	})

	secret, err := svc.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	if err := svc.SetSecret(secret); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	encrypted, err := svc.GetEncryptedSecret()
	if err != nil {
		t.Fatalf("GetEncryptedSecret: %v", err)
	}

	if encrypted == secret {
		t.Error("encrypted secret should not equal plaintext secret")
	}

	svc2 := NewTOTPService(&TOTPServiceConfig{
		Issuer:    "AdGuardHome",
		Encryptor: encryptor,
	})

	if err := svc2.SetEncryptedSecret(encrypted); err != nil {
		t.Fatalf("SetEncryptedSecret: %v", err)
	}

	if !svc2.IsEnabled() {
		t.Error("svc2 should be enabled after setting encrypted secret")
	}
}

func TestTOTPNotEnabled(t *testing.T) {
	svc := NewTOTPService(&TOTPServiceConfig{
		Issuer: "AdGuardHome",
	})

	_, err := svc.Validate("123456")
	if err != ErrTOTPNotEnabled {
		t.Errorf("Validate error = %v, want %v", err, ErrTOTPNotEnabled)
	}

	_, err = svc.GenerateQRCode("admin")
	if err != ErrTOTPNotEnabled {
		t.Errorf("GenerateQRCode error = %v, want %v", err, ErrTOTPNotEnabled)
	}
}

func TestTOTPDisable(t *testing.T) {
	svc := NewTOTPService(&TOTPServiceConfig{
		Issuer: "AdGuardHome",
	})

	secret, err := svc.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	if err := svc.SetSecret(secret); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	if !svc.IsEnabled() {
		t.Error("IsEnabled should return true")
	}

	svc.Disable()

	if svc.IsEnabled() {
		t.Error("IsEnabled should return false after disable")
	}
}

func TestTOTPLockout(t *testing.T) {
	svc := NewTOTPService(&TOTPServiceConfig{
		Issuer:      "AdGuardHome",
		MaxAttempts: 3,
	})

	secret, err := svc.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	if err := svc.SetSecret(secret); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	clientIP := "192.168.1.100"

	for i := 0; i < 3; i++ {
		svc.ValidateWithTracking("000000", clientIP)
	}

	if !svc.IsLocked(clientIP) {
		t.Error("client should be locked after 3 failed attempts")
	}

	svc.clearFailedAttempts(clientIP)

	if svc.IsLocked(clientIP) {
		t.Error("client should not be locked after clearing attempts")
	}
}

func NewTestEncryptor(dataDir string) (*crypto.EncryptedStore, error) {
	return crypto.NewEncryptedStore(dataDir)
}
