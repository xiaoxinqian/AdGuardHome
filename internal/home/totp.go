package home

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/png"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/crypto"
	"github.com/skip2/go-qrcode"
)

const (
	TOTPSecretLength  = 20
	TOTPDefaultPeriod = 30
	TOTPDefaultDigits = 6
	TOTPDefaultWindow = 1
)

var (
	ErrTOTPNotEnabled     = errors.New("totp not enabled")
	ErrTOTPInvalidCode    = errors.New("invalid totp code")
	ErrTOTPAlreadyEnabled = errors.New("totp already enabled")
)

type TOTPConfig struct {
	Enabled bool   `yaml:"enabled"`
	Secret  string `yaml:"secret"`
	Issuer  string `yaml:"issuer"`
}

type TOTPService struct {
	secret         []byte
	encrypted      bool
	encryptor      *crypto.EncryptedStore
	issuer         string
	period         uint
	digits         uint
	windowSize     uint
	failedAttempts map[string]int
	maxAttempts    int
	mu             sync.RWMutex
}

type TOTPServiceConfig struct {
	Secret      []byte
	Encrypted   bool
	Encryptor   *crypto.EncryptedStore
	Issuer      string
	Period      uint
	Digits      uint
	WindowSize  uint
	MaxAttempts int
}

func NewTOTPService(conf *TOTPServiceConfig) *TOTPService {
	if conf.Period == 0 {
		conf.Period = TOTPDefaultPeriod
	}
	if conf.Digits == 0 {
		conf.Digits = TOTPDefaultDigits
	}
	if conf.WindowSize == 0 {
		conf.WindowSize = TOTPDefaultWindow
	}
	if conf.MaxAttempts == 0 {
		conf.MaxAttempts = 5
	}

	return &TOTPService{
		secret:         conf.Secret,
		encrypted:      conf.Encrypted,
		encryptor:      conf.Encryptor,
		issuer:         conf.Issuer,
		period:         conf.Period,
		digits:         conf.Digits,
		windowSize:     conf.WindowSize,
		failedAttempts: make(map[string]int),
		maxAttempts:    conf.MaxAttempts,
	}
}

func (t *TOTPService) GenerateSecret() (secret string, err error) {
	secretBytes := make([]byte, TOTPSecretLength)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", fmt.Errorf("generating secret: %w", err)
	}

	secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)
	return secret, nil
}

func (t *TOTPService) SetSecret(secret string) error {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	secret = strings.ReplaceAll(secret, " ", "")

	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return fmt.Errorf("decoding secret: %w", err)
	}

	t.secret = secretBytes
	return nil
}

func (t *TOTPService) SetEncryptedSecret(encryptedSecret string) error {
	if t.encryptor == nil {
		return errors.New("encryptor not configured")
	}

	secret, err := t.encryptor.DecryptString(encryptedSecret)
	if err != nil {
		return fmt.Errorf("decrypting secret: %w", err)
	}

	return t.SetSecret(secret)
}

func (t *TOTPService) GetEncryptedSecret() (string, error) {
	if len(t.secret) == 0 {
		return "", ErrTOTPNotEnabled
	}

	if t.encryptor == nil {
		return "", errors.New("encryptor not configured")
	}

	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(t.secret)
	return t.encryptor.EncryptString(secret)
}

func (t *TOTPService) Validate(code string) (bool, error) {
	if len(t.secret) == 0 {
		return false, ErrTOTPNotEnabled
	}

	code = strings.TrimSpace(code)
	if len(code) != int(t.digits) {
		return false, ErrTOTPInvalidCode
	}

	currentTime := time.Now().Unix() / int64(t.period)

	for i := -int64(t.windowSize); i <= int64(t.windowSize); i++ {
		expectedCode := t.generateCode(currentTime + i)
		if hmacEqual([]byte(expectedCode), []byte(code)) {
			return true, nil
		}
	}

	return false, ErrTOTPInvalidCode
}

func (t *TOTPService) ValidateWithTracking(code, clientIP string) (bool, error) {
	if t.IsLocked(clientIP) {
		return false, errors.New("totp locked due to too many failed attempts")
	}

	valid, err := t.Validate(code)
	if err != nil && err != ErrTOTPInvalidCode {
		return false, err
	}

	if !valid {
		t.recordFailedAttempt(clientIP)
		return false, ErrTOTPInvalidCode
	}

	t.clearFailedAttempts(clientIP)
	return true, nil
}

func (t *TOTPService) IsLocked(clientIP string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.failedAttempts[clientIP] >= t.maxAttempts
}

func (t *TOTPService) recordFailedAttempt(clientIP string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failedAttempts[clientIP]++
}

func (t *TOTPService) clearFailedAttempts(clientIP string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failedAttempts, clientIP)
}

func (t *TOTPService) generateCode(timestamp int64) string {
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(timestamp))

	mac := hmac.New(sha1.New, t.secret)
	mac.Write(counter)
	hash := mac.Sum(nil)

	if len(hash) < sha1.Size {
		return ""
	}

	offset := hash[len(hash)-1] & 0x0f
	if int(offset)+4 > len(hash) {
		return ""
	}
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	format := fmt.Sprintf("%%0%dd", t.digits)
	return fmt.Sprintf(format, code%uint32(pow10(int(t.digits))))
}

func (t *TOTPService) GenerateQRCode(accountName string) ([]byte, error) {
	if len(t.secret) == 0 {
		return nil, ErrTOTPNotEnabled
	}

	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(t.secret)
	otpURL := t.buildOTPURL(accountName, secret)

	qr, err := qrcode.Encode(otpURL, qrcode.Medium, 256)
	if err != nil {
		return nil, fmt.Errorf("generating qr code: %w", err)
	}

	return qr, nil
}

func (t *TOTPService) GenerateQRCodePNG(accountName string) (image.Image, error) {
	qrBytes, err := t.GenerateQRCode(accountName)
	if err != nil {
		return nil, err
	}

	img, err := png.Decode(bytes.NewReader(qrBytes))
	if err != nil {
		return nil, fmt.Errorf("decoding qr code png: %w", err)
	}

	return img, nil
}

func (t *TOTPService) buildOTPURL(accountName, secret string) string {
	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", t.issuer)
	params.Set("algorithm", "SHA1")
	params.Set("digits", fmt.Sprintf("%d", t.digits))
	params.Set("period", fmt.Sprintf("%d", t.period))

	return fmt.Sprintf("otpauth://totp/%s:%s?%s",
		url.PathEscape(t.issuer),
		url.PathEscape(accountName),
		params.Encode(),
	)
}

func (t *TOTPService) IsEnabled() bool {
	return len(t.secret) > 0
}

func (t *TOTPService) Disable() {
	t.secret = nil
}

func (t *TOTPService) GetSecret() string {
	if len(t.secret) == 0 {
		return ""
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(t.secret)
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

func pow10(n int) int {
	result := 1
	for i := 0; i < n; i++ {
		result *= 10
	}
	return result
}
