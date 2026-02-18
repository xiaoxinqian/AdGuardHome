package home

import (
	"errors"
	"strings"
	"unicode"
)

const (
	DefaultMinLength    = 12
	DefaultSpecialChars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"
)

var (
	ErrPasswordTooShort  = errors.New("password must be at least 12 characters")
	ErrPasswordNoUpper   = errors.New("password must contain at least one uppercase letter")
	ErrPasswordNoLower   = errors.New("password must contain at least one lowercase letter")
	ErrPasswordNoDigit   = errors.New("password must contain at least one digit")
	ErrPasswordNoSpecial = errors.New("password must contain at least one special character")
)

type PasswordPolicy struct {
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireDigit   bool
	RequireSpecial bool
	SpecialChars   string
}

type PasswordPolicyConfig struct {
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireDigit   bool
	RequireSpecial bool
	SpecialChars   string
}

func NewDefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:      DefaultMinLength,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: true,
		SpecialChars:   DefaultSpecialChars,
	}
}

func NewPasswordPolicy(conf *PasswordPolicyConfig) *PasswordPolicy {
	p := &PasswordPolicy{
		MinLength:      conf.MinLength,
		RequireUpper:   conf.RequireUpper,
		RequireLower:   conf.RequireLower,
		RequireDigit:   conf.RequireDigit,
		RequireSpecial: conf.RequireSpecial,
		SpecialChars:   conf.SpecialChars,
	}

	if p.MinLength == 0 {
		p.MinLength = DefaultMinLength
	}
	if p.SpecialChars == "" {
		p.SpecialChars = DefaultSpecialChars
	}

	return p
}

func (p *PasswordPolicy) Validate(password string) error {
	var errs []error

	if len(password) < p.MinLength {
		errs = append(errs, ErrPasswordTooShort)
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case strings.ContainsRune(p.SpecialChars, r):
			hasSpecial = true
		}
	}

	if p.RequireUpper && !hasUpper {
		errs = append(errs, ErrPasswordNoUpper)
	}
	if p.RequireLower && !hasLower {
		errs = append(errs, ErrPasswordNoLower)
	}
	if p.RequireDigit && !hasDigit {
		errs = append(errs, ErrPasswordNoDigit)
	}
	if p.RequireSpecial && !hasSpecial {
		errs = append(errs, ErrPasswordNoSpecial)
	}

	if len(errs) == 0 {
		return nil
	}

	return &PasswordPolicyError{Errors: errs}
}

func (p *PasswordPolicy) ValidateSimple(password string) bool {
	return p.Validate(password) == nil
}

type PasswordPolicyError struct {
	Errors []error
}

func (e *PasswordPolicyError) Error() string {
	if len(e.Errors) == 0 {
		return "password policy error"
	}

	var msgs []string
	for _, err := range e.Errors {
		msgs = append(msgs, err.Error())
	}

	return strings.Join(msgs, "; ")
}

func (e *PasswordPolicyError) GetErrors() []error {
	return e.Errors
}

func ValidatePasswordDefault(password string) error {
	return NewDefaultPasswordPolicy().Validate(password)
}
