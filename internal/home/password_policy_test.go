package home

import (
	"strings"
	"testing"
)

func TestPasswordPolicyValidate(t *testing.T) {
	policy := NewDefaultPasswordPolicy()

	tests := []struct {
		name     string
		password string
		wantErr  bool
		errCount int
	}{
		{
			name:     "valid password",
			password: "ValidPass123!",
			wantErr:  false,
		},
		{
			name:     "too short",
			password: "Short1!",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "no uppercase",
			password: "validpass123!",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "no lowercase",
			password: "VALIDPASS123!",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "no digit",
			password: "ValidPassword!",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "no special",
			password: "ValidPassword123",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "multiple errors",
			password: "short",
			wantErr:  true,
			errCount: 4,
		},
		{
			name:     "empty",
			password: "",
			wantErr:  true,
			errCount: 5,
		},
		{
			name:     "strong password",
			password: "MyStr0ng@Password2024!",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := policy.Validate(tt.password)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				policyErr, ok := err.(*PasswordPolicyError)
				if !ok {
					t.Fatalf("expected PasswordPolicyError, got %T", err)
				}

				if len(policyErr.Errors) != tt.errCount {
					t.Errorf("error count = %d, want %d", len(policyErr.Errors), tt.errCount)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPasswordPolicyCustomConfig(t *testing.T) {
	policy := NewPasswordPolicy(&PasswordPolicyConfig{
		MinLength:      8,
		RequireUpper:   false,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: false,
	})

	if err := policy.Validate("lowercase1"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if err := policy.Validate("LOWERCASE1"); err == nil {
		t.Error("expected error for missing lowercase")
	}

	if err := policy.Validate("lowercase"); err == nil {
		t.Error("expected error for missing digit")
	}
}

func TestPasswordPolicyError(t *testing.T) {
	err := &PasswordPolicyError{
		Errors: []error{
			ErrPasswordTooShort,
			ErrPasswordNoUpper,
		},
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "12 characters") {
		t.Errorf("error message should contain '12 characters', got: %s", errStr)
	}
	if !strings.Contains(errStr, "uppercase") {
		t.Errorf("error message should contain 'uppercase', got: %s", errStr)
	}
}

func TestValidatePasswordDefault(t *testing.T) {
	if err := ValidatePasswordDefault("ValidPass123!"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if err := ValidatePasswordDefault("weak"); err == nil {
		t.Error("expected error for weak password")
	}
}
