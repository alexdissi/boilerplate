package validator

import (
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

type testPassword struct {
	Password string `validate:"strongpassword"`
}

func TestValidateStrongPassword(t *testing.T) {
	v := validator.New()
	RegisterPasswordValidation(v)

	tests := []struct {
		name      string
		password  string
		wantValid bool
		reason    string
	}{
		// Valid passwords
		{
			name:      "valid password - all requirements",
			password:  "Password123!",
			wantValid: true,
			reason:    "meets all requirements",
		},
		{
			name:      "valid password - complex",
			password:  "MyS3cure!P@ssw0rd#2024",
			wantValid: true,
			reason:    "complex password with all requirements",
		},
		{
			name:      "valid password - minimum length",
			password:  "Pass1!aa",
			wantValid: true,
			reason:    "exactly 8 characters with all requirements",
		},

		// Invalid passwords - too short
		{
			name:      "invalid - too short",
			password:  "Pass1!",
			wantValid: false,
			reason:    "less than 8 characters",
		},
		{
			name:      "invalid - very short",
			password:  "P1!",
			wantValid: false,
			reason:    "way too short",
		},

		// Invalid passwords - no uppercase
		{
			name:      "invalid - no uppercase",
			password:  "password123!",
			wantValid: false,
			reason:    "missing uppercase letter",
		},

		// Invalid passwords - no lowercase
		{
			name:      "invalid - no lowercase",
			password:  "PASSWORD123!",
			wantValid: false,
			reason:    "missing lowercase letter",
		},

		// Invalid passwords - no number
		{
			name:      "invalid - no number",
			password:  "Password!",
			wantValid: false,
			reason:    "missing number",
		},

		// Invalid passwords - no special character
		{
			name:      "invalid - no special",
			password:  "Password123",
			wantValid: false,
			reason:    "missing special character",
		},
		{
			name:      "invalid - only letters and numbers",
			password:  "Password123",
			wantValid: false,
			reason:    "missing special character",
		},

		// Edge cases
		{
			name:      "invalid - only lowercase",
			password:  "password",
			wantValid: false,
			reason:    "only lowercase letters",
		},
		{
			name:      "invalid - only numbers",
			password:  "12345678",
			wantValid: false,
			reason:    "only numbers",
		},
		{
			name:      "invalid - only special chars",
			password:  "!@#$%^&*",
			wantValid: false,
			reason:    "only special characters",
		},
		{
			name:      "valid - with spaces",
			password:  "Pass 123!",
			wantValid: true,
			reason:    "contains spaces (allowed, spaces are valid Unicode)",
		},
		{
			name:      "invalid - empty",
			password:  "",
			wantValid: false,
			reason:    "empty string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := testPassword{Password: tt.password}
			err := v.Struct(input)

			if tt.wantValid {
				assert.NoError(t, err, tt.reason)
			} else {
				assert.Error(t, err, tt.reason)
			}
		})
	}
}

func TestValidateStrongPassword_Length(t *testing.T) {
	v := validator.New()
	RegisterPasswordValidation(v)

	tests := []struct {
		name     string
		password string
		valid    bool
	}{
		{name: "7 chars", password: "Pass1!", valid: false},
		{name: "8 chars", password: "Pass1!aa", valid: true},
		{name: "128 chars", password: string(make([]byte, 128)), valid: false}, // Need valid chars
		{name: "129 chars", password: "Password123!" + string(make([]byte, 121)), valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := testPassword{Password: tt.password}
			err := v.Struct(input)

			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidateStrongPassword_Requirements(t *testing.T) {
	v := validator.New()
	RegisterPasswordValidation(v)

	// Test each requirement individually
	requirements := []struct {
		name      string
		password  string
		wantError bool
	}{
		{"missing uppercase", "password123!", true},
		{"missing lowercase", "PASSWORD123!", true},
		{"missing number", "Password!!!", true},
		{"missing special", "Password123", true},
		{"all present", "Password123!", false},
	}

	for _, tt := range requirements {
		t.Run(tt.name, func(t *testing.T) {
			input := testPassword{Password: tt.password}
			err := v.Struct(input)

			if tt.wantError {
				assert.Error(t, err, "should have failed validation")
			} else {
				assert.NoError(t, err, "should have passed validation")
			}
		})
	}
}

func TestMinPasswordLength(t *testing.T) {
	assert.Equal(t, 8, MinPasswordLength, "MinPasswordLength should be 8")
}

func TestMaxPasswordLength(t *testing.T) {
	assert.Equal(t, 128, MaxPasswordLength, "MaxPasswordLength should be 128")
}
