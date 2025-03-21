package jwt_test

import (
	"os"
	"testing"
	"jwt/internal/domain/hash"
	"jwt/internal/domain/jwt"
)

func TestJWTDecoder_Decode(t *testing.T) {
	mockHasher := &hash.MockHasher{
		NameFunc: func() string {
			return "HS256"
		},
		VerifyFunc: func(data []byte, signature string, key []byte) bool {
			return true
		},
	}

	decoder := jwt.NewDecoder(mockHasher)

	tests := []struct {
		name           string
		token          string
		validate       bool
		expectedOutput string
		expectedError  string
		setSecret      bool
	}{
		{
			name:           "Valid JWT without validation",
			token:          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			validate:       false,
			expectedOutput: "Header:\n{\n  \"alg\": \"HS256\",\n  \"typ\": \"JWT\"\n}\n\nPayload:\n{\n  \"iat\": 1516239022,\n  \"name\": \"John Doe\",\n  \"sub\": \"1234567890\"\n}\n",
			setSecret:      false,
		},
		{
			name:           "Valid JWT with validation",
			token:          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			validate:       true,
			expectedOutput: "Header:\n{\n  \"alg\": \"HS256\",\n  \"typ\": \"JWT\"\n}\n\nPayload:\n{\n  \"iat\": 1516239022,\n  \"name\": \"John Doe\",\n  \"sub\": \"1234567890\"\n}\n\nSignature: Valid",
			setSecret:      true,
		},
		{
			name:          "Empty token",
			token:         "",
			validate:      false,
			expectedError: "empty token provided",
			setSecret:     false,
		},
		{
			name:          "Invalid JWT format",
			token:         "invalid.token",
			validate:      false,
			expectedError: "invalid JWT format: expected 3 parts, got 2",
			setSecret:     false,
		},
		{
			name:          "Invalid JSON in header",
			token:         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVA.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			validate:      false,
			expectedError: "invalid JWT format: header is not valid JSON",
			setSecret:     false,
		},
		{
			name:          "Unsupported algorithm",
			token:         "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			validate:      false,
			expectedError: "unsupported algorithm: HS384",
			setSecret:     false,
		},
		{
			name:          "Validation with missing secret key",
			token:         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			validate:      true,
			expectedError: "JWT_SECRET_KEY environment variable is required for validation",
			setSecret:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv("JWT_SECRET_KEY")

			if tt.setSecret {
				os.Setenv("JWT_SECRET_KEY", "your-256-bit-secret")
				defer os.Unsetenv("JWT_SECRET_KEY")
			}

			output, err := decoder.Decode(tt.token, tt.validate)

			if tt.expectedError != "" {
				if err == nil {
					t.Error("Expected error but got none")
				} else if err.Error() != tt.expectedError {
					t.Errorf("Expected error %q, got %q", tt.expectedError, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if output != tt.expectedOutput {
				t.Errorf("Expected output %q, got %q", tt.expectedOutput, output)
			}
		})
	}
}
