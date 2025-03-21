package jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"jwt/internal/domain/hash"
	"jwt/internal/domain/jwt"
	"os"
	"strings"
	"testing"
)

func testDecoder(t *testing.T, decoder jwt.Decoder, name string) {
	headerWithoutAlg := map[string]interface{}{
		"typ": "JWT",
	}
	headerWithoutAlgBytes, _ := json.Marshal(headerWithoutAlg)
	headerWithoutAlgB64 := base64.RawURLEncoding.EncodeToString(headerWithoutAlgBytes)

	headerWithWrongAlg := map[string]interface{}{
		"alg": "HS512",
		"typ": "JWT",
	}
	headerWithWrongAlgBytes, _ := json.Marshal(headerWithWrongAlg)
	headerWithWrongAlgB64 := base64.RawURLEncoding.EncodeToString(headerWithWrongAlgBytes)

	payload := map[string]interface{}{
		"sub": "1234567890",
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	invalidJSONHeader := `{"alg":"HS256","typ":"JWT`
	invalidJSONHeaderB64 := base64.RawURLEncoding.EncodeToString([]byte(invalidJSONHeader))

	validHeader := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}
	validHeaderBytes, _ := json.Marshal(validHeader)
	validHeaderB64 := base64.RawURLEncoding.EncodeToString(validHeaderBytes)

	signature := "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	validToken := validHeaderB64 + "." + payloadB64 + "." + signature

	tests := []struct {
		name           string
		token          string
		validate       bool
		setSecret      bool
		wantErr        bool
		errContains    string
		expectedOutput string
	}{
		{
			name:           "Valid JWT without validation",
			token:          validToken,
			validate:       false,
			setSecret:      false,
			wantErr:        false,
			expectedOutput: "Header:\n{\n  \"alg\": \"HS256\",\n  \"typ\": \"JWT\"\n}\n\nPayload:\n{\n  \"sub\": \"1234567890\"\n}\n",
		},
		{
			name:           "Valid JWT with validation",
			token:          validToken,
			validate:       true,
			setSecret:      true,
			wantErr:        false,
			expectedOutput: "Header:\n{\n  \"alg\": \"HS256\",\n  \"typ\": \"JWT\"\n}\n\nPayload:\n{\n  \"sub\": \"1234567890\"\n}\n\nSignature: Valid",
		},
		{
			name:        "Empty token",
			token:       "",
			validate:    false,
			setSecret:   false,
			wantErr:     true,
			errContains: "empty token",
		},
		{
			name:        "Invalid JWT format - wrong number of parts",
			token:       "header.payload.signature.extra",
			validate:    false,
			setSecret:   false,
			wantErr:     true,
			errContains: "invalid JWT format: expected 3 parts",
		},
		{
			name:        "Invalid JWT format - too few parts",
			token:       "header.payload",
			validate:    false,
			setSecret:   false,
			wantErr:     true,
			errContains: "invalid JWT format: expected 3 parts",
		},
		{
			name:        "Invalid JWT format - empty parts",
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			validate:    false,
			setSecret:   false,
			wantErr:     true,
			errContains: "invalid JWT format: part 2 is empty",
		},
		{
			name:        "Invalid base64 in header",
			token:       "invalid-base64!.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
			validate:    false,
			setSecret:   false,
			wantErr:     true,
			errContains: "part 1 is not valid base64",
		},
		{
			name:        "Invalid base64 in payload",
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid-base64!.signature",
			validate:    false,
			setSecret:   false,
			wantErr:     true,
			errContains: "part 2 is not valid base64",
		},
		{
			name:        "Invalid JSON in header",
			token:       invalidJSONHeaderB64 + "." + payloadB64 + "." + signature,
			validate:    false,
			setSecret:   false,
			wantErr:     true,
			errContains: "header is not valid JSON",
		},
		{
			name:        "Missing algorithm in header",
			token:       headerWithoutAlgB64 + "." + payloadB64 + "." + signature,
			validate:    false,
			setSecret:   false,
			wantErr:     true,
			errContains: "unsupported algorithm",
		},
		{
			name:        "Invalid algorithm type in header",
			token:       headerWithWrongAlgB64 + "." + payloadB64 + "." + signature,
			validate:    false,
			setSecret:   false,
			wantErr:     true,
			errContains: "unsupported algorithm",
		},
		{
			name:        "Validation with missing secret key",
			token:       validToken,
			validate:    true,
			setSecret:   false,
			wantErr:     true,
			errContains: "JWT_SECRET_KEY environment variable is required for validation",
		},
	}

	for _, tt := range tests {
		t.Run(name+": "+tt.name, func(t *testing.T) {
			os.Unsetenv("JWT_SECRET_KEY")

			if tt.setSecret {
				os.Setenv("JWT_SECRET_KEY", "your-256-bit-secret")
				defer os.Unsetenv("JWT_SECRET_KEY")
			}

			if !tt.setSecret && os.Getenv("JWT_SECRET_KEY") != "" {
				t.Fatal("JWT_SECRET_KEY was unexpectedly set")
			}

			output, err := decoder.Decode(tt.token, tt.validate)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Expected error to contain %q, got %v", tt.errContains, err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if tt.expectedOutput != "" && output != tt.expectedOutput {
				t.Errorf("Expected output %q, got %q", tt.expectedOutput, output)
			}
		})
	}
}

func TestDecoder(t *testing.T) {
	mockHasher := &hash.MockHasher{
		NameFunc: func() string {
			return "HS256"
		},
		VerifyFunc: func(data []byte, signature string, key []byte) bool {
			return signature == "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
		},
	}
	decoder := jwt.NewDecoder(mockHasher)
	testDecoder(t, decoder, "Decoder")
}
