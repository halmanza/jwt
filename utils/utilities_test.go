package utils

import (
	"bufio"
	"os"
	"strings"
	"testing"
	"jwt/utils/hash"
)

func TestNewCLI(t *testing.T) {
	cli, err := NewCLI("test-secret", hash.HS256)
	if err != nil {
		t.Errorf("NewCLI returned error: %v", err)
	}
	if cli == nil {
		t.Error("NewCLI returned nil")
	}
}

func TestSetInputs(t *testing.T) {
	cli, err := NewCLI("test-secret", hash.HS256)
	if err != nil {
		t.Fatalf("NewCLI returned error: %v", err)
	}
	commands := []string{"decode"}
	args := []string{"test-token"}

	cli.SetInputs(commands, args)

	// Test commands were set correctly
	if len(cli.Commands()) != 1 || cli.Commands()[0] != "decode" {
		t.Error("Commands were not set correctly")
	}

	// Test arguments were set correctly
	if len(cli.Args()) != 1 || cli.Args()[0] != "test-token" {
		t.Error("Arguments were not set correctly")
	}
}

func TestDecodeJWT(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		validate    bool
		secretKey   string
		algorithm   hash.Algorithm
		wantErr     bool
		errContains string
	}{
		{
			name:      "Valid JWT without validation",
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			validate:  false,
			secretKey: "test-secret",
			algorithm: hash.HS256,
			wantErr:   false,
		},
		{
			name:        "Empty token",
			token:       "",
			validate:    false,
			secretKey:   "test-secret",
			algorithm:   hash.HS256,
			wantErr:     true,
			errContains: "empty token",
		},
		{
			name:        "Invalid JWT format",
			token:       "invalid.jwt.format",
			validate:    false,
			secretKey:   "test-secret",
			algorithm:   hash.HS256,
			wantErr:     true,
			errContains: "invalid JWT format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, err := NewCLI(tt.secretKey, tt.algorithm)
			if err != nil {
				t.Fatalf("NewCLI returned error: %v", err)
			}
			result, err := cli.DecodeJWT(tt.token, tt.validate)

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

			if !strings.Contains(result, "Header:") || !strings.Contains(result, "Payload:") {
				t.Error("Result missing required components")
			}

			if tt.validate && !strings.Contains(result, "Signature: Valid") {
				t.Error("Validation enabled but signature validation not shown in result")
			}
		})
	}
}

func TestPrintCommands(t *testing.T) {
	cli, err := NewCLI("test-secret", hash.HS256)
	if err != nil {
		t.Fatalf("NewCLI returned error: %v", err)
	}
	commands := []string{"decode", "validate"}
	cli.SetInputs(commands, nil)

	// Capture stdout to test PrintCommands
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cli.PrintCommands()
	w.Close()

	// Read the output
	var output string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		output += scanner.Text()
	}

	// Restore stdout
	os.Stdout = old

	// Verify output
	if output != "decodevalidate" {
		t.Errorf("Expected 'decodevalidate', got %q", output)
	}
}

func TestTokenValidation(t *testing.T) {
	// Test with a valid JWT and correct secret
	validToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	cli, err := NewCLI("your-256-bit-secret", hash.HS256)
	if err != nil {
		t.Fatalf("NewCLI returned error: %v", err)
	}
	result, err := cli.DecodeJWT(validToken, true)

	if err != nil {
		t.Errorf("Unexpected error with valid token: %v", err)
	}

	if !strings.Contains(result, "Signature: Valid") {
		t.Error("Valid token should show valid signature")
	}

	// Test with invalid signature
	invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid-signature"
	_, err = cli.DecodeJWT(invalidToken, true)
	if err == nil {
		t.Error("Expected error with invalid signature")
	}
}

func TestDifferentAlgorithms(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		algorithm hash.Algorithm
		secretKey string
		wantErr   bool
	}{
		{
			name:      "HS256 token with HS256 algorithm",
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			algorithm: hash.HS256,
			secretKey: "your-256-bit-secret",
			wantErr:   false,
		},
		{
			name:      "HS256 token with HS384 algorithm",
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			algorithm: hash.HS384,
			secretKey: "your-256-bit-secret",
			wantErr:   true,
		},
		{
			name:      "HS256 token with HS512 algorithm",
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			algorithm: hash.HS512,
			secretKey: "your-256-bit-secret",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, err := NewCLI(tt.secretKey, tt.algorithm)
			if err != nil {
				t.Fatalf("NewCLI returned error: %v", err)
			}
			_, err = cli.DecodeJWT(tt.token, true)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if !strings.Contains(err.Error(), "unsupported algorithm") {
					t.Errorf("Expected 'unsupported algorithm' error, got %v", err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestHasherInterface(t *testing.T) {
	algorithms := []hash.Algorithm{hash.HS256, hash.HS384, hash.HS512}

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			hasher, err := hash.NewHasher(alg)
			if err != nil {
				t.Fatalf("Failed to create hasher for %s: %v", alg, err)
			}

			// Test Name method
			if hasher.Name() != string(alg) {
				t.Errorf("Expected name %s, got %s", alg, hasher.Name())
			}

			// Test Sign and Verify methods
			data := []byte("test data")
			key := []byte("test key")

			signature := hasher.Sign(data, key)
			if signature == "" {
				t.Error("Sign returned empty signature")
			}

			if !hasher.Verify(data, signature, key) {
				t.Error("Verify failed for valid signature")
			}

			// Test with wrong key
			if hasher.Verify(data, signature, []byte("wrong key")) {
				t.Error("Verify succeeded with wrong key")
			}
		})
	}
}
