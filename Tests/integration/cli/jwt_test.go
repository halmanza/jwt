package cli_test

import (
	"bufio"
	"os"
	"strings"
	"testing"
	"jwt/internal/interface/cli"
)

func TestJWTCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		env         map[string]string
		wantErr     bool
		errContains string
	}{
		{
			name:    "Decode valid JWT without validation",
			args:    []string{"decode", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
			env:     map[string]string{},
			wantErr: false,
		},
		{
			name:    "Decode valid JWT with validation",
			args:    []string{"-validate", "-algorithm", "HS256", "decode", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
			env:     map[string]string{"JWT_SECRET_KEY": "your-256-bit-secret"},
			wantErr: false,
		},
		{
			name:        "Decode with validation but no secret key",
			args:        []string{"-validate", "decode", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
			env:         map[string]string{},
			wantErr:     true,
			errContains: "JWT_SECRET_KEY environment variable is required",
		},
		{
			name:        "Invalid algorithm",
			args:        []string{"-algorithm", "INVALID", "decode", "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
			env:         map[string]string{},
			wantErr:     true,
			errContains: "unsupported algorithm: HS384",
		},
		{
			name:    "Show help",
			args:    []string{"-h"},
			env:     map[string]string{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for k, v := range tt.env {
				os.Setenv(k, v)
			}
			defer func() {
				for k := range tt.env {
					os.Unsetenv(k)
				}
			}()

			// Capture stdout
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Run command
			err := cli.Run(tt.args...)
			w.Close()

			// Read output
			var output string
			scanner := bufio.NewScanner(r)
			for scanner.Scan() {
				output += scanner.Text() + "\n"
			}

			// Restore stdout
			os.Stdout = old

			// Check results
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

			// Check output for help message
			if tt.args[0] == "-h" && !strings.Contains(output, "Usage:") {
				t.Error("Help message not found in output")
			}

			// Check output for JWT decode
			if tt.args[0] == "decode" {
				if !strings.Contains(output, "Header:") || !strings.Contains(output, "Payload:") {
					t.Error("Decoded JWT output missing required components")
				}
				if tt.args[1] == "-validate" && !strings.Contains(output, "Signature: Valid") {
					t.Error("Validation enabled but signature validation not shown in output")
				}
			}
		})
	}
}
