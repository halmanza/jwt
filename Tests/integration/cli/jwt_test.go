package cli_test

import (
	"bufio"
	"jwt/internal/interface/cli"
	"os"
	"strings"
	"testing"
)

// TestVersion is used to inject version during tests
var TestVersion = "dev"

func init() {
	// Override the version for testing
	cli.SetVersion(TestVersion)
}

func TestJWTCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		env         map[string]string
		wantErr     bool
		errContains string
		checkOutput func(string) bool
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
			name:    "Decode valid JWT with validation using single dash",
			args:    []string{"-validate", "-algorithm", "HS256", "decode", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
			env:     map[string]string{"JWT_SECRET_KEY": "your-256-bit-secret"},
			wantErr: false,
		},
		{
			name:    "Decode valid JWT with validation using double dash",
			args:    []string{"--validate", "--algorithm", "HS256", "decode", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
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
			name:        "Decode with validation but no secret key using single dash",
			args:        []string{"-validate", "decode", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
			env:         map[string]string{},
			wantErr:     true,
			errContains: "JWT_SECRET_KEY environment variable is required for validation",
		},
		{
			name:        "Decode with validation but no secret key using double dash",
			args:        []string{"--validate", "decode", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
			env:         map[string]string{},
			wantErr:     true,
			errContains: "JWT_SECRET_KEY environment variable is required for validation",
		},
		{
			name:        "Invalid algorithm",
			args:        []string{"-algorithm", "INVALID", "decode", "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
			env:         map[string]string{},
			wantErr:     true,
			errContains: "unsupported algorithm: HS384",
		},
		{
			name:        "Invalid algorithm using single dash",
			args:        []string{"-algorithm", "INVALID", "decode", "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
			env:         map[string]string{},
			wantErr:     true,
			errContains: "unsupported algorithm: HS384",
		},
		{
			name:        "Invalid algorithm using double dash",
			args:        []string{"--algorithm", "INVALID", "decode", "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
			env:         map[string]string{},
			wantErr:     true,
			errContains: "unsupported algorithm: HS384",
		},
		{
			name:    "Show help with --help flag",
			args:    []string{"--help"},
			env:     map[string]string{},
			wantErr: false,
			checkOutput: func(output string) bool {
				return strings.Contains(output, "Usage:") &&
					strings.Contains(output, "Commands:") &&
					strings.Contains(output, "Flags:") &&
					strings.Contains(output, "Examples:") &&
					strings.Contains(output, "Environment Variables:")
			},
		},
		{
			name:    "Show help with -h flag",
			args:    []string{"-h"},
			env:     map[string]string{},
			wantErr: false,
			checkOutput: func(output string) bool {
				return strings.Contains(output, "Usage:") &&
					strings.Contains(output, "Commands:") &&
					strings.Contains(output, "Flags:") &&
					strings.Contains(output, "Examples:") &&
					strings.Contains(output, "Environment Variables:")
			},
		},
		{
			name:    "Show help with no arguments",
			args:    []string{},
			env:     map[string]string{},
			wantErr: false,
			checkOutput: func(output string) bool {
				return strings.Contains(output, "Usage:") &&
					strings.Contains(output, "Commands:") &&
					strings.Contains(output, "Flags:") &&
					strings.Contains(output, "Examples:") &&
					strings.Contains(output, "Environment Variables:")
			},
		},
		{
			name:    "Show version with --version flag (dev)",
			args:    []string{"--version"},
			env:     map[string]string{},
			wantErr: false,
			checkOutput: func(output string) bool {
				return strings.Contains(output, "jwt version dev")
			},
		},
		{
			name:    "Show version with -v flag (dev)",
			args:    []string{"-v"},
			env:     map[string]string{},
			wantErr: false,
			checkOutput: func(output string) bool {
				return strings.Contains(output, "jwt version dev")
			},
		},
		{
			name:    "Generate token using single dash",
			args:    []string{"generate", "-algorithm", "HS256"},
			env:     map[string]string{},
			wantErr: false,
			checkOutput: func(output string) bool {
				return strings.Contains(output, "Generated JWT Token:")
			},
		},
		{
			name:    "Generate token using double dash",
			args:    []string{"generate", "--algorithm", "HS256"},
			env:     map[string]string{},
			wantErr: false,
			checkOutput: func(output string) bool {
				return strings.Contains(output, "Generated JWT Token:")
			},
		},
		{
			name:    "Generate token without algorithm flag",
			args:    []string{"generate"},
			env:     map[string]string{},
			wantErr: false,
			checkOutput: func(output string) bool {
				return strings.Contains(output, "Generated JWT Token:")
			},
		},
	}

	// Run tests with dev version
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

			// Check output using the checkOutput function if provided
			if tt.checkOutput != nil {
				if !tt.checkOutput(output) {
					t.Error("Output did not match expected format")
				}
				return
			}

			// Check output for JWT decode
			if len(tt.args) > 0 && tt.args[0] == "decode" {
				if !strings.Contains(output, "Header:") || !strings.Contains(output, "Payload:") {
					t.Error("Decoded JWT output missing required components")
				}
				if len(tt.args) > 1 && tt.args[1] == "-validate" && !strings.Contains(output, "Signature: Valid") {
					t.Error("Validation enabled but signature validation not shown in output")
				}
			}
		})
	}

	// Test with semantic version
	t.Run("Show version with semantic version", func(t *testing.T) {
		// Set version to semantic version
		cli.SetVersion("1.0.0")

		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		// Run command
		err := cli.Run("--version")
		w.Close()

		// Read output
		var output string
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			output += scanner.Text() + "\n"
		}

		// Restore stdout
		os.Stdout = old

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
			return
		}

		if !strings.Contains(output, "jwt version 1.0.0") {
			t.Error("Output did not contain expected version string")
		}

		// Reset version for other tests
		cli.SetVersion(TestVersion)
	})
}
