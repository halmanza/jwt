package hash_test

import (
	"jwt/internal/domain/hash"
	hashimpl "jwt/internal/interface/hash"
	"strings"
	"testing"
)

func TestHasher_HS256(t *testing.T) {
	testHasher(t, &hashimpl.HS256Hasher{}, "HS256")
}

func TestHasher_HS384(t *testing.T) {
	testHasher(t, &hashimpl.HS384Hasher{}, "HS384")
}

func TestHasher_HS512(t *testing.T) {
	testHasher(t, &hashimpl.HS512Hasher{}, "HS512")
}

func testHasher(t *testing.T, h hash.Hasher, expectedName string) {
	// Test algorithm name
	if h.Name() != expectedName {
		t.Errorf("Expected algorithm name %s, got %s", expectedName, h.Name())
	}

	// Test data
	data := []byte("test data")
	key := []byte("test key")

	// Test signing
	signature := h.Sign(data, key)
	if signature == "" {
		t.Error("Sign returned empty signature")
	}

	// Test verification
	if !h.Verify(data, signature, key) {
		t.Error("Verify failed for valid signature")
	}

	// Test verification with wrong key
	if h.Verify(data, signature, []byte("wrong key")) {
		t.Error("Verify succeeded with wrong key")
	}

	// Test verification with wrong data
	if h.Verify([]byte("wrong data"), signature, key) {
		t.Error("Verify succeeded with wrong data")
	}

	// Test empty key
	if h.Sign(data, []byte{}) != "" {
		t.Error("Sign should return empty string for empty key")
	}
}

func TestNewHasher(t *testing.T) {
	tests := []struct {
		name        string
		algorithm   hash.Algorithm
		wantErr     bool
		errContains string
	}{
		{
			name:      "HS256",
			algorithm: hash.HS256,
			wantErr:   false,
		},
		{
			name:      "HS384",
			algorithm: hash.HS384,
			wantErr:   false,
		},
		{
			name:      "HS512",
			algorithm: hash.HS512,
			wantErr:   false,
		},
		{
			name:        "Invalid algorithm",
			algorithm:   "INVALID",
			wantErr:     true,
			errContains: "unsupported algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := hash.NewHasher(tt.algorithm)
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

			if h == nil {
				t.Error("Expected non-nil hasher")
			}
		})
	}
}
