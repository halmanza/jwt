package hash

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// HS256Hasher implements the Hasher interface using HMAC-SHA256
type HS256Hasher struct{}

// Sign signs the data using HS256 algorithm
func (h *HS256Hasher) Sign(data []byte, key []byte) string {
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify verifies the signature using HS256 algorithm
func (h *HS256Hasher) Verify(data []byte, signature string, key []byte) bool {
	expected := h.Sign(data, key)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// Name returns the name of the hashing algorithm
func (h *HS256Hasher) Name() string {
	return "HS256"
}
