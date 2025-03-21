package hash

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
)

// HS512Hasher implements the Hasher interface using HMAC-SHA512
type HS512Hasher struct{}

// Sign signs the data using HS512 algorithm
func (h *HS512Hasher) Sign(data []byte, key []byte) string {
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify verifies the signature using HS512 algorithm
func (h *HS512Hasher) Verify(data []byte, signature string, key []byte) bool {
	expected := h.Sign(data, key)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// Name returns the name of the hashing algorithm
func (h *HS512Hasher) Name() string {
	return "HS512"
}
