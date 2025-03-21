package hash

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
)

// HS384Hasher implements the Hasher interface using HMAC-SHA384
type HS384Hasher struct{}

// Sign signs the data using HS384 algorithm
func (h *HS384Hasher) Sign(data []byte, key []byte) string {
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha512.New384, key)
	mac.Write(data)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify verifies the signature using HS384 algorithm
func (h *HS384Hasher) Verify(data []byte, signature string, key []byte) bool {
	expected := h.Sign(data, key)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// Name returns the name of the hashing algorithm
func (h *HS384Hasher) Name() string {
	return "HS384"
}
