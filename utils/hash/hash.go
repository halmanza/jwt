package hash

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
)

// Algorithm represents the supported hashing algorithms
type Algorithm string

// Algorithm constants represent supported hashing algorithms
const (
	// HS256 represents HMAC-SHA256 algorithm
	HS256 Algorithm = "HS256"
	// HS384 represents HMAC-SHA384 algorithm
	HS384 Algorithm = "HS384"
	// HS512 represents HMAC-SHA512 algorithm
	HS512 Algorithm = "HS512"
	// RS256 represents RSA-SHA256 algorithm
	RS256 Algorithm = "RS256"
)

// Hasher interface defines the methods for hashing operations
type Hasher interface {
	// Sign creates a signature for the given input using the secret key
	Sign(data []byte, key []byte) string
	// Verify checks if the signature is valid for the given input and secret
	Verify(data []byte, signature string, key []byte) bool
	// Name returns the name of the algorithm
	Name() string
}

// HS256Hasher implements HMAC-SHA256
type HS256Hasher struct{}

// Sign creates a signature for the given data using HMAC-SHA256
func (h *HS256Hasher) Sign(input []byte, secret []byte) string {
	hash := hmac.New(sha256.New, secret)
	hash.Write(input)
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

// Verify checks if the signature is valid for the given data using HMAC-SHA256
func (h *HS256Hasher) Verify(input []byte, signature string, secret []byte) bool {
	expected := h.Sign(input, secret)
	return hmac.Equal([]byte(signature), []byte(expected))
}

// Name returns the name of the hashing algorithm (HS256)
func (h *HS256Hasher) Name() string {
	return string(HS256)
}

// HS384Hasher implements HMAC-SHA384
type HS384Hasher struct{}

// Sign creates a signature for the given data using HMAC-SHA384
func (h *HS384Hasher) Sign(input []byte, secret []byte) string {
	hash := hmac.New(sha512.New384, secret)
	hash.Write(input)
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

// Verify checks if the signature is valid for the given data using HMAC-SHA384
func (h *HS384Hasher) Verify(input []byte, signature string, secret []byte) bool {
	expected := h.Sign(input, secret)
	return hmac.Equal([]byte(signature), []byte(expected))
}

// Name returns the name of the hashing algorithm (HS384)
func (h *HS384Hasher) Name() string {
	return string(HS384)
}

// HS512Hasher implements HMAC-SHA512
type HS512Hasher struct{}

// Sign creates a signature for the given data using HMAC-SHA512
func (h *HS512Hasher) Sign(input []byte, secret []byte) string {
	hash := hmac.New(sha512.New, secret)
	hash.Write(input)
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

// Verify checks if the signature is valid for the given data using HMAC-SHA512
func (h *HS512Hasher) Verify(input []byte, signature string, secret []byte) bool {
	expected := h.Sign(input, secret)
	return hmac.Equal([]byte(signature), []byte(expected))
}

// Name returns the name of the hashing algorithm (HS512)
func (h *HS512Hasher) Name() string {
	return string(HS512)
}

// NewHasher creates a new hasher instance based on the specified algorithm
func NewHasher(algorithm Algorithm) (Hasher, error) {
	switch algorithm {
	case HS256:
		return &HS256Hasher{}, nil
	case HS384:
		return &HS384Hasher{}, nil
	case HS512:
		return &HS512Hasher{}, nil
	case RS256:
		return &RS256Hasher{}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}
