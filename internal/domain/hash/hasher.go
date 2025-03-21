package hash

import (
	"fmt"
	"jwt/internal/interface/hash"
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

// Hasher defines the interface for JWT signature algorithms
type Hasher interface {
	// Sign creates a signature for the given data using the provided key
	Sign(data []byte, key []byte) string
	// Verify checks if the signature is valid for the given data and key
	Verify(data []byte, signature string, key []byte) bool
	// Name returns the name of the algorithm
	Name() string
}

// NewHasher creates a new hasher instance for the specified algorithm
func NewHasher(algorithm Algorithm) (Hasher, error) {
	switch algorithm {
	case HS256:
		return &hash.HS256Hasher{}, nil
	case HS384:
		return &hash.HS384Hasher{}, nil
	case HS512:
		return &hash.HS512Hasher{}, nil
	case RS256:
		return &hash.RS256Hasher{}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}
