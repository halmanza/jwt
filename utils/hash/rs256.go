package hash

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

// RS256Hasher implements the Hasher interface using RSA-SHA256
type RS256Hasher struct{}

// Sign signs the data using RS256 algorithm
func (h *RS256Hasher) Sign(data []byte, key []byte) string {
	if len(key) == 0 {
		return ""
	}

	// Parse the private key
	block, _ := pem.Decode(key)
	if block == nil {
		return ""
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return ""
	}

	mac := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, mac[:])

	if err != nil {
		return ""
	}

	return base64.RawURLEncoding.EncodeToString(signature)
}

// Verify verifies the signature using RS256 algorithm
func (h *RS256Hasher) Verify(data []byte, signature string, key []byte) bool {
	if len(key) == 0 {
		return false
	}

	// Parse the public key
	block, _ := pem.Decode(key)
	if block == nil {
		return false
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return false
	}

	// Decode the signature
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return false
	}

	mac := sha256.Sum256(data)
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, mac[:], signatureBytes)

	return err == nil
}

// Name returns the name of the hashing algorithm
func (h *RS256Hasher) Name() string {
	return "RS256"
}
