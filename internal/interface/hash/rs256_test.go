package hash

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestRS256Hasher_Sign(t *testing.T) {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Convert private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// Create an instance of RS256Hasher
	hasher := &RS256Hasher{}

	// Test data
	data := []byte("Hello, World!")

	// Sign the data
	signature := hasher.Sign(data, privateKeyPEM)

	// Check if the signature is not empty
	if signature == "" {
		t.Error("Expected non-empty signature, got empty")
	}
}

func TestRS256Hasher_Verify(t *testing.T) {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Convert private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// Convert public key to PEM format
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)})

	// Create an instance of RS256Hasher
	hasher := &RS256Hasher{}

	// Test data
	data := []byte("Hello, World!")

	// Sign the data
	signature := hasher.Sign(data, privateKeyPEM)

	// Verify the signature
	isValid := hasher.Verify(data, signature, publicKeyPEM)

	// Check if the verification is successful
	if !isValid {
		t.Error("Expected valid signature, got invalid")
	}
}

func TestRS256Hasher_Interface(t *testing.T) {
	// Create an instance of RS256Hasher
	hasher := &RS256Hasher{}

	// Test the Name method
	if hasher.Name() != "RS256" {
		t.Error("Expected name to be RS256, got", hasher.Name())
	}

	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Convert private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// Test data
	data := []byte("Hello, World!")

	// Sign the data
	signature := hasher.Sign(data, privateKeyPEM)

	// Check if the signature is not empty
	if signature == "" {
		t.Error("Expected non-empty signature, got empty")
	}

	// Convert public key to PEM format
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)})

	// Verify the signature
	isValid := hasher.Verify(data, signature, publicKeyPEM)

	// Check if the verification is successful
	if !isValid {
		t.Error("Expected valid signature, got invalid")
	}
}
