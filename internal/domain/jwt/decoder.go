package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"jwt/internal/domain/hash"
	"os"
	"strings"
	"time"
)

// Decoder defines the interface for JWT token decoding operations
type Decoder interface {
	// Decode decodes a JWT token and returns the decoded parts
	Decode(token string, validate bool) (string, error)
	// GenerateTestToken generates a test JWT token with the specified algorithm
	GenerateTestToken(algorithm hash.Algorithm) (string, error)
}

// DecoderImpl implements the Decoder interface
type DecoderImpl struct {
	hasher hash.Hasher
}

// NewDecoder creates a new JWT decoder instance
func NewDecoder(hasher hash.Hasher) Decoder {
	return &DecoderImpl{
		hasher: hasher,
	}
}

// Decode decodes a JWT token and returns the decoded parts and any error
func (d *DecoderImpl) Decode(token string, validate bool) (string, error) {
	if token == "" {
		return "", fmt.Errorf("empty token provided")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Validate each part is valid base64
	for i, part := range parts {
		if _, err := base64.RawURLEncoding.DecodeString(part); err != nil {
			return "", fmt.Errorf("invalid JWT format: part %d is not valid base64", i+1)
		}
		if part == "" {
			return "", fmt.Errorf("invalid JWT format: part %d is empty", i+1)
		}
	}

	// Parse header to get algorithm
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid JWT format: header is not valid base64")
	}

	var headerMap map[string]any
	if err := json.Unmarshal(header, &headerMap); err != nil {
		return "", fmt.Errorf("invalid JWT format: header is not valid JSON")
	}

	// Verify algorithm matches
	if alg, ok := headerMap["alg"].(string); !ok || alg != d.hasher.Name() {
		return "", fmt.Errorf("unsupported algorithm: %v", headerMap["alg"])
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid JWT format: payload is not valid base64")
	}

	// Format header and payload JSON with indentation
	var headerFormatted, payloadFormatted []byte
	if headerFormatted, err = json.MarshalIndent(headerMap, "", "  "); err != nil {
		return "", fmt.Errorf("error formatting header JSON: %v", err)
	}

	var payloadMap map[string]any
	if err := json.Unmarshal(payload, &payloadMap); err != nil {
		return "", fmt.Errorf("invalid JWT format: payload is not valid JSON")
	}
	if payloadFormatted, err = json.MarshalIndent(payloadMap, "", "  "); err != nil {
		return "", fmt.Errorf("error formatting payload JSON: %v", err)
	}

	// Create a buffer to build the output
	var outputBuilder strings.Builder

	// Add header section
	outputBuilder.WriteString("Header:\n")
	outputBuilder.Write(headerFormatted)
	outputBuilder.WriteString("\n\n")

	// Add payload section
	outputBuilder.WriteString("Payload:\n")
	outputBuilder.Write(payloadFormatted)
	outputBuilder.WriteString("\n")

	// Validate signature if requested
	if validate {
		secretKey := []byte(os.Getenv("JWT_SECRET_KEY"))
		if len(secretKey) == 0 {
			return "", fmt.Errorf("JWT_SECRET_KEY environment variable is required for validation")
		}

		signatureInput := parts[0] + "." + parts[1]
		if !d.hasher.Verify([]byte(signatureInput), parts[2], secretKey) {
			return "", fmt.Errorf("invalid signature")
		}
		outputBuilder.WriteString("\nSignature: Valid")
	}

	return outputBuilder.String(), nil
}

// GenerateTestToken generates a test JWT token with the specified algorithm
func (d *DecoderImpl) GenerateTestToken(algorithm hash.Algorithm) (string, error) {
	// Create a new hasher with the specified algorithm
	hasher, err := hash.NewHasher(algorithm)
	if err != nil {
		return "", fmt.Errorf("failed to create hasher: %w", err)
	}

	// Header
	header := map[string]string{
		"alg": string(algorithm),
		"typ": "JWT",
	}
	headerJSON, _ := json.Marshal(header)
	headerBase64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Payload with realistic claims
	payload := map[string]interface{}{
		"iss":   "test-issuer",
		"sub":   "test-user-123",
		"aud":   "test-audience",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
		"name":  "Test User",
		"email": "test@example.com",
		"roles": []string{"user", "admin"},
		"permissions": []string{
			"read:users",
			"write:users",
			"delete:users",
		},
		"metadata": map[string]interface{}{
			"department":  "Engineering",
			"location":    "HQ",
			"employee_id": "EMP123",
		},
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signature
	secretKey := "your-super-secret-key-123!@#$%^&*()"
	signatureInput := headerBase64 + "." + payloadBase64
	signature := hasher.Sign([]byte(signatureInput), []byte(secretKey))

	// Combine all parts
	token := fmt.Sprintf("%s.%s.%s", headerBase64, payloadBase64, signature)
	return token, nil
}
