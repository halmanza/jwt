package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"jwt/internal/domain/hash"
	"jwt/internal/domain/jwt"
)

// Decoder implements the JWT decoder use case
type Decoder struct {
	hasher hash.Hasher
}

// NewDecoder creates a new JWT decoder instance
func NewDecoder(hasher hash.Hasher) jwt.Decoder {
	return &Decoder{
		hasher: hasher,
	}
}

// isPowerShell checks if we're running in PowerShell

// GenerateTestToken generates a test JWT token for testing purposes
func (d *Decoder) GenerateTestToken(algorithm hash.Algorithm) (string, error) {
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

// Decode decodes a JWT token and returns the decoded parts and any error
func (d *Decoder) Decode(token string, validate bool) (string, error) {
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

	// Validate signature if requested
	if validate {
		signatureInput := parts[0] + "." + parts[1]
		key := []byte(os.Getenv("JWT_SECRET_KEY"))
		if len(key) == 0 {
			return "", fmt.Errorf("JWT_SECRET_KEY environment variable is required for validation")
		}
		if !d.hasher.Verify([]byte(signatureInput), parts[2], key) {
			return "", fmt.Errorf("invalid signature")
		}
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid JWT format: payload is not valid base64")
	}

	// Parse header and payload as JSON and pretty print
	var headerObj, payloadObj map[string]interface{}
	if err := json.Unmarshal(header, &headerObj); err != nil {
		// If can't parse as JSON, use raw string
	} else {
		headerBytes, err := json.MarshalIndent(headerObj, "", "  ")
		if err == nil {
			header = headerBytes
		}
	}

	if err := json.Unmarshal(payload, &payloadObj); err != nil {
		// If can't parse as JSON, use raw string
	} else {
		payloadBytes, err := json.MarshalIndent(payloadObj, "", "  ")
		if err == nil {
			payload = payloadBytes
		}
	}

	// Return the decoded parts in a standard format
	output := fmt.Sprintf("Header: %s\nPayload: %s", string(header), string(payload))
	if validate {
		output += "\nSignature: Valid"
	}
	return output, nil
}
