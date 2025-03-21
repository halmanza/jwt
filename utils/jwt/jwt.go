package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"jwt/utils/hash"
)

// Decoder handles JWT token decoding operations
type Decoder struct {
	token     string
	secretKey []byte
	hasher    hash.Hasher
}

// NewDecoder creates a new JWT decoder instance
func NewDecoder(secretKey string, algorithm hash.Algorithm) (*Decoder, error) {
	hasher, err := hash.NewHasher(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to create hasher: %w", err)
	}

	return &Decoder{
		secretKey: []byte(secretKey),
		hasher:    hasher,
	}, nil
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
		if !d.hasher.Verify([]byte(signatureInput), parts[2], d.secretKey) {
			return "", fmt.Errorf("invalid signature")
		}
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid JWT format: payload is not valid base64")
	}

	// Store the token for potential future use
	d.token = token

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

// Token returns the current token being processed
func (d *Decoder) Token() string {
	return d.token
}
