package cli

import (
	"fmt"
	"os"
	"strings"

	"jwt/internal/domain/hash"
	"jwt/internal/domain/jwt"
	jwtusecase "jwt/internal/usecase/jwt"
)

// Run executes the CLI command with default configuration
func Run(args ...string) error {
	hasher, err := hash.NewHasher(hash.HS256)
	if err != nil {
		return fmt.Errorf("failed to create hasher: %w", err)
	}
	decoder := jwtusecase.NewDecoder(hasher)
	handler := NewHandler(decoder)
	return handler.Run(args...)
}

// Handler handles CLI commands
type Handler struct {
	decoder jwt.Decoder
}

// NewHandler creates a new CLI handler
func NewHandler(decoder jwt.Decoder) *Handler {
	return &Handler{
		decoder: decoder,
	}
}

// Run executes the CLI command
func (h *Handler) Run(args ...string) error {
	if len(args) < 1 {
		fmt.Print(UsageMessage)
		return nil
	}

	// Find the command and validate flag
	command := ""
	validate := false
	algorithm := hash.HS256
	for i, arg := range args {
		if arg == "decode" {
			command = arg
			break
		}
		if arg == "-validate" {
			validate = true
		}
		if arg == "-generate" {
			command = "generate"
			break
		}
		if arg == "-algorithm" && i+1 < len(args) {
			algo := strings.ToUpper(args[i+1])
			algorithm = hash.Algorithm(algo)
		}
	}

	if command == "" {
		fmt.Print(UsageMessage)
		return nil
	}

	switch command {
	case "decode":
		// Find the token (last argument)
		token := args[len(args)-1]
		if token == "" {
			return fmt.Errorf("JWT token is required")
		}

		if validate {
			if algorithm == hash.RS256 {
				if os.Getenv("JWT_PUBLIC_KEY") == "" {
					return fmt.Errorf("JWT_PUBLIC_KEY environment variable is required for RS256 validation")
				}
			} else {
				if os.Getenv("JWT_SECRET_KEY") == "" {
					return fmt.Errorf("JWT_SECRET_KEY environment variable is required for validation")
				}
			}
		}

		jwtData, err := h.decoder.Decode(token, validate)
		if err != nil {
			return fmt.Errorf("failed to decode JWT: %w", err)
		}

		// Just print the formatted output directly
		fmt.Print(jwtData)
		return nil
	case "generate":
		// Generate a test token with the specified algorithm
		token, err := h.decoder.GenerateTestToken(algorithm)
		if err != nil {
			return fmt.Errorf("failed to generate test token: %w", err)
		}
		fmt.Println("Generated JWT Token:")
		fmt.Println(token)
		return nil
	default:
		fmt.Print(UsageMessage)
		return nil
	}
}

// UsageMessage is the help text displayed when no arguments are provided
const UsageMessage = `JWT CLI Tool

Usage:
  jwt [flags] command [arguments]

Commands:
  decode <token>    Decode a JWT token
  generate         Generate a test JWT token (uses HS256 by default)

Flags:
  -algorithm string
        Hash algorithm to use (HS256, HS384, HS512) (default "HS256")
  -validate
        Validate JWT signature
  -generate
        Generate a test JWT token with realistic claims

Examples:
  # Decode a JWT token
  jwt decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

  # Decode and validate a JWT token
  jwt decode -validate eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

  # Generate a test JWT token (uses HS256)
  jwt -generate

  # Generate a test JWT token with a specific algorithm
  jwt -generate -algorithm HS384

  # Use a different algorithm
  jwt -algorithm HS384 decode eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9...

Environment Variables:
  JWT_SECRET_KEY    Secret key for validating JWT signatures
`
