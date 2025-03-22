package main

import (
	"flag"
	"fmt"
	"jwt/internal/domain/hash"
	"jwt/internal/interface/cli"
	jwtusecase "jwt/internal/usecase/jwt"
	"os"
	"strings"
)

// Version will be set during build
var Version = "dev"

func main() {
	// Set custom usage message
	flag.Usage = func() {
		fmt.Print(cli.UsageMessage)
	}

	// Parse flags
	versionFlag := flag.Bool("version", false, "Display version information")
	helpFlag := flag.Bool("help", false, "Display help information")
	validateFlag := flag.Bool("validate", false, "Validate JWT signature")
	algorithmFlag := flag.String("algorithm", "HS256", "Hash algorithm to use (HS256, HS384, HS512)")
	generateFlag := flag.Bool("generate", false, "Generate a test JWT token")
	flag.Parse()

	// Show version if requested
	if *versionFlag {
		fmt.Printf("jwt version %s\n", Version)
		os.Exit(0)
	}

	// Show help if requested
	if *helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	// Get the command and args after flag parsing
	args := flag.Args()
	if len(args) < 1 && !*generateFlag {
		flag.Usage()
		os.Exit(1)
	}

	// Parse algorithm (case-insensitive)
	algorithm := hash.Algorithm(strings.ToUpper(*algorithmFlag))
	hasher, err := hash.NewHasher(algorithm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid algorithm %s. Supported algorithms: HS256, HS384, HS512\n", algorithm)
		os.Exit(1)
	}

	// Create decoder
	decoder := jwtusecase.NewDecoder(hasher)

	// Create CLI handler
	handler := cli.NewHandler(decoder)

	// Handle generate command
	if *generateFlag {
		token, err := decoder.GenerateTestToken(algorithm)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating test token: %v\n", err)
			os.Exit(1)
		}
		fmt.Print("Test JWT Token:\n")
		fmt.Print(token)
		fmt.Print("\n\nSecret Key (for decoding):\n")
		fmt.Print("your-super-secret-key-123!@#$%^&*()\n")
		os.Exit(0)
	}

	// Add validate flag to args if set
	if *validateFlag {
		args = append([]string{"-validate"}, args...)
	}

	// Run command
	if err := handler.Run(args...); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
