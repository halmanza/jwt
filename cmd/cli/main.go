package main

import (
	"flag"
	"fmt"
	"os"

	"jwt/internal/domain/hash"
	"jwt/internal/interface/cli"
	jwtusecase "jwt/internal/usecase/jwt"
)

func main() {
	// Set custom usage message
	flag.Usage = func() {
		fmt.Print(cli.UsageMessage)
	}

	// Parse flags
	validateFlag := flag.Bool("validate", false, "Validate JWT signature")
	algorithmFlag := flag.String("algorithm", "HS256", "Hash algorithm to use (HS256, HS384, HS512)")
	flag.Parse()

	// Get the command and args after flag parsing
	args := flag.Args()
	if len(args) < 1 {
		fmt.Print(cli.UsageMessage)
		os.Exit(1)
	}

	// Parse algorithm
	algorithm := hash.Algorithm(*algorithmFlag)
	hasher, err := hash.NewHasher(algorithm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid algorithm %s. Supported algorithms: HS256, HS384, HS512\n", algorithm)
		os.Exit(1)
	}

	// Create decoder
	decoder := jwtusecase.NewDecoder(hasher)

	// Create CLI handler
	handler := cli.NewHandler(decoder)

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
