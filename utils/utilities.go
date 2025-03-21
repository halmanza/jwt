package utils

import (
	"fmt"
	"jwt/utils/hash"
	Decoder "jwt/utils/jwt"
)

// CLI represents a command-line interface user with their commands and arguments
type CLI struct {
	args     []string
	commands []string
	decoder  *Decoder.Decoder
}

// NewCLI creates a new CLI instance with initialized fields
func NewCLI(secretKey string, algorithm hash.Algorithm) (*CLI, error) {
	decoder, err := Decoder.NewDecoder(secretKey, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder: %w", err)
	}

	return &CLI{
		args:     make([]string, 0),
		commands: make([]string, 0),
		decoder:  decoder,
	}, nil
}

// SetInputs sets the commands and arguments for the CLI
func (c *CLI) SetInputs(commands, args []string) {
	c.commands = commands
	c.args = args
}

// Args returns the current arguments
func (c *CLI) Args() []string {
	return c.args
}

// Commands returns the current commands
func (c *CLI) Commands() []string {
	return c.commands
}

// PrintCommands prints all current commands
func (c *CLI) PrintCommands() {
	for _, cmd := range c.commands {
		fmt.Print(cmd)
	}
}

// DecodeJWT decodes a JWT token and returns the decoded string and any error
func (c *CLI) DecodeJWT(token string, validate bool) (string, error) {
	output, err := c.decoder.Decode(token, validate)
	if err != nil {
		return "", err
	}

	// Add title and formatting to the output
	formattedOutput := "JWT Decoded\n"
	formattedOutput += "===========\n\n"
	formattedOutput += output
	formattedOutput += "\n\n==========="

	return formattedOutput, nil
}
