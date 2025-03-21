# JWT CLI

A CLI tool for common tasks with JavaScript Web Tokens (JWT), including decoding and signature validation.

## Installation

### Windows Installation

1. Download the latest release from [Releases](https://github.com/yourusername/jwt/releases):
   - Download `jwt_windows_x86_64.zip`

2. Create installation directory:
   ```powershell
   # Create a directory in your user's Programs folder
   mkdir "$env:LOCALAPPDATA\Programs\JWT"
   ```

3. Extract the downloaded zip and create batch file:
   - Extract `jwt.exe` to `%LOCALAPPDATA%\Programs\JWT\` (typically `C:\Users\YourUsername\AppData\Local\Programs\JWT\`)
   - Create a new file `jwt.bat` in the same directory with these contents:
     ```batch
     @echo off
     "%~dp0jwt.exe" %*
     ```

4. Add to User PATH:
   - Press Win + X and select "System"
   - Click "Advanced system settings"
   - Click "Environment Variables"
   - Under "User variables for YourUsername", find and select "Path"
   - Click "Edit" → "New"
   - Add `%LOCALAPPDATA%\Programs\JWT`
   - Click "OK" on all windows
   - Restart any open command prompts or PowerShell windows

5. Verify installation:
   ```powershell
   jwt
   ```
   This should display the CLI's help information and available commands.

### Option 1: Download Pre-built Binaries

Visit the [Releases](https://github.com/yourusername/jwt/releases) page to download pre-built binaries for your platform:

- Windows (amd64): `jwt_windows_x86_64.zip`
- macOS (amd64): `jwt_darwin_x86_64.tar.gz`
- macOS (arm64): `jwt_darwin_arm64.tar.gz`
- Linux (amd64): `jwt_linux_x86_64.tar.gz`
- Linux (arm64): `jwt_linux_arm64.tar.gz`

### Adding to System PATH

#### macOS
1. Extract the tar.gz file
2. Option A - Using /usr/local/bin (requires admin rights):
   ```bash
   sudo mv jwt /usr/local/bin/
   ```
   
   Option B - Using ~/bin (no admin rights needed):
   ```bash
   mkdir -p ~/bin
   mv jwt ~/bin/
   echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc  # For Zsh
   echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bash_profile  # For Bash
   source ~/.zshrc  # Or source ~/.bash_profile for Bash
   ```

#### Linux
1. Extract the tar.gz file
2. Option A - System-wide installation (requires sudo):
   ```bash
   sudo mv jwt /usr/local/bin/
   ```

   Option B - User-specific installation:
   ```bash
   mkdir -p ~/.local/bin
   mv jwt ~/.local/bin/
   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
   # If using Zsh, also add to ~/.zshrc:
   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
   source ~/.bashrc  # Or source ~/.zshrc for Zsh
   ```

### Verify Installation
After adding to PATH, verify the installation:
```bash
jwt --version
```

If successful, you can now use the `jwt` command from any terminal location.

## Features

- **JWT Decoder**: Parse and display JWT tokens
  - Formats JSON nicely for readable headers and payloads
  - Supports multiple algorithms:
    - HMAC algorithms (HS256, HS384, HS512)
    - RSA algorithm (RS256)
  - Signature validation
  - Cross-platform support (Windows, Linux, macOS)
  - PowerShell-friendly output formatting

## Usage

### Basic JWT Decoding

```bash
# Decode a JWT token without validation
jwt decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...  # Replace with your actual JWT token

# Decode with specific algorithm (case-insensitive)
jwt -algorithm HS256 decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
jwt -algorithm RS256 decode eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

### JWT Validation

#### For HMAC Algorithms (HS256, HS384, HS512)

```bash
# Set the secret key
export JWT_SECRET_KEY="your-secret-key"  # Unix/Linux
$env:JWT_SECRET_KEY="your-secret-key"    # PowerShell

# Validate JWT with HS256
jwt -validate -algorithm HS256 decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Validate JWT with HS384
jwt -validate -algorithm HS384 decode eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9...

# Validate JWT with HS512
jwt -validate -algorithm HS512 decode eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...
```

#### For RSA Algorithm (RS256)

```bash
# Set the public key (PEM format)
# Note: The public key must be in PEM format with proper BEGIN and END markers
export JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."  # Unix/Linux
$env:JWT_PUBLIC_KEY = @"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
"@  # PowerShell

# Validate JWT with RS256
jwt -validate -algorithm RS256 decode eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Example Output

```bash
# Without validation
Header:
{
  "alg": "RS256",
  "typ": "JWT"
}

Payload:
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1710920400,  # Issued at: Unix timestamp (seconds since epoch)
  "exp": 1710924000   # Expiration: Unix timestamp (seconds since epoch)
}

# With validation
Header:
{
  "alg": "RS256",
  "typ": "JWT"
}

Payload:
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1710920400,
  "exp": 1710924000
}

Signature: Valid
```

## Requirements

- Go 1.21 or higher (for building from source)
- Pre-built binaries are available for:
  - Windows (amd64)
  - macOS (amd64, arm64)
  - Linux (amd64, arm64)

## Environment Variables

- `JWT_SECRET_KEY`: Required for HMAC algorithm validation (HS256, HS384, HS512)
- `JWT_PUBLIC_KEY`: Required for RSA algorithm validation (RS256)
  - Must be in PEM format
  - Must include proper BEGIN and END markers
  - Example format:
    ```
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
    -----END PUBLIC KEY-----
    ```

## Error Handling

The CLI will return appropriate error messages for:
- Invalid JWT format
- Missing environment variables
- Invalid signatures
- Unsupported algorithms
- Expired tokens (when validation is enabled)
- Invalid PEM format for public keys

## Notes

- Algorithm names are case-insensitive (e.g., "RS256" and "rs256" are equivalent)
- JWT timestamps (iat, exp) are Unix timestamps in seconds since epoch
- Replace example tokens with your actual JWT tokens
- For RS256, ensure your public key is in proper PEM format

## What's Next?

I'm planning to add more utilities as I need them. Feel free to suggest ideas or contribute!

---

**P.S.** From the Westminster Shorter Catechism:

**Question 1: What is the chief end of man?**

*Answer: Man's chief end is to glorify God, and to enjoy him forever.* 