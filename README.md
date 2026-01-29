# esec: Encrypted Secrets Management for Go

**esec** is a Go library and CLI tool for managing encrypted secrets using **environment files (`.env`), JSON (`.ejson`), and other formats**. It allows developers to securely store and retrieve sensitive configurations using **public-key cryptography**.

It draws heavy inspiration from the [EJSON](https://github.com/Shopify/ejson) project and aims to provide a similar experience for Go developers. A large part of the crypto related code and the file format handling is also inspired by or directly taken from the EJSON project.

Main differences are that **esec** is more opinionated on the file naming conventions and the key lookup process. EJSON writes the keys to a local dir in the format of `keydir/<public-key>/<private-key>` and then looks up the keys from there. **esec** uses environment variables and a `.esec-keyring` file for key lookup.

## Features

- **Secure secrets storage** using public/private key encryption (NaCl box)
- **Support for multiple formats** (`.env`, `.ejson`)
- **Decryption of secrets in embedded or external vaults**
- **CLI tool for encryption & decryption**
- **Run commands with decrypted environment variables**
- **Extract specific keys** from encrypted files
- **Flexible environment & key management** via keyring file
- **Debug logging** with `--debug` flag

## Installation

### Using Go Modules

```sh
go get github.com/mscno/esec
```

### CLI Installation

```sh
go install github.com/mscno/esec/cmd/esec@latest
```

---

## CLI Usage

```
Usage: esec <command> [flags]

Commands:
  keygen     Generate a new keypair
  encrypt    Encrypt a secrets file
  decrypt    Decrypt a secrets file
  get        Decrypt and extract a specific key
  run        Decrypt secrets and run a command with them as env vars

Global Flags:
  --help       Show help
  --version    Show version
  --debug      Enable debug logging
```

### Generate Keys

Generate a new public/private keypair:

```sh
esec keygen
```

Output:

```
Public Key:
e50e7c0086bfac43263dc087dc9a0118d3b567d26a87c22876690bca8b50c00c
Private Key:
dfe357ede9f3b42b34ac1fca814a27a99f610e4fde361d09b78adcc659b88b79
```

### Encrypt Secrets

```sh
# Encrypt a file directly
esec encrypt .ejson.dev

# Encrypt using environment name (resolves to .ejson.dev)
esec encrypt dev

# Encrypt with a specific format
esec encrypt dev -f .env

# Dry run (print without writing)
esec encrypt dev --dry-run
```

**Flags:**
| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `.ejson` | File format (`.ejson`, `.env`) |
| `--dry-run` | `-d` | `false` | Print encrypted output without writing to file |

### Decrypt Secrets

```sh
# Decrypt a file directly
esec decrypt .ejson.dev

# Decrypt using environment name
esec decrypt dev

# Decrypt with a specific format
esec decrypt dev -f .env

# Decrypt with key from stdin
echo "your-private-key" | esec decrypt dev -k

# Decrypt using keyring from specific directory
esec decrypt dev -d /path/to/keyring/dir
```

**Flags:**
| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `.ejson` | File format (`.ejson`, `.env`) |
| `--key-from-stdin` | `-k` | `false` | Read private key from stdin |
| `--key-dir` | `-d` | `.` | Directory containing `.esec-keyring` file |

### Get a Specific Key

Extract a single value from an encrypted file:

```sh
# Get a specific key from encrypted file
esec get dev DATABASE_URL

# Get with specific format
esec get dev API_KEY -f .env

# Get with key from stdin
echo "your-private-key" | esec get dev SECRET -k
```

**Flags:**
| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `.ejson` | File format (`.ejson`, `.env`) |
| `--key-from-stdin` | `-k` | `false` | Read private key from stdin |
| `--key-dir` | `-d` | `.` | Directory containing `.esec-keyring` file |

### Run Commands with Secrets

Decrypt secrets and run a command with them as environment variables:

```sh
# Run with ejson format (default)
esec run dev -- myapp serve

# Run with env format
esec run production -f .env -- myapp serve

# Equivalent explicit file paths
esec run .ejson.dev -- myapp serve
esec run .env.production -- myapp serve

# With key from stdin
echo "your-private-key" | esec run dev -k -- myapp serve
```

**Flags:**
| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `.ejson` | File format (`.ejson`, `.env`) |
| `--key-from-stdin` | `-k` | `false` | Read private key from stdin |
| `--key-dir` | `-d` | `.` | Directory containing `.esec-keyring` file |

### Debug Mode

Enable detailed logging with the `--debug` flag:

```sh
esec --debug decrypt dev
esec --debug run dev -- myapp serve
```

---

## File Naming Convention

esec follows a structured naming convention for environment-based encryption files:

| Format | Base Name | With Environment |
|--------|-----------|------------------|
| JSON | `.ejson` | `.ejson.dev`, `.ejson.prod` |
| Dotenv | `.env` | `.env.dev`, `.env.prod` |

### Environment Resolution

When you pass an environment name instead of a filename, esec automatically resolves it:

| Command | Resolves To | Private Key Lookup |
|---------|-------------|-------------------|
| `esec encrypt` | `.ejson` | `ESEC_PRIVATE_KEY` |
| `esec encrypt dev` | `.ejson.dev` | `ESEC_PRIVATE_KEY_DEV` |
| `esec decrypt prod` | `.ejson.prod` | `ESEC_PRIVATE_KEY_PROD` |
| `esec decrypt dev -f .env` | `.env.dev` | `ESEC_PRIVATE_KEY_DEV` |

---

## Private Key Lookup

When decrypting, esec searches for the private key in this order:

### 1. Environment Variables

```sh
export ESEC_PRIVATE_KEY=your-private-key           # Default environment
export ESEC_PRIVATE_KEY_DEV=your-dev-key           # Dev environment
export ESEC_PRIVATE_KEY_PROD=your-prod-key         # Prod environment
```

### 2. Keyring File (`.esec-keyring`)

If not found in environment variables, esec looks for a `.esec-keyring` file:

```dotenv
###########################################################
### Private key file - Do not commit to version control ###
###########################################################

### Active Key
ESEC_ACTIVE_ENVIRONMENT=dev

### Private Keys
ESEC_PRIVATE_KEY_DEV=your-dev-private-key
ESEC_PRIVATE_KEY_PROD=your-prod-private-key
```

**Special Variables:**

| Variable | Description |
|----------|-------------|
| `ESEC_ACTIVE_ENVIRONMENT` | Specifies which environment to use (e.g., `dev`, `prod`) |
| `ESEC_ACTIVE_KEY` | Alternative: specifies which key variable to use (e.g., `ESEC_PRIVATE_KEY_DEV`) |

If neither is set and multiple keys exist, esec matches based on the file being decrypted.

---

## File Formats

### JSON Format (`.ejson`)

```json
{
  "_ESEC_PUBLIC_KEY": "493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d",
  "DATABASE_URL": "postgres://localhost/mydb",
  "API_KEY": "secret123",
  "nested": {
    "value": "also encrypted"
  },
  "_metadata": {
    "note": "underscore prefix prevents encryption"
  }
}
```

**Rules:**
- Must have `ESEC_PUBLIC_KEY` or `_ESEC_PUBLIC_KEY` at top level
- All string values are encrypted (except object keys)
- Keys starting with `_` are not encrypted
- Numbers, booleans, and nulls are not encrypted

**Encrypted:**

```json
{
  "_ESEC_PUBLIC_KEY": "493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d",
  "DATABASE_URL": "ESEC[1:HMvqzjm4wFgQzL0qo6fDsgfiS1e7y1knsTvgskUEvRo=:gwjm0ng6DE3FlL8F617cRMb8cBeJ2v1b:KryYDmzxT0OxjuLlIgZHx73DhNvE]",
  "API_KEY": "ESEC[1:HMvqzjm4wFgQzL0qo6fDsgfiS1e7y1knsTvgskUEvRo=:05gVhGzlZ+uAkDhUQkF/Ek8ketC9ta9f:bxHz36i/Etrl3BSGwCw5CmNix89t]",
  "nested": {
    "value": "ESEC[1:HMvqzjm4wFgQzL0qo6fDsgfiS1e7y1knsTvgskUEvRo=:3Zcx6Quy0mj5MdUDJduNKGgPDqBOLHYB:s9/u1dhQtYoeWGymnZlWogT8UnMR]"
  },
  "_metadata": {
    "note": "underscore prefix prevents encryption"
  }
}
```

### Dotenv Format (`.env`)

```dotenv
# Database configuration
ESEC_PUBLIC_KEY=493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d

DATABASE_URL=postgres://localhost/mydb
API_KEY=secret123
```

**Rules:**
- Must have `ESEC_PUBLIC_KEY` field
- Only values are encrypted, not keys
- Comments and blank lines are preserved
- `ESEC_PUBLIC_KEY` is never encrypted

**Encrypted:**

```dotenv
# Database configuration
ESEC_PUBLIC_KEY=493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d

DATABASE_URL=ESEC[1:uFOJzedrCFCn2wBvZJT+5hG/nFY6pDPJ3cP6E2OxHTQ=:dMlog4zL55ar0O2szkZWYPZUWgA5ypRv:CPOF3sboowCHClcvE7hidYh/9PzX]
API_KEY=ESEC[1:uFOJzedrCFCn2wBvZJT+5hG/nFY6pDPJ3cP6E2OxHTQ=:aBcDefGhIjKlMnOpQrStUvWxYz012345:Base64EncryptedValue==]
```

---

## Go Library Usage

### Generate Keypair

```go
package main

import (
    "fmt"
    "github.com/mscno/esec"
)

func main() {
    pub, priv, err := esec.GenerateKeypair()
    if err != nil {
        panic(err)
    }
    fmt.Printf("Public:  %s\nPrivate: %s\n", pub, priv)
}
```

### Encrypt Data

```go
package main

import (
    "bytes"
    "fmt"
    "github.com/mscno/esec"
)

func main() {
    data := []byte(`{"_ESEC_PUBLIC_KEY": "493ffcfba...", "secret": "myvalue"}`)

    var output bytes.Buffer
    _, err := esec.Encrypt(bytes.NewReader(data), &output, esec.FileFormatEjson)
    if err != nil {
        panic(err)
    }

    fmt.Println(output.String())
}
```

### Decrypt Data

```go
package main

import (
    "bytes"
    "fmt"
    "os"
    "github.com/mscno/esec"
)

func main() {
    os.Setenv("ESEC_PRIVATE_KEY", "your-private-key")

    encrypted := []byte(`{"_ESEC_PUBLIC_KEY": "...", "secret": "ESEC[...]"}`)

    var output bytes.Buffer
    _, err := esec.Decrypt(bytes.NewReader(encrypted), &output, "", esec.FileFormatEjson, ".", "")
    if err != nil {
        panic(err)
    }

    fmt.Println(output.String())
}
```

### Decrypt File

```go
package main

import (
    "fmt"
    "os"
    "github.com/mscno/esec"
)

func main() {
    os.Setenv("ESEC_PRIVATE_KEY_DEV", "your-private-key")

    data, err := esec.DecryptFile(".ejson.dev", ".", "")
    if err != nil {
        panic(err)
    }

    fmt.Println(string(data))
}
```

### Decrypt from Embedded Filesystem

```go
package main

import (
    "embed"
    "fmt"
    "log/slog"
    "os"
    "github.com/mscno/esec"
)

//go:embed secrets/*
var vault embed.FS

func main() {
    os.Setenv("ESEC_PRIVATE_KEY_PROD", "your-private-key")

    config := esec.DecryptFromEmbedConfig{
        EnvName: "prod",
        Format:  esec.FileFormatEjson,
        Logger:  slog.Default(),
        Keydir:  ".",
    }

    data, err := esec.DecryptFromEmbedFSWithConfig(vault, config)
    if err != nil {
        panic(err)
    }

    fmt.Println(string(data))
}
```

### Convert to Environment Map

```go
package main

import (
    "fmt"
    "os"
    "github.com/mscno/esec"
)

func main() {
    os.Setenv("ESEC_PRIVATE_KEY", "your-private-key")

    // Decrypt file
    data, err := esec.DecryptFile(".ejson", ".", "")
    if err != nil {
        panic(err)
    }

    // Convert to map (for ejson)
    envMap, err := esec.EjsonToEnv(data)
    if err != nil {
        panic(err)
    }

    // Or for dotenv
    // envMap, err := esec.DotEnvToEnv(data)

    for k, v := range envMap {
        fmt.Printf("%s=%s\n", k, v)
    }
}
```

---

## Security Notes

- **Never commit** `.esec-keyring` or private keys to version control
- Add to `.gitignore`:
  ```
  .esec-keyring
  ```
- Encrypted files (`.ejson`, `.env` with ESEC values) **can** be committed safely
- Use environment-specific keys for different deployments
- The `run` command validates commands to prevent shell injection attacks

---

## Encryption Format

Encrypted values use the format:

```
ESEC[<version>:<public-key>:<nonce>:<ciphertext>]
```

- **Version**: Schema version (currently `1`)
- **Public key**: Ephemeral public key (base64, 32 bytes)
- **Nonce**: Random nonce (base64, 24 bytes)
- **Ciphertext**: Encrypted data (base64)

Encryption uses NaCl box (Curve25519, XSalsa20, Poly1305).
