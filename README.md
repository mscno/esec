# esec: Encrypted Secrets Management for Go

**Esec** is a Go library and CLI tool for managing encrypted secrets using **environment files (`.env`), JSON (`.ejson`), and other formats**. It allows developers to securely store and retrieve sensitive configurations using **public-key cryptography**.

It draws heavy inspiration from the [EJSON](https://github.com/Shopify/ejson) project and aims to provide a similar experience for Go developers. A large part of the crypto related  code and the file format handling is also inspired by or directly taken from the EJSON project.

Main differences are that **esec** is more opinionated on the file naming conventions and the key lookup process. Ejson writes the keys to a local dir in the format of `keydir/<public-key>/<private-key>` and then looks up the keys from there. **esec** uses environment variables and a `.esec-keyring` file for key lookup. 


### Features
✅ **Secure secrets storage** using public/private key encryption.  
✅ **Support for multiple formats** (`.env`, `.ejson`).  
✅ **Decryption of secrets in embedded or external vaults**.  
✅ **CLI tool for encryption & decryption**.  
✅ **Integrates easily into Go applications**.

### Todo
- [ ] Add support for more file formats (`.eyaml`, `.etoml`).
- [ ] Add more test coverage.
- [ ] Standardize the package API.

---

## Installation

### Using Go Modules
```sh
go get github.com/mscno/esec
```

### CLI Installation

```sh
go install github.com/mscno/esec/cmd/esec@latest
```

## Using the CLI

```sh
esec keygen
```

Output:

```text
Public Key:
e50e7c0086bfac43263dc087dc9a0118d3b567d26a87c22876690bca8b50c00c
Private Key:
dfe357ede9f3b42b34ac1fca814a27a99f610e4fde361d09b78adcc659b88b79

```

## **ESEC Naming Convention and Key Lookup Process**

## **Naming Convention**

The **esec** library follows a structured naming convention for **environment-based encryption files**. This convention ensures consistency when encrypting and decrypting secrets across multiple formats.

### **File Naming Conventions**
| File Type                       | Naming Pattern       | Naming with Environment (`dev`) | Description |
|---------------------------------|----------------------|--------------------------------|-------------|
| **Encrypted Environment Files** | `.env`        | `.env.ejson.dev`               | An encrypted `.env` file. |
| **Encrypted JSON Files**        | `.ejson`            | `.ejson.dev`                   | A JSON file with encrypted fields. |
| **Encrypted YAML Files**        | `.eyaml`            | `.eyaml.dev`                   | A YAML file with encrypted fields. |
| **Encrypted TOML Files**        | `.etoml`            | `.etoml.dev`                   | A TOML file with encrypted fields. |

---

## **Standard vs. Environment-Specific Naming**
### **What Happens if No Environment is Provided?**
If no **environment name** is provided when running an encryption or decryption command, `esec` assumes the **standard environment**. This means:
- The filename will **not** include an environment suffix.
- The key lookup process will only use the **default private key** (`ESEC_PRIVATE_KEY`).

#### **Example Behavior**
| Command                      | Resolves To          | Private Key Lookup |
|------------------------------|----------------------|---------------------|
| `esec encrypt`               | `.ejson`            | `ESEC_PRIVATE_KEY` |
| `esec encrypt dev`           | `.ejson.dev`        | `ESEC_PRIVATE_KEY_DEV` |
| `esec decrypt`               | `.ejson`            | `ESEC_PRIVATE_KEY` |
| `esec decrypt dev`           | `.ejson.dev`        | `ESEC_PRIVATE_KEY_DEV` |

If no **specific environment** is provided, `esec` defaults to using the **blank/standard environment**, meaning:
1. **For encryption**, it encrypts to `.ejson`.
2. **For decryption**, it tries to find `ESEC_PRIVATE_KEY` to decrypt `.ejson`.

---

## **How File Naming Works in Encryption & Decryption**

### **1. `esec encrypt dev` vs. `esec encrypt .ejson.dev`**

These two commands **produce the same output** because **`dev`** is treated as an **environment name**, and the system automatically constructs the corresponding filename.

```sh
esec encrypt dev
```

```sh
esec encrypt .ejson.dev
```
---

Why?
•	When you pass an environment name, esec automatically generates the corresponding file name using the .ejson format.
•	The default format for encrypted environment files is .ejson, so dev becomes .ejson.dev.


## 2. How the Private Key is Located

When decrypting an encrypted file, esec looks for the private key in the following order:

#### Step 1: Search for Environment Variables

esec first checks if the private key is set in environment variables:
```sh
export ESEC_PRIVATE_KEY=your-private-key
export ESEC_PRIVATE_KEY_DEV=your-private-key
export ESEC_PRIVATE_KEY_PROD=your-private-key
```

If the input file is .ejson.dev, esec searches for:
1.	ESEC_PRIVATE_KEY_DEV

If the file is .ejson.prod, esec searches for:
1.	ESEC_PRIVATE_KEY_PROD

If a matching private key is found, it is used for decryption.

#### Step 2: Check .esec-keyring File

If the private key is not found in environment variables, esec looks for a .esec-keyring file in the current directory.

Example .esec-keyring file:

```dotenv
# .esec-keyring file
ESEC_PRIVATE_KEY_DEV=your-private-key
ESEC_PRIVATE_KEY_PROD=your-private-key
```
If esec is decrypting .ejson.dev, it searches for ESEC_PRIVATE_KEY_DEV inside .esec-keyring.

If a matching key is found, it is used for decryption.

## esec File Formats

### esec JSON (.ejson)

The **esec** JSON document format is simple, but there are a few points to be aware of:

- It's just JSON.
- The file must have a ESEC_PUBLIC_KEY field at the top level.
- There must be a key at the top level named _public_key, whose value is a 32-byte hex-encoded (i.e. 64 ASCII byte) public key as generated by ejson keygen.
- Any string literal that isn't an object key will be encrypted by default (ie. in {"a": "b"}, "b" will be encrypted, but "a" will not.
- Numbers, booleans, and nulls aren't encrypted.
- If a key begins with an underscore, its corresponding value will not be encrypted. This is used to prevent the _public_key field from being encrypted, and is useful for implementing metadata schemes.
- Underscores do not propagate downward. For example, in {"_a": {"b": "c"}}, "c" will be encrypted.

Example:

```json
{
  "_ESEC_PUBLIC_KEY": "493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d",
  "MY_VALUE": "hello",
  "MY_NUMBER": 123,
    "MY_ARRAY": [
        "hello",
        "world"],
  "MY_OBJECT": {
      "hello": "world"
  },
  "_metadata": {
    "_created_at": "2021-10-10T10:10:10Z"
  }
}
```

Encrypted Example:

```json
{
  "_ESEC_PUBLIC_KEY": "493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d",
  "MY_VALUE": "ESEC[1:HMvqzjm4wFgQzL0qo6fDsgfiS1e7y1knsTvgskUEvRo=:gwjm0ng6DE3FlL8F617cRMb8cBeJ2v1b:KryYDmzxT0OxjuLlIgZHx73DhNvE]",
  "MY_NUMBER": 123,
    "MY_ARRAY": [
        "ESEC[1:HMvqzjm4wFgQzL0qo6fDsgfiS1e7y1knsTvgskUEvRo=:05gVhGzlZ+uAkDhUQkF/Ek8ketC9ta9f:bxHz36i/Etrl3BSGwCw5CmNix89t]",
        "ESEC[1:HMvqzjm4wFgQzL0qo6fDsgfiS1e7y1knsTvgskUEvRo=:grLDhSld77JjdwXfSrooIp1Trl0/4/5u:iz+qKEJgk4+xD0f04VRInoL3AJOH]"],
  "MY_OBJECT": {
      "hello": "ESEC[1:HMvqzjm4wFgQzL0qo6fDsgfiS1e7y1knsTvgskUEvRo=:3Zcx6Quy0mj5MdUDJduNKGgPDqBOLHYB:s9/u1dhQtYoeWGymnZlWogT8UnMR]"
  },
  "_metadata": {
      "_created_at": "2021-10-10T10:10:10Z"
  }
}
```


### esec Dotenv (.env)

The **esec** dotenv format is a simple extension of the standard dotenv format. It allows you to encrypt values in your .env files.

- The file must have a ESEC_PUBLIC_KEY field.
- It's just a standard dotenv file.
- Encrypted values are prefixed with ESEC[ and suffixed with ].
- The key is not encrypted, only the value.
- Comments are not encrypted.
- Blank lines are not encrypted.
- The ESEC_PUBLIC_KEY field is not encrypted.

Example:

```dotenv
# Some comment

ESEC_PUBLIC_KEY=493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d #secret

MY_VALUE=some_secret_value
```

Encrypted Example:

```dotenv
# Some comment

ESEC_PUBLIC_KEY=493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d #secret

MY_VALUE=ESEC[1:uFOJzedrCFCn2wBvZJT+5hG/nFY6pDPJ3cP6E2OxHTQ=:dMlog4zL55ar0O2szkZWYPZUWgA5ypRv:CPOF3sboowCHClcvE7hidYh/9PzX]
```


## Integrating with Go

### 1. Encrypting Secrets in Go

```go
package main

import (
	"bytes"
	"fmt"
	"github.com/mscno/esec"
)

func main() {
	// Sample secret data
	data := []byte(`{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6...", "api_key": "supersecret"}`)
	
	// Encrypt the data
	var output bytes.Buffer
	_, err := esec.Encrypt(bytes.NewReader(data), &output, esec.Ejson)
	if err != nil {
		panic(err)
	}

	fmt.Println("Encrypted Output:", output.String())
}
```

### 2. Decrypting Secrets in Go

```go
package main

import (
	"bytes"
	"fmt"
	"github.com/mscno/esec"
	"os"
)

func main() {
	// Set private key as an env variable
	os.Setenv("ESEC_PRIVATE_KEY", "c5caa31a5b8cb...")

	// Encrypted JSON string
	encryptedData := `{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6...", "api_key": "ESEC[...]"}`
	
	// Decrypt the data
	var output bytes.Buffer
	_, err := esec.Decrypt(bytes.NewReader([]byte(encryptedData)), &output, "", esec.Ejson, "", "")
	if err != nil {
		panic(err)
	}

	fmt.Println("Decrypted Output:", output.String())
}
```


### 3. Decrypting from an Embedded Vault

These example demonstrates how to decrypt secrets from an embedded vault using the `embed` package.


This example assumes that the vault contains an encrypted file named `.ejson`.

```go
package main

import (
	"embed"
	"fmt"
	"github.com/mscno/esec"
	"os"
)

//go:embed secrets/*
var vault embed.FS

func main() {
	// Set private key
	os.Setenv("ESEC_PRIVATE_KEY", "c5caa31a5b8cb2...")

	// Decrypt from embedded vault
	data, err := esec.DecryptFromVault(vault, "", esec.Ejson)
	if err != nil {
		panic(err)
	}

	fmt.Println("Decrypted Vault Data:", string(data))
}
```

This example assumes that the vault contains an encrypted file named `.ejson.prod`.

```go
package main

import (
	"embed"
	"fmt"
	"github.com/mscno/esec"
	"os"
)

//go:embed secrets/*
var vault embed.FS

func main() {
	// Set private key
	os.Setenv("ESEC_PRIVATE_KEY_PROD", "c5caa31a5b8cb2...")

	// Decrypt from embedded vault
	data, err := esec.DecryptFromVault(vault, "", esec.Ejson)
	if err != nil {
		panic(err)
	}

	fmt.Println("Decrypted Vault Data:", string(data))
}
```


## Why Use esec?

- ✅ Simple & Secure
- ✅ Supports Multiple Formats
- ✅ Works with Embedded & External Secrets
- ✅ CLI & Go Integration