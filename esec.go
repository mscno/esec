package esec

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/dotenv"
	"github.com/mscno/esec/pkg/format"
	"github.com/mscno/esec/pkg/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const (
	ESEC_PUBLIC_KEY  = "ESEC_PUBLIC_KEY"
	ESEC_PRIVATE_KEY = "ESEC_PRIVATE_KEY"
)

func GenerateKeypair() (pub string, priv string, err error) {
	var kp crypto.Keypair
	if err := kp.Generate(); err != nil {
		return "", "", err
	}
	return kp.PublicString(), kp.PrivateString(), nil
}

type FormatType string

const (
	Env   FormatType = ".env"
	Ejson FormatType = ".ejson"
	Eyaml FormatType = ".eyaml"
	Eyml  FormatType = ".eyml"
	Etoml FormatType = ".etoml"
)

// DecryptFromVault retrieves and decrypts a file from an embedded filesystem.
// It determines the environment name automatically unless an override is provided.
// The function reads the encrypted file based on the specified format, then decrypts it
// and returns the decrypted data.
//
// Parameters:
//   - v: An embedded filesystem containing the encrypted files.
//   - envOverride: An optional environment name override.
//   - format: The format type of the encrypted file.
//
// Returns:
//   - The decrypted file content as a byte slice.
//   - An error if any step fails (e.g., environment detection, file reading, decryption).
func DecryptFromVault(v embed.FS, envOverride string, format FormatType) ([]byte, error) {
	// Try to determine the environment name automatically.
	envName, err := sniffEnvName()
	if err != nil {
		return nil, fmt.Errorf("error sniffing environment name: %v", err)
	}

	// If an environment override is provided, use it instead of the detected name.
	if envOverride != "" {
		envName = envOverride
	}

	// Generate the filename based on the format and environment name.
	fileName, err := generateFilename(format, envName)
	if err != nil {
		return nil, err // Return the error if filename generation fails.
	}

	// Attempt to read the file from the embedded filesystem.
	data, err := v.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("error reading file from vault: %v", err)
	}

	// Decrypt the file data and return the decrypted bytes.
	privkey, err := findPrivateKey("", envName, "")
	if err != nil {
		return nil, err
	}
	// Decrypt the file data and return the decrypted bytes.
	return decryptData(privkey, data, format)
}

// EncryptFileInPlace takes a path to a file on disk, which must be a valid ecfg file
// (see README.md for more on what constitutes a valid ecfg file). Any
// encryptable-but-unencrypted fields in the file will be encrypted using the
// public key embdded in the file, and the resulting text will be written over
// the file present on disk.
func EncryptFileInPlace(input string) (int, error) {
	filePath, _, err := processFileOrEnv(input)
	if err != nil {
		return -1, fmt.Errorf("error processing file or env: %v", err)
	}
	data, err := readFile(filePath)
	if err != nil {
		return -1, err
	}

	fileMode, err := getMode(filePath)
	if err != nil {
		return -1, err
	}

	formatType, err := detectFormat(filePath)
	if err != nil {
		return -1, err
	}

	newdata, err := encryptData(data, formatType)
	if err != nil {
		return -1, err
	}

	if err := writeFile(filePath, newdata, fileMode); err != nil {
		return -1, err
	}

	return len(newdata), nil
}

func Encrypt(in io.Reader, out io.Writer, fileFormat FormatType) (int, error) {
	// Read the input data
	data, err := io.ReadAll(in)
	if err != nil {
		return -1, err
	}

	encryptedData, err := encryptData(data, fileFormat)
	if err != nil {
		return -1, err
	}
	return out.Write(encryptedData)
}

func encryptData(data []byte, fileFormat FormatType) ([]byte, error) {
	// Extract the public key
	var formatter format.FormatHandler
	switch fileFormat {
	case Env:
		formatter = &dotenv.DotEnvFormatter{}
	case Ejson:
		formatter = &json.JsonFormatter{}
	default:
		return nil, fmt.Errorf("unsupported format: %s", fileFormat)
	}

	pubkey, err := formatter.ExtractPublicKey(data)
	if err != nil {
		return nil, err
	}

	// Generate a new keypair for encryption
	var kp crypto.Keypair
	err = kp.Generate()
	if err != nil {
		return nil, err
	}

	// Create an encrypter using the public key extracted from the input data
	enc := kp.Encrypter(pubkey)

	formattedData, err := formatter.TransformScalarValues(data, enc.Encrypt)
	if err != nil {
		return nil, err
	}
	return formattedData, nil
}

func DecryptFile(input string, keydir string, userSuppliedPrivateKey string) ([]byte, error) {
	fileName, envName, err := processFileOrEnv(input)
	if err != nil {
		fmt.Errorf("error processing file or env: %v", err)
	}

	data, err := readFile(fileName)
	if err != nil {
		return nil, err
	}

	fileFormat, err := detectFormat(fileName)
	if err != nil {
		return nil, err
	}

	privkey, err := findPrivateKey(keydir, envName, userSuppliedPrivateKey)
	if err != nil {
		return nil, err
	}

	decryptedData, err := decryptData(privkey, data, fileFormat)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

func Decrypt(in io.Reader, out io.Writer, envName string, fileFormat FormatType, keydir string, userSuppliedPrivateKey string) (int, error) {

	data, err := io.ReadAll(in)
	if err != nil {
		return -1, err
	}

	privkey, err := findPrivateKey(keydir, envName, userSuppliedPrivateKey)
	if err != nil {
		return -1, err
	}

	decryptedData, err := decryptData(privkey, data, fileFormat)
	if err != nil {
		return -1, err
	}

	return out.Write(decryptedData)
}

func decryptData(privkey [32]byte, data []byte, fileFormat FormatType) ([]byte, error) {
	var formatter format.FormatHandler
	switch fileFormat {
	case Env:
		formatter = &dotenv.DotEnvFormatter{}
	case Ejson:
		formatter = &json.JsonFormatter{}
	default:
		return nil, fmt.Errorf("unsupported format: %s", fileFormat)
	}
	pubkey, err := formatter.ExtractPublicKey(data)
	if err != nil {
		return nil, err
	}

	myKP := crypto.Keypair{
		Public:  pubkey,
		Private: privkey,
	}

	decrypter := myKP.Decrypter()

	decryptedData, err := formatter.TransformScalarValues(data, decrypter.Decrypt)
	if err != nil {
		return nil, err
	}
	return decryptedData, nil
}

// findPrivateKey retrieves a private key from user input, environment variables, or keyring file.
// It prioritizes user-supplied keys, then environment variables, and finally the keyring file.
func findPrivateKey(keyPath, envName, userSuppliedPrivateKey string) ([32]byte, error) {
	var privKey [32]byte

	// If the user supplied a private key, use it directly.
	if userSuppliedPrivateKey != "" {
		return format.ParseKey(userSuppliedPrivateKey)
	}

	// Determine the key name to look up.
	keyToLookup := ESEC_PRIVATE_KEY
	if envName != "" {
		keyToLookup = fmt.Sprintf("%s_%s", ESEC_PRIVATE_KEY, strings.ToUpper(envName))
	}
	vars := os.Environ()
	_ = vars
	// Check if the private key is in environment variables.
	if privKeyString, exists := os.LookupEnv(keyToLookup); exists {
		return format.ParseKey(privKeyString)
	}

	// If not found in env vars, try reading from the keyring file.
	keyringPath := filepath.Join(keyPath, ".esec-keyring")
	privateKeyFile, err := os.ReadFile(keyringPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return privKey, fmt.Errorf("private key not found in environment variables, and keyring file does not exist at %q", keyringPath)
		}
		return privKey, fmt.Errorf("failed to read keyring file at %q: %w", keyringPath, err)
	}

	// Parse the keyring file as environment variables.
	privateKeyEnvs, err := godotenv.Parse(bytes.NewBuffer(privateKeyFile))
	if err != nil {
		return privKey, fmt.Errorf("failed to parse keyring file %q: %w", keyringPath, err)
	}

	// Retrieve the private key from the parsed keyring file.
	privKeyString, found := privateKeyEnvs[keyToLookup]
	if !found {
		return privKey, fmt.Errorf("private key %q not found in keyring file %q", keyToLookup, keyringPath)
	}

	// Parse and return the private key.
	return format.ParseKey(privKeyString)
}

// for mocking in tests
func _getMode(path string) (os.FileMode, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Mode(), nil
}

// for mocking in tests
var (
	readFile  = ioutil.ReadFile
	writeFile = ioutil.WriteFile
	getMode   = _getMode
	getuid    = os.Getuid
	getenv    = os.Getenv
)
