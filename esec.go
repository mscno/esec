package esec

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/dotenv"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/format"
	"github.com/mscno/esec/pkg/json"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	EsecPublicKey  = "ESEC_PUBLIC_KEY"
	EsecPrivateKey = "ESEC_PRIVATE_KEY"
)

func GenerateKeypair() (pub string, priv string, err error) {
	var kp crypto.Keypair
	if err := kp.Generate(); err != nil {
		return "", "", err
	}
	return kp.PublicString(), kp.PrivateString(), nil
}

type FileFormat string

const (
	FileFormatEnv   FileFormat = ".env"
	FileFormatEjson FileFormat = ".ejson"
	FileFormatEyaml FileFormat = ".eyaml"
	FileFormatEyml  FileFormat = ".eyml"
	FileFormatEtoml FileFormat = ".etoml"
)

func validFormats() []FileFormat {
	return []FileFormat{FileFormatEnv, FileFormatEjson, FileFormatEyaml, FileFormatEyml, FileFormatEtoml}
}

// EncryptFileInPlace takes a path to a file on disk, which must be a valid ecfg file
// (see README.md for more on what constitutes a valid ecfg file). Any
// encryptable-but-unencrypted fields in the file will be encrypted using the
// public key embdded in the file, and the resulting text will be written over
// the file present on disk.
func EncryptFileInPlace(filePath string) (int, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return -1, err
	}

	fileMode, err := os.Stat(filePath)
	if err != nil {
		return -1, err
	}

	formatType, err := fileutils.ParseFormat(filePath)
	if err != nil {
		return -1, err
	}

	newdata, err := encryptData(data, FileFormat(formatType))
	if err != nil {
		return -1, err
	}

	if err := os.WriteFile(filePath, newdata, fileMode.Mode()); err != nil {
		return -1, err
	}

	return len(newdata), nil
}

func Encrypt(in io.Reader, out io.Writer, fileFormat FileFormat) (int, error) {
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

func encryptData(data []byte, fileFormat FileFormat) ([]byte, error) {
	// Get the formatter for the file format
	formatter, err := getFormatter(fileFormat)
	if err != nil {
		return nil, err
	}
	// Extract the public key
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

// DecryptFromEmbedFS retrieves and decrypts a file from an embedded filesystem.
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
type DecryptFromEmbedOption func(*decryptFromEmbedOptions) error

type decryptFromEmbedOptions struct {
	envOverride string
	logger      *slog.Logger
	format      FileFormat
}

func WithEnvOverride(envOverride string) DecryptFromEmbedOption {
	return func(o *decryptFromEmbedOptions) error {
		o.envOverride = envOverride
		return nil
	}
}

func WithLogger(logger *slog.Logger) DecryptFromEmbedOption {
	return func(o *decryptFromEmbedOptions) error {
		o.logger = logger
		return nil
	}
}

func WithFormat(format FileFormat) DecryptFromEmbedOption {
	return func(o *decryptFromEmbedOptions) error {
		o.format = format
		return nil
	}
}

func DecryptFromEmbedFS(v embed.FS, opts ...DecryptFromEmbedOption) ([]byte, error) {
	// Create a new options struct and apply the provided options
	o := &decryptFromEmbedOptions{
		format: FileFormatEjson,
		logger: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
			AddSource:   false,
			Level:       slog.LevelInfo,
			ReplaceAttr: nil,
		})),
		envOverride: "",
	}
	// Apply the options
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	// Try to determine the environment name automatically.
	var err error
	envName := o.envOverride
	// If an environment override is not provided, use it instead of the detected name.
	if envName == "" {
		envName, err = sniffEnvName()
		if err != nil {
			return nil, fmt.Errorf("error sniffing environment name: %v", err)
		}
		o.logger.Info("detected environment", "env", envName)
	} else {
		o.logger.Info("using environment override", "env", envName)
	}

	// Generate the filename based on the format and environment name.
	fileName := fileutils.GenerateFilename(fileutils.FileFormat(o.format), envName)
	o.logger.Debug("reading file from vault", "file", fileName)
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
	return decryptData(privkey, data, o.format)
}

// DecryptFile reads an encrypted file from disk, decrypts it, and returns the decrypted data.
func DecryptFile(filePath string, keydir string, userSuppliedPrivateKey string) ([]byte, error) {
	envName, err := parseEnvironment(filePath)
	if err != nil {
		fmt.Errorf("error parsing env from file: %v", err)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	fileFormat, err := fileutils.ParseFormat(filePath)
	if err != nil {
		return nil, err
	}

	privkey, err := findPrivateKey(keydir, envName, userSuppliedPrivateKey)
	if err != nil {
		return nil, err
	}

	decryptedData, err := decryptData(privkey, data, FileFormat(fileFormat))
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// Decrypt reads encrypted data from the input reader, decrypts it, and writes the decrypted data to the output writer.
func Decrypt(in io.Reader, out io.Writer, envName string, fileFormat FileFormat, keydir string, userSuppliedPrivateKey string) (int, error) {

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

func decryptData(privkey [32]byte, data []byte, fileFormat FileFormat) ([]byte, error) {
	// Get the formatter for the file format
	formatter, err := getFormatter(fileFormat)
	if err != nil {
		return nil, err
	}

	// Extract the public key
	pubkey, err := formatter.ExtractPublicKey(data)
	if err != nil {
		return nil, err
	}

	// Create a keypair using the extracted public and provided private keys
	myKP := crypto.Keypair{
		Public:  pubkey,
		Private: privkey,
	}

	// Create a decrypter using the private key
	decrypter := myKP.Decrypter()

	// Decrypt the data
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
	keyToLookup := EsecPrivateKey
	if envName != "" {
		keyToLookup = fmt.Sprintf("%s_%s", EsecPrivateKey, strings.ToUpper(envName))
	}

	// Check if the private key is in environment variables.
	if privKeyString, exists := os.LookupEnv(keyToLookup); exists {
		return format.ParseKey(privKeyString)
	}

	// If not found in env vars, try reading from the keyring file.
	keyringPath := filepath.Join(keyPath, ".esec-keyring")
	privateKeyFile, err := os.ReadFile(keyringPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return privKey, fmt.Errorf("private key %q not found in environment variables, and keyring file does not exist at %q", keyToLookup, keyringPath)
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

// getFormatter returns the appropriate FormatHandler based on the given file format.
func getFormatter(fileFormat FileFormat) (format.FormatHandler, error) {
	switch fileFormat {
	case FileFormatEnv:
		return &dotenv.DotEnvFormatter{}, nil
	case FileFormatEjson:
		return &json.JsonFormatter{}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %s", fileFormat)
	}
}

func sniffEnvName() (string, error) {
	var setKeys []string

	// Scan environment variables for keys starting with ESEC_PRIVATE_KEY
	for _, envVar := range os.Environ() {
		if strings.HasPrefix(envVar, EsecPrivateKey) {
			key := strings.SplitN(envVar, "=", 2)[0]
			setKeys = append(setKeys, key)
		}
	}

	switch len(setKeys) {
	case 0:
		return "", nil // Default to "" (blank env) if no key is found
	case 1:
		// Extract the environment name from the key
		if setKeys[0] == EsecPrivateKey {
			return "", nil
		}
		return strings.ToLower(strings.TrimPrefix(setKeys[0], EsecPrivateKey+"_")), nil
	default:
		return "", fmt.Errorf("multiple private keys found: %v", setKeys)
	}
}

// Helper functions from before
func parseEnvironment(filename string) (string, error) {
	filename = path.Base(filename)

	validPrefixes := []string{string(FileFormatEnv), string(FileFormatEjson), string(FileFormatEyaml), string(FileFormatEyml), string(FileFormatEtoml)}
	isValidPrefix := false
	for _, prefix := range validPrefixes {
		if strings.HasPrefix(filename, prefix) {
			isValidPrefix = true
			break
		}
	}

	if !isValidPrefix {
		return "", fmt.Errorf("invalid file type: %s", filename)
	}

	parts := strings.Split(filename, ".")
	if len(parts) <= 2 {
		return "", nil
	}

	return parts[len(parts)-1], nil
}
