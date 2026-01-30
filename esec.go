// Package esec provides encrypted secrets management using public-key cryptography.
//
// esec supports encrypting and decrypting secrets in various file formats including
// .env (dotenv) and .ejson (JSON). It uses NaCl box encryption (Curve25519, XSalsa20, Poly1305)
// for secure secret storage.
//
// Basic usage for encryption:
//
//	data := []byte(`{"_ESEC_PUBLIC_KEY": "...", "secret": "myvalue"}`)
//	var output bytes.Buffer
//	esec.Encrypt(bytes.NewReader(data), &output, esec.FileFormatEjson)
//
// Basic usage for decryption:
//
//	os.Setenv("ESEC_PRIVATE_KEY", "your-private-key")
//	data, err := esec.DecryptFile(".ejson", ".", "")
package esec

import (
	"bytes"
	"embed"
	gojson "encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/joho/godotenv"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/dotenv"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/format"
	"github.com/mscno/esec/pkg/json"
	"github.com/mscno/esec/pkg/toml"
	"github.com/mscno/esec/pkg/yaml"
)

const (
	// EsecPublicKey is the key name used to store the public key in encrypted files.
	EsecPublicKey = "ESEC_PUBLIC_KEY"
	// EsecPrivateKey is the base name for private key environment variables.
	// For environment-specific keys, use ESEC_PRIVATE_KEY_<ENV> (e.g., ESEC_PRIVATE_KEY_PROD).
	EsecPrivateKey = "ESEC_PRIVATE_KEY"
	// DefaultKeyringFilename is the default name for the file storing private keys.
	DefaultKeyringFilename = ".esec-keyring"
	// EsecKeyringPath is the environment variable for the full keyring file path.
	EsecKeyringPath = "ESEC_KEYRING_PATH"
)

// resolveKeyringPath returns the keyring path, checking ESEC_KEYRING_PATH first.
func resolveKeyringPath(keyPath string) string {
	if envPath := os.Getenv(EsecKeyringPath); envPath != "" {
		return envPath
	}
	return filepath.Join(keyPath, DefaultKeyringFilename)
}

// GenerateKeypair generates a new Curve25519 keypair for use with esec encryption.
// It returns the public and private keys as hex-encoded strings (64 characters each).
func GenerateKeypair() (pub string, priv string, err error) {
	var kp crypto.Keypair
	if err := kp.Generate(); err != nil {
		return "", "", err
	}
	return kp.PublicString(), kp.PrivateString(), nil
}

// FileFormat represents the supported encrypted file formats.
type FileFormat string

// Supported file formats for encrypted secrets.
const (
	// FileFormatEnv represents the .env (dotenv) file format.
	FileFormatEnv FileFormat = ".env"
	// FileFormatEjson represents the .ejson (encrypted JSON) file format.
	FileFormatEjson FileFormat = ".ejson"
	// FileFormatEyaml represents the .eyaml (encrypted YAML) file format (not yet implemented).
	FileFormatEyaml FileFormat = ".eyaml"
	// FileFormatEyml represents the .eyml (encrypted YAML) file format (not yet implemented).
	FileFormatEyml FileFormat = ".eyml"
	// FileFormatEtoml represents the .etoml (encrypted TOML) file format (not yet implemented).
	FileFormatEtoml FileFormat = ".etoml"
)

// EncryptFileInPlace takes a path to a file on disk, which must be a valid ecfg file
// (see README.md for more on what constitutes a valid ecfg file). Any
// encryptable-but-unencrypted fields in the file will be encrypted using the
// public key embdded in the file, and the resulting text will be written over
// the file present on disk.
func EncryptFileInPlace(filePath string) (int, error) {
	data, err := os.ReadFile(filePath) //nolint:gosec // File path is user-provided
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

// Encrypt reads data from the input reader, encrypts all encryptable values using the
// public key embedded in the data, and writes the encrypted result to the output writer.
// The fileFormat parameter determines how the data is parsed and which fields are encrypted.
// It returns the number of bytes written and any error encountered.
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

// EnvironmentLookupFn is a function type that attempts to find an environment name
// Returns the environment name (empty string for default environment) and any error encountered
type EnvironmentLookupFn func() (string, error)

// DecryptFromEmbedConfig defines the configuration options for DecryptFromEmbedFSWithConfig.
type DecryptFromEmbedConfig struct {
	// EnvName specifies an explicit environment name (e.g., "dev", "prod").
	// If set, this overrides automatic environment detection.
	EnvName string
	// Format specifies the file format. Defaults to FileFormatEjson if not set.
	Format FileFormat
	// Logger for outputting debug and info messages. If nil, logging is disabled.
	Logger *slog.Logger
	// EnvironmentLookuper is a function that determines the environment name.
	// If not provided, EnvironmentVarLookup will be used.
	EnvironmentLookuper EnvironmentLookupFn
	// Keydir is the directory containing the .esec-keyring file.
	// Defaults to the current directory if empty.
	Keydir string
	// UserSuppliedPrivateKey allows passing the private key directly as a hex string.
	// If set, this takes precedence over environment variables and keyring file.
	UserSuppliedPrivateKey string
}

// CombineLookupers creates a single environment lookup function from multiple functions
// It tries each function in order until one returns a non-empty environment or all fail
// If all lookupers fail, the errors are collected and returned in a combined error
func CombineLookupers(lookupers ...EnvironmentLookupFn) EnvironmentLookupFn {
	return func() (string, error) {
		var errors []string

		for _, lookupFn := range lookupers {
			env, err := lookupFn()
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}

			// Return the first successful result
			return env, nil
		}

		// If all lookupers failed, combine the errors
		if len(errors) > 0 {
			return "", fmt.Errorf("all environment lookupers failed: %s", strings.Join(errors, "; "))
		}

		// If no lookupers were provided
		return "", fmt.Errorf("no environment lookupers were provided")
	}
}

// EnvironmentVarLookup tries to determine the environment from environment variables
func EnvironmentVarLookup() (string, error) {
	logger := slog.Default()
	return sniffEnvName(logger)
}

// KeyringLookup returns a lookup function that checks the keyring file
func KeyringLookup(keyPath string) EnvironmentLookupFn {
	return func() (string, error) {
		logger := slog.Default()
		return sniffFromKeyring(logger, keyPath, "")
	}
}

// DecryptFromEmbedFSWithConfig retrieves and decrypts a file from an embedded filesystem.
// It uses the provided configuration to determine the environment name and file format.
// The function reads the encrypted file based on the configuration, then decrypts it
// and returns the decrypted data.
//
// Parameters:
//   - v: An embedded filesystem containing the encrypted files.
//   - config: Configuration options for decryption.
//
// Returns:
//   - The decrypted file content as a byte slice.
//   - An error if any step fails (e.g., environment detection, file reading, decryption).
func DecryptFromEmbedFSWithConfig(v embed.FS, config DecryptFromEmbedConfig) ([]byte, error) {
	// Set defaults for unspecified options
	if config.Format == "" {
		config.Format = FileFormatEjson
	}

	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
			AddSource:   false,
			Level:       slog.LevelInfo,
			ReplaceAttr: nil,
		}))
	}

	// Determine environment name
	var envName string
	var err error

	if config.EnvName != "" {
		// Use explicit environment name if provided
		envName = config.EnvName
		config.Logger.Info("using environment override", "env", envName)
	} else {
		// Use environment lookuper or default to EnvironmentVarLookup
		lookupFn := config.EnvironmentLookuper
		if lookupFn == nil {
			// If no explicit lookuper is provided, use EnvironmentVarLookup
			lookupFn = EnvironmentVarLookup
		}

		// Execute the lookup function
		envName, err = lookupFn()
		if err != nil {
			return nil, fmt.Errorf("error determining environment name: %v", err)
		}
		config.Logger.Info("detected environment", "env", envName)
	}

	// Generate the filename based on the format and environment name
	fileName := fileutils.GenerateFilename(fileutils.FileFormat(config.Format), envName)
	config.Logger.Debug("reading file from vault", "file", fileName)

	// Attempt to read the file from the embedded filesystem
	data, err := v.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("error reading file from vault: %v", err)
	}

	// Find the private key
	privkey, err := findPrivateKey(config.Keydir, envName, config.UserSuppliedPrivateKey)
	if err != nil {
		return nil, err
	}

	// Decrypt the file data and return the decrypted bytes
	return decryptData(privkey, data, config.Format)
}

// DecryptFromEmbedFS is a convenience function that decrypts an embedded file.
// If envName is empty, it attempts to auto-detect the environment from ESEC_PRIVATE_KEY* env vars.
// If envName is provided, it uses that environment directly.
func DecryptFromEmbedFS(v embed.FS, envName string, format FileFormat) ([]byte, error) {
	// If envName is empty, try to auto-detect from environment variables
	if envName == "" {
		detected, err := sniffEnvName(slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			return nil, fmt.Errorf("error sniffing environment name: %v", err)
		}
		envName = detected
	}

	// Generate the filename based on the format and environment name
	fileName := fileutils.GenerateFilename(fileutils.FileFormat(format), envName)

	// Attempt to read the file from the embedded filesystem
	data, err := v.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("error reading file from vault: %v", err)
	}

	// Find the private key
	privkey, err := findPrivateKey("", envName, "")
	if err != nil {
		return nil, err
	}

	// Decrypt the file data and return the decrypted bytes
	return decryptData(privkey, data, format)
}

// DecryptFromEmbedOption is a functional option for configuring DecryptFromEmbedFSWithOptions.
//
// Deprecated: Use DecryptFromEmbedConfig with DecryptFromEmbedFSWithConfig instead.
type DecryptFromEmbedOption func(*decryptFromEmbedOptions) error

type decryptFromEmbedOptions struct {
	envOverride    string
	envSniffer     bool
	keyringSniffer bool
	logger         *slog.Logger
	format         FileFormat
}

// WithEnvOverride sets an explicit environment name, overriding automatic detection.
//
// Deprecated: Use DecryptFromEmbedConfig.EnvName instead.
func WithEnvOverride(envOverride string) DecryptFromEmbedOption {
	return func(o *decryptFromEmbedOptions) error {
		o.envOverride = envOverride
		return nil
	}
}

// WithLogger sets a logger for debug and info messages.
//
// Deprecated: Use DecryptFromEmbedConfig.Logger instead.
func WithLogger(logger *slog.Logger) DecryptFromEmbedOption {
	return func(o *decryptFromEmbedOptions) error {
		o.logger = logger
		return nil
	}
}

// WithFormat sets the file format to use.
//
// Deprecated: Use DecryptFromEmbedConfig.Format instead.
func WithFormat(format FileFormat) DecryptFromEmbedOption {
	return func(o *decryptFromEmbedOptions) error {
		o.format = format
		return nil
	}
}

// WithEnvSniffer enables automatic environment detection from environment variables.
//
// Deprecated: Use DecryptFromEmbedConfig.EnvironmentLookuper with EnvironmentVarLookup instead.
func WithEnvSniffer() DecryptFromEmbedOption {
	return func(o *decryptFromEmbedOptions) error {
		o.envSniffer = true
		return nil
	}
}

// WithKeyringSniffer enables automatic environment detection from the keyring file.
//
// Deprecated: Use DecryptFromEmbedConfig.EnvironmentLookuper with KeyringLookup instead.
func WithKeyringSniffer() DecryptFromEmbedOption {
	return func(o *decryptFromEmbedOptions) error {
		o.keyringSniffer = true
		return nil
	}
}

// DecryptFromEmbedFSWithOptions retrieves and decrypts a file from an embedded filesystem using functional options.
//
// Deprecated: Use DecryptFromEmbedFSWithConfig instead.
func DecryptFromEmbedFSWithOptions(v embed.FS, opts ...DecryptFromEmbedOption) ([]byte, error) {
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

	// Convert old options to new config
	config := DecryptFromEmbedConfig{
		EnvName: o.envOverride,
		Format:  o.format,
		Logger:  o.logger,
	}

	// Note: keyringSniffer option is deprecated and no longer used
	// The new config-based API should be used instead

	// Call the new implementation
	return DecryptFromEmbedFSWithConfig(v, config)
}

// DecryptFile reads an encrypted file from disk, decrypts it, and returns the decrypted data.
func DecryptFile(filePath string, keydir string, userSuppliedPrivateKey string) ([]byte, error) {
	envName, err := parseEnvironment(filePath)
	if err != nil {
		return nil, fmt.Errorf("error parsing env from file: %w", err)
	}

	data, err := os.ReadFile(filePath) //nolint:gosec // File path is user-provided
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
	// Validate keyPath to prevent directory traversal attacks
	if err := validateKeyPath(keyPath); err != nil {
		return privKey, err
	}

	// If not found in env vars, try reading from the keyring file.
	keyringPath := resolveKeyringPath(keyPath)

	// Check keyring file permissions on non-Windows systems
	checkKeyringPermissions(keyringPath)
	privateKeyFile, err := os.ReadFile(keyringPath) //nolint:gosec // File path is constructed from user-provided keyPath
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

// getFormatter returns the appropriate Handler based on the given file format.
func getFormatter(fileFormat FileFormat) (format.Handler, error) {
	switch fileFormat {
	case FileFormatEnv:
		return &dotenv.Formatter{}, nil
	case FileFormatEjson:
		return &json.Formatter{}, nil
	case FileFormatEyaml, FileFormatEyml:
		return &yaml.Formatter{}, nil
	case FileFormatEtoml:
		return &toml.Formatter{}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %s", fileFormat)
	}
}

func sniffEnvName(logger *slog.Logger) (string, error) {
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
		logger.Debug("no private key found in environment variables")
		return "", fmt.Errorf("no private key found in environment variables")
	case 1:
		logger.Debug("found private key in environment variables", "key", setKeys[0])
		// Extract the environment name from the key
		if setKeys[0] == EsecPrivateKey {
			return "", nil
		}
		return strings.ToLower(strings.TrimPrefix(setKeys[0], EsecPrivateKey+"_")), nil
	default:
		return "", fmt.Errorf("multiple private keys found: %v", setKeys)
	}
}

// ActiveKey is the keyring variable name that specifies which private key to use.
// Its value should be a private key variable name (e.g., "ESEC_PRIVATE_KEY_DEV").
const ActiveKey = "ESEC_ACTIVE_KEY"

// ActiveEnvironment is the keyring variable name that specifies the active environment.
// Its value should be an environment name (e.g., "dev", "prod").
const ActiveEnvironment = "ESEC_ACTIVE_ENVIRONMENT"

func sniffFromKeyring(logger *slog.Logger, keyPath string, envName string) (string, error) {
	// If envName is already provided, just return it
	if envName != "" {
		return envName, nil
	}

	// If not found in env vars, try reading from the keyring file.
	keyringPath := resolveKeyringPath(keyPath)
	privateKeyFile, err := os.ReadFile(keyringPath) //nolint:gosec // File path is constructed from user-provided keyPath
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("keyring file does not exist at %q", keyringPath)
		}
		return "", fmt.Errorf("failed to read keyring file at %q: %w", keyringPath, err)
	}

	// Parse the keyring file as environment variables.
	privateKeyEnvs, err := godotenv.Parse(bytes.NewBuffer(privateKeyFile))
	if err != nil {
		return "", fmt.Errorf("failed to parse keyring file %q: %w", keyringPath, err)
	}

	// Check if both ACTIVE_KEY and ACTIVE_ENVIRONMENT are set (conflict)
	activeKey, hasActiveKey := privateKeyEnvs[ActiveKey]
	activeEnv, hasActiveEnv := privateKeyEnvs[ActiveEnvironment]

	if hasActiveKey && hasActiveEnv {
		return "", fmt.Errorf("conflicting configuration: both %s and %s are set in keyring file",
			ActiveKey, ActiveEnvironment)
	}

	// If we have an active environment directly specified, use it
	if hasActiveEnv {
		if activeEnv == "" {
			return "", fmt.Errorf("%s is set but empty in keyring file", ActiveEnvironment)
		}
		logger.Debug("using active environment from keyring", "env", activeEnv)
		return activeEnv, nil
	}

	// If we have an active key, extract environment from it
	if hasActiveKey {
		if !strings.HasPrefix(activeKey, "ESEC_PRIVATE_KEY") {
			return "", fmt.Errorf("%s value must be an ESEC_PRIVATE_KEY variable name", ActiveKey)
		}

		// Extract environment from key name
		if activeKey == "ESEC_PRIVATE_KEY" {
			// This is the default key with no environment
			logger.Debug("using default environment from keyring active key")
			return "", nil
		}

		// Remove prefix and any underscores
		envFromKey := strings.TrimPrefix(activeKey, "ESEC_PRIVATE_KEY")
		envFromKey = strings.TrimLeft(envFromKey, "_")
		envFromKey = strings.ToLower(envFromKey)

		if envFromKey == "" {
			return "", fmt.Errorf("could not extract environment from %s=%s", ActiveKey, activeKey)
		}

		logger.Debug("extracted environment from active key", "env", envFromKey)
		return envFromKey, nil
	}

	// If we get here, neither ACTIVE_KEY nor ACTIVE_ENVIRONMENT is set

	// As a fallback, look for any ESEC_PRIVATE_KEY_* variables
	var envKeys []string
	for key := range privateKeyEnvs {
		if strings.HasPrefix(key, "ESEC_PRIVATE_KEY") {
			envKeys = append(envKeys, key)
		}
	}

	// If there's exactly one environment key, use it
	if len(envKeys) == 1 {
		envFromKey := strings.TrimPrefix(envKeys[0], "ESEC_PRIVATE_KEY")
		envFromKey = strings.TrimLeft(envFromKey, "_")
		envFromKey = strings.ToLower(envFromKey)
		logger.Debug("using single environment key from keyring", "env", envFromKey)
		return envFromKey, nil
	} else if len(envKeys) > 1 {
		// If there are multiple, that's ambiguous
		return "", fmt.Errorf("multiple environment keys found in keyring (%v) but no %s or %s specified",
			envKeys, ActiveKey, ActiveEnvironment)
	}

	// Check if there's a default key
	if _, hasDefault := privateKeyEnvs["ESEC_PRIVATE_KEY"]; hasDefault {
		logger.Debug("using default environment from keyring")
		return "", nil
	}

	// We couldn't determine an environment
	return "", fmt.Errorf("no environment keys found in keyring")
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

// EjsonToEnv parses decrypted EJSON data and returns a map of environment variables.
// It extracts all top-level string values, excluding the ESEC_PUBLIC_KEY field.
// Non-string values (numbers, booleans, objects, arrays) are skipped.
func EjsonToEnv(payload []byte) (map[string]string, error) {
	var data map[string]interface{}
	err := gojson.Unmarshal(payload, &data)
	if err != nil {
		return nil, err
	}

	return extractEnv(data)
}

// DotEnvToEnv parses decrypted dotenv data and returns a map of environment variables.
// It uses the standard dotenv parsing rules.
func DotEnvToEnv(payload []byte) (map[string]string, error) {
	return godotenv.Parse(bytes.NewBuffer(payload))
}

var validIdentifierPattern = regexp.MustCompile(`\A[a-zA-Z_][a-zA-Z0-9_]*\z`)

func extractEnv(envMap map[string]interface{}) (map[string]string, error) {
	envSecrets := make(map[string]string, len(envMap))
	for key, rawValue := range envMap {
		if key == EsecPublicKey {
			continue
		}
		// Reject keys that would be invalid environment variable identifiers
		if !validIdentifierPattern.MatchString(key) {
			err := fmt.Errorf("invalid identifier as key in environment: %q", key)

			return nil, err
		}

		// Only export values that convert to strings properly.
		if value, ok := rawValue.(string); ok {
			envSecrets[key] = value
		}
	}

	return envSecrets, nil
}

// validateKeyPath checks for directory traversal attempts in key paths
func validateKeyPath(keyPath string) error {
	if strings.Contains(keyPath, "..") {
		return fmt.Errorf("invalid keyPath containing directory traversal sequences: %s", keyPath)
	}
	if keyPath == "" {
		return nil
	}
	absPath, err := filepath.Abs(keyPath)
	if err != nil {
		return fmt.Errorf("invalid keyPath: %w", err)
	}
	if strings.Contains(filepath.Clean(absPath), "..") {
		return fmt.Errorf("invalid keyPath after resolution: %s", keyPath)
	}
	return nil
}

// checkKeyringPermissions warns if the keyring file has insecure permissions
func checkKeyringPermissions(path string) {
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		slog.Warn("keyring file has insecure permissions",
			"path", path, "mode", fmt.Sprintf("%04o", mode), "recommended", "0600")
	}
}
