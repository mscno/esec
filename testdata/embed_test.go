package testdata

import (
	"os"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/mscno/esec"
)

// JSON Format Tests

func TestEmbedDecryptWithNoVars(t *testing.T) {
	clearEnvVars(t)
	_, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEjson)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no private key found in environment variables")
}

func TestEmbedDecryptWithNoVarsAndOverride(t *testing.T) {
	clearEnvVars(t)
	_, err := esec.DecryptFromEmbedFS(TestEmbed, "dev", esec.FileFormatEjson)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in environment variables")
}

func TestEmbedDecryptWithNoVarsAndMissingFile(t *testing.T) {
	clearEnvVars(t)
	_, err := esec.DecryptFromEmbedFS(TestEmbed, "missing", esec.FileFormatEjson)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error reading file from vault: open .ejson.missing: file does not exist")
}

func TestEmbedDecryptBadKey(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
	_, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEjson)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "couldn't decrypt message")
}

func TestEmbedDecryptMultipleKeys(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
	os.Setenv("ESEC_PRIVATE_KEYS", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
	_, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEjson)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "multiple private keys found")
}

func TestEmbedDecryptGoodKey(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	_, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEjson)
	assert.NoError(t, err)
}

func TestEmbedDecryptGoodKeyWithDevSuffix(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY_DEV", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	_, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEjson)
	assert.NoError(t, err)
}

func TestEmbedDecryptGoodKeyWithMissingSuffix(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY_MISSING", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	_, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEjson)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error reading file from vault: open .ejson.missing: file does not exist")
}

// YAML Format Tests

func TestEmbedDecryptYamlWithNoVars(t *testing.T) {
	clearEnvVars(t)
	_, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no private key found in environment variables")
}

func TestEmbedDecryptYamlGoodKey(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	data, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.NoError(t, err)
	assert.True(t, len(data) > 0)

	// Verify decrypted content
	content := string(data)
	assert.Contains(t, content, "MY_VALUE:")
	assert.Contains(t, content, "my_secret_value")
	assert.Contains(t, content, "MY_NUMBER: 123")
	assert.Contains(t, content, "MY_BOOL_TRUE: true")
}

func TestEmbedDecryptYamlDevEnvironment(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY_DEV", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	data, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.NoError(t, err)

	content := string(data)
	// Verify dev-specific content
	assert.Contains(t, content, "my_dev_secret_value")
	assert.Contains(t, content, "MY_NUMBER: 456")
}

func TestEmbedDecryptYamlPreservesComments(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	data, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.NoError(t, err)

	content := string(data)
	// Verify comments are preserved
	assert.Contains(t, content, "# ESEC Test File")
	assert.Contains(t, content, "# Simple string value")
	assert.Contains(t, content, "# Numeric values should NOT be encrypted")
}

func TestEmbedDecryptYamlPreservesNonStringTypes(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	data, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.NoError(t, err)

	content := string(data)
	// Numbers should be unchanged
	assert.Contains(t, content, "MY_NUMBER: 123")
	assert.Contains(t, content, "MY_FLOAT: 3.14159")
	assert.Contains(t, content, "MY_SCIENTIFIC: 1.5e10")

	// Booleans should be unchanged
	assert.Contains(t, content, "MY_BOOL_TRUE: true")
	assert.Contains(t, content, "MY_BOOL_FALSE: false")

	// Null should be unchanged
	assert.Contains(t, content, "MY_NULL: null")
}

func TestEmbedDecryptYamlUnderscorePrefixNotEncrypted(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	data, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.NoError(t, err)

	content := string(data)
	// Underscore prefix value should not be encrypted (raw value)
	assert.Contains(t, content, "_MY_COMMENT: this_is_not_encrypted")
}

func TestEmbedDecryptYamlNestedUnderUnderscoreKeyIsEncrypted(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	data, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.NoError(t, err)

	content := string(data)
	// Children under _MY_METADATA should be encrypted (and thus decrypted)
	assert.Contains(t, content, "this_should_be_encrypted")
	// The version should also be decrypted
	assert.Contains(t, content, `version: "1.0"`)
}

func TestEmbedDecryptYamlArraysDecrypted(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	data, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.NoError(t, err)

	content := string(data)
	// Array elements should be decrypted
	assert.Contains(t, content, "array_item_1")
	assert.Contains(t, content, "array_item_2")
}

func TestEmbedDecryptYamlNestedObjectsDecrypted(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	data, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.NoError(t, err)

	content := string(data)
	// Nested object values should be decrypted
	assert.Contains(t, content, `hello: "world"`)
	assert.Contains(t, content, `deep: "value"`)
}

func TestEmbedDecryptYamlMultilineStrings(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	data, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.NoError(t, err)

	content := string(data)
	// Multiline literal block should be decrypted
	assert.Contains(t, content, "This is a multiline string")
	assert.Contains(t, content, "spans multiple lines")
}

func TestEmbedDecryptYamlDeepNesting(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	data, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.NoError(t, err)

	content := string(data)
	// Deeply nested value should be decrypted
	assert.Contains(t, content, "deeply_nested_secret")
}

func TestEmbedDecryptYamlUnicodeContent(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	data, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.NoError(t, err)

	content := string(data)
	// Unicode content should be preserved
	assert.Contains(t, content, "Hello 世界")
}

func TestEmbedDecryptYamlSpecialCharacters(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	data, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.NoError(t, err)

	content := string(data)
	// Special characters should be preserved
	assert.Contains(t, content, "special:")
	assert.Contains(t, content, "@#$%")
}

func TestEmbedDecryptYamlDevInlineComments(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY_DEV", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	data, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.NoError(t, err)

	content := string(data)
	// Inline comments should be preserved
	assert.Contains(t, content, "# This is the dev database")
	assert.Contains(t, content, "# sensitive!")
	assert.Contains(t, content, "# seconds")
}

func TestEmbedDecryptYamlDevFlowStyleCollections(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY_DEV", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	data, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.NoError(t, err)

	content := string(data)
	// Flow style arrays should be decrypted
	assert.Contains(t, content, "secret1")
	assert.Contains(t, content, "secret2")
	// Flow style maps should be decrypted
	assert.Contains(t, content, "value1")
	assert.Contains(t, content, "value2")
}

func TestEmbedDecryptYamlDevNestedUnderscoreVariations(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY_DEV", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	data, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.NoError(t, err)

	content := string(data)
	// _SKIP_THIS should not be encrypted
	assert.Contains(t, content, "_SKIP_THIS: not_encrypted_at_all")
	// Children under _SKIP_NESTED should be encrypted
	assert.Contains(t, content, "should_be_encrypted")
	// But _and_skip_this should not be encrypted
	assert.Contains(t, content, "_and_skip_this: not_encrypted")
}

func TestEmbedDecryptYamlBadKey(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
	_, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "couldn't decrypt message")
}

func TestEmbedDecryptYamlMissingFile(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY_STAGING", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	_, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyaml)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error reading file from vault: open .eyaml.staging: file does not exist")
}

// Also test .eyml extension
func TestEmbedDecryptEymlFormatGoodKey(t *testing.T) {
	clearEnvVars(t)
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	// .eyml should use same files as .eyaml (just different extension)
	_, err := esec.DecryptFromEmbedFS(TestEmbed, "", esec.FileFormatEyml)
	// This will fail because we don't have .eyml files, but it should fail looking for the file
	assert.Error(t, err)
	assert.Contains(t, err.Error(), ".eyml")
}

// Helper to clean up environment variables between tests
func clearEnvVars(t *testing.T) {
	t.Helper()
	// Get all env vars and clear ESEC ones
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "ESEC_PRIVATE_KEY") {
			key := strings.SplitN(env, "=", 2)[0]
			os.Unsetenv(key)
		}
	}
	t.Cleanup(func() {
		for _, env := range os.Environ() {
			if strings.HasPrefix(env, "ESEC_PRIVATE_KEY") {
				key := strings.SplitN(env, "=", 2)[0]
				os.Unsetenv(key)
			}
		}
	})
}
