package testdata

import (
	"github.com/alecthomas/assert/v2"
	"github.com/mscno/esec"
	"os"
	"testing"
)

func TestEmbedDecryptWithNoVars(t *testing.T) {
	_, err := esec.DecryptFromVault(TestEmbed, "", esec.Ejson)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private key not found in environment variables, and keyring file does not exist at \".esec-keyring\"")
}

func TestEmbedDecryptWithNoVarsAndOverride(t *testing.T) {
	_, err := esec.DecryptFromVault(TestEmbed, "dev", esec.Ejson)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private key not found in environment variables, and keyring file does not exist at \".esec-keyring\"")
}

func TestEmbedDecryptWithNoVarsAndMissingFile(t *testing.T) {
	_, err := esec.DecryptFromVault(TestEmbed, "missing", esec.Ejson)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error reading file from vault: open .ejson.missing: file does not exist")
}

func TestEmbedDecryptBadKey(t *testing.T) {
	os.Setenv("ESEC_PRIVATE_KEY", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
	_, err := esec.DecryptFromVault(TestEmbed, "", esec.Ejson)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "couldn't decrypt message")
}

func TestEmbedDecryptMultipleKeys(t *testing.T) {
	os.Setenv("ESEC_PRIVATE_KEY", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
	os.Setenv("ESEC_PRIVATE_KEYS", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
	_, err := esec.DecryptFromVault(TestEmbed, "", esec.Ejson)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error sniffing environment name: multiple private keys found: [ESEC_PRIVATE_KEY ESEC_PRIVATE_KEYS]")
}

func TestEmbedDecryptGoodKey(t *testing.T) {
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	_, err := esec.DecryptFromVault(TestEmbed, "", esec.Ejson)
	assert.NoError(t, err)
}

func TestEmbedDecryptGoodKeyWithDevSuffix(t *testing.T) {
	os.Setenv("ESEC_PRIVATE_KEY_DEV", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	_, err := esec.DecryptFromVault(TestEmbed, "", esec.Ejson)
	assert.NoError(t, err)
}

func TestEmbedDecryptGoodKeyWithMissingSuffix(t *testing.T) {
	os.Setenv("ESEC_PRIVATE_KEY_MISSING", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	_, err := esec.DecryptFromVault(TestEmbed, "", esec.Ejson)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error reading file from vault: open .ejson.missing: file does not exist")
}
