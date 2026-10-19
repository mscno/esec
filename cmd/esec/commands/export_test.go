package commands

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/joho/godotenv"
	"github.com/mscno/esec"
)

// writeEncryptedEnv writes content (which must start with the public key line
// for pub) to dir/.env.test, encrypts it in place and returns its path.
func writeEncryptedEnv(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, ".env.test")
	assert.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	_, err := esec.EncryptFileInPlace(path)
	assert.NoError(t, err)
	return path
}

const envFixture = `PLAIN=abc
SPACED="hello world"
QUOTE="it's"
MULTI="line1\nline2"
DOLLAR='$HOME'
HASH="a#b"
`

func TestExportCmdEnv(t *testing.T) {
	pub, priv, err := esec.GenerateKeypair()
	assert.NoError(t, err)
	t.Setenv("ESEC_PRIVATE_KEY_TEST", priv)
	path := writeEncryptedEnv(t, t.TempDir(), "ESEC_PUBLIC_KEY="+pub+"\n"+envFixture)

	out, errString := captureOutput(func() error {
		return (&ExportCmd{File: path, Format: ".env"}).Run(&cliCtx{Logger: slog.Default()})
	})
	assert.Equal(t, errString, "")
	assert.Equal(t, out, `DOLLAR='$HOME'
HASH="a#b"
MULTI="line1\nline2"
PLAIN=abc
QUOTE="it's"
SPACED='hello world'
`)

	parsed, err := godotenv.Unmarshal(out)
	assert.NoError(t, err)
	assert.Equal(t, parsed, map[string]string{
		"PLAIN":  "abc",
		"SPACED": "hello world",
		"QUOTE":  "it's",
		"MULTI":  "line1\nline2",
		"DOLLAR": "$HOME",
		"HASH":   "a#b",
	})
}

func TestExportCmdEjsonDropsUnderscoredPublicKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".ejson")
	assert.NoError(t, os.WriteFile(path, []byte(`{"_ESEC_PUBLIC_KEY":"493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d","secret": "ESEC[1:HMvqzjm4wFgQzL0qo6fDsgfiS1e7y1knsTvgskUEvRo=:gwjm0ng6DE3FlL8F617cRMb8cBeJ2v1b:KryYDmzxT0OxjuLlIgZHx73DhNvE]"}`), 0o600))
	t.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")

	out, errString := captureOutput(func() error {
		return (&ExportCmd{File: path, Format: ".ejson"}).Run(&cliCtx{Logger: slog.Default()})
	})
	assert.Equal(t, errString, "")
	assert.Equal(t, out, "secret=hello\n")
}

func TestExportCmdRejectsOtherFormats(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".eyaml")
	assert.NoError(t, os.WriteFile(path, []byte("_ESEC_PUBLIC_KEY: 493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d\n"), 0o600))

	_, errString := captureOutput(func() error {
		return (&ExportCmd{File: path, Format: ".ejson"}).Run(&cliCtx{Logger: slog.Default()})
	})
	assert.Contains(t, errString, "only .env and .ejson files hold environment variables")
}

func TestRunLeavesOutPublicKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses printenv(1)")
	}
	pub, priv, err := esec.GenerateKeypair()
	assert.NoError(t, err)
	t.Setenv("ESEC_PRIVATE_KEY_TEST", priv)
	path := writeEncryptedEnv(t, t.TempDir(), "ESEC_PUBLIC_KEY="+pub+"\nPLAIN=abc\n")
	ctx := &cliCtx{Logger: slog.Default()}

	// printenv, not env: the whole environment can overflow the capture pipe.
	out, errString := captureOutput(func() error {
		return (&RunCmd{File: path, Format: ".env", Command: []string{"printenv", "PLAIN"}}).Run(ctx)
	})
	assert.Equal(t, errString, "")
	assert.Equal(t, out, "abc\n")

	// printenv exits 1 when the variable is not set.
	err = (&RunCmd{File: path, Format: ".env", Command: []string{"printenv", "ESEC_PUBLIC_KEY"}}).Run(ctx)
	assert.Equal(t, error(&ExitError{Code: 1}), err)
}

func TestDotenvValue(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{"", ""},
		{"abc", "abc"},
		{"postgres://u:p@host:5432/db?sslmode=require", "postgres://u:p@host:5432/db?sslmode=require"},
		{"a=b", "a=b"},
		{"hello world", "'hello world'"},
		{" padded ", "' padded '"},
		{`say "hi"`, `'say "hi"'`},
		{`"quoted"`, `'"quoted"'`},
		{"$HOME", "'$HOME'"},
		{"${HOME}", "'${HOME}'"},
		{"a#b", `"a#b"`},
		{"a #b", `"a #b"`},
		{"it's", `"it's"`},
		{"line1\nline2", `"line1\nline2"`},
		{"cr\r\nlf", `"cr\r\nlf"`},
		{`back\slash`, `"back\\slash"`},
		{`literal\n`, `"literal\\n"`},
		{`ends\`, `ends\`},
		{`it's\`, `it's\`},
		{"$it's", `"\$it's"`},
		{"-----BEGIN KEY-----\nabc\n-----END KEY-----\n", `"-----BEGIN KEY-----\nabc\n-----END KEY-----\n"`},
		{"tab\there", "'tab\there'"},
		{"ünïcode", "'ünïcode'"},
	}
	for _, tt := range tests {
		got, err := dotenvValue("V", tt.value)
		assert.NoError(t, err, "value %q", tt.value)
		assert.Equal(t, tt.want, got, "value %q", tt.value)
		parsed, err := godotenv.Unmarshal("V=" + got)
		assert.NoError(t, err)
		assert.Equal(t, tt.value, parsed["V"], "round trip of %q", tt.value)
	}
}

func TestDotenvValueUnrepresentable(t *testing.T) {
	_, err := dotenvValue("V", "it's\nend\"")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be written as a dotenv line")

	// Nothing is written when one value fails.
	var b strings.Builder
	err = writeDotenv(&b, map[string]string{"A": "ok", "B": "it's\nend\""})
	assert.Error(t, err)
	assert.Equal(t, b.String(), "")
}

// flyParseLine applies the rules flyctl (secrets import) uses for a
// single-line NAME=VALUE pair: a '#' starts a comment unless an odd number of
// double quotes comes before it, and one pair of surrounding quotes is
// removed without any unescaping.
func flyParseLine(line string) (string, string) {
	key, value, _ := strings.Cut(line, "=")
	value = strings.TrimLeft(value, " ")
	if l, _, ok := strings.Cut(value, "#"); ok && strings.Count(l, `"`)%2 == 0 {
		value = strings.TrimRight(l, " ")
	}
	if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' || value[0] == '\'' && value[len(value)-1] == '\'') {
		value = value[1 : len(value)-1]
	}
	return strings.TrimSpace(key), value
}

func TestDotenvValueImportsIntoFly(t *testing.T) {
	// Single-line values without characters that need escaping in double
	// quotes come out of fly secrets import unchanged.
	for _, value := range []string{"", "abc", "a=b", "hello world", " padded ", `say "hi"`, "$HOME", "a#b", "a #b", "it's", "tab\there", "https://x.example/?a=1&b=2"} {
		got, err := dotenvValue("V", value)
		assert.NoError(t, err)
		key, parsed := flyParseLine("V=" + got)
		assert.Equal(t, "V", key)
		assert.Equal(t, value, parsed, "fly import of %q (written as %s)", value, got)
	}
}
