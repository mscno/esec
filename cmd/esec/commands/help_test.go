package commands

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/mscno/esec"
)

// Every command of the CLI is a builtin, so the passthrough never runs an
// esec-<command> program in its place.
func TestBuiltinCommandsCoverTheCLI(t *testing.T) {
	var c cli
	p, err := kong.New(&c, kong.Vars{"version": "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range p.Model.Children {
		if !builtinCommands[n.Name] {
			t.Errorf("command %q is missing from builtinCommands", n.Name)
		}
		if !n.Hidden && commandDetails[n.Name] == "" {
			t.Errorf("command %q has no examples", n.Name)
		}
	}
	for name := range commandDetails {
		if !builtinCommands[name] {
			t.Errorf("commandDetails names %q, which is no command", name)
		}
	}
}

func TestHelpArgs(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		{nil, []string{"--help"}},
		{[]string{"help"}, []string{"--help"}},
		{[]string{"help", "run"}, []string{"run", "--help"}},
		{[]string{"decrypt", "help"}, []string{"decrypt", "help"}},
	} {
		if got := helpArgs(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("helpArgs(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMissingFile(t *testing.T) {
	dir := t.TempDir()
	if err := missingFile(filepath.Join(dir, ".ejson.dev")); !strings.Contains(err.Error(), "no secrets files in "+dir) {
		t.Errorf("empty directory: %v", err)
	}
	for _, f := range []string{".env.dev", ".ejson.prod", ".esec-keyring", ".envrc"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := missingFile(filepath.Join(dir, ".ejson.dev"))
	if !strings.Contains(err.Error(), filepath.Join(dir, ".env.dev")+" does") || !strings.Contains(err.Error(), "--format env") {
		t.Errorf("other format of the environment: %v", err)
	}
	err = missingFile(filepath.Join(dir, ".ejson.qa"))
	if !strings.Contains(err.Error(), ".ejson.prod, .env.dev") || strings.Contains(err.Error(), "keyring") || strings.Contains(err.Error(), "envrc") {
		t.Errorf("other files: %v", err)
	}
}

func TestKeyNotFoundHint(t *testing.T) {
	err := fmt.Errorf("decrypting file .env.prod: %w", &esec.KeyNotFoundError{Name: "ESEC_PRIVATE_KEY_PROD", Tried: []string{".esec-keyring"}, NoFiles: true})
	if !errors.Is(err, esec.ErrKeyNotFound) {
		t.Fatal("not ErrKeyNotFound")
	}
	h := hints(err)
	if len(h) != 1 || !strings.Contains(h[0], "export ESEC_PRIVATE_KEY_PROD=") || !strings.Contains(h[0], "esec vault team sync") {
		t.Fatalf("hints: %q", h)
	}
	if hints(errors.New("other")) != nil {
		t.Fatal("hint for an unrelated error")
	}
}

// The top-level help lists esec vault, installed or not.
func TestHelpListsVault(t *testing.T) {
	var buf bytes.Buffer
	t.Setenv("PATH", t.TempDir())
	printExternal(&buf)
	if !strings.Contains(buf.String(), "vault") || !strings.Contains(buf.String(), "not installed") {
		t.Fatalf("without esec-vault:\n%s", buf.String())
	}
}

func TestVaultNotInstalled(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	code, handled := maybeExecExternal([]string{"esec", "vault", "status"})
	if !handled || code != 1 {
		t.Fatalf("handled %v, code %d", handled, code)
	}
}
