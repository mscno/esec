//nolint:gosec // test files contain only synthetic secrets in temporary directories
package commands

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/blob"
)

func blobFixture(t *testing.T, format string) (string, *cliCtx) {
	t.Helper()
	root, _, _, ctx := standaloneFixture(t)
	if err := (&InitCmd{Project: "test/blobs", Env: "dev", Dir: root, Format: format, Yes: true}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	return root, ctx
}

func setTestBlob(t *testing.T, ctx *cliCtx, key string, data []byte, create bool) {
	t.Helper()
	from := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(from, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := (&BlobSetCmd{Environment: "dev", Key: key, From: from, Create: create}).Run(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestBlobAllFormatsExactBytesAndRotation(t *testing.T) {
	for _, format := range []string{"env", "ejson", "etoml", "eyaml", "eyml"} {
		t.Run(format, func(t *testing.T) {
			root, ctx := blobFixture(t, format)
			data := []byte("synthetic-private-key\r\n\x00\xff\x80\n\n")
			setTestBlob(t, ctx, "CREDENTIAL", data, true)
			setTestBlob(t, ctx, "EMPTY_FILE", nil, true)
			for _, pair := range []struct {
				key  string
				data []byte
			}{{"CREDENTIAL", data}, {"EMPTY_FILE", nil}} {
				out, errs := captureOutput(func() error { return (&BlobGetCmd{Environment: "dev", Key: pair.key}).Run(ctx) })
				if errs != "" || !bytes.Equal([]byte(out), pair.data) {
					t.Fatalf("exact stdout mismatch: %s", errs)
				}
			}
			target, err := esec.ResolveRead(root, "dev", "")
			if err != nil || bytes.Contains(target.Content, []byte("synthetic-private-key")) {
				t.Fatal("plaintext persisted", err)
			}
			if report := checkProject(root); len(report.Findings) != 0 {
				t.Fatalf("blob ciphertext failed check: %+v", report.Findings)
			}
			if err := (&RotateCmd{File: "dev"}).Run(ctx); err != nil {
				t.Fatal(err)
			}
			out, errs := captureOutput(func() error { return (&BlobGetCmd{Environment: "dev", Key: "CREDENTIAL"}).Run(ctx) })
			if errs != "" || !bytes.Equal([]byte(out), data) {
				t.Fatal("rotation lost blob", errs)
			}
			setTestBlob(t, ctx, "CREDENTIAL", []byte("replacement\n"), false)
			out, errs = captureOutput(func() error { return (&BlobGetCmd{Environment: "dev", Key: "CREDENTIAL"}).Run(ctx) })
			if out != "replacement\n" || errs != "" {
				t.Fatal("replacement failed", errs)
			}
		})
	}
}

func TestBlobSetStdinLimitsAndNoPrivateKey(t *testing.T) {
	root, ctx := blobFixture(t, "env")
	t.Setenv("ESEC_AGE_IDENTITY", "invalid-unused-identity")
	input := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(input, []byte("\x00\xffstdin\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	original := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = original })
	if err := (&BlobSetCmd{Environment: "dev", Key: "INPUT", Stdin: true, Create: true}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ESEC_AGE_IDENTITY", "")
	out, errs := captureOutput(func() error { return (&BlobGetCmd{Environment: "dev", Key: "INPUT"}).Run(ctx) })
	if errs != "" || out != "\x00\xffstdin\n" {
		t.Fatal("stdin bytes changed", errs)
	}
	target, err := esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(target.Content)
	large := filepath.Join(t.TempDir(), "large")
	if err := os.WriteFile(large, make([]byte, blob.MaxSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*BlobSetCmd{
		{Environment: "dev", Key: "INPUT", From: large},
		{Environment: "dev", Key: "INPUT"},
		{Environment: "dev", Key: "INPUT", From: input, Stdin: true},
		{Environment: "dev", Key: "INPUT", From: input, Create: true},
	} {
		if err := c.Run(ctx); err == nil {
			t.Fatal("invalid import accepted")
		}
	}
	largeInput, err := os.Open(large)
	if err != nil {
		t.Fatal(err)
	}
	defer largeInput.Close()
	os.Stdin = largeInput
	if err := (&BlobSetCmd{Environment: "dev", Key: "INPUT", Stdin: true}).Run(ctx); err == nil {
		t.Fatal("oversize stdin accepted")
	}
	after, err := os.ReadFile(target.Path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed import modified ciphertext", err)
	}
	// A revision captured before stdin input may not overwrite another edit.
	stale := target.Digest
	setTestBlob(t, ctx, "INPUT", []byte("new"), false)
	v, _ := blob.Encode([]byte("stale"))
	if _, err := updateSecretDocument(target.Path, secretUpdate{Revision: stale, Key: "INPUT", Value: &v}); err == nil {
		t.Fatal("stale blob update accepted")
	}
	if bytes.Contains(before, []byte("stdin")) {
		t.Fatal("input stored in clear")
	}
}

func TestBlobRejectsPlaintextNonBlobAndUnauthorizedReads(t *testing.T) {
	root, ctx := blobFixture(t, "env")
	setTestBlob(t, ctx, "VALID", []byte("valid"), true)
	value := "ordinary-secret-never-print"
	target, err := esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := updateSecretDocument(target.Path, secretUpdate{Revision: target.Digest, Key: "ORDINARY", Value: &value, Create: true}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(target.Path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(f, "PLAINTEXT=esec-blob-v1:cGxhaW50ZXh0LXNlY3JldA==\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	for _, key := range []string{"ORDINARY", "PLAINTEXT", "MISSING"} {
		out, errs := captureOutput(func() error { return (&BlobGetCmd{Environment: "dev", Key: key}).Run(ctx) })
		if out != "" || errs == "" || strings.Contains(errs, "ordinary-secret") || strings.Contains(errs, "plaintext-secret") {
			t.Fatal("invalid blob exposed content")
		}
	}
	t.Setenv("ESEC_AGE_IDENTITY", "invalid")
	out, errs := captureOutput(func() error { return (&BlobGetCmd{Environment: "dev", Key: "VALID"}).Run(ctx) })
	if out != "" || errs == "" {
		t.Fatal("unauthorized read produced output")
	}
}

func TestBlobPrivateOutputRefusesOverwriteAndSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions")
	}
	_, ctx := blobFixture(t, "etoml")
	setTestBlob(t, ctx, "CREDENTIAL", []byte("synthetic\x00\xff\n"), true)
	output := filepath.Join(t.TempDir(), "restored")
	c := &BlobGetCmd{Environment: "dev", Key: "CREDENTIAL", Out: output}
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("output not private", err)
	}
	if err := c.Run(ctx); err == nil {
		t.Fatal("existing output overwritten")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(output, link); err != nil {
		t.Fatal(err)
	}
	c.Out = link
	if err := c.Run(ctx); err == nil {
		t.Fatal("symlink output accepted")
	}
	c.Out = filepath.Join(t.TempDir(), "missing")
	c.Key = "MISSING"
	if err := c.Run(ctx); err == nil {
		t.Fatal("missing blob accepted")
	}
	if _, err := os.Stat(c.Out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failure created plaintext output")
	}
	values, err := os.ReadFile(output)
	if err != nil || string(values) != "synthetic\x00\xff\n" {
		t.Fatal("export corrupted or overwritten")
	}
}

func TestBlobRunCleanupAndSelectedScope(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix temporary file support")
	}
	_, ctx := blobFixture(t, "etoml")
	setTestBlob(t, ctx, "SELECTED", []byte("file-secret\n"), true)
	setTestBlob(t, ctx, "NOT_EXPOSED", []byte("other-secret"), true)
	base := t.TempDir()
	t.Setenv("TMPDIR", base)
	t.Setenv("CRED_PATH", "stale-inherited")
	t.Setenv("SELECTED", "")
	c := &BlobRunCmd{Environment: "dev", Files: []string{"CRED_PATH=SELECTED"}, Command: []string{"sh", "-c", `test -f "$CRED_PATH" && test -z "$SELECTED" && test -z "$NOT_EXPOSED" && cat "$CRED_PATH"`}}
	out, errs := captureOutput(func() error { return c.Run(ctx) })
	if errs != "" || out != "file-secret\n" {
		t.Fatalf("child scope or path failed: %q %s", out, errs)
	}
	for _, command := range [][]string{{"sh", "-c", "exit 17"}, {filepath.Join(t.TempDir(), "nonexistent")}} {
		c.Command = command
		if err := c.Run(ctx); err == nil {
			t.Fatal("expected command failure")
		} else if command[0] == "sh" {
			var exit *ExitError
			if !errors.As(err, &exit) || exit.Code != 17 {
				t.Fatal("exit status not preserved")
			}
		}
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 0 {
		t.Fatal("temporary plaintext left behind", err)
	}
}

func TestBlobCLIParsingAndBindingValidation(t *testing.T) {
	var cli cli
	p, err := kong.New(&cli, kong.Vars{"version": "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Parse([]string{"blob", "run", "dev", "--file", "ONE=KEY", "--file", "TWO=other.nested", "--", "echo", "--file", "unchanged"}); err != nil {
		t.Fatal(err)
	}
	if len(cli.Blob.Run.Files) != 2 || strings.Join(cli.Blob.Run.Command, " ") != "echo --file unchanged" {
		t.Fatal("blob arguments parsed incorrectly")
	}
	for _, files := range [][]string{nil, {"PATH=KEY"}, {"ESEC_AGE_IDENTITY=KEY"}, {"LD_PRELOAD=KEY"}, {"=KEY"}, {"X="}, {"X=KEY", "X=OTHER"}} {
		if _, err := (&BlobRunCmd{Files: files}).bindings(); err == nil {
			t.Fatal("unsafe or duplicate binding accepted")
		}
	}
}
