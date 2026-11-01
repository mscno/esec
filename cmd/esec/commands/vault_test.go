package commands

import (
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/seal"
)

// guardedRepo makes a repository whose prod key is guarded and sealed to
// someone else, and changes into it.
func guardedRepo(t *testing.T, guard string) {
	t.Helper()
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	t.Setenv("ESEC_KEYRING_DIR", t.TempDir())
	t.Setenv(esec.EsecKeyringPath, "")
	t.Setenv("ESEC_CONFIG", "")
	t.Setenv(seal.EnvIdentity, "")
	t.Setenv("ESEC_PRIVATE_KEY_PROD", "") // restored after the test
	if err := os.Unsetenv("ESEC_PRIVATE_KEY_PROD"); err != nil {
		t.Fatal(err)
	}
	f := &projectfile.File{Project: "acme/store"}
	f.SetEnv("prod", pub)
	e := f.Env["prod"]
	e.Guard = guard
	f.Env["prod"] = e
	if err := f.Save(repo); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(repo, ".env.prod")
	if err := os.WriteFile(file, []byte("ESEC_PUBLIC_KEY="+pub+"\nAPI=sk_live\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := esec.EncryptFileInPlace(file); err != nil {
		t.Fatal(err)
	}
	someone, _ := age.GenerateX25519Identity()
	data, err := seal.Seal(seal.Payload{Project: "acme/store", Env: "prod", Guard: guard, Private: priv}, someone.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := seal.Write(repo, "prod", data); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
}

func TestGuardedReadsUseDocumentProtocolForNamesAndFiles(t *testing.T) {
	guardedRepo(t, projectfile.GuardTouch)
	dir, err := os.MkdirTemp("", "esec-read-") //nolint:usetesting // Darwin Unix sockets need a short path
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "r.sock")
	t.Setenv("ESEC_VAULT_SOCK", sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	defer close(done)
	target, err := esec.ResolveRead(".", "prod", "")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				var req map[string]string
				if json.NewDecoder(conn).Decode(&req) != nil {
					return
				}
				if req["op"] != "read_document" || req["env"] != "prod" {
					if err := json.NewEncoder(conn).Encode(map[string]any{"ok": false, "error": "wrong canonical read"}); err != nil {
						t.Error(err)
					}
					return
				}
				if err := json.NewEncoder(conn).Encode(map[string]any{"ok": true, "document": []byte("ESEC_PUBLIC_KEY=" + target.PublicKey + "\nAPI=sk_live\n")}); err != nil {
					t.Error(err)
				}
			}()
		}
	}()
	ctx := &cliCtx{Logger: slog.New(slog.DiscardHandler)}
	for _, input := range []string{"prod", ".env.prod"} {
		got, msg := captureOutput(func() error { return (&DecryptCmd{File: input, KeyDir: "."}).Run(ctx) })
		if msg != "" || !strings.Contains(got, "API=sk_live") {
			t.Fatalf("decrypt %s: %q %s", input, got, msg)
		}
		got, msg = captureOutput(func() error { return (&GetCmd{File: input, Key: "API", KeyDir: "."}).Run(ctx) })
		if msg != "" || got != "sk_live" {
			t.Fatalf("get %s: %q %s", input, got, msg)
		}
	}
}
