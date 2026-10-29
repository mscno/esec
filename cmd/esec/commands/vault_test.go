package commands

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
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

// fakeVault puts an esec-vault on PATH and records what esec would run.
func fakeVault(t *testing.T) *[][]string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "esec-vault"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // an executable test fixture
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	var calls [][]string
	orig := execExternalFn
	t.Cleanup(func() { execExternalFn = orig })
	execExternalFn = func(_ string, args []string) int {
		calls = append(calls, args)
		return 7
	}
	return &calls
}

// run, decrypt and get of a guarded environment, whose key esec cannot be
// given, are handed to esec vault, which asks for the touch.
func TestGuardedReadsGoThroughVault(t *testing.T) {
	guardedRepo(t, projectfile.GuardTouch)
	calls := fakeVault(t)
	ctx := &cliCtx{Logger: slog.New(slog.DiscardHandler)}

	for _, tc := range []struct {
		cmd  interface{ Run(ctx *cliCtx) error }
		want []string
	}{
		{&DecryptCmd{File: "prod", KeyDir: "."}, []string{"decrypt", "prod"}},
		{&GetCmd{File: "prod", Key: "API", KeyDir: "."}, []string{"decrypt", "prod", "API"}},
		{&RunCmd{File: "prod", Format: "env", KeyDir: ".", Command: []string{"./deploy", "--now"}}, []string{"run", "prod", "--format", "env", "--", "./deploy", "--now"}},
	} {
		*calls = nil
		err := tc.cmd.Run(ctx)
		var exit *ExitError
		if !errors.As(err, &exit) || exit.Code != 7 {
			t.Fatalf("%T: %v, want esec vault's exit code", tc.cmd, err)
		}
		if len(*calls) != 1 || !reflect.DeepEqual((*calls)[0], tc.want) {
			t.Fatalf("%T ran %v, want %v", tc.cmd, *calls, tc.want)
		}
	}

	// A file path is esec's own to resolve: the error stands.
	*calls = nil
	if err := (&DecryptCmd{File: ".env.prod", KeyDir: "."}).Run(ctx); !errors.Is(err, esec.ErrKeyNotFound) || len(*calls) != 0 {
		t.Fatalf("a path was handed over: %v %v", err, *calls)
	}
	// Without esec-vault the error says how to read it.
	t.Setenv("PATH", t.TempDir())
	if err := (&DecryptCmd{File: "prod", KeyDir: "."}).Run(ctx); !errors.Is(err, esec.ErrKeyNotFound) || len(*calls) != 0 {
		t.Fatalf("without esec-vault: %v %v", err, *calls)
	}
}

// A sealed key that is not guarded is not handed over: a reader's identity
// opens it, and esec says so.
func TestUnguardedSealStaysWithEsec(t *testing.T) {
	guardedRepo(t, projectfile.GuardNone)
	calls := fakeVault(t)
	ctx := &cliCtx{Logger: slog.New(slog.DiscardHandler)}
	if err := (&DecryptCmd{File: "prod", KeyDir: "."}).Run(ctx); !errors.Is(err, esec.ErrKeyNotFound) || len(*calls) != 0 {
		t.Fatalf("unguarded: %v %v", err, *calls)
	}
}
