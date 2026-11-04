package commands

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/joho/godotenv"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/seal"
)

func standaloneFixture(t *testing.T) (string, *age.X25519Identity, *age.X25519Identity, *cliCtx) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("ESEC_CONFIG", filepath.Join(dir, "config.toml"))
	t.Setenv("ESEC_AGE_IDENTITY", "")
	t.Setenv("ESEC_AGE_IDENTITY_FILE", "")
	t.Setenv("ESEC_KEYRING_PATH", filepath.Join(dir, "no-keyring"))
	t.Setenv("ESEC_PRIVATE_KEY_DEV", "")
	t.Setenv("ESEC_PRIVATE_KEY", "")
	t.Setenv("ESEC_VAULT_HOME", filepath.Join(dir, "vault"))
	dev, _ := age.GenerateX25519Identity()
	recovery, _ := age.GenerateX25519Identity()
	identity := filepath.Join(dir, "dev.age")
	if err := os.WriteFile(identity, []byte(dev.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Age = config.Age{DeveloperRecipient: dev.Recipient().String(), IdentityFiles: []string{identity}, RecoveryRecipients: []string{recovery.Recipient().String()}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "project")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root, dev, recovery, &cliCtx{Logger: slog.New(slog.DiscardHandler), Quiet: true}
}
func initStandalone(t *testing.T, root string, ctx *cliCtx) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, ".env.dev"), []byte("DATABASE_URL=synthetic-dev\nEMPTY=\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := InitCmd{Project: "test/app", Env: "dev", Dir: root, EncryptExisting: true, Yes: true}
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestStandaloneRecoveryAndNoPrivateKeyFallback(t *testing.T) {
	root, dev, recovery, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	target, err := esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	if target.Route() != "local_age" {
		t.Fatal("expected local age route")
	}
	plain, err := esec.ReadDocument(target, esec.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plain, []byte("synthetic-dev")) {
		t.Fatal("missing original value")
	}
	cfg, _ := config.Load()
	if err := os.Remove(cfg.Age.IdentityFiles[0]); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ESEC_AGE_IDENTITY", recovery.String())
	if _, err := esec.ReadDocument(target, esec.ReadOptions{}); err != nil {
		t.Fatal("offline recovery failed", err)
	}
	// Even a correct raw Esec key is not a fallback for a standalone seal.
	sealed, err := os.ReadFile(target.Seal)
	if err != nil {
		t.Fatal(err)
	}
	p, err := seal.Open(sealed, target.Project, "dev", target.PublicKey, dev)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := age.GenerateX25519Identity()
	t.Setenv("ESEC_AGE_IDENTITY", wrong.String())
	t.Setenv("ESEC_PRIVATE_KEY_DEV", p.Private)
	if _, err := esec.ReadDocument(target, esec.ReadOptions{PrivateKey: p.Private}); err == nil {
		t.Fatal("raw key bypassed standalone identity")
	}
	// Inspection does not contact a broker or open the key.
	if got := esec.InspectRead(target, esec.ReadOptions{}); got.Route != "local_age" {
		t.Fatal("unexpected broker route")
	}
}
func TestStandaloneInitNeverCopiesExampleAndRequiresPlaintextConsent(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	if err := os.WriteFile(filepath.Join(root, ".env.example"), []byte("EXAMPLE=must-not-copy\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := InitCmd{Project: "test/app", Env: "dev", Dir: root, Yes: true}
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, ".env.dev")) //nolint:gosec // local synthetic fixture created under t.TempDir
	if strings.Contains(string(b), "EXAMPLE") || strings.Count(strings.TrimSpace(string(b)), "\n") != 0 {
		t.Fatal("new file should contain only a public key")
	}
	if err := os.WriteFile(filepath.Join(root, ".env.test"), []byte("LOCAL=synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c.Env = "test"
	if err := c.Run(ctx); err == nil || !strings.Contains(err.Error(), "--encrypt-existing") {
		t.Fatal("missing plaintext consent error", err)
	}
	b, _ = os.ReadFile(filepath.Join(root, ".env.test")) //nolint:gosec // local synthetic fixture created under t.TempDir
	if string(b) != "LOCAL=synthetic\n" {
		t.Fatal("changed plaintext without consent")
	}
}
func TestRecipientsRotateAndPreserveHistory(t *testing.T) {
	root, dev, recovery, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	before, err := esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ESEC_AGE_IDENTITY", dev.String())
	if err := rotateStandalone(ctx, before, []string{recovery.Recipient().String()}); err != nil {
		t.Fatal(err)
	}
	after, err := esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	if before.PublicKey == after.PublicKey {
		t.Fatal("recipient removal did not rotate the key")
	}
	if _, err := os.Stat(before.Seal); err != nil {
		t.Fatal("old recovery seal was lost", err)
	}
	if _, err := esec.ReadDocument(after, esec.ReadOptions{}); err == nil {
		t.Fatal("removed identity can still decrypt new ciphertext")
	}
	t.Setenv("ESEC_AGE_IDENTITY", recovery.String())
	if _, err := esec.ReadDocument(after, esec.ReadOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := esec.ReadDocument(before, esec.ReadOptions{}); err != nil {
		t.Fatal("historical recovery failed", err)
	}
}
func TestStandaloneProductionExcludesDeveloper(t *testing.T) {
	root, dev, _, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	cfg, _ := config.Load()
	// Public test recipient: parsing performs no hardware interaction.
	cfg.Age.YubiKeyRecipients = []string{plugin.EncodeRecipient("yubikey", []byte("synthetic-test-recipient")), plugin.EncodeRecipient("yubikey", []byte("synthetic-second-recipient"))}
	machine, _ := age.GenerateX25519Identity()
	rs, err := defaultRecipients(cfg, true, []string{machine.Recipient().String()}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 4 || !slicesContains(rs, cfg.Age.RecoveryRecipients[0]) || slicesContains(rs, dev.Recipient().String()) || !slicesContains(rs, machine.Recipient().String()) {
		t.Fatal("production recipients are incorrect")
	}
	if _, err := defaultRecipients(cfg, true, []string{dev.Recipient().String()}, false); err == nil {
		t.Fatal("developer was accepted as production machine")
	}
}
func slicesContains(xs []string, s string) bool {
	for _, v := range xs {
		if v == s {
			return true
		}
	}
	return false
}
func TestStandaloneRejectsSymlinkAndRepairsInterruptedWrite(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".esec")); err != nil {
		t.Fatal(err)
	}
	if err := (&InitCmd{Project: "test/app", Env: "dev", Dir: root, Yes: true}).Run(ctx); err == nil {
		t.Fatal("followed symlink")
	}
	os.Remove(filepath.Join(root, ".esec"))
	initStandalone(t, root, ctx)
	t1, _ := esec.ResolveRead(root, "dev", "")
	journal := filepath.Join(root, ".esec", "pending")
	if err := os.MkdirAll(journal, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journal, ".env.dev"), t1.Content, 0600); err != nil {
		t.Fatal(err)
	}
	marker, _ := os.ReadFile(filepath.Join(root, projectfile.ProjectFileName))                              //nolint:gosec // local synthetic fixture created under t.TempDir
	if err := os.WriteFile(filepath.Join(journal, projectfile.ProjectFileName), marker, 0600); err != nil { //nolint:gosec // synthetic fixture in t.TempDir
		t.Fatal(err)
	}
	manifest, err := json.Marshal(map[string]journalEntry{
		".env.dev":                  {Before: digest(t1.Content), After: digest(t1.Content)},
		projectfile.ProjectFileName: {Before: digest(marker), After: digest(marker)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journal, "manifest.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	if err := (&RepairCmd{Dir: root}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(journal); !os.IsNotExist(err) {
		t.Fatal("journal not completed")
	}
}
func TestMachineSetupDoesNotOverwriteIdentity(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	p := filepath.Join(root, "machine.age")
	pub, err := createAgeIdentity(p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p) //nolint:gosec // local synthetic fixture created under t.TempDir
	st, _ := os.Stat(p)
	if pub == "" || st.Mode().Perm() != 0600 {
		t.Fatal("invalid identity output")
	}
	if _, err := createAgeIdentity(p); err == nil {
		t.Fatal("overwrote identity")
	}
	after, _ := os.ReadFile(p) //nolint:gosec // local synthetic fixture created under t.TempDir
	if !bytes.Equal(b, after) {
		t.Fatal("identity changed")
	}
	c := MachineSetupCmd{GenerateDev: true, Yes: true}
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestStandaloneMultilinePlaintextNeverReachesCiphertext(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	original := []byte("TOKEN=\"first\n# synthetic-secret-continuation\nlast\"\nURL: synthetic-url\nDOLLAR='literal$dollar'\n")
	if err := os.WriteFile(filepath.Join(root, ".env.dev"), original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := (&InitCmd{Project: "test/app", Env: "dev", Dir: root, EncryptExisting: true, Yes: true}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	target, err := esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(target.Content, []byte("synthetic-secret-continuation")) || bytes.Contains(target.Content, []byte("synthetic-url")) {
		t.Fatal("plaintext leaked into encrypted file")
	}
	plain, err := esec.ReadDocument(target, esec.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want, err := godotenv.Unmarshal(string(original))
	if err != nil {
		t.Fatal(err)
	}
	got, err := godotenv.Unmarshal(string(plain))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("value changed for %s", k)
		}
	}
	testConflictingRepair(t, root, ctx, target)
}

func testConflictingRepair(t *testing.T, root string, ctx *cliCtx, target *esec.ReadTarget) {
	// The staged bytes are the same ciphertext; a blocked repair must not expose
	// multiline continuations or overwrite a concurrent edit.
	p := filepath.Join(root, ".env.dev")
	before, err := snapshot(p)
	if err != nil {
		t.Fatal(err)
	}
	edited := append(append([]byte{}, target.Content...), []byte("# concurrent edit\n")...)
	if err := os.WriteFile(p, edited, 0600); err != nil {
		t.Fatal(err)
	}
	if err := applyCiphertextChanges(root, map[string][]byte{p: target.Content}, map[string]sourceSnapshot{p: before}); err == nil {
		t.Fatal("stale write accepted")
	}
	actual, _ := os.ReadFile(p) //nolint:gosec // local synthetic fixture created under t.TempDir
	if !bytes.Equal(actual, edited) {
		t.Fatal("concurrent edit overwritten")
	}
	journal := filepath.Join(root, ".esec", "pending")
	if err := os.Mkdir(journal, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journal, ".env.dev"), target.Content, 0600); err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(map[string]journalEntry{".env.dev": {Before: before.Hash, After: digest(target.Content)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journal, "manifest.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	if err := (&RepairCmd{Dir: root}).Run(ctx); err == nil {
		t.Fatal("repair overwrote edited file")
	}
	staged, _ := os.ReadFile(filepath.Join(journal, ".env.dev")) //nolint:gosec // local synthetic fixture created under t.TempDir
	if bytes.Contains(staged, []byte("synthetic-secret-continuation")) {
		t.Fatal("plaintext in journal")
	}
	actual, _ = os.ReadFile(p) //nolint:gosec // local synthetic fixture created under t.TempDir
	if !bytes.Equal(actual, edited) {
		t.Fatal("repair changed concurrent edit")
	}
	// Restoring the expected original makes the interrupted transaction recoverable.
	if err := os.WriteFile(p, target.Content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := (&RepairCmd{Dir: root}).Run(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestStandaloneRotationRefusesStaleSource(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	target, err := esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	edited := append(append([]byte{}, target.Content...), []byte("# new edit\n")...)
	if err := os.WriteFile(target.Path, edited, 0600); err != nil {
		t.Fatal(err)
	}
	if err := rotateStandalone(ctx, target, target.Recipients); err == nil {
		t.Fatal("rotation accepted stale file")
	}
	actual, _ := os.ReadFile(target.Path)
	if !bytes.Equal(actual, edited) {
		t.Fatal("rotation overwrote edit")
	}
}

func TestStandaloneRunExplicitOverrides(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	t.Chdir(root)
	t.Setenv("DATABASE_URL", "synthetic-local-override")
	t.Setenv("EMPTY", "")
	c := RunCmd{File: "dev", PreserveEnv: []string{"DATABASE_URL,EMPTY"}, Command: []string{"/bin/sh", "-c", `test "$DATABASE_URL" = synthetic-local-override && test "${EMPTY+x}" = x && test -z "$EMPTY"`}}
	if err := c.Run(ctx); err != nil {
		t.Fatal("explicit overrides lost", err)
	}
	c.PreserveEnv = nil
	c.Command = []string{"/bin/sh", "-c", `test "$DATABASE_URL" = synthetic-dev`}
	if err := c.Run(ctx); err != nil {
		t.Fatal("file defaults not applied", err)
	}
}

func TestStandaloneMissingMetadataDoesNotEnableRawKey(t *testing.T) {
	root, dev, _, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	target, err := esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(target.Seal)
	if err != nil {
		t.Fatal(err)
	}
	p, err := seal.Open(b, target.Project, "dev", target.PublicKey, dev)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ESEC_PRIVATE_KEY_DEV", p.Private)
	marker := filepath.Join(root, projectfile.ProjectFileName)
	pf, err := projectfile.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	pf.Env["dev"] = projectfile.Env{Key: target.PublicKey}
	legacy, err := pf.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := esec.ResolveRead(root, "dev", ""); err == nil {
		t.Fatal("missing recipients enabled raw key fallback")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if _, err := esec.ResolveRead(root, ".env.dev", ""); err == nil {
		t.Fatal("missing project marker enabled raw key fallback")
	}
}

func TestMachineSetupAcceptsPastedRecipientOffline(t *testing.T) {
	ctx := &cliCtx{Logger: slog.New(slog.DiscardHandler), Quiet: true}
	t.Setenv("ESEC_CONFIG", filepath.Join(t.TempDir(), "config.toml"))
	cfg := config.Defaults()
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	basePath, err := config.Path()
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(basePath) //nolint:gosec // local synthetic fixture created under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir()) // No plugin or physical key is required for pasting.
	recipient := plugin.EncodeRecipient("yubikey", []byte("synthetic-public-recipient"))
	c := MachineSetupCmd{YubikeyRecipient: []string{recipient}, Yes: true}
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	saved, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.Age.DeveloperRecipient != "" || !slicesContains(saved.Age.YubiKeyRecipients, recipient) {
		t.Fatal("public-only setup was not retained")
	}
	after, err := os.ReadFile(basePath) //nolint:gosec // local synthetic fixture created under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("setup rewrote legacy shared configuration")
	}
	c.YubikeyRecipient = nil
	c.GenerateDev = true
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	saved, err = config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.Age.DeveloperRecipient == "" || len(saved.Age.IdentityFiles) != 1 {
		t.Fatal("developer identity was not created")
	}
	st, err := os.Stat(saved.Age.IdentityFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatal("private identity permissions are not 0600")
	}
}

func TestStandaloneMissingMetadataCustomFilename(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	pf := &projectfile.File{Project: "test/app", Files: projectfile.Files{Format: "etoml", Name: "secrets/app.{env}.etoml"}}
	marker, err := pf.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "esec.toml"), marker, 0600); err != nil {
		t.Fatal(err)
	}
	if err := (&InitCmd{Project: "test/app", Env: "dev", Dir: root, Yes: true}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	target, err := esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	if target.Environment != "dev" {
		t.Fatal("fixture did not resolve custom filename")
	}
	if err := os.Remove(filepath.Join(root, "esec.toml")); err != nil {
		t.Fatal(err)
	}
	if _, err := esec.ResolveRead(root, target.Path, ""); err == nil {
		t.Fatal("custom filename bypassed missing-metadata guard")
	}
}
