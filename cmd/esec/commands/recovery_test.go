package commands

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/recovery"
	"github.com/mscno/esec/pkg/seal"
	"github.com/tyler-smith/go-bip39"
)

type syntheticRecoveryTerminal struct {
	answers       []string
	output        strings.Builder
	confirmBackup bool
}

func (t *syntheticRecoveryTerminal) Secret(label string) (string, error) {
	if t.confirmBackup && strings.HasPrefix(label, "Re-enter") {
		for _, line := range strings.Split(t.output.String(), "\n") {
			if len(strings.Fields(line)) == 24 && bip39.IsMnemonicValid(line) {
				return line, nil
			}
		}
		return "", errors.New("test did not receive generated phrase")
	}
	if len(t.answers) == 0 {
		return "", errors.New("unexpected recovery prompt")
	}
	a := t.answers[0]
	t.answers = t.answers[1:]
	return a, nil
}
func (t *syntheticRecoveryTerminal) Write(s string) error {
	_, err := t.output.WriteString(s)
	return err
}
func (*syntheticRecoveryTerminal) Close() error { return nil }
func useRecoveryTerminal(t *testing.T, terminal *syntheticRecoveryTerminal) {
	t.Helper()
	old := openRecoveryTerminal
	openRecoveryTerminal = func() (recoveryTerminal, error) { return terminal, nil }
	t.Cleanup(func() { openRecoveryTerminal = old })
}

func TestRecoveryCreateStoresOnlyPublicDefaults(t *testing.T) {
	_, _, _, ctx := standaloneFixture(t) //nolint:dogsled // only the isolated configuration and CLI context are relevant
	before, _ := config.Load()
	terminal := &syntheticRecoveryTerminal{answers: []string{"synthetic-passphrase", "synthetic-passphrase", "add recovery"}, confirmBackup: true}
	useRecoveryTerminal(t, terminal)
	if err := (&RecoveryCreateCmd{}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(before.Age.IdentityFiles, after.Age.IdentityFiles) || len(after.Age.RecoveryRecipients) != len(before.Age.RecoveryRecipients)+1 {
		t.Fatal("creation must store only the public recovery default")
	}
	path, _ := config.AgePath()
	b, err := os.ReadFile(path) //nolint:gosec // synthetic test config
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("synthetic-passphrase")) || bytes.Contains(b, []byte("AGE-SECRET-KEY")) {
		t.Fatal("recovery secret was saved in configuration")
	}
	for _, line := range strings.Split(terminal.output.String(), "\n") {
		if len(strings.Fields(line)) == 24 && bip39.IsMnemonicValid(line) && bytes.Contains(b, []byte(line)) {
			t.Fatal("recovery phrase was saved")
		}
	}
}

func TestRecoveryCancellationAndExportProtection(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	before, _ := config.Load()
	useRecoveryTerminal(t, &syntheticRecoveryTerminal{answers: []string{"one", "two"}})
	if err := (&RecoveryCreateCmd{}).Run(ctx); err == nil {
		t.Fatal("passphrase mismatch accepted")
	}
	after, _ := config.Load()
	if !slices.Equal(before.Age.RecoveryRecipients, after.Age.RecoveryRecipients) {
		t.Fatal("cancelled creation modified config")
	}
	phrase, _ := bip39.NewMnemonic(make([]byte, 32))
	id, err := recovery.Derive(phrase, "", recovery.Format)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "export.age")
	useRecoveryTerminal(t, &syntheticRecoveryTerminal{answers: []string{phrase, "wrong"}})
	c := &RecoveryExportCmd{Out: output, ExpectRecipient: id.Recipient().String(), Format: recovery.Format}
	if err := c.Run(ctx); err == nil {
		t.Fatal("wrong passphrase exported")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrong-passphrase export created a file")
	}
	useRecoveryTerminal(t, &syntheticRecoveryTerminal{answers: []string{phrase, "", "export recovery"}})
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(output)
	if info.Mode().Perm() != 0600 {
		t.Fatal("export is not private")
	}
	if err := writeRecoveryIdentity(output, id, recovery.Format); err == nil {
		t.Fatal("export overwrote existing identity")
	}
	after, _ = config.Load()
	if !slices.Equal(before.Age.IdentityFiles, after.Age.IdentityFiles) {
		t.Fatal("export configured a persistent recovery identity")
	}
}

//nolint:gocyclo // one grant/revoke scenario verifies the same ciphertext history throughout
func TestPhraseRecoveryApplyAndRemovalNeverReaddsDefault(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	phrase, _ := bip39.NewMnemonic(make([]byte, 32))
	id, err := recovery.Derive(phrase, "synthetic", recovery.Format)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load()
	cfg.Age.RecoveryRecipients = []string{id.Recipient().String()}
	if err := cfg.SaveAge(); err != nil {
		t.Fatal(err)
	}
	initStandalone(t, root, ctx)
	t.Chdir(root)
	before, err := esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	useRecoveryTerminal(t, &syntheticRecoveryTerminal{answers: []string{phrase, "wrong"}})
	if _, err := readRecoveryDocument("dev", "", recovery.Format); err == nil {
		t.Fatal("wrong phrase fell back to valid configured developer identity")
	}
	useRecoveryTerminal(t, &syntheticRecoveryTerminal{answers: []string{phrase, "synthetic"}})
	data, err := readRecoveryDocument("dev", "", recovery.Format)
	if err != nil || !bytes.Contains(data, []byte("synthetic-dev")) {
		t.Fatal("phrase recovery failed", err)
	}
	clear(data)
	linux, _ := age.GenerateX25519Identity()
	pf, _ := projectfile.Load(root)
	e := pf.Env["dev"]
	e.Recipients = append(e.Recipients, linux.Recipient().String())
	pf.Env["dev"] = e
	if err := pf.Save(root); err != nil {
		t.Fatal(err)
	}
	plan, err := buildAccessPlan(root, "dev")
	if err != nil {
		t.Fatal(err)
	}
	useRecoveryTerminal(t, &syntheticRecoveryTerminal{answers: []string{phrase, "wrong"}})
	c := &ApplyCmd{Dir: root, Env: "dev", PlanHash: plan.Hash, Yes: true, Recovery: true, RecoveryFormat: recovery.Format}
	if err := c.Run(ctx); err == nil {
		t.Fatal("wrong recovery identity fell back during apply")
	}
	current, _ := esec.ResolveRead(root, "dev", "")
	if current.Digest != before.Digest {
		t.Fatal("failed recovery changed ciphertext")
	}
	useRecoveryTerminal(t, &syntheticRecoveryTerminal{answers: []string{phrase, "synthetic"}})
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	granted, _ := esec.ResolveRead(root, "dev", "")
	if _, err := esec.ReadDocument(granted, esec.ReadOptions{AgeIdentities: []age.Identity{linux}}); err != nil {
		t.Fatal("recovery failed to grant new machine", err)
	}
	pf, _ = projectfile.Load(root)
	e = pf.Env["dev"]
	e.Recipients = slices.DeleteFunc(e.Recipients, func(r string) bool { return r == id.Recipient().String() })
	pf.Env["dev"] = e
	if err := pf.Save(root); err != nil {
		t.Fatal(err)
	}
	plan, err = buildAccessPlan(root, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if err := (&ApplyCmd{Dir: root, Env: "dev", PlanHash: plan.Hash, Yes: true, ApproveSensitive: true}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ := esec.ResolveRead(root, "dev", "")
	if slices.Contains(after.Recipients, id.Recipient().String()) {
		t.Fatal("local default was silently re-added")
	}
	if _, err := esec.ReadDocument(after, esec.ReadOptions{AgeIdentities: []age.Identity{id}}); err == nil {
		t.Fatal("removed phrase can read current ciphertext")
	}
	if _, err := esec.ReadDocument(before, esec.ReadOptions{AgeIdentities: []age.Identity{id}}); err != nil {
		t.Fatal("historical recovery lost", err)
	}
	plan, err = buildAccessPlan(root, "dev")
	if err != nil || plan.changed() {
		t.Fatal("removed default reported as drift", err)
	}
}

func TestRecoveryRoleIsExplicitAndDoesNotGrantAccess(t *testing.T) {
	root, dev, recoveryID, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	pf, _ := projectfile.Load(root)
	hardware := plugin.EncodeRecipient("yubikey", []byte("synthetic-test-recipient"))
	pf.Env["production"] = projectfile.Env{Access: "production", Recipients: []string{hardware, recoveryID.Recipient().String()}}
	if err := pf.Save(root); err != nil {
		t.Fatal(err)
	}
	if _, err := buildAccessPlan(root, "production"); err != nil {
		t.Fatal("explicit offline recovery rejected across dev/production", err)
	}
	pf.RecoveryRecipients = nil
	if err := pf.Save(root); err != nil {
		t.Fatal(err)
	}
	if _, err := buildAccessPlan(root, "production"); err == nil {
		t.Fatal("unclassified developer software identity accepted in production")
	}
	pf.RecoveryRecipients = []string{recoveryID.Recipient().String(), dev.Recipient().String()}
	e := pf.Env["production"]
	e.Recipients = []string{hardware}
	pf.Env["production"] = e
	if err := pf.Save(root); err != nil {
		t.Fatal(err)
	}
	plan, err := buildAccessPlan(root, "production")
	if err != nil || slices.Contains(plan.Environments[0].Recipients, recoveryID.Recipient().String()) {
		t.Fatal("role label granted access", err)
	}
	e.Recipients = append(e.Recipients, dev.Recipient().String())
	pf.Env["production"] = e
	if err := pf.Save(root); err != nil {
		t.Fatal(err)
	}
	if _, err := buildAccessPlan(root, "production"); err == nil {
		t.Fatal("recovery label bypassed known everyday developer exclusion")
	}
}

func TestPhraseAdoptsLegacySealWithoutSavingIdentity(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	phrase, _ := bip39.NewMnemonic(make([]byte, 32))
	id, err := recovery.Derive(phrase, "", recovery.VaultFormat)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load()
	cfg.Age.RecoveryRecipients = []string{id.Recipient().String()}
	if err := cfg.SaveAge(); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pf := &projectfile.File{Project: "test/app", Env: map[string]projectfile.Env{"dev": {Key: pub}}}
	if err := pf.Save(root); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, ".env.dev")
	if err := os.WriteFile(file, []byte("ESEC_PUBLIC_KEY="+pub+"\nTOKEN=synthetic-legacy\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := esec.EncryptFileInPlace(file); err != nil {
		t.Fatal(err)
	}
	sealed, err := seal.Seal(seal.Payload{Project: "test/app", Env: "dev", Private: priv}, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := seal.Write(root, "dev", sealed); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	useRecoveryTerminal(t, &syntheticRecoveryTerminal{answers: []string{phrase, ""}})
	if err := (&AdoptCmd{File: "dev", Recovery: true, RecoveryFormat: recovery.VaultFormat}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	target, err := esec.ResolveRead(root, "dev", "")
	if err != nil || !target.Standalone || target.PublicKey == pub {
		t.Fatal("legacy adoption did not rotate to standalone access", err)
	}
	data, err := esec.ReadDocument(target, esec.ReadOptions{AgeIdentities: []age.Identity{id}})
	if err != nil || !bytes.Contains(data, []byte("synthetic-legacy")) {
		t.Fatal("adopted document is not recoverable", err)
	}
	pf, _ = projectfile.Load(root)
	if !slices.Contains(pf.RecoveryRecipients, id.Recipient().String()) {
		t.Fatal("adoption omitted the public recovery role")
	}
}

func TestRecoveryImportChecksPassphraseAndExpectedRecipient(t *testing.T) {
	_, _, _, ctx := standaloneFixture(t) //nolint:dogsled // this test only changes isolated machine public defaults
	phrase, _ := bip39.NewMnemonic(make([]byte, 32))
	id, err := recovery.Derive(phrase, "pass", recovery.Format)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := config.Load()
	useRecoveryTerminal(t, &syntheticRecoveryTerminal{answers: []string{phrase, "pass", "typo"}})
	c := &RecoveryImportCmd{Format: recovery.Format, ExpectRecipient: id.Recipient().String()}
	if err := c.Run(ctx); err == nil {
		t.Fatal("passphrase mismatch imported")
	}
	useRecoveryTerminal(t, &syntheticRecoveryTerminal{answers: []string{phrase, "wrong", "wrong"}})
	if err := c.Run(ctx); err == nil {
		t.Fatal("unexpected recipient imported")
	}
	after, _ := config.Load()
	if !slices.Equal(before.Age.RecoveryRecipients, after.Age.RecoveryRecipients) {
		t.Fatal("failed import changed defaults")
	}
	useRecoveryTerminal(t, &syntheticRecoveryTerminal{answers: []string{phrase, "pass", "pass", "add recovery"}})
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ = config.Load()
	if !slices.Contains(after.Age.RecoveryRecipients, id.Recipient().String()) || !slices.Equal(before.Age.IdentityFiles, after.Age.IdentityFiles) {
		t.Fatal("import must register only a public default")
	}
}
