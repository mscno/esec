package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/seal"
)

func editRecipients(t *testing.T, root, env string, rs []string) {
	t.Helper()
	pf, err := projectfile.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	e := pf.Env[env]
	e.Recipients = rs
	pf.Env[env] = e
	if err := pf.Save(root); err != nil {
		t.Fatal(err)
	}
}

func TestPlanApplyNewMachineAndRemoval(t *testing.T) { //nolint:gocyclo // complete addition, revocation, and independent recovery story
	root, dev, recovery, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	initial, err := buildAccessPlan(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if initial.changed() {
		t.Fatal("new environment drifted")
	}
	old, err := esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	linux, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	rs := append([]string{}, old.Recipients...)
	rs = append(rs, linux.Recipient().String())
	editRecipients(t, root, "dev", rs)
	plan, err := buildAccessPlan(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Environments[0].Action != "drift" || len(plan.Environments[0].Added) != 1 {
		t.Fatalf("bad plan: %+v", plan.Environments)
	}
	if err := (&ApplyCmd{Dir: root, Yes: true, PlanHash: initial.Hash}).Run(ctx); err == nil {
		t.Fatal("accepted stale plan")
	}
	if err := (&ApplyCmd{Dir: root, Yes: true, PlanHash: plan.Hash}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	if current.PublicKey == old.PublicKey || current.PolicyStatus != "current" {
		t.Fatal("key was not rotated and tracked")
	}
	if _, err := os.Stat(old.Seal); err != nil {
		t.Fatal("deleted old seal", err)
	}
	t.Setenv("ESEC_AGE_IDENTITY", linux.String())
	plain, err := esec.ReadDocument(current, esec.ReadOptions{})
	if err != nil || !bytes.Contains(plain, []byte("synthetic-dev")) {
		t.Fatal("new Linux identity could not read unchanged secret", err)
	}
	editRecipients(t, root, "dev", []string{dev.Recipient().String(), recovery.Recipient().String()})
	plan, err = buildAccessPlan(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := (&ApplyCmd{Dir: root, Yes: true, PlanHash: plan.Hash}).Run(ctx); err == nil {
		t.Fatal("removal lacked extra approval")
	}
	t.Setenv("ESEC_AGE_IDENTITY", dev.String())
	if err := (&ApplyCmd{Dir: root, Yes: true, PlanHash: plan.Hash, ApproveSensitive: true}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	current, err = esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ESEC_AGE_IDENTITY", linux.String())
	if _, err := esec.ReadDocument(current, esec.ReadOptions{}); err == nil {
		t.Fatal("removed identity opened new generation")
	}
	t.Setenv("ESEC_AGE_IDENTITY", recovery.String())
	if _, err := esec.ReadDocument(current, esec.ReadOptions{}); err != nil {
		t.Fatal("lost recovery access", err)
	}
}

func TestDeclarativeCreationAndPlaintextConsent(t *testing.T) {
	root, dev, recovery, ctx := standaloneFixture(t)
	pf := &projectfile.File{Project: "test/app", Env: map[string]projectfile.Env{
		"dev":  {Access: "development", Recipients: []string{dev.Recipient().String(), recovery.Recipient().String()}},
		"test": {Access: "development", Recipients: []string{dev.Recipient().String(), recovery.Recipient().String()}},
	}}
	if err := pf.Save(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".env.test")
	if err := os.WriteFile(path, []byte("EXISTING=synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env.example"), []byte("NEVER_COPY=example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := buildAccessPlan(root, "")
	if err != nil {
		t.Fatal(err)
	}
	cmd := ApplyCmd{Dir: root, Yes: true, PlanHash: plan.Hash}
	if err := cmd.Run(ctx); err == nil {
		t.Fatal("encrypted plaintext without consent")
	}
	if _, err := os.Stat(filepath.Join(root, ".env.dev")); !os.IsNotExist(err) {
		t.Fatal("partially created environments")
	}
	cmd.EncryptExisting = true
	if err := cmd.Run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, env := range []string{"dev", "test"} {
		target, err := esec.ResolveRead(root, env, "")
		if err != nil {
			t.Fatal(err)
		}
		plain, err := esec.ReadDocument(target, esec.ReadOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(plain, []byte("NEVER_COPY")) {
			t.Fatal("copied example")
		}
		if env == "test" && !bytes.Contains(plain, []byte("EXISTING=synthetic")) {
			t.Fatal("lost existing plaintext")
		}
	}
	plan, err = buildAccessPlan(root, "")
	if err != nil || plan.changed() {
		t.Fatal("apply did not converge", err)
	}
}

func TestApplyPreparesEveryEnvironmentBeforeChangingFiles(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	if err := (&InitCmd{Dir: root, Env: "test", Yes: true}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(root, ".env.test")
	f, err := os.OpenFile(bad, os.O_APPEND|os.O_WRONLY, 0600) //nolint:gosec // synthetic fixture in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("BROKEN=ESEC[not-valid]\n")
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	pf, err := projectfile.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	newMachine, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range []string{"dev", "test"} {
		editRecipients(t, root, env, append(pf.Env[env].Recipients, newMachine.Recipient().String()))
	}
	before := map[string][]byte{}
	for _, name := range []string{"esec.toml", ".env.dev", ".env.test"} {
		data, err := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // bounded synthetic fixture files
		if err != nil {
			t.Fatal(err)
		}
		before[name] = data
	}
	plan, err := buildAccessPlan(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := (&ApplyCmd{Dir: root, Yes: true, PlanHash: plan.Hash}).Run(ctx); err == nil {
		t.Fatal("accepted corrupt encrypted value")
	}
	for name, want := range before {
		got, err := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // bounded synthetic fixture files
		if err != nil || !bytes.Equal(want, got) {
			t.Fatalf("partially modified %s", name)
		}
	}
}

func TestAppliedRecordIsAuthenticatedAndMissingDeclarationFails(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	target, err := esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	target.AppliedPolicy.Recipients = []string{other.Recipient().String()}
	data, err := json.Marshal(target.AppliedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seal.AccessRecordPath(root, "dev", target.PublicKey), data, 0600); err != nil {
		t.Fatal(err)
	}
	target, err = esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := esec.ReadDocument(target, esec.ReadOptions{}); err == nil || !strings.Contains(err.Error(), "authenticated policy") {
		t.Fatal("accepted tampered policy record", err)
	}
	pf, err := projectfile.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	delete(pf.Env, "dev")
	if err := pf.Save(root); err != nil {
		t.Fatal(err)
	}
	if _, err := buildAccessPlan(root, ""); err == nil {
		t.Fatal("ignored removed declaration with live sealed keys")
	}
}

func TestApplyRequiresReviewAndStatusReportsDrift(t *testing.T) {
	root, dev, _, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	editRecipients(t, root, "dev", []string{dev.Recipient().String()})
	if err := (&ApplyCmd{Dir: root, Yes: true}).Run(ctx); err == nil {
		t.Fatal("unreviewed noninteractive apply")
	}
	err := (&StatusCmd{Dir: root, Check: true}).Run(ctx)
	code, ok := commandExit(err)
	if !ok || code != 2 {
		t.Fatalf("status exit: %v", err)
	}
}

func TestProductionPoliciesSeparateDeveloperAndDeployment(t *testing.T) {
	_, dev, _, _ := standaloneFixture(t) //nolint:dogsled // only the synthetic developer identity is needed
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	yubi := plugin.EncodeRecipient("yubikey", []byte("synthetic-recipient"))
	deployment, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	e := projectfile.Env{Access: "production", Recipients: []string{yubi, dev.Recipient().String()}}
	if err := validateAccessPolicy("production", e, cfg); err == nil {
		t.Fatal("developer accepted in production")
	}
	e.Recipients = []string{deployment.Recipient().String()}
	if err := validateAccessPolicy("production", e, cfg); err == nil {
		t.Fatal("production without hardware")
	}
	e.Recipients = append(e.Recipients, yubi)
	if err := validateAccessPolicy("production", e, cfg); err != nil {
		t.Fatal(err)
	}
	pf := &projectfile.File{Env: map[string]projectfile.Env{"dev": {Access: "development", Recipients: []string{deployment.Recipient().String()}}}}
	if err := rejectDevelopmentRecipients(pf, "production", e.Access, e.Recipients); err == nil {
		t.Fatal("another developer machine reused as deployment")
	}
	if err := (&ApplyCmd{Yes: true, PlanHash: "reviewed"}).confirm(&AccessPlan{Environments: []EnvironmentPlan{{Sensitive: true}}}); err == nil {
		t.Fatal("production approval omitted")
	}
}

func TestCancelledApplyLeavesFilesUntouched(t *testing.T) {
	root, dev, _, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	editRecipients(t, root, "dev", []string{dev.Recipient().String()})
	path := filepath.Join(root, ".env.dev")
	before, err := os.ReadFile(path) //nolint:gosec // synthetic fixture in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	oldInteractive, oldInput := setupInteractive, os.Stdin
	t.Cleanup(func() { setupInteractive = oldInteractive; os.Stdin = oldInput })
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, err = w.WriteString("no\n")
	_ = w.Close()
	if err != nil {
		t.Fatal(err)
	}
	setupInteractive = func() bool { return true }
	os.Stdin = r
	if err := (&ApplyCmd{Dir: root}).Run(ctx); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatal("cancellation ignored", err)
	}
	after, err := os.ReadFile(path) //nolint:gosec // synthetic fixture in t.TempDir
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("cancelled mutation changed ciphertext")
	}
}
