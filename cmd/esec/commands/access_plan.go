package commands

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/filelock"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/seal"
)

// AccessPlan is public review metadata, never a decrypted document.
type AccessPlan struct {
	Project      string            `json:"project"`
	Hash         string            `json:"hash"`
	Environments []EnvironmentPlan `json:"environments"`
	root         string
	project      *projectfile.File
	expected     map[string]sourceSnapshot
	targets      map[string]*esec.ReadTarget
}

// EnvironmentPlan describes one public recipient change.
type EnvironmentPlan struct {
	Environment        string   `json:"environment"`
	File               string   `json:"file"`
	Action             string   `json:"action"`
	Access             string   `json:"access"`
	Added              []string `json:"added"`
	Removed            []string `json:"removed"`
	Recipients         []string `json:"recipients"`
	SoftwareRecipients []string `json:"software_recipients,omitempty"`
	Sensitive          bool     `json:"sensitive"`
	Plaintext          bool     `json:"plaintext,omitempty"`
}

// PlanCmd previews public access changes.
type PlanCmd struct {
	Dir  string `default:"." type:"path" help:"Project directory"`
	Env  string `help:"Comma-separated environments; default: all"`
	JSON bool   `help:"Print the public plan and its approval hash as JSON"`
}

// Run prints a plan without decrypting any key.
func (c *PlanCmd) Run(_ *cliCtx) error {
	p, err := buildAccessPlan(c.Dir, c.Env)
	if err != nil {
		return err
	}
	return printAccessPlan(p, c.JSON)
}

// StatusCmd reports unapplied access changes.
type StatusCmd struct {
	Dir   string `default:"." type:"path" help:"Project directory"`
	Env   string `help:"Comma-separated environments; default: all"`
	JSON  bool   `help:"Print public access status as JSON"`
	Check bool   `help:"Exit 2 if any environment needs creation, migration, or application"`
}

// Run optionally returns a nonzero exit code for drift.
func (c *StatusCmd) Run(_ *cliCtx) error {
	p, err := buildAccessPlan(c.Dir, c.Env)
	if err != nil {
		return err
	}
	if err := printAccessPlan(p, c.JSON); err != nil {
		return err
	}
	if c.Check && p.changed() {
		return &ExitError{Code: 2}
	}
	return nil
}

func (p *AccessPlan) changed() bool {
	for _, e := range p.Environments {
		if e.Action != "current" {
			return true
		}
	}
	return false
}

func validateAccessPolicy(env string, e projectfile.Env, cfg config.Config) error {
	if e.Access != "development" && e.Access != "production" {
		return fmt.Errorf("%s: set access = development or production in esec.toml", env)
	}
	if isProduction(env) && e.Access != "production" {
		return fmt.Errorf("%s: production environments cannot use development access", env)
	}
	if len(e.Recipients) == 0 {
		return fmt.Errorf("%s: at least one public age recipient is required", env)
	}
	hardware := false
	for _, r := range e.Recipients {
		if _, err := seal.ParseRecipient(r); err != nil {
			return fmt.Errorf("%s: invalid recipient: %w", env, err)
		}
		if strings.HasPrefix(r, "age1yubikey1") {
			hardware = true
		}
		if e.Access == "production" && r == cfg.Age.DeveloperRecipient {
			return fmt.Errorf("%s: the everyday developer identity cannot be a production recipient", env)
		}
	}
	if e.Access == "production" && !hardware {
		return fmt.Errorf("%s: production requires a YubiKey recipient; software recipients are additional deployment identities", env)
	}
	return nil
}

func newAccessPlan(dir string) (*AccessPlan, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	_, marker, err := projectfile.Find(root)
	if err != nil {
		return nil, err
	}
	root = filepath.Dir(marker)
	markerBefore, err := snapshot(marker)
	if err != nil {
		return nil, err
	}
	markerData, err := os.ReadFile(marker) //nolint:gosec // selected project marker
	if err != nil {
		return nil, err
	}
	if digest(markerData) != markerBefore.Hash {
		return nil, errors.New("esec.toml changed while planning; retry")
	}
	pf, err := projectfile.Parse(markerData)
	if err != nil {
		return nil, err
	}
	if err := safeProjectPath(root, filepath.Join(root, ".esec")); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(root, ".esec", "pending")); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("a pending write needs attention; run esec repair before planning access changes")
	}
	if unknown := pf.Unknown(); len(unknown) > 0 {
		return nil, fmt.Errorf("unknown esec.toml fields: %s", strings.Join(unknown, ", "))
	}
	p := &AccessPlan{Project: pf.Project, root: root, project: pf, expected: map[string]sourceSnapshot{}, targets: map[string]*esec.ReadTarget{}, Environments: []EnvironmentPlan{}}
	p.expected[marker] = markerBefore
	return p, nil
}

func buildAccessPlan(dir, selection string) (*AccessPlan, error) {
	p, err := newAccessPlan(dir)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	envs, err := parseEnvList(selection)
	if err != nil {
		return nil, err
	}
	if len(envs) == 0 {
		envs = p.project.Envs()
	}
	slices.Sort(envs)
	for _, name := range envs {
		item, err := p.planEnvironment(name, cfg)
		if err != nil {
			return nil, err
		}
		p.Environments = append(p.Environments, item)
	}
	if selection == "" {
		if err := p.checkDeclarations(); err != nil {
			return nil, err
		}
	}
	for path, before := range p.expected {
		if err := before.check(path); err != nil {
			return nil, err
		}
	}
	hashes := map[string]string{}
	for path, s := range p.expected {
		rel, _ := filepath.Rel(p.root, path)
		hashes[rel] = s.Hash
		if s.Absent {
			hashes[rel] = "absent"
		}
	}
	data, err := json.Marshal(struct {
		Project      string            `json:"project"`
		Environments []EnvironmentPlan `json:"environments"`
		Inputs       map[string]string `json:"inputs"`
	}{p.Project, p.Environments, hashes})
	if err != nil {
		return nil, err
	}
	p.Hash = digest(data)
	return p, nil
}

func (p *AccessPlan) planEnvironment(name string, cfg config.Config) (EnvironmentPlan, error) {
	e, ok := p.project.Env[name]
	item := EnvironmentPlan{Environment: name, Access: e.Access, Recipients: seal.CanonicalRecipients(e.Recipients), Added: []string{}, Removed: []string{}}
	if !ok {
		return item, fmt.Errorf("environment %s is absent from esec.toml", name)
	}
	if len(e.Recipients) == 0 && e.Key != "" {
		item.Action = "legacy"
		return item, nil
	}
	if err := validateAccessPolicy(name, e, cfg); err != nil {
		return item, err
	}
	if err := rejectDevelopmentRecipients(p.project, name, e.Access, e.Recipients); err != nil {
		return item, err
	}
	for _, r := range item.Recipients {
		if !strings.HasPrefix(r, "age1yubikey1") {
			item.SoftwareRecipients = append(item.SoftwareRecipients, r)
		}
	}
	if e.Key == "" {
		if err := p.planCreation(&item); err != nil {
			return item, err
		}
	} else {
		if err := p.planExisting(&item); err != nil {
			return item, err
		}
	}
	item.Sensitive = item.Action != "current" && (e.Access == "production" || len(item.Removed) > 0 || item.Action == "untracked")
	return item, nil
}

func (p *AccessPlan) planCreation(item *EnvironmentPlan) error {
	format := p.project.FilesFormat()
	if format == "" {
		format = "env"
	}
	pattern := p.project.Files.Name
	if pattern == "" {
		pattern = "." + format + ".{env}"
	}
	rel, err := config.Expand(pattern, item.Environment, format)
	if err != nil {
		return err
	}
	item.File = rel
	path := filepath.Join(p.root, rel)
	if err := p.track(path); err != nil {
		return err
	}
	if !p.expected[path].Absent {
		data, err := os.ReadFile(path) //nolint:gosec // tracked regular file within the project
		if err != nil {
			return err
		}
		if _, err := esec.ExtractPublicKey(data, esec.FileFormat("."+format)); err == nil {
			return fmt.Errorf("%s already has an encryption key; recover its original metadata and use esec adopt", rel)
		}
		if format != "env" || strings.Contains(string(data), "ESEC[") {
			return fmt.Errorf("%s is not a plaintext dotenv file; refusing to replace it", rel)
		}
		item.Plaintext = true
	}
	item.Action = "create"
	item.Added = slices.Clone(item.Recipients)
	return nil
}

func (p *AccessPlan) planExisting(item *EnvironmentPlan) error {
	name := item.Environment
	key := p.project.Env[name].Key
	for _, path := range []string{seal.StandaloneKeyPath(p.root, name, key), seal.AccessRecordPath(p.root, name, key)} {
		if err := p.track(path); err != nil {
			return err
		}
	}
	t, err := esec.ResolveRead(p.root, name, "")
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if !t.Standalone {
		return fmt.Errorf("%s requires esec adopt before declarative access changes", name)
	}
	p.targets[name] = t
	item.File, _ = filepath.Rel(p.root, t.Path)
	if err := p.track(t.Path); err != nil {
		return err
	}
	if p.expected[t.Path].Hash != t.Digest {
		return errors.New("encrypted file changed while planning; retry")
	}

	item.Action = t.PolicyStatus
	if t.PolicyStatus == "untracked" {
		item.Added = slices.Clone(item.Recipients)
	}
	if applied := t.AppliedPolicy; applied != nil {
		if applied.Access == "production" && item.Access != "production" {
			return fmt.Errorf("%s: production access cannot be downgraded by editing esec.toml", name)
		}
		item.Added = recipientDifference(item.Recipients, applied.Recipients)
		item.Removed = recipientDifference(applied.Recipients, item.Recipients)
	}
	return nil
}

func (p *AccessPlan) checkDeclarations() error {
	entries, err := os.ReadDir(filepath.Join(p.root, ".esec", "keys"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			if _, ok := p.project.Env[entry.Name()]; !ok {
				return fmt.Errorf("sealed environment %s is missing from esec.toml; restore its declaration before applying (deleting a declaration does not revoke access)", entry.Name())
			}
		}
	}
	return nil
}

// Known development identities must never be silently reused for deployment.
func rejectDevelopmentRecipients(pf *projectfile.File, env, access string, rs []string) error {
	if access != "production" {
		return nil
	}
	for name, e := range pf.Env {
		if name == env || e.Access != "development" {
			continue
		}
		for _, r := range rs {
			if !strings.HasPrefix(r, "age1yubikey1") && slices.Contains(e.Recipients, r) {
				return fmt.Errorf("%s: a software recipient already used by development environment %s cannot be a production deployment identity; create a separate identity", env, name)
			}
		}
	}
	return nil
}

func (p *AccessPlan) track(path string) error {
	if err := safeProjectPath(p.root, path); err != nil {
		return err
	}
	s, err := snapshot(path)
	if err != nil {
		return err
	}
	p.expected[path] = s
	return nil
}

func recipientDifference(a, b []string) []string {
	out := []string{}
	for _, r := range seal.CanonicalRecipients(a) {
		if !slices.Contains(b, r) {
			out = append(out, r)
		}
	}
	return out
}

func printAccessPlan(p *AccessPlan, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(p)
	}
	fmt.Printf("Project: %s\n", p.Project)
	for _, e := range p.Environments {
		fmt.Printf("%s: %s (%s)\n", e.Environment, e.Action, e.Access)
		for _, r := range e.Added {
			fmt.Printf("  + %s\n", r)
		}
		for _, r := range e.Removed {
			fmt.Printf("  - %s\n", r)
		}
		if e.Action == "legacy" {
			fmt.Printf("  Use esec adopt %s with existing local recovery access first.\n", e.Environment)
		}
		if e.Plaintext {
			fmt.Println("  Existing plaintext requires --encrypt-existing.")
		}
		if e.Action == "untracked" {
			fmt.Println("  Previous recipients cannot be verified from public metadata; all requested recipients will be applied with a new key.")
		}
		if e.Access == "production" && len(e.SoftwareRecipients) > 0 {
			fmt.Println("  Software deployment recipients can decrypt without YubiKey touch:")
			for _, r := range e.SoftwareRecipients {
				fmt.Printf("    %s\n", r)
			}
		}
		if len(e.Removed) > 0 {
			fmt.Println("  Removal rotates the key; old commits and previously copied secrets remain readable.")
		}
	}
	fmt.Printf("Plan hash: %s\n", p.Hash)
	return nil
}

// ApplyCmd applies an explicitly reviewed access plan.
type ApplyCmd struct {
	Dir              string `default:"." type:"path" help:"Project directory"`
	Env              string `help:"Comma-separated environments; default: all"`
	PlanHash         string `help:"Require the exact hash printed by esec plan (required with --yes)"`
	Yes              bool   `help:"Apply a reviewed plan without prompting; requires --plan-hash"`
	ApproveSensitive bool   `help:"With --yes, explicitly approve production, removals, and untracked generations"`
	EncryptExisting  bool   `help:"Allow creation to encrypt an existing plaintext dotenv file"`
}

// Run confirms the plan and commits verified ciphertext changes.
func (c *ApplyCmd) Run(ctx *cliCtx) error {
	p, err := buildAccessPlan(c.Dir, c.Env)
	if err != nil {
		return err
	}
	if c.PlanHash != "" && c.PlanHash != p.Hash {
		return errors.New("plan is stale; run esec plan and review the current changes")
	}
	if !p.changed() {
		say(ctx, "All configured access is already applied.")
		return nil
	}
	for _, e := range p.Environments {
		if e.Action == "legacy" {
			return fmt.Errorf("%s needs esec adopt with offline recovery access first", e.Environment)
		}
		if e.Plaintext && !c.EncryptExisting {
			return fmt.Errorf("%s is plaintext; pass --encrypt-existing only after reviewing esec plan", e.File)
		}
	}
	if err := printAccessPlan(p, false); err != nil {
		return err
	}
	if err := c.confirm(p); err != nil {
		return err
	}
	release, err := filelock.Acquire(filepath.Join(p.root, ".esec"))
	if err != nil {
		return err
	}
	defer release()
	fresh, err := buildAccessPlan(p.root, c.Env)
	if err != nil {
		return err
	}
	if fresh.Hash != p.Hash {
		return errors.New("files or policy changed after confirmation; review a fresh plan")
	}
	return applyAccessPlan(ctx, fresh, c.EncryptExisting)
}

func (c *ApplyCmd) confirm(p *AccessPlan) error {
	sensitive := false
	for _, e := range p.Environments {
		sensitive = sensitive || e.Sensitive
	}
	if c.Yes {
		if c.PlanHash == "" {
			return errors.New("--yes requires --plan-hash from a reviewed esec plan")
		}
		if sensitive && !c.ApproveSensitive {
			return errors.New("production, recipient removal, or untracked access requires --approve-sensitive with --yes")
		}
		return nil
	}
	if !setupInteractive() {
		return errors.New("confirmation requires a terminal; scripts need --yes --plan-hash and, for sensitive changes, --approve-sensitive")
	}
	want := "yes"
	if sensitive {
		want = "apply " + p.Project
	}
	fmt.Fprintf(os.Stderr, "Type %q to apply these access changes: ", want)
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(answer) != want {
		return errors.New("cancelled; files unchanged")
	}
	return nil
}

func applyAccessPlan(ctx *cliCtx, p *AccessPlan, encryptExisting bool) error {
	var writes []pendingEnvironment
	for _, e := range p.Environments {
		if e.Action == "current" {
			continue
		}
		if e.Action == "create" {
			c := InitCmd{EncryptExisting: encryptExisting}
			w, _, err := c.prepareConfiguredEnvironment(ctx, p.root, e.Environment, p.project, e.Access == "production", e.Recipients)
			if err != nil {
				return err
			}
			writes = append(writes, w)
			continue
		}
		t := p.targets[e.Environment]
		if err := rejectSharedFiles(t); err != nil {
			return err
		}
		for name, other := range p.project.Env {
			if name != e.Environment && other.Key == t.PublicKey {
				return errors.New("shared-key aliases require a combined offline migration")
			}
		}
		pub, priv, encrypted, err := rotatedCiphertext(t)
		if err != nil {
			return err
		}
		sealed, err := sealStandalone(p.Project, e.Environment, priv, e.Access, e.Recipients)
		if err != nil {
			return err
		}
		writes = append(writes, pendingEnvironment{env: e.Environment, path: t.Path, pub: pub, data: encrypted, sealed: sealed, recipients: e.Recipients, production: e.Access == "production"})
	}
	// No active file is changed until every environment has been prepared and verified.
	for path, before := range p.expected {
		if err := before.check(path); err != nil {
			return err
		}
	}
	changes := map[string][]byte{}
	for _, w := range writes {
		access := accessName(w.production)
		if err := writeStandaloneGeneration(p.root, p.Project, w.env, w.pub, access, w.recipients, w.sealed); err != nil {
			return err
		}
		p.project.Env[w.env] = projectfile.Env{Key: w.pub, Recipients: w.recipients, Access: access}
		changes[w.path] = w.data
	}
	marker, err := p.project.Marshal()
	if err != nil {
		return err
	}
	changes[filepath.Join(p.root, projectfile.ProjectFileName)] = marker
	if err := applyCiphertextChanges(p.root, changes, p.expected); err != nil {
		return err
	}
	say(ctx, "Applied %d environment(s). Verify access, then commit esec.toml, the encrypted files, and .esec/keys/ together.", len(writes))
	return nil
}
