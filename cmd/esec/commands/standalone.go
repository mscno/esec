package commands

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"filippo.io/age"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/filelock"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/seal"
)

// InitCmd creates standalone environments without replacing existing keys.
type InitCmd struct {
	Project          string   `help:"Project label, org/repo; defaults to the existing esec.toml"`
	Env              string   `required:"" help:"Comma-separated environments to create"`
	Dir              string   `default:"." type:"path" help:"Project directory"`
	Production       bool     `help:"Use production recipients even for a custom environment name"`
	MachineRecipient []string `help:"Explicit deployment recipients; never added to local identities"`
	NoRecovery       bool     `help:"Allow development without a YubiKey or offline recovery recipient"`
	EncryptExisting  bool     `help:"Explicitly adopt a plaintext dotenv file with no public key"`
	Yes              bool     `help:"Confirm creation without prompting"`
}

// Run creates and verifies encrypted files before publishing their metadata.
func (c *InitCmd) Run(ctx *cliCtx) error {
	if !c.Yes {
		return errors.New("pass --yes to create the requested environments; use --encrypt-existing to consent to encrypting existing plaintext")
	}
	root, err := filepath.Abs(c.Dir)
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	envs, err := parseEnvList(c.Env)
	if err != nil {
		return err
	}
	if len(envs) == 0 {
		return errors.New("name at least one environment")
	}
	if err := safeProjectPath(root, filepath.Join(root, ".esec")); err != nil {
		return err
	}
	release, err := filelock.Acquire(filepath.Join(root, ".esec"))
	if err != nil {
		return err
	}
	defer release()
	markerPath := filepath.Join(root, projectfile.ProjectFileName)
	markerBefore, err := snapshot(markerPath)
	if err != nil {
		return err
	}
	expected := map[string]sourceSnapshot{markerPath: markerBefore}
	pf, err := c.loadProject(root, cfg)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(root, ".esec", "pending")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("resolve .esec/pending with esec repair before creating environments")
	}
	var writes []pendingEnvironment
	for _, env := range envs {
		w, before, err := c.prepareEnvironment(ctx, root, env, pf, cfg)
		if err != nil {
			return err
		}
		expected[w.path] = before
		writes = append(writes, w)
	}
	// Persist every recovery seal before changing any secrets file.
	for _, w := range writes {
		if err := writeStandaloneSeal(root, w.env, w.pub, w.sealed); err != nil {
			return err
		}
	}
	changes := map[string][]byte{}
	for _, w := range writes {
		access := "development"
		if w.production {
			access = "production"
		}
		pf.Env[w.env] = projectfile.Env{Key: w.pub, Recipients: w.recipients, Access: access}
		changes[w.path] = w.data
	}
	marker, err := pf.Marshal()
	if err != nil {
		return err
	}
	changes[filepath.Join(root, projectfile.ProjectFileName)] = marker
	if err := applyCiphertextChanges(root, changes, expected); err != nil {
		return err
	}
	for _, w := range writes {
		say(ctx, "Created %s (%s); key sealed to %d recipients.", w.env, pf.Env[w.env].Access, len(w.recipients))
	}
	return nil
}

func isProduction(env string) bool {
	parts := strings.Split(env, ".")
	last := parts[len(parts)-1]
	return last == "prod" || last == "production"
}
func defaultRecipients(c config.Config, production bool, machines []string, noRecovery bool) ([]string, error) {
	var out []string
	if production {
		if len(c.Age.YubiKeyRecipients) == 0 {
			return nil, errors.New("configure an always-touch YubiKey with esec setup before creating production")
		}
		out = append(out, c.Age.YubiKeyRecipients...)
	} else {
		if c.Age.DeveloperRecipient == "" {
			return nil, errors.New("run esec setup to configure a developer identity")
		}
		out = append(out, c.Age.DeveloperRecipient)
		if len(c.Age.YubiKeyRecipients) > 0 {
			for _, r := range c.Age.YubiKeyRecipients {
				out = appendUnique(out, r)
			}
		}
		if !noRecovery && len(c.Age.YubiKeyRecipients) == 0 && len(c.Age.RecoveryRecipients) == 0 {
			return nil, errors.New("no recovery recipient configured; add a YubiKey/offline recipient with esec setup, or explicitly use --no-recovery")
		}
	}
	for _, r := range append(append([]string{}, c.Age.RecoveryRecipients...), machines...) {
		out = appendUnique(out, r)
	}
	for _, r := range out {
		if production && r == c.Age.DeveloperRecipient {
			return nil, errors.New("the everyday developer identity cannot be a production recipient")
		}
		if _, err := seal.ParseRecipient(r); err != nil {
			return nil, err
		}
	}
	return out, nil
}
func sealStandalone(project, env, priv string, recipients []string) ([]byte, error) {
	var rs []age.Recipient
	for _, s := range recipients {
		r, err := seal.ParseRecipient(s)
		if err != nil {
			return nil, err
		}
		rs = append(rs, r)
	}
	// Access is enforced by the actual age recipients. No daemon/session guard.
	return seal.Seal(seal.Payload{Project: project, Env: env, Private: priv, Guard: "none"}, rs...)
}
func encryptBytes(b []byte, f esec.FileFormat) ([]byte, error) {
	var out bytes.Buffer
	_, err := esec.Encrypt(bytes.NewReader(b), &out, f)
	return out.Bytes(), err
}

func writeStandaloneSeal(root, env, pub string, data []byte) error {
	p := seal.StandaloneKeyPath(root, env, pub)
	if err := safeProjectPath(root, p); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	// A new generation has a new public key. An old generation is never replaced.
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) //nolint:gosec // validated project path, immutable generation created exclusively
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(p)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

// safeProjectPath rejects symlink ancestors, including .esec and the destination.
func safeProjectPath(root, p string) error {
	rel, err := filepath.Rel(root, p)
	if err != nil || !filepath.IsLocal(rel) {
		return errors.New("path escapes project")
	}
	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		st, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink %s", current)
		}
	}
	return nil
}

// The journal contains new ciphertext plus hashes, never original plaintext.
// Repair accepts only the expected old bytes or already-published new bytes.
type sourceSnapshot struct {
	Hash   string
	Absent bool
	info   fs.FileInfo
}
type journalEntry struct {
	Before string `json:"before"`
	After  string `json:"after"`
	Absent bool   `json:"absent"`
}

func digest(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func snapshot(p string) (sourceSnapshot, error) {
	st, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return sourceSnapshot{Absent: true}, nil
	}
	if err != nil {
		return sourceSnapshot{}, err
	}
	if !st.Mode().IsRegular() {
		return sourceSnapshot{}, fmt.Errorf("not a regular file: %s", p)
	}
	b, err := os.ReadFile(p) //nolint:gosec // snapshot of a selected local project file
	if err != nil {
		return sourceSnapshot{}, err
	}
	return sourceSnapshot{Hash: digest(b), info: st}, nil
}
func (s sourceSnapshot) check(p string) error {
	now, err := snapshot(p)
	if err != nil {
		return err
	}
	if s.Absent != now.Absent || s.Hash != now.Hash || (!s.Absent && (!os.SameFile(s.info, now.info) || s.info.Mode() != now.info.Mode())) {
		return fmt.Errorf("%s changed during the operation; retry without editing it", p)
	}
	return nil
}
func validateJournalPath(rel string) error {
	if !filepath.IsLocal(rel) || filepath.Clean(rel) != rel {
		return errors.New("invalid journal path")
	}
	if rel == projectfile.ProjectFileName {
		return nil
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if strings.EqualFold(part, ".git") || strings.EqualFold(part, ".esec") {
			return errors.New("reserved journal destination")
		}
	}
	_, err := fileutils.ParseFormat(rel)
	return err
}
func applyCiphertextChanges(root string, changes map[string][]byte, expected map[string]sourceSnapshot) error {
	journal := filepath.Join(root, ".esec", "pending")
	if err := safeProjectPath(root, journal); err != nil {
		return err
	}
	for p := range changes {
		before, ok := expected[p]
		if !ok {
			return errors.New("missing original snapshot")
		}
		if err := before.check(p); err != nil {
			return err
		}
	}
	for p, before := range expected {
		if err := before.check(p); err != nil {
			return err
		}
	}
	if err := os.Mkdir(journal, 0700); err != nil {
		return fmt.Errorf("pending write exists; run esec repair: %w", err)
	}
	manifest := map[string]journalEntry{}
	for p, b := range changes {
		if err := safeProjectPath(root, p); err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if err := validateJournalPath(rel); err != nil {
			return err
		}
		target := filepath.Join(journal, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		if err := atomicFile(target, b, 0600); err != nil {
			return err
		}
		old := expected[p]
		manifest[rel] = journalEntry{Before: old.Hash, Absent: old.Absent, After: digest(b)}
	}
	for p := range expected {
		if err := expected[p].check(p); err != nil {
			return err
		}
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	// Publishing the manifest is the commit point for a recoverable transaction.
	if err := atomicFile(filepath.Join(journal, "manifest.json"), data, 0600); err != nil {
		return err
	}
	return finishPending(root)
}
func finishPending(root string) error {
	journal := filepath.Join(root, ".esec", "pending")
	if err := safeProjectPath(root, filepath.Join(journal, "manifest.json")); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(journal, "manifest.json")) //nolint:gosec // validated local transaction directory
	if err != nil {
		return errors.New("incomplete transaction: no files were replaced; preserve .esec/pending and investigate")
	}
	manifest := map[string]journalEntry{}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	if len(manifest) == 0 {
		return errors.New("empty transaction")
	}
	paths := make([]string, 0, len(manifest))
	content := map[string][]byte{}

	for rel, e := range manifest {
		b, err := readJournalCiphertext(journal, rel, e)
		if err != nil {
			return err
		}
		if err := checkJournalDestination(root, rel, e); err != nil {
			return err
		}
		paths = append(paths, rel)
		content[rel] = b
	}
	slices.SortFunc(paths, func(a, b string) int {
		if a == b {
			return 0
		}
		if a == projectfile.ProjectFileName {
			return 1
		}
		if b == projectfile.ProjectFileName {
			return -1
		}
		return strings.Compare(a, b)
	})
	for _, rel := range paths {
		if err := checkJournalDestination(root, rel, manifest[rel]); err != nil {
			return err
		}
		dest := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			return err
		}
		if err := atomicFile(dest, content[rel], 0600); err != nil {
			return err
		}
	}
	return os.RemoveAll(journal)
}
func atomicFile(p string, b []byte, mode fs.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(p), ".esec-write-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), p)
}

// RepairCmd completes an interrupted encrypted write.
type RepairCmd struct {
	Dir string `default:"." type:"path"`
}

// Run finishes a prepared ciphertext transaction.
func (c *RepairCmd) Run(ctx *cliCtx) error {
	root, err := filepath.Abs(c.Dir)
	if err != nil {
		return err
	}
	if err := safeProjectPath(root, filepath.Join(root, ".esec")); err != nil {
		return err
	}
	release, err := filelock.Acquire(filepath.Join(root, ".esec"))
	if err != nil {
		return err
	}
	defer release()
	if err := finishPending(root); err != nil {
		return err
	}
	say(ctx, "Completed the pending encrypted write.")
	return nil
}

// RecipientsCmd always rotates the Esec key. Removing recipients without
// rotation would leave copied old private keys valid for future values.
type RecipientsCmd struct {
	File   string   `arg:"" help:"Environment or encrypted file"`
	Add    []string `help:"Public age recipients to add"`
	Remove []string `help:"Public age recipients to remove (rotates the environment key)"`
}

// Run lists or updates environment recipients.
func (c *RecipientsCmd) Run(ctx *cliCtx) error {
	t, err := esec.ResolveRead(".", c.File, "")
	if err != nil {
		return err
	}
	if !t.Standalone {
		return errors.New("legacy environment: run esec adopt first")
	}
	if len(c.Add) == 0 && len(c.Remove) == 0 {
		for _, r := range t.Recipients {
			fmt.Println(r)
		}
		return nil
	}
	rs := slices.Clone(t.Recipients)
	for _, r := range c.Remove {
		rs = slices.DeleteFunc(rs, func(s string) bool { return s == r })
	}
	for _, r := range c.Add {
		rs = appendUnique(rs, r)
	}
	return rotateStandalone(ctx, t, rs)
}

// RotateCmd rekeys an existing standalone environment.
type RotateCmd struct {
	File string `arg:"" help:"Standalone environment to rotate"`
}

// Run rotates an environment key.
func (c *RotateCmd) Run(ctx *cliCtx) error {
	t, e := esec.ResolveRead(".", c.File, "")
	if e != nil {
		return e
	}
	if !t.Standalone {
		return errors.New("legacy environment: run esec adopt first")
	}
	return rotateStandalone(ctx, t, t.Recipients)
}

// AdoptCmd migrates an existing environment while preserving legacy recovery.
type AdoptCmd struct {
	File             string   `arg:"" help:"Existing environment to migrate with a new key"`
	MachineRecipient []string `help:"Explicit deployment recipients"`
	Production       bool     `help:"Treat this custom environment as production"`
	NoRecovery       bool     `help:"Allow development without an offline recovery recipient"`
}

// Run migrates a legacy environment.
func (c *AdoptCmd) Run(ctx *cliCtx) error {
	t, err := esec.ResolveRead(".", c.File, "")
	if err != nil {
		return err
	}
	if t.Standalone {
		return errors.New("already standalone; use esec rotate or esec recipients")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	production := c.Production || isProduction(t.Environment) || t.Guard != "none"
	rs, err := defaultRecipients(cfg, production, c.MachineRecipient, c.NoRecovery)
	if err != nil {
		return err
	}
	if production {
		t.Access = "production"
	} else {
		t.Access = "development"
	}
	return rotateStandalone(ctx, t, rs)
}

func rotateStandalone(ctx *cliCtx, t *esec.ReadTarget, rs []string) error {
	if err := validateRecipientChange(t, rs); err != nil {
		return err
	}
	if err := safeProjectPath(t.Root, filepath.Join(t.Root, ".esec")); err != nil {
		return err
	}
	release, err := filelock.Acquire(filepath.Join(t.Root, ".esec"))
	if err != nil {
		return err
	}
	defer release()
	if _, err := os.Stat(filepath.Join(t.Root, ".esec", "pending")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("resolve .esec/pending with esec repair before rotating")
	}
	if err := validateRotationTarget(t); err != nil {
		return err
	}
	markerPath := filepath.Join(t.Root, projectfile.ProjectFileName)
	fileBefore, err := snapshot(t.Path)
	if err != nil {
		return err
	}
	if fileBefore.Hash != t.Digest {
		return errors.New("file changed before rotation; retry")
	}
	markerBefore, err := snapshot(markerPath)
	if err != nil {
		return err
	}
	expected := map[string]sourceSnapshot{t.Path: fileBefore, markerPath: markerBefore}
	pub, priv, encrypted, err := rotatedCiphertext(t)
	if err != nil {
		return err
	}
	if err := rejectSharedFiles(t); err != nil {
		return err
	}
	pf, err := projectfile.Load(t.Root)
	if err != nil {
		return err
	}
	for env, e := range pf.Env {
		if env != t.Environment && e.Key == t.PublicKey {
			return errors.New("shared-key environment aliases require an explicit combined migration")
		}
	}
	sealed, err := sealStandalone(t.Project, t.Environment, priv, rs)
	if err != nil {
		return err
	}
	if err := writeStandaloneSeal(t.Root, t.Environment, pub, sealed); err != nil {
		return err
	}
	pf.Env[t.Environment] = projectfile.Env{Key: pub, Recipients: rs, Access: t.Access}
	marker, err := pf.Marshal()
	if err != nil {
		return err
	}
	if err := applyCiphertextChanges(t.Root, map[string][]byte{t.Path: encrypted, filepath.Join(t.Root, projectfile.ProjectFileName): marker}, expected); err != nil {
		return err
	}
	say(ctx, "Rotated %s to standalone age access (%d recipients). Historical seals and legacy caches were preserved; old application secrets must be rotated separately if exposed.", t.Environment, len(rs))
	return nil
}

type pendingEnvironment struct {
	env, path, pub string
	data, sealed   []byte
	recipients     []string
	production     bool
}

func (c *InitCmd) loadProject(root string, cfg config.Config) (*projectfile.File, error) {
	pf, err := projectfile.Load(root)
	if errors.Is(err, projectfile.ErrNotFound) {
		if err := projectfile.ValidateOrgRepo(c.Project); err != nil {
			return nil, err
		}
		format := strings.TrimPrefix(cfg.DefaultFormat, ".")
		name, err := derivedName(format, cfg.Files.Create, "")
		if err != nil {
			return nil, err
		}
		pf = &projectfile.File{Project: c.Project, Files: projectfile.Files{Format: format, Name: name}, Env: map[string]projectfile.Env{}}
	} else if err != nil {
		return nil, err
	}
	if c.Project != "" && c.Project != pf.Project {
		return nil, errors.New("--project differs from esec.toml")
	}
	if pf.Env == nil {
		pf.Env = map[string]projectfile.Env{}
	}
	return pf, nil
}

func (c *InitCmd) prepareEnvironment(ctx *cliCtx, root, env string, pf *projectfile.File, cfg config.Config) (w pendingEnvironment, before sourceSnapshot, err error) {
	if _, ok := pf.Env[env]; ok {
		return w, before, fmt.Errorf("environment %s already exists; use esec recipients or esec rotate", env)
	}
	production := c.Production || isProduction(env)
	recips, err := defaultRecipients(cfg, production, c.MachineRecipient, c.NoRecovery)
	if err != nil {
		return w, before, fmt.Errorf("%s: %w", env, err)
	}
	format := pf.FilesFormat()
	if format == "" {
		format = "env"
	}
	name := pf.Files.Name
	if name == "" {
		name = "." + format + ".{env}"
	}
	rel, err := config.Expand(name, env, format)
	if err != nil {
		return w, before, err
	}
	path := filepath.Join(root, rel)
	if err := safeProjectPath(root, path); err != nil {
		return w, before, err
	}
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		return w, before, err
	}
	before, err = snapshot(path)
	if err != nil {
		return w, before, err
	}
	body, err := c.initialPlaintext(ctx, path, format, pub)
	if err != nil {
		return w, before, err
	}
	encrypted, err := encryptBytes(body, esec.FileFormat("."+format))
	if err != nil {
		return w, before, err
	}
	var verified bytes.Buffer
	if _, err := esec.Decrypt(bytes.NewReader(encrypted), &verified, env, esec.FileFormat("."+format), "", priv); err != nil {
		return w, before, err
	}
	if !bytes.Equal(verified.Bytes(), body) {
		return w, before, errors.New("new environment failed round-trip verification; existing file was not changed")
	}
	sealed, err := sealStandalone(pf.Project, env, priv, recips)
	if err != nil {
		return w, before, err
	}

	w = pendingEnvironment{env, path, pub, encrypted, sealed, recips, production}
	return w, before, nil
}

func (c *InitCmd) initialPlaintext(ctx *cliCtx, path, format, pub string) ([]byte, error) {
	body := []byte(skeleton(format, pub))
	existing, err := os.ReadFile(path) //nolint:gosec // validated project destination
	if err == nil {
		if _, e := esec.ExtractPublicKey(existing, esec.FileFormat("."+format)); e == nil {
			return nil, fmt.Errorf("%s already has an Esec public key; use esec adopt to rotate and seal its key without losing values", path)
		}
		if format != "env" || bytes.Contains(existing, []byte("ESEC[")) {
			return nil, fmt.Errorf("%s is not an unencrypted dotenv file without a public key; not changed", path)
		}
		if !c.EncryptExisting {
			return nil, fmt.Errorf("%s is plaintext; rerun with --encrypt-existing to add a new public key and encrypt its existing values", path)
		}
		normalized, changed, err := normalizeInitDotenv(existing)
		if err != nil {
			return nil, err
		}
		if changed {
			say(ctx, "Normalized multiline dotenv entries to single lines; comments were removed and values preserved.")
		}
		body = append([]byte("ESEC_PUBLIC_KEY="+pub+"\n"), normalized...)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	return body, nil
}

func rejectSharedFiles(t *esec.ReadTarget) error {
	return filepath.WalkDir(t.Root, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			if p != t.Root && (d.Name() == ".git" || d.Name() == ".esec" || d.Name() == "node_modules" || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || p == t.Path {
			return nil
		}
		f, e := fileutils.ParseFormat(p)
		if e != nil {
			return nil //nolint:nilerr // unrelated file formats cannot share an Esec file key
		}
		b, e := os.ReadFile(p) //nolint:gosec // regular file found while scanning this project
		if e != nil {
			return e
		}
		key, e := esec.ExtractPublicKey(b, esec.FileFormat(f))
		if e == nil && hex.EncodeToString(key[:]) == t.PublicKey {
			return fmt.Errorf("another file uses this key: %s; migrate shared-key files together before retiring Vault", p)
		}
		return nil
	})
}

func rotatedCiphertext(t *esec.ReadTarget) (pub, priv string, encrypted []byte, err error) {
	// Ask the normal reader to decrypt: legacy hardware protection is honored.
	plain, err := esec.ReadDocument(t, esec.ReadOptions{})
	if err != nil {
		return "", "", nil, err
	}
	pub, priv, err = esec.GenerateKeypair()
	if err != nil {
		return "", "", nil, err
	}
	// Refuse ambiguous textual replacement instead of modifying an unrelated value.
	if bytes.Count(bytes.ToLower(plain), []byte(t.PublicKey)) != 1 {
		return "", "", nil, errors.New("public key must appear exactly once in the plaintext before rotation")
	}
	replaced := bytes.Replace(plain, []byte(t.PublicKey), []byte(pub), 1)
	encrypted, err = encryptBytes(replaced, t.Format)
	if err != nil {
		return "", "", nil, err
	}
	var verified bytes.Buffer
	if _, err := esec.Decrypt(bytes.NewReader(encrypted), &verified, t.Environment, t.Format, "", priv); err != nil {
		return "", "", nil, err
	}
	if !bytes.Equal(verified.Bytes(), replaced) {
		return "", "", nil, errors.New("rotated file failed round-trip verification")
	}

	return pub, priv, encrypted, nil
}

func validateRotationTarget(t *esec.ReadTarget) error {
	fresh, err := esec.ResolveRead(t.Root, t.Path, "")
	if err != nil {
		return err
	}
	if fresh.Digest != t.Digest || fresh.PublicKey != t.PublicKey || fresh.Standalone != t.Standalone || !slices.Equal(fresh.Recipients, t.Recipients) || fresh.Guard != t.Guard || (t.Standalone && fresh.Access != t.Access) {
		return errors.New("file or recipient configuration changed before rotation; retry")
	}

	return nil
}

func checkJournalDestination(root, rel string, e journalEntry) error {
	dest := filepath.Join(root, rel)
	if err := safeProjectPath(root, dest); err != nil {
		return err
	}
	now, err := snapshot(dest)
	if err != nil {
		return err
	}
	if (now.Absent && e.Absent) || (!now.Absent && (now.Hash == e.Before || now.Hash == e.After)) {
		return nil
	}
	return fmt.Errorf("%s changed since the transaction began; repair refused to overwrite it", rel)
}

func readJournalCiphertext(journal, rel string, e journalEntry) ([]byte, error) {
	if err := validateJournalPath(rel); err != nil {
		return nil, err
	}
	src := filepath.Join(journal, rel)
	if err := safeProjectPath(journal, src); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(src) //nolint:gosec // validated journal-relative ciphertext path
	if err != nil {
		return nil, err
	}
	if digest(b) != e.After {
		return nil, errors.New("transaction ciphertext changed")
	}
	if rel == projectfile.ProjectFileName {
		if _, err := projectfile.Parse(b); err != nil {
			return nil, err
		}
	} else {
		f, _ := fileutils.ParseFormat(rel)
		if _, err := esec.ExtractPublicKey(b, esec.FileFormat(f)); err != nil {
			return nil, errors.New("transaction secrets file has no public key")
		}
	}

	return b, nil
}

func validateRecipientChange(t *esec.ReadTarget, rs []string) error {
	if len(rs) == 0 {
		return errors.New("at least one recipient must remain")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	for _, r := range rs {
		if _, err := seal.ParseRecipient(r); err != nil {
			return err
		}
		if t.Access == "production" && r == cfg.Age.DeveloperRecipient {
			return errors.New("refusing to grant the everyday developer identity production access")
		}
	}

	return nil
}
