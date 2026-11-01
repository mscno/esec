package esec

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/seal"
)

// ReadTarget is one resolved, immutable read. Content is ciphertext, never plaintext.
// The logical environment remains distinct from an environment sharing its key.
type ReadTarget struct {
	Project        string     `json:"project,omitempty"`
	Environment    string     `json:"environment"`
	Path           string     `json:"file"`
	Root           string     `json:"root,omitempty"`
	Format         FileFormat `json:"format"`
	PublicKey      string     `json:"public_key"`
	Digest         string     `json:"digest"`
	Guard          string     `json:"guard"`
	KeyEnvironment string     `json:"key_environment"`
	Seal           string     `json:"seal,omitempty"`
	SealStatus     string     `json:"seal_status"`
	Readers        []string   `json:"readers,omitempty"`
	Content        []byte     `json:"-"`
}

// ReadError is a stable, machine-readable failure with an actionable explanation.
type ReadError struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func (e *ReadError) Error() string { return e.Code + ": " + e.Detail }

// ResolveRead binds a filename or exact environment to its project, key and guard.
// It reads ciphertext once. No secret store, plugin, network or approval is touched.
func ResolveRead(dir, input, format string) (*ReadTarget, error) {
	var err error
	dir, input, err = explicitReadInput(dir, input)
	if err != nil {
		return nil, err
	}
	path, f, err := fileutils.Resolve(dir, input, format)
	if err != nil {
		code := "environment_invalid"
		if errors.Is(err, fileutils.ErrAmbiguous) {
			code = "environment_ambiguous"
		}
		if errors.Is(err, fileutils.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			code = "environment_missing"
		}
		return nil, &ReadError{code, err.Error()}
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, err := ExtractPublicKey(data, FileFormat(f))
	if err != nil {
		return nil, &ReadError{"invalid_file", err.Error()}
	}
	sum := sha256.Sum256(data)
	t := &ReadTarget{Path: path, Format: FileFormat(f), Content: data, PublicKey: hex.EncodeToString(pub[:]), Digest: hex.EncodeToString(sum[:]), Guard: "none", SealStatus: "absent"}
	pf, marker, err := projectfile.Find(filepath.Dir(path))
	if err != nil && !errors.Is(err, projectfile.ErrNotFound) {
		return nil, err
	}
	base := filepath.Dir(path)
	if pf != nil {
		t.Project = pf.Project
		t.Root = filepath.Dir(marker)
		base = t.Root
	}
	t.Environment, err = readEnvironment(base, path, string(f))
	if err != nil && pf == nil {
		t.Environment = fileutils.Environment(path)
		err = nil
	}
	if err != nil {
		return nil, err
	}
	t.KeyEnvironment = t.Environment
	if pf == nil {
		return t, nil
	}
	if err := t.applyProject(pf); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *ReadTarget) applyProject(pf *projectfile.File) error {
	// A shared public key cannot downgrade another environment's guard.
	for _, env := range pf.Envs() {
		e := pf.Env[env]
		if env != t.Environment && !strings.EqualFold(e.Key, t.PublicKey) {
			continue
		}
		if env == t.Environment && e.Key != "" && !strings.EqualFold(e.Key, t.PublicKey) {
			return &ReadError{"key_mismatch", "the file's public key differs from esec.toml for " + env}
		}
		if t.Seal == "" || (env == t.Environment && guardRank(e.GuardLevel()) >= guardRank(t.Guard)) {
			t.KeyEnvironment = env
			t.Seal = seal.Path(t.Root, env)
			t.Readers = e.Readers
		}
		if guardRank(e.GuardLevel()) > guardRank(t.Guard) {
			t.Guard = e.GuardLevel()
			t.KeyEnvironment = env
			t.Seal = seal.Path(t.Root, env)
			t.Readers = e.Readers
		}
	}
	if err := t.applyRecords(); err != nil {
		return err
	}

	if t.Seal == "" {
		t.Seal = seal.Path(t.Root, t.KeyEnvironment)
	}
	if _, err := os.Stat(t.Seal); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		t.Seal = ""
	} else if t.SealStatus == "absent" {
		t.SealStatus = "present_unverified"
	}
	return nil
}

func (t *ReadTarget) applyRecords() error {
	recs, err := seal.LoadRecords(t.Root)
	if err != nil {
		return err
	}
	for _, env := range sortedRecords(recs) {
		rec := recs[env]
		if rec == nil || (env != t.Environment && !strings.EqualFold(rec.Key, t.PublicKey)) {
			continue
		}
		if err := projectfile.ValidateGuard(rec.Guard); err != nil {
			return &ReadError{"invalid_seal_record", err.Error()}
		}
		if !strings.EqualFold(rec.Key, t.PublicKey) {
			return &ReadError{"key_mismatch", "seal record and file public keys differ"}
		}
		if err := rec.Verify(t.Project, env); err != nil {
			return &ReadError{"invalid_seal_record", err.Error()}
		}
		sealed, err := seal.Read(t.Root, env)
		if err != nil || seal.Hash(sealed) != rec.Sealed {
			return &ReadError{"invalid_seal_record", "sealed key missing or changed for " + env}
		}
		if guardRank(rec.Guard) > guardRank(t.Guard) {
			t.Guard = rec.Guard
			t.KeyEnvironment = env
			t.Seal = seal.Path(t.Root, env)
		}
		if env == t.KeyEnvironment {
			t.SealStatus = "signature_and_hash_verified"
		}
	}
	return nil
}

func sortedRecords(rs seal.Records) []string {
	out := make([]string, 0, len(rs))
	for k := range rs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func guardRank(g string) int {
	switch g {
	case "touch":
		return 2
	case "session":
		return 1
	}
	return 0
}

// readEnvironment reverses the configured filename patterns; it never guesses
// an environment from a public-key match. Custom subdirectories are supported.
func readEnvironment(root, path, format string) (string, error) {
	c, err := config.LoadDir(root)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", err
	}
	found := map[string]bool{}
	for _, p := range c.Files.Patterns {
		p = strings.ReplaceAll(p, "{format}", strings.TrimPrefix(format, "."))
		before, after, ok := strings.Cut(p, "{env}")
		if !ok || strings.Contains(after, "{env}") {
			continue
		}
		paths := []string{rel}
		if filepath.Base(p) == p {
			paths = append(paths, filepath.Base(path))
		}
		for _, candidate := range paths {
			if strings.HasPrefix(candidate, before) && strings.HasSuffix(candidate, after) && len(candidate) >= len(before)+len(after) {
				env := candidate[len(before) : len(candidate)-len(after)]
				if config.ValidateEnvironment(env) == nil {
					found[env] = true
				}
			}
		}
	}
	if filepath.Base(path) == format {
		found[""] = true
	}

	if len(found) != 1 {
		return "", &ReadError{"environment_ambiguous", "cannot map the file to one exact environment using its project's filename patterns"}
	}
	for env := range found {
		return env, nil
	}
	panic("unreachable")
}

func explicitReadInput(dir, input string) (string, string, error) {
	if _, err := fileutils.ParseFormat(input); err == nil {
		candidate := input
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(dir, candidate)
		}
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			return "", "", err
		}
		if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
			absolute = resolved
		}
		input = absolute
		dir = filepath.Dir(absolute)
	}
	return dir, input, nil
}
