// Package projectfile reads and writes esec.toml, the committed project file.
//
// esec.toml names the project ("org/repo") and, optionally, how its secrets
// files are named and which environments it has, with each environment's
// current public key and how its private key is guarded. It holds no secret.
// Tooling uses the project id to locate project-scoped resources, such as
// keyrings in the global keyring store
// (~/.config/esec/keyrings/<org>_<repo>.keyring).
//
//	project = "acme/store"
//
//	[files]
//	format = "env"
//	name = ".env.{env}"
//
//	[env.dev]
//	key = "a1b2…"
//
//	[env.prod]
//	key = "c3d4…"
//	guard = "touch"
package projectfile

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// ProjectFileName is the name of the project file.
const ProjectFileName = "esec.toml"

// Guard levels: how an environment's private key is protected on devices.
const (
	// GuardNone keeps the key in the keyring; tools read it directly.
	GuardNone = "none"
	// GuardSession wraps the key to the hardware guard; one touch unlocks it
	// for a broker session.
	GuardSession = "session"
	// GuardTouch wraps the key to the hardware guard; every read needs a touch.
	GuardTouch = "touch"
)

var projectFormatRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+(/[a-zA-Z0-9._-]+)*$`)

// ErrNotFound is returned when no project file can be found.
var ErrNotFound = errors.New("project file not found")

// File is the content of esec.toml.
type File struct {
	Project string `toml:"project"`
	// Requires is the oldest esec that may work with this project, such as
	// ">= 0.14" (CheckRequires). Older versions cannot enforce it: they list
	// it as unknown and carry on.
	Requires string         `toml:"requires,omitempty"`
	Files    Files          `toml:"files,omitempty"`
	Env      map[string]Env `toml:"env,omitempty"`

	// raw and orig are the file as read, so Save changes only what changed
	// and keeps comments and layout.
	raw  []byte
	orig *File
	// unknown are keys this version does not know, ignored.
	unknown []string
}

// Unknown returns the keys in the file this version of esec does not know
// (from a newer version, or a typo). They are ignored.
func (f *File) Unknown() []string { return f.unknown }

// Files says how the project's secrets files are named. Empty fields fall
// back to the shared esec configuration.
type Files struct {
	// Format is env, ejson, eyaml, eyml or etoml.
	Format string `toml:"format,omitempty"`
	// Name is the filename pattern, such as ".env.{env}" or "{env}.etoml".
	Name string `toml:"name,omitempty"`
}

// Env describes one environment.
type Env struct {
	// Key is the environment's current public key (64 lowercase hex).
	Key string `toml:"key,omitempty"`
	// Guard is none (the default), session or touch.
	Guard string `toml:"guard,omitempty"`
	// Readers are who the environment's key is sealed to, in .esec/: people
	// ("mads (gh:583231)"), groups ("group acme/backend") and keys
	// ("deploy (age1…)"). esec vault writes it; the seal is the authority.
	Readers []string `toml:"readers,omitempty"`
}

// Equal reports whether two environments say the same.
func (e Env) Equal(o Env) bool {
	return e.Key == o.Key && e.Guard == o.Guard && slices.Equal(e.Readers, o.Readers)
}

// GuardLevel returns the environment's guard, none when unset.
func (e Env) GuardLevel() string {
	if e.Guard == "" {
		return GuardNone
	}
	return e.Guard
}

// ValidateOrgRepo checks if the project identifier conforms to the project
// format: 'org/repo', optionally with path segments for monorepo subprojects
// ('org/repo/services/registry').
func ValidateOrgRepo(orgRepo string) error {
	if !projectFormatRegex.MatchString(orgRepo) {
		return fmt.Errorf("invalid project format: must be 'org/repo[/path...]'")
	}
	// Reject dot-only segments; they carry path semantics.
	for _, seg := range strings.Split(orgRepo, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("invalid project format: must be 'org/repo[/path...]'")
		}
	}
	return nil
}

// ValidateGuard checks a guard level; empty means none.
func ValidateGuard(g string) error {
	switch g {
	case "", GuardNone, GuardSession, GuardTouch:
		return nil
	}
	return fmt.Errorf("invalid guard %q: use none, session or touch", g)
}

// validEnv reports whether env is dot-separated lowercase letters and digits.
func validEnv(env string) bool {
	if env == "" {
		return false
	}
	for _, s := range strings.Split(env, ".") {
		if s == "" {
			return false
		}
		for _, r := range s {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return false
			}
		}
	}
	return true
}

// Validate checks the whole file.
func (f *File) Validate() error {
	if err := ValidateOrgRepo(f.Project); err != nil {
		return err
	}
	switch strings.TrimPrefix(f.Files.Format, ".") {
	case "", "env", "ejson", "eyaml", "eyml", "etoml":
	default:
		return fmt.Errorf("invalid files.format %q: use env, ejson, eyaml, eyml or etoml", f.Files.Format)
	}
	if n := f.Files.Name; n != "" {
		if !strings.Contains(n, "{env}") || !filepath.IsLocal(n) || strings.ContainsAny(n, "*?[]\\\x00\r\n") {
			return fmt.Errorf("invalid files.name %q: a relative filename with {env}, such as .env.{env}", n)
		}
		named := NameFormat(n)
		if named == "" {
			return fmt.Errorf("invalid files.name %q: it must show the format, as in .env.{env}, .ejson.{env} or {env}.etoml", n)
		}
		if format := strings.TrimPrefix(f.Files.Format, "."); format != "" && format != named {
			return fmt.Errorf("files.name %q is a %s file but files.format is %s", n, named, format)
		}
	}
	for name, e := range f.Env {
		if err := e.validate(name); err != nil {
			return err
		}
	}
	return nil
}

// validate checks one environment of the file.
func (e Env) validate(name string) error {
	if !validEnv(name) {
		return fmt.Errorf("invalid environment %q: use dot-separated lowercase letters and digits", name)
	}
	if e.Key != "" {
		if raw, err := hex.DecodeString(e.Key); err != nil || len(raw) != 32 || strings.ToLower(e.Key) != e.Key {
			return fmt.Errorf("environment %s: key must be 64 lowercase hex characters", name)
		}
	}
	if err := ValidateGuard(e.Guard); err != nil {
		return fmt.Errorf("environment %s: %w", name, err)
	}
	for _, r := range e.Readers {
		if strings.TrimSpace(r) == "" || strings.ContainsAny(r, "\"\\\x00\r\n") || len(r) > 4096 {
			return fmt.Errorf("environment %s: invalid reader %q", name, r)
		}
	}
	return nil
}

// NameFormat returns the format a files.name pattern names (env of
// ".env.{env}", etoml of "{env}.etoml"), or "" if it names none.
func NameFormat(name string) string {
	base := filepath.Base(name)
	for _, f := range []string{"ejson", "eyaml", "eyml", "etoml", "env"} {
		if base == "."+f || strings.HasPrefix(base, "."+f+".") || strings.HasSuffix(base, "."+f) {
			return f
		}
	}
	return ""
}

// FilesFormat returns the project's file format: files.format, or the one
// files.name shows. It is "" when the project sets neither.
func (f *File) FilesFormat() string {
	if format := strings.TrimPrefix(f.Files.Format, "."); format != "" {
		return format
	}
	return NameFormat(f.Files.Name)
}

// Envs returns the environment names in order.
func (f *File) Envs() []string {
	out := make([]string, 0, len(f.Env))
	for name := range f.Env {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// SetEnv records an environment's public key, keeping its guard.
func (f *File) SetEnv(name, pub string) {
	if f.Env == nil {
		f.Env = map[string]Env{}
	}
	e := f.Env[name]
	e.Key = pub
	f.Env[name] = e
}

// KeyringName converts a project identifier ("org/repo") into a flat file
// name ("org_repo.keyring") suitable for the global keyring store.
func KeyringName(orgRepo string) string {
	return strings.ReplaceAll(orgRepo, "/", "_") + ".keyring"
}

// Parse decodes and validates esec.toml content. Keys it does not know are
// ignored and listed by Unknown, so a file written by a newer esec still
// works with an older one.
func Parse(data []byte) (*File, error) {
	var f File
	var strict *toml.StrictMissingError
	err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&f)
	if errors.As(err, &strict) {
		for _, e := range strict.Errors {
			f.unknown = append(f.unknown, strings.Join(e.Key(), "."))
		}
		f = File{unknown: f.unknown}
		err = toml.Unmarshal(data, &f)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", ProjectFileName, err)
	}
	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", ProjectFileName, err)
	}
	f.raw = data
	f.orig = f.clone()
	return &f, nil
}

const header = "# esec project file: commit it. It holds no secret.\n"

// Marshal encodes the file. A file that was read keeps its comments and
// layout: only the values that changed are rewritten.
func (f *File) Marshal() ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	raw, orig := f.raw, f.orig
	if raw == nil {
		raw, orig = []byte(header), &File{}
	}
	if out, ok := edit(raw, orig, f); ok {
		return out, nil
	}
	// The file uses a layout edit does not handle (inline tables, dotted
	// keys): write it afresh.
	var buf bytes.Buffer
	buf.WriteString(header)
	enc := toml.NewEncoder(&buf)
	enc.SetIndentTables(false)
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Load reads esec.toml directly in dir. It returns ErrNotFound if the file
// does not exist.
func Load(dir string) (*File, error) {
	data, err := os.ReadFile(filepath.Join(dir, ProjectFileName)) //nolint:gosec // dir is caller-provided
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to read project file: %w", err)
	}
	return Parse(data)
}

// Save writes f as esec.toml in dir, atomically.
func (f *File) Save(dir string) error {
	data, err := f.Marshal()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".esec-toml-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, ProjectFileName))
}

func (f *File) clone() *File {
	c := &File{Project: f.Project, Files: f.Files, Env: make(map[string]Env, len(f.Env))}
	for k, v := range f.Env {
		v.Readers = slices.Clone(v.Readers)
		c.Env[k] = v
	}
	return c
}

// same reports whether two files say the same.
func (f *File) same(o *File) bool {
	if f.Project != o.Project || f.Files != o.Files {
		return false
	}
	for k, v := range f.Env {
		if !v.Equal(o.Env[k]) {
			return false
		}
	}
	for k, v := range o.Env {
		if !v.Equal(f.Env[k]) {
			return false
		}
	}
	return true
}

// Find searches dir and its parents for esec.toml, returning the file and
// its path. The search never crosses a repository boundary: it stops after
// checking the directory containing .git. It returns ErrNotFound if no
// project file exists.
func Find(dir string) (*File, string, error) {
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve directory: %w", err)
	}
	for {
		f, err := Load(abs)
		if err == nil {
			return f, filepath.Join(abs, ProjectFileName), nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, "", err
		}
		// Never climb out of a repository: a project file above the git root
		// must not claim this repo.
		if _, gerr := os.Stat(filepath.Join(abs, ".git")); gerr == nil {
			return nil, "", ErrNotFound
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return nil, "", ErrNotFound
		}
		abs = parent
	}
}

// WriteProjectFile sets the project id in dir's esec.toml, creating the file
// or keeping the rest of an existing one.
func WriteProjectFile(dir string, orgRepo string) error {
	if err := ValidateOrgRepo(orgRepo); err != nil {
		return err
	}
	f, err := Load(dir)
	if errors.Is(err, ErrNotFound) {
		f, err = &File{}, nil
	}
	if err != nil {
		return err
	}
	f.Project = orgRepo
	return f.Save(dir)
}

// ReadProjectFile reads esec.toml directly in dir and returns the project
// identifier. It returns ErrNotFound if the file does not exist.
func ReadProjectFile(dir string) (string, error) {
	f, err := Load(dir)
	if err != nil {
		return "", err
	}
	return f.Project, nil
}

// FindProjectFile searches dir and its parents for esec.toml (see Find),
// returning the project identifier and the path of the file found.
func FindProjectFile(dir string) (project string, path string, err error) {
	f, p, err := Find(dir)
	if err != nil {
		return "", "", err
	}
	return f.Project, p, nil
}
