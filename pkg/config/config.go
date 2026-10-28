// Package config loads the shared, non-secret esec preferences.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/mscno/esec/pkg/projectfile"
)

// Config contains preferences shared by esec and esec-vault.
type Config struct {
	DefaultFormat string            `toml:"default_format"`
	Files         Files             `toml:"files"`
	Aliases       map[string]string `toml:"aliases"`
	// ProjectFormat is the format a project's esec.toml fixes for its
	// secrets files; discovery then looks for that format only.
	ProjectFormat string `toml:"-"`
}

// Files describes relative filenames, using {env} and {format} placeholders.
type Files struct {
	Patterns  []string `toml:"patterns"`
	Create    string   `toml:"create"`
	Templates []string `toml:"templates"`
}

// Defaults preserves existing creation names and discovers both naming styles.
func Defaults() Config {
	return Config{DefaultFormat: "env", Files: Files{
		Patterns: []string{".{format}.{env}", "{env}.{format}"},
		Create:   ".{format}.{env}", Templates: []string{"example.{format}", ".{format}.example"},
	}, Aliases: map[string]string{"prod": "production", "dev": "development", "stage": "staging"}}
}

// Path follows esec-vault's existing config home, with a file-level override.
func Path() (string, error) {
	if p := os.Getenv("ESEC_CONFIG"); p != "" {
		return p, nil
	}
	if p := os.Getenv("ESEC_VAULT_HOME"); p != "" {
		return filepath.Join(p, "config.toml"), nil
	}
	if p := os.Getenv("XDG_CONFIG_HOME"); p != "" {
		return filepath.Join(p, "esec", "config.toml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "esec", "config.toml"), nil
}

// Load returns defaults when the file is absent, and rejects invalid settings.
func Load() (Config, error) {
	c := Defaults()
	p, err := Path()
	if err != nil {
		if os.Getenv("ESEC_CONFIG") == "" {
			return c, nil
		}
		return c, err
	}
	b, err := os.ReadFile(p) //nolint:gosec // explicitly selected local preferences, not a remote path
	if errors.Is(err, os.ErrNotExist) && os.Getenv("ESEC_CONFIG") == "" {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("read esec config %s: %w", p, err)
	}
	if err := toml.NewDecoder(bytes.NewReader(b)).DisallowUnknownFields().Decode(&c); err != nil {
		return c, fmt.Errorf("invalid esec config %s: %w", p, err)
	}
	if err := c.Validate(); err != nil {
		return c, fmt.Errorf("invalid esec config %s: %w", p, err)
	}
	return c, nil
}

// LoadDir is Load with the [files] settings of the esec.toml nearest to dir
// on top: a project names its files the same way on every machine.
func LoadDir(dir string) (Config, error) {
	c, err := Load()
	if err != nil {
		return c, err
	}
	f, _, err := projectfile.Find(dir)
	if errors.Is(err, projectfile.ErrNotFound) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	return c.WithProject(f), nil
}

// WithProject applies a project file's [files] settings.
func (c Config) WithProject(f *projectfile.File) Config {
	if format := strings.TrimPrefix(f.Files.Format, "."); format != "" {
		c.DefaultFormat = format
		c.ProjectFormat = format
	}
	if name := f.Files.Name; name != "" {
		c.Files.Create = name
		c.Files.Patterns = []string{name}
	}
	return c
}

// Validate checks settings before filesystem or key mutations.
func (c Config) Validate() error {
	switch strings.TrimPrefix(c.DefaultFormat, ".") {
	case "env", "ejson", "etoml", "eyaml", "eyml":
	default:
		return fmt.Errorf("unsupported default_format %q", c.DefaultFormat)
	}
	if len(c.Files.Patterns) == 0 {
		return errors.New("files.patterns must not be empty")
	}
	for _, p := range append(append([]string{c.Files.Create}, c.Files.Patterns...), c.Files.Templates...) {
		if !strings.Contains(p, "{format}") {
			return errors.New("filename patterns must contain {format}")
		}
		if _, err := Expand(p, "prod", "etoml"); err != nil {
			return err
		}
	}
	for a, b := range c.Aliases {
		if ValidateEnvironment(a) != nil || ValidateEnvironment(b) != nil || a == "" || b == "" {
			return errors.New("aliases must map nonempty environment names to environment names")
		}
	}
	return nil
}

// ValidateEnvironment accepts dot-separated lowercase letters and digits.
func ValidateEnvironment(env string) error {
	if env == "" {
		return nil
	}
	for _, s := range strings.Split(env, ".") {
		if s == "" {
			return fmt.Errorf("invalid environment name %q", env)
		}
		for _, r := range s {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return fmt.Errorf("invalid environment name %q", env)
			}
		}
	}
	return nil
}

// Expand produces a confined relative path; patterns are not shell commands or globs.
func Expand(pattern, env, format string) (string, error) {
	p := strings.NewReplacer("{env}", env, "{format}", strings.TrimPrefix(format, ".")).Replace(pattern)
	if !filepath.IsLocal(p) || strings.ContainsAny(p, "{}*?[]\\\x00\r\n") {
		return "", fmt.Errorf("unsafe filename pattern %q: use relative paths and {env}/{format}", pattern)
	}
	return filepath.Clean(p), nil
}
