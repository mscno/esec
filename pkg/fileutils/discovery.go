package fileutils

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mscno/esec/pkg/config"
)

// ErrNotFound and ErrAmbiguous distinguish discovery failures from I/O errors.
var (
	ErrNotFound  = errors.New("no secrets file found")
	ErrAmbiguous = errors.New("ambiguous secrets files")
)

// Resolve finds exactly one secrets file. A format hint filters discovery;
// it never overrides the actual format of an explicit filename.
func Resolve(dir, input, formatHint string) (string, FileFormat, error) {
	c, err := config.LoadDir(dir)
	if err != nil {
		return "", "", err
	}
	var formats = ValidFormats()
	if c.ProjectFormat != "" {
		f, err := ParseFormat(c.ProjectFormat)
		if err != nil {
			return "", "", err
		}
		formats = []FileFormat{f}
	}
	if formatHint != "" {
		f, err := ParseFormat(formatHint)
		if err != nil {
			return "", "", err
		}
		formats = []FileFormat{f}
	}
	if f, err := ParseFormat(input); err == nil {
		p := input
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		if err := regularFile(p); err != nil {
			return "", "", err
		}
		return p, f, nil
	}
	if err := config.ValidateEnvironment(input); err != nil {
		return "", "", err
	}
	candidates, err := discoveryCandidates(dir, input, formats, c)
	if err != nil {
		return "", "", err
	}
	var searched, matches []string
	for p := range candidates {
		searched = append(searched, p)
	}
	sort.Strings(searched)
	for _, p := range searched {
		err := regularFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", "", err
		}
		matches = append(matches, p)
	}
	if len(matches) == 0 {
		return "", "", fmt.Errorf("%w for environment %q; searched: %s; pass an explicit file or --format", ErrNotFound, input, strings.Join(searched, ", "))
	}
	if len(matches) > 1 {
		return "", "", fmt.Errorf("%w for environment %q: %s; pass an explicit file or --format", ErrAmbiguous, input, strings.Join(matches, ", "))
	}
	return matches[0], candidates[matches[0]], nil
}

func regularFile(p string) error {
	s, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("secrets file %s: %w", p, err)
	}
	if !s.Mode().IsRegular() {
		return fmt.Errorf("secrets file %s is not a regular file", p)
	}
	return nil
}

func discoveryCandidates(dir, input string, formats []FileFormat, c config.Config) (map[string]FileFormat, error) {
	envs := map[string]bool{input: true}
	// Aliases are additional discovery candidates, not silent precedence rules.
	if a, ok := c.Aliases[input]; ok {
		envs[a] = true
	}
	for a, b := range c.Aliases {
		if b == input {
			envs[a] = true
		}
	}
	candidates := map[string]FileFormat{}
	for env := range envs {
		for _, f := range formats {
			patterns := c.Files.Patterns
			if env == "" {
				patterns = []string{".{format}"}
			}
			for _, pattern := range patterns {
				name, err := config.Expand(pattern, env, string(f))
				if err != nil {
					return nil, err
				}
				actual, err := ParseFormat(name)
				if err != nil || actual != f {
					return nil, fmt.Errorf("filename pattern %q does not identify format %s", pattern, f)
				}
				candidates[filepath.Join(dir, name)] = f
			}
		}
	}
	return candidates, nil
}
