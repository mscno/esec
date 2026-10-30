package projectfile

import (
	"fmt"
	"strconv"
	"strings"
)

// CheckRequires reports whether an esec of version (such as "v0.14.0", or
// "v0.14.0 (commit: …)") meets the project's Requires. A build with no
// release version ("dev", "(devel)") is not checked, nor is a project that
// requires nothing.
func (f *File) CheckRequires(version string) error {
	if f == nil || strings.TrimSpace(f.Requires) == "" {
		return nil
	}
	want, err := parseRequires(f.Requires)
	if err != nil {
		return fmt.Errorf("invalid %s: requires %q: %w", ProjectFileName, f.Requires, err)
	}
	have, ok := parseVersion(strings.Fields(version + " ")[0])
	if !ok {
		return nil
	}
	if less(have, want) {
		return fmt.Errorf("%s requires esec %s, and this is %s: update it (go install github.com/mscno/esec/cmd/esec@latest, or a release from https://github.com/mscno/esec/releases)", ProjectFileName, strings.TrimSpace(f.Requires), strings.Fields(version + " ")[0])
	}
	return nil
}

// parseRequires reads ">= X.Y[.Z]", or a bare "X.Y[.Z]" meaning the same.
func parseRequires(s string) ([3]int, error) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), ">="))
	v, ok := parseVersion(s)
	if !ok {
		return v, fmt.Errorf(`want a minimum version, such as ">= 0.14"`)
	}
	return v, nil
}

// parseVersion reads "v0.14.0", "0.14" or "0.14.1-rc.1" (the pre-release
// counts as its release); ok is false for anything else.
func parseVersion(s string) (v [3]int, ok bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func less(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
