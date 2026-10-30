package projectfile

import (
	"strings"
	"testing"
)

func TestCheckRequires(t *testing.T) {
	for _, tc := range []struct {
		requires, version string
		ok                bool
	}{
		{"", "v0.1.0", true},
		{">= 0.14", "v0.14.0", true},
		{">=0.14", "v0.15.2 (commit: abc, built: x)", true},
		{"0.14.1", "v0.14.0", false},
		{">= 0.14", "v0.13.9", false},
		{">= 1.0", "v0.99.0", false},
		{">= 0.14", "v0.14.0-rc.1", true},
		{">= 0.14", "dev", true},
		{">= 0.14", "(devel)", true},
	} {
		f := &File{Project: "acme/store", Requires: tc.requires}
		err := f.CheckRequires(tc.version)
		if (err == nil) != tc.ok {
			t.Errorf("requires %q, version %q: %v", tc.requires, tc.version, err)
		}
		if err != nil && !strings.Contains(err.Error(), "go install github.com/mscno/esec/cmd/esec@latest") {
			t.Errorf("no way to update in %v", err)
		}
	}
	for _, bad := range []string{"~0.14", "latest", ">= 0", "< 0.14"} {
		if err := (&File{Project: "a/b", Requires: bad}).CheckRequires("v0.14.0"); err == nil {
			t.Errorf("requires %q accepted", bad)
		}
	}
}

// requires is a known key, kept when the file is saved.
func TestRequiresRoundTrip(t *testing.T) {
	dir := t.TempDir()
	f, err := Parse([]byte("project = \"acme/store\"\nrequires = \">= 0.14\" # oldest esec\n"))
	if err != nil || len(f.Unknown()) != 0 || f.Requires != ">= 0.14" {
		t.Fatalf("parse: %+v %v", f, err)
	}
	f.SetEnv("dev", strings.Repeat("ab", 32))
	if err := f.Save(dir); err != nil {
		t.Fatal(err)
	}
	g, err := Load(dir)
	if err != nil || g.Requires != ">= 0.14" {
		t.Fatalf("after save: %+v %v", g, err)
	}
}
