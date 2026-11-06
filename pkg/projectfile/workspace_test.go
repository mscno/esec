package projectfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceSchemaAndRoundTrip(t *testing.T) {
	data := []byte("# root index\n[workspace.members]\nbackend='backend'\nmobile='secrets/mobile-release'\n")
	f, err := Parse(data)
	if err != nil || f.Workspace.Members["mobile"] != "secrets/mobile-release" {
		t.Fatal("workspace parse", err)
	}
	if out, err := f.Marshal(); err != nil || string(out) != string(data) {
		t.Fatal("workspace roundtrip", err)
	}
	f.Workspace.Members["web"] = "web"
	out, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Parse(out); err != nil || got.Workspace.Members["web"] != "web" {
		t.Fatal("changed workspace lost", err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "esec.toml"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Find(root); !errors.Is(err, ErrWorkspace) {
		t.Fatal("workspace treated as store", err)
	}
	if _, err := ReadProjectFile(root); !errors.Is(err, ErrWorkspace) {
		t.Fatal("workspace treated as project", err)
	}
}

func TestWorkspaceRejectsMixedPolicyAndUnsafePaths(t *testing.T) {
	for _, source := range []string{
		"project='acme/root'\n[workspace.members]\na='a'",
		"recovery_recipients=['age1test']\n[workspace.members]\na='a'",
		"[env.dev]\nkey=''\n[workspace.members]\na='a'",
		"[run]\nenvironment_variable='APP_ENV'\n[workspace.members]\na='a'",
		"[files]\nformat='env'\n[workspace.members]\na='a'",
		"[workspace.members]",
		"[workspace.members]\na='../escape'",
		"[workspace.members]\na='/tmp/escape'",
		"[workspace.members]\na='.'",
		"[workspace.members]\na='a/../b'",
		"[workspace.members]\na='*'",
		"[workspace.members]\na='.esec/keys'",
		"[workspace.members]\na='.GIT/hidden'",
		"[workspace.members]\na='.ESEC/hidden'",
		"[workspace.members]\na='a'\nb='./a'",
		"[workspace.members]\na='a'\nb='a/nested'",
		"[workspace.members]\n'bad.name'='a'",
	} {
		if _, err := Parse([]byte(source)); err == nil {
			t.Fatalf("accepted invalid workspace: %s", source)
		}
	}
}
