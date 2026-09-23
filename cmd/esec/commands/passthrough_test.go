package commands

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestMaybeExecExternal(t *testing.T) {
	// A directory with a fake esec-hello executable on PATH.
	binDir := t.TempDir()
	fake := filepath.Join(binDir, "esec-hello")
	content := "#!/bin/sh\nexit 0\n"
	if runtime.GOOS == "windows" {
		fake += ".exe"
		content = ""
	}
	if err := os.WriteFile(fake, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fake, 0700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	orig := execExternalFn
	defer func() { execExternalFn = orig }()

	type call struct {
		bin  string
		args []string
	}
	var calls []call
	execExternalFn = func(bin string, args []string) int {
		calls = append(calls, call{bin, args})
		return 42
	}

	tests := []struct {
		name        string
		args        []string
		wantHandled bool
		wantCode    int
		wantArgs    []string
	}{
		{"no args", []string{"esec"}, false, 0, nil},
		{"builtin", []string{"esec", "decrypt", "dev"}, false, 0, nil},
		{"flag", []string{"esec", "--help"}, false, 0, nil},
		{"path-like name", []string{"esec", "./hello"}, false, 0, nil},
		{"unknown without binary", []string{"esec", "nosuchthing"}, false, 0, nil},
		{"passthrough", []string{"esec", "hello", "a", "b"}, true, 42, []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls = nil
			code, handled := maybeExecExternal(tt.args)
			if handled != tt.wantHandled {
				t.Fatalf("handled = %v, want %v", handled, tt.wantHandled)
			}
			if !handled {
				return
			}
			if code != tt.wantCode {
				t.Errorf("code = %d, want %d", code, tt.wantCode)
			}
			if len(calls) != 1 {
				t.Fatalf("expected 1 exec call, got %d", len(calls))
			}
			if !reflect.DeepEqual(calls[0].args, tt.wantArgs) {
				t.Errorf("args = %v, want %v", calls[0].args, tt.wantArgs)
			}
		})
	}
}
