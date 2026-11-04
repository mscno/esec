package esec

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Missing keys and legacy guards must fail locally even with old socket settings.
func TestReadsAndInspectionNeverContactRetiredServices(t *testing.T) {
	for _, guard := range []string{"none", "touch"} {
		t.Run(guard, func(t *testing.T) {
			root, _ := readFixture(t, guard)
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if strings.HasPrefix(key, EsecPrivateKey) {
					t.Setenv(key, "")
				}
			}
			dir, err := os.MkdirTemp("", "esec-offline-") //nolint:usetesting // short Darwin socket path
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			sock := filepath.Join(dir, "s")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			t.Setenv("ESEC_VAULT_SOCK", sock)
			t.Setenv("ESEC_VAULT_FORWARD", sock)
			target, err := ResolveRead(root, "production", "")
			if err != nil {
				t.Fatal(err)
			}
			inspection := InspectRead(target, ReadOptions{})
			if len(inspection.Blockers) == 0 {
				t.Fatal("missing credential has no explanation")
			}
			data, info, err := ReadDocumentWithInfo(target, ReadOptions{})
			if err == nil || data != nil || info != (ReadInfo{}) {
				t.Fatal("read succeeded without a local credential")
			}
			if strings.Contains(err.Error(), "daemon") || strings.Contains(err.Error(), "esec vault") {
				t.Fatalf("retired recovery advice: %v", err)
			}
			if err := listener.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			conn, err := listener.Accept()
			if conn != nil {
				conn.Close()
				t.Fatal("contacted retired service")
			}
			var networkError net.Error
			if !errors.As(err, &networkError) || !networkError.Timeout() {
				t.Fatalf("unexpected accept: %v", err)
			}
		})
	}
}
