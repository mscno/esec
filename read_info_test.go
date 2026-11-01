package esec

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadInfoReportsActualBrokerRoute(t *testing.T) {
	for _, tc := range []struct {
		name, guard, source                             string
		localCandidate, forward, explicitSocket, denied bool
	}{
		{name: "missing local key", guard: "none", source: "broker"},
		{name: "fallback after local lookup", guard: "none", source: "broker", localCandidate: true},
		{name: "guarded", guard: "touch", source: "broker"},
		{name: "forwarded", guard: "touch", source: "forwarded_broker", forward: true},
		{name: "explicit socket overrides forwarding", guard: "touch", source: "broker", forward: true, explicitSocket: true},
		{name: "denied read has no provenance", guard: "touch", denied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _ := readFixture(t, tc.guard)
			clearReadInfoCredentials(t)
			if tc.localCandidate {
				if err := os.WriteFile(filepath.Join(root, ".esec-keyring"), []byte("# no matching key\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			target, err := ResolveRead(root, "production", "")
			if err != nil {
				t.Fatal(err)
			}
			listener, sock := readInfoListener(t)
			t.Setenv("ESEC_VAULT_SOCK", sock)
			if tc.forward {
				t.Setenv("ESEC_VAULT_FORWARD", sock)
				target.Seal = filepath.Join(root, "test.age")
				if err := os.WriteFile(target.Seal, []byte("synthetic test seal"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			options := ReadOptions{}
			if tc.explicitSocket {
				options.Socket = sock
			}
			if tc.localCandidate && InspectLocalRead(target, options).Route != "direct" {
				t.Fatal("fixture must begin with a direct plan")
			}
			served := serveReadInfoFixture(listener, target.PublicKey, tc.denied)
			data, info, err := ReadDocumentWithInfo(target, options)
			if tc.denied {
				if err == nil || data != nil || info != (ReadInfo{}) {
					t.Fatal("failed read returned data or successful-route metadata")
				}
			} else if err != nil || info.Source != tc.source || info.Guard != tc.guard || !strings.Contains(string(data), "TOKEN=synthetic") {
				t.Fatalf("incorrect successful provenance: %+v, %v", info, err)
			}
			if err := <-served; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// serveReadInfoFixture returns only synthetic document data from a one-shot broker.
func serveReadInfoFixture(listener *net.UnixListener, publicKey string, denied bool) <-chan error {
	served := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var request readRequest
		if err := json.NewDecoder(conn).Decode(&request); err != nil {
			served <- err
			return
		}
		response := readResponse{OK: true, Document: []byte("ESEC_PUBLIC_KEY=" + publicKey + "\nTOKEN=synthetic\n")}
		if denied {
			response = readResponse{Error: "denied by policy", Code: "policy_denied"}
		}
		if err := json.NewEncoder(conn).Encode(response); err != nil {
			served <- err
			return
		}
		served <- nil
	}()
	return served
}

func clearReadInfoCredentials(t *testing.T) {
	t.Helper()
	for _, e := range os.Environ() {
		key, _, _ := strings.Cut(e, "=")
		if strings.HasPrefix(key, EsecPrivateKey) {
			t.Setenv(key, "")
		}
	}
	t.Setenv("ESEC_VAULT_FORWARD", "")
}

func readInfoListener(t *testing.T) (*net.UnixListener, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "read-info-") //nolint:usetesting // short path required by macOS unix sockets
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return listener, sock
}
