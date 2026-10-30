package esec

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/mscno/esec/pkg/format"
	"github.com/mscno/esec/pkg/seal"
	"github.com/mscno/esec/pkg/secretstore"
)

// ReadOptions selects credentials and the optional broker; it never changes protection.
type ReadOptions struct {
	KeyDir     string
	PrivateKey string
	Socket     string
	Session    string
}

// Route reports the required executor before any keyring can be opened.
func (t *ReadTarget) Route() string {
	if t.Guard != "none" {
		if hasReadIdentity() {
			return "workload_identity"
		}
		if workloadReadKey(t) != "" {
			return "workload_key"
		}
		return "daemon"
	}
	return "direct"
}

// ReadDocument executes the shared plan. Guarded keys never fall through to
// ordinary cached private keys. Explicit age workload recipients stay unattended.
func ReadDocument(t *ReadTarget, o ReadOptions) ([]byte, error) {
	if InspectLocalRead(t, o).Route == "daemon" {
		return readBroker(t, o)
	}
	if t.Route() == "workload_key" {
		return decryptReadKey(t, workloadReadKey(t))
	}
	keyDir := readKeyDirectory(t, o.KeyDir)
	if t.Route() == "workload_identity" {
		p, err := openReadSeal(t, false)
		if err != nil {
			return nil, err
		}
		if guardRank(p.Guard) < guardRank(t.Guard) {
			return nil, &ReadError{"protection_mismatch", "the sealed payload has weaker protection than its metadata"}
		}
		return decryptReadKey(t, p.Private)
	}
	key, err := findPrivateKeyForData(keyDir, t.Environment, o.PrivateKey, t.Content, t.Format, slog.New(slog.DiscardHandler))
	if err == nil {
		return decryptData(key, t.Content, t.Format)
	}
	if !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}
	if t.Seal != "" {
		p, openErr := openReadSeal(t, true)
		if openErr == nil {
			if guardRank(p.Guard) > 0 {
				return nil, &ReadError{"protection_mismatch", "the sealed key requires hardware protection; refresh the project metadata"}
			}
			return decryptReadKey(t, p.Private)
		}
		var unavailable *ReadError
		if !errors.As(openErr, &unavailable) || unavailable.Code != "identity_unavailable" {
			return nil, openErr
		}
	}
	// A broker may hold a key the process has no local credential for. Only a
	// missing key allows this transition; corruption and denied reads do not.
	if t.Project != "" {
		return readBroker(t, o)
	}
	return nil, err
}

func openReadSeal(t *ReadTarget, personal bool) (*seal.Payload, error) {
	if t.Seal == "" {
		return nil, &ReadError{"seal_missing", "no sealed key for " + t.Environment}
	}
	data, err := os.ReadFile(t.Seal)
	if err != nil {
		return nil, err
	}
	ids, err := seal.EnvIdentities()
	if err != nil {
		return nil, err
	}
	if personal && len(ids) == 0 {
		store, err := secretstore.Default()
		if err != nil {
			return nil, err
		}
		private, err := store.Get("identity-private")
		if errors.Is(err, secretstore.ErrNotFound) {
			return nil, &ReadError{"identity_unavailable", "the local identity is unavailable; run esec vault setup"}
		}
		if err != nil {
			return nil, &ReadError{"identity_access_failed", err.Error()}
		}
		id, err := seal.X25519Identity(private)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	p, err := seal.Open(data, t.Project, t.KeyEnvironment, t.PublicKey, ids...)
	if err != nil {
		return nil, &ReadError{"recipient_missing", fmt.Sprintf("the supplied identity cannot open %s: %v", t.Seal, err)}
	}
	return p, nil
}

func decryptReadKey(t *ReadTarget, private string) ([]byte, error) {
	pub, err := seal.PublicHex(private)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(pub, t.PublicKey) {
		return nil, &ReadError{"key_mismatch", "the private key does not match the file"}
	}
	key, err := format.ParseKey(private)
	if err != nil {
		return nil, err
	}
	return decryptData(key, t.Content, t.Format)
}

// Public-key-addressed process credentials are explicit per-key workload
// capabilities (machine run emits them). Named variables and keyring caches
// alone never choose this route for a guarded read.
func workloadReadKey(t *ReadTarget) string {
	for _, suffix := range []string{strings.ToUpper(t.PublicKey), strings.ToLower(t.PublicKey)} {
		if key := os.Getenv(EsecPrivateKey + "_" + suffix); key != "" {
			return key
		}
	}
	return ""
}

func hasReadIdentity() bool {
	return os.Getenv(seal.EnvIdentity) != "" || os.Getenv(seal.EnvIdentityFile) != ""
}

func readKeyDirectory(t *ReadTarget, configured string) string {
	if configured != "" && configured != "." {
		return configured
	}
	if t.Root != "" {
		return t.Root
	}
	return filepath.Dir(t.Path)
}
