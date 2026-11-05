package esec

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/mscno/esec/pkg/format"
	"github.com/mscno/esec/pkg/seal"
)

// ReadOptions selects local credentials and age plugin prompts.
type ReadOptions struct {
	// AgeIdentities, when non-nil, are exclusive in-memory identities for this read.
	// They never fall back to process credentials, local files, or keyrings.
	AgeIdentities []age.Identity
	// AgeUI supplies prompts for standalone age identities; nil uses a terminal.
	AgeUI      *plugin.ClientUI
	KeyDir     string
	PrivateKey string
}

// Route reports the required executor before any keyring can be opened.
func (t *ReadTarget) Route() string {
	if t.Standalone {
		return "local_age"
	}
	if t.Guard != "none" {
		if hasReadIdentity() {
			return "workload_identity"
		}
		if workloadReadKey(t) != "" {
			return "workload_key"
		}
		return "blocked"
	}
	return "direct"
}

// ReadDocument executes the shared plan. Guarded keys never fall through to
// ordinary cached private keys. Explicit age workload recipients stay unattended.
func ReadDocument(t *ReadTarget, o ReadOptions) ([]byte, error) {
	data, _, err := ReadDocumentWithInfo(t, o)
	return data, err
}

// ReadInfo describes the executor of a successful read. It contains no keys,
// values, credential paths or account identifiers. It does not attest key origin.
type ReadInfo struct {
	Source string `json:"source"`
	Guard  string `json:"guard"`
}

// ReadDocumentWithInfo returns the successful local read route.
// Errors return no data or provenance.
func ReadDocumentWithInfo(t *ReadTarget, o ReadOptions) ([]byte, ReadInfo, error) {
	info := ReadInfo{Guard: t.Guard}
	data, err := readDocument(t, o, &info)
	if err != nil {
		return nil, ReadInfo{}, err
	}
	return data, info, nil
}

func readDocument(t *ReadTarget, o ReadOptions, info *ReadInfo) ([]byte, error) {
	if t.Standalone {
		info.Source = "local_age"
		return readStandaloneDocument(t, o)
	}
	if o.AgeIdentities != nil {
		info.Source = "workload_identity"
		p, err := openReadSealWithIdentities(t, o.AgeIdentities)
		if err != nil {
			return nil, err
		}
		if guardRank(p.Guard) < guardRank(t.Guard) {
			return nil, &ReadError{"protection_mismatch", "the sealed payload has weaker protection than its metadata"}
		}
		return decryptReadKey(t, p.Private)
	}
	if t.Route() == "blocked" {
		return nil, legacyGuardError()
	}
	if t.Route() == "workload_key" {
		info.Source = "workload_key"
		return decryptReadKey(t, workloadReadKey(t))
	}
	keyDir := readKeyDirectory(t, o.KeyDir)
	if t.Route() == "workload_identity" {
		info.Source = "workload_identity"
		p, err := openReadSeal(t, o.AgeUI)
		if err != nil {
			return nil, err
		}
		if guardRank(p.Guard) < guardRank(t.Guard) {
			return nil, &ReadError{"protection_mismatch", "the sealed payload has weaker protection than its metadata"}
		}
		return decryptReadKey(t, p.Private)
	}
	key, err := findPrivateKeyForProjectData(keyDir, t.Project, t.Environment, o.PrivateKey, t.Content, t.Format, slog.New(slog.DiscardHandler))
	if err == nil {
		info.Source = "local_key"
		return decryptData(key, t.Content, t.Format)
	}
	if !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}
	if t.Seal != "" {
		p, openErr := openReadSeal(t, o.AgeUI)
		if openErr == nil {
			if guardRank(p.Guard) > 0 {
				return nil, &ReadError{"protection_mismatch", "the sealed key requires hardware protection; refresh the project metadata"}
			}
			info.Source = "sealed_identity"
			return decryptReadKey(t, p.Private)
		}
		var unavailable *ReadError
		if !errors.As(openErr, &unavailable) || unavailable.Code != "identity_unavailable" {
			return nil, openErr
		}
	}

	return nil, err
}

func legacyGuardError() *ReadError {
	return &ReadError{"legacy_guard_requires_migration", "this legacy guarded file needs an explicit age identity (ESEC_AGE_IDENTITY_FILE) or a recovered public-key-addressed credential; then run esec adopt to migrate it to local age access"}
}

func openReadSeal(t *ReadTarget, ui *plugin.ClientUI) (*seal.Payload, error) {
	ids, err := seal.LocalIdentitiesWithUI(ui)
	if err != nil {
		return nil, &ReadError{"identity_unavailable", err.Error()}
	}
	return openReadSealWithIdentities(t, ids)
}

func openReadSealWithIdentities(t *ReadTarget, ids []age.Identity) (*seal.Payload, error) {
	if t.Seal == "" {
		return nil, &ReadError{"seal_missing", "no sealed key for " + t.Environment}
	}
	data, err := os.ReadFile(t.Seal)
	if err != nil {
		return nil, err
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
// capabilities for deployment or offline recovery. Named variables and keyring caches
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

func readStandaloneDocument(t *ReadTarget, o ReadOptions) ([]byte, error) {
	ids := o.AgeIdentities
	if ids == nil {
		var err error
		ids, err = seal.LocalIdentitiesWithUI(o.AgeUI)
		if err != nil {
			return nil, err
		}
	}
	data, err := os.ReadFile(t.Seal)
	if err != nil {
		return nil, err
	}
	p, err := seal.Open(data, t.Project, t.KeyEnvironment, t.PublicKey, ids...)
	if err != nil {
		return nil, fmt.Errorf("open standalone age key for %s: %w", t.Environment, err)
	}
	if err := t.AppliedPolicy.CheckPayload(p); err != nil {
		return nil, err
	}
	if t.PolicyStatus == "drift" {
		slog.Warn("esec.toml access differs from the sealed key; run esec plan, then esec apply", "environment", t.Environment)
	}
	if guardRank(p.Guard) < guardRank(t.Guard) {
		return nil, &ReadError{"protection_mismatch", "the sealed payload has weaker protection than its metadata"}
	}
	return decryptReadKey(t, p.Private)
}
