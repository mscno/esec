package seal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// RecordsFile is the name of the signed record of a project's seals, in
// .esec/ beside the seals.
const RecordsFile = "seals.toml"

// Record says who one environment's seal was made for, signed by whoever
// made it. Lint, the pre-commit hook and CI check it against esec.toml and
// the seal, so a swapped key or a reader nobody sealed in shows up.
type Record struct {
	// Key is the environment's public key (hex), as in esec.toml.
	Key   string `toml:"key"`
	Guard string `toml:"guard"`
	// Sealed is the hash of .esec/<env>.age.
	Sealed  string      `toml:"sealed"`
	Readers []SealedFor `toml:"reader"`
	// Recovery are the recovery recipients the seal includes: the readers'
	// recovery keys, which their 24-word phrases derive.
	Recovery []string `toml:"recovery"`
	// By is who sealed: "gh:<id>", or "key:<fingerprint>" without an
	// account. SignPub is their signing key, Sig the signature.
	By      string    `toml:"by"`
	At      time.Time `toml:"at"`
	SignPub string    `toml:"sign_pub"`
	Sig     string    `toml:"sig"`
}

// SealedFor is one reader and the recipients it resolved to.
type SealedFor struct {
	Reader     string   `toml:"reader"`
	Recipients []string `toml:"recipients"`
	// Pending says the reader could not be sealed in yet (no account, or no
	// security key for a guarded environment), and why.
	Pending string `toml:"pending,omitempty"`
}

// Records are a project's records, by environment.
type Records map[string]*Record

func recordsPath(root string) string { return filepath.Join(root, Dir, RecordsFile) }

// LoadRecords reads a project's records; none is an empty set.
func LoadRecords(root string) (Records, error) {
	data, err := os.ReadFile(recordsPath(root))
	if errors.Is(err, os.ErrNotExist) {
		return Records{}, nil
	}
	if err != nil {
		return nil, err
	}
	return ParseRecords(data)
}

// ParseRecords decodes records.
func ParseRecords(data []byte) (Records, error) {
	r := Records{}
	if err := toml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", RecordsFile, err)
	}
	return r, nil
}

// Save writes the records atomically.
func (rs Records) Save(root string) error {
	var buf bytes.Buffer
	buf.WriteString("# Who each environment's key in .esec/ is sealed to, signed by whoever sealed it.\n# Written by esec vault: do not edit. Change readers with esec vault share / unshare.\n\n")
	enc := toml.NewEncoder(&buf)
	enc.SetIndentTables(false)
	if err := enc.Encode(map[string]*Record(rs)); err != nil {
		return err
	}
	dir := filepath.Join(root, Dir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".seals-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), recordsPath(root))
}

// Sign signs the record with key, as by.
func (r *Record) Sign(project, env, by string, key ed25519.PrivateKey) {
	pub, _ := key.Public().(ed25519.PublicKey)
	r.By, r.SignPub = by, hex.EncodeToString(pub)
	r.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(key, r.statement(project, env)))
}

// Verify checks the signature against the record's own signing key. Who
// that key belongs to is checked separately, against the signer's chain.
func (r *Record) Verify(project, env string) error {
	pub, err := hex.DecodeString(r.SignPub)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("the record has no valid signing key")
	}
	sig, err := base64.StdEncoding.DecodeString(r.Sig)
	if err != nil || !ed25519.Verify(pub, r.statement(project, env), sig) {
		return errors.New("the record's signature does not verify")
	}
	return nil
}

// Recipients are all the recipients the seal was made for.
func (r *Record) Recipients() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range r.Readers {
		for _, x := range s.Recipients {
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	for _, x := range r.Recovery {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// statement is what a record's signature covers: every field but the
// signature, with the project and environment it is for.
func (r *Record) statement(project, env string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "esec seal record v1\nproject %s\nenv %s\nkey %s\nguard %s\nsealed %s\n", project, env, r.Key, r.Guard, r.Sealed)
	readers := append([]SealedFor(nil), r.Readers...)
	sort.Slice(readers, func(i, j int) bool { return readers[i].Reader < readers[j].Reader })
	for _, s := range readers {
		recips := append([]string(nil), s.Recipients...)
		sort.Strings(recips)
		fmt.Fprintf(&b, "reader %s\n pending %s\n", s.Reader, s.Pending)
		for _, x := range recips {
			fmt.Fprintf(&b, " to %s\n", x)
		}
	}
	recovery := append([]string(nil), r.Recovery...)
	sort.Strings(recovery)
	for _, x := range recovery {
		fmt.Fprintf(&b, "recovery %s\n", x)
	}
	fmt.Fprintf(&b, "by %s\nat %s\nsign_pub %s\n", r.By, r.At.UTC().Format(time.RFC3339), r.SignPub)
	return []byte(b.String())
}
