// Package seal reads and writes sealed environment keys: an environment's
// private key committed beside its secrets files, in .esec/<env>.age, as a
// standard age file encrypted to the environment's readers (people, their
// security keys, machines) and to a recovery key.
//
// Whoever can open the file has the key, so a repository and one identity
// that reads it are enough to decrypt its secrets, in every commit. The file
// is plain age: `age -d -i IDENTITY .esec/prod.age` opens it with no esec.
//
// Inside is a small JSON payload naming the project and environment, so a
// sealed key copied to another project or environment is refused.
package seal

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"filippo.io/age/plugin"
	"golang.org/x/crypto/curve25519"
)

// Dir is the directory, beside esec.toml, that holds sealed keys.
const Dir = ".esec"

// Environment variables naming the age identities that open seals, for
// machines (CI, deploys) that have no esec vault: the identity itself, or a
// file of identities.
const (
	EnvIdentity     = "ESEC_AGE_IDENTITY"
	EnvIdentityFile = "ESEC_AGE_IDENTITY_FILE"
)

// ErrNotSealed is returned when an environment has no sealed key.
var ErrNotSealed = errors.New("no sealed key")

// Payload is what a seal holds.
type Payload struct {
	Project string `json:"project"`
	Env     string `json:"env"`
	// Guard is none, session or touch: how readers who are people open it.
	Guard string `json:"guard"`
	// Private is the environment's private key, 64 lowercase hex.
	Private string `json:"private"`
}

// Public returns the public key of the payload's private key, lowercase hex.
func (p *Payload) Public() (string, error) { return PublicHex(p.Private) }

// PublicHex returns the X25519 public key of a hex private key.
func PublicHex(private string) (string, error) {
	raw, err := hex.DecodeString(private)
	if err != nil || len(raw) != 32 {
		return "", errors.New("private key must be 64 hex characters")
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pub), nil
}

// Path is where env's sealed key lives in a project rooted at root.
func Path(root, env string) string {
	return filepath.Join(root, Dir, env+".age")
}

// Seal encrypts p to recipients, armored.
func Seal(p Payload, recipients ...age.Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("a seal needs at least one recipient")
	}
	if _, err := p.Public(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	buf.WriteString("\n")
	return buf.Bytes(), nil
}

// Open decrypts a seal with any of ids and checks that it is the key of
// project's env with public key pub ("" skips the public key check).
func Open(data []byte, project, env, pub string, ids ...age.Identity) (*Payload, error) {
	if len(ids) == 0 {
		return nil, errors.New("no identity to open the sealed key with")
	}
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(data)), ids...)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(r, 64<<10))
	if err != nil {
		return nil, err
	}
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("sealed key: %w", err)
	}
	if p.Project != project || p.Env != env {
		return nil, fmt.Errorf("the sealed key is %s %s's, not %s %s's", p.Project, p.Env, project, env)
	}
	got, err := p.Public()
	if err != nil {
		return nil, err
	}
	if pub != "" && !strings.EqualFold(got, pub) {
		return nil, fmt.Errorf("the sealed key of %s %s is not the key its files use", project, env)
	}
	return &p, nil
}

// Read reads env's seal in the project rooted at root.
func Read(root, env string) ([]byte, error) {
	data, err := os.ReadFile(Path(root, env))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w for %s in %s", ErrNotSealed, env, filepath.Join(root, Dir))
	}
	return data, err
}

// Hash is the SHA-256 of a seal, as recorded beside it.
func Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Write stores a seal atomically.
func Write(root, env string, data []byte) error {
	dir := filepath.Join(root, Dir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+env+"-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
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
	return os.Rename(tmp.Name(), Path(root, env))
}

// ParseRecipient parses one age recipient: X25519 (age1…), post-quantum
// (age1pq1…), an SSH public key, or a plugin's (age1yubikey1…, age1se1…).
func ParseRecipient(s string) (age.Recipient, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "age1pq1"):
		return age.ParseHybridRecipient(s)
	case strings.HasPrefix(s, "ssh-"):
		return parseSSHRecipient(s)
	case pluginName(s) != "":
		return plugin.NewRecipient(s, plugin.NewTerminalUI(func(string, ...any) {}, func(string, ...any) {}))
	case strings.HasPrefix(s, "age1"):
		return age.ParseX25519Recipient(s)
	}
	return nil, fmt.Errorf("not an age recipient: %.20q", s)
}

// pluginName returns the plugin of a recipient such as age1yubikey1…
// ("yubikey"), or "" for a native one.
func pluginName(recipient string) string {
	rest, ok := strings.CutPrefix(recipient, "age1")
	if !ok {
		return ""
	}
	name, _, ok := strings.Cut(rest, "1")
	if !ok || name == "" || name == "pq" {
		return ""
	}
	return name
}

// ParseIdentities parses age identities, one per line: native ones
// (AGE-SECRET-KEY-1…) and plugin ones (AGE-PLUGIN-…), which ui serves.
// Blank lines and # comments are skipped.
func ParseIdentities(text string, ui *plugin.ClientUI) ([]age.Identity, error) {
	var out []age.Identity
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "AGE-PLUGIN-") {
			id, err := plugin.NewIdentity(line, ui)
			if err != nil {
				return nil, err
			}
			out = append(out, id)
			continue
		}
		ids, err := age.ParseIdentities(strings.NewReader(line))
		if err != nil {
			return nil, err
		}
		out = append(out, ids...)
	}
	return out, sc.Err()
}

// EnvIdentities returns the identities ESEC_AGE_IDENTITY and
// ESEC_AGE_IDENTITY_FILE name, none when neither is set.
func EnvIdentities() ([]age.Identity, error) {
	text := os.Getenv(EnvIdentity)
	if f := os.Getenv(EnvIdentityFile); f != "" {
		data, err := os.ReadFile(f) //nolint:gosec // a file the person named
		if err != nil {
			return nil, fmt.Errorf("%s: %w", EnvIdentityFile, err)
		}
		text += "\n" + string(data)
	}
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	ui := plugin.NewTerminalUI(func(string, ...any) {}, func(string, ...any) {})
	return ParseIdentities(text, ui)
}

// X25519Identity turns a hex private key into an age identity.
func X25519Identity(private string) (*age.X25519Identity, error) {
	raw, err := hex.DecodeString(private)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("private key must be 64 hex characters")
	}
	return age.ParseX25519Identity(encodeIdentity(raw))
}

// X25519Recipient turns a hex public key into an age recipient string.
func X25519Recipient(public string) (string, error) {
	raw, err := hex.DecodeString(public)
	if err != nil || len(raw) != 32 {
		return "", errors.New("public key must be 64 hex characters")
	}
	return bech32Encode("age", raw)
}

// RecipientHex returns the hex public key of an X25519 recipient (age1…),
// the form esec uses in secrets files and esec.toml.
func RecipientHex(recipient string) (string, error) {
	hrp, data, err := bech32Decode(recipient)
	if err != nil || hrp != "age" || len(data) != 32 {
		return "", fmt.Errorf("not an X25519 age recipient: %.20q", recipient)
	}
	return hex.EncodeToString(data), nil
}
