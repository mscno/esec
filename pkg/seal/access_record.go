package seal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
)

// AccessRecord describes an immutable encrypted key generation. Public records
// detect configuration drift; the same access/recipients inside the encrypted
// payload authenticate the record when an authorized identity opens the key.
type AccessRecord struct {
	Version     int      `json:"version"`
	Project     string   `json:"project"`
	Environment string   `json:"environment"`
	PublicKey   string   `json:"public_key"`
	Access      string   `json:"access"`
	Recipients  []string `json:"recipients"`
	SealHash    string   `json:"seal_hash"`
}

// CanonicalRecipients sorts and deduplicates public recipient strings.
func CanonicalRecipients(rs []string) []string {
	out := slices.Clone(rs)
	slices.Sort(out)
	return slices.Compact(out)
}

// AccessRecordPath returns the immutable public record beside its age seal.
func AccessRecordPath(root, env, pub string) string {
	return StandaloneKeyPath(root, env, pub) + ".json"
}

// LoadAccessRecord returns nil for pre-record generations. It verifies public
// binding and the seal hash, without decrypting or claiming recipient ownership.
func LoadAccessRecord(root, project, env, pub string) (*AccessRecord, error) {
	data, err := os.ReadFile(AccessRecordPath(root, env, pub))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r AccessRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("invalid applied access record: %w", err)
	}
	if r.Version != 1 || r.Project != project || r.Environment != env || r.PublicKey != pub || len(r.Recipients) == 0 || (r.Access != "development" && r.Access != "production") {
		return nil, errors.New("applied access record does not match this environment")
	}
	sealed, err := os.ReadFile(StandaloneKeyPath(root, env, pub))
	if err != nil {
		return nil, err
	}
	if Hash(sealed) != r.SealHash {
		return nil, errors.New("sealed key differs from its applied access record; restore the matching generation from version control")
	}
	return &r, nil
}

// Matches compares desired policy with this applied generation.
func (r *AccessRecord) Matches(access string, rs []string) bool {
	return r.Access == access && slices.Equal(CanonicalRecipients(r.Recipients), CanonicalRecipients(rs))
}

// CheckPayload prevents a rewritten public record from misrepresenting the
// recipients authenticated by the encrypted key payload.
func (r *AccessRecord) CheckPayload(p *Payload) error {
	if r == nil {
		if len(p.Recipients) > 0 || p.Access != "" {
			return errors.New("applied access record is missing; restore the matching .age.json file from version control")
		}
		return nil
	}
	if !r.Matches(p.Access, p.Recipients) {
		return errors.New("applied access record differs from the encrypted key's authenticated policy")
	}
	return nil
}
