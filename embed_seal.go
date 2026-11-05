package esec

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/seal"
)

// A binary can embed, beside its encrypted file, the file's sealed key
// (.esec/<env>.age) and esec.toml, and hold one secret: an age identity in
// ESEC_AGE_IDENTITY, a reader of that seal. Rotating the environment's key
// then changes nothing where the binary runs: the next build embeds the new
// seal, which the same identity opens.
//
//	//go:embed esec.toml .env.prod .esec/prod.age
//	var secrets embed.FS

// openEmbeddedSeal opens env's key from the seal embedded in fsys with the
// identities ESEC_AGE_IDENTITY names. It returns notFound when there is no
// seal or no identity.
func openEmbeddedSeal(fsys fs.FS, env string, data []byte, fileFormat FileFormat, notFound error) ([32]byte, error) {
	var key [32]byte
	if env == "" {
		return key, notFound
	}
	name := path.Join(seal.Dir, env+".age")
	standalone, err := embeddedStandalone(fsys, env)
	if err != nil {
		return key, err
	}
	if pf, e := embeddedProject(fsys); e == nil && len(pf.Env[env].Recipients) > 0 {
		standalone = true
		name = path.Join(seal.Dir, "keys", env, pf.Env[env].Key+".age")
	}
	sealed, err := fs.ReadFile(fsys, name)
	if err != nil {
		if standalone {
			return key, fmt.Errorf("standalone embedded seal missing: %w", err)
		}
		return key, notFound
	}
	ids, err := seal.EnvIdentities()
	if standalone {
		ids, err = seal.LocalIdentities()
	}
	if err != nil {
		return key, err
	}
	if len(ids) == 0 {
		return key, notFound
	}
	pub, err := ExtractPublicKey(data, fileFormat)
	if err != nil {
		return key, err
	}
	want := fmt.Sprintf("%x", pub)
	var p *seal.Payload
	if pf, perr := embeddedProject(fsys); perr == nil {
		p, err = seal.Open(sealed, pf.Project, env, want, ids...)
	} else {
		p, err = seal.OpenKey(sealed, env, want, ids...)
	}
	if err != nil {
		return key, fmt.Errorf("the embedded %s: %w", path.Join(seal.Dir, env+".age"), err)
	}
	if standalone {
		if err := checkEmbeddedPolicy(fsys, env, name, sealed, p); err != nil {
			return key, err
		}
	}
	return parseResolvedKey(p.Private, seal.EnvIdentity, &pub, nil)
}

func embeddedStandalone(fsys fs.FS, env string) (bool, error) {
	pf, err := embeddedProject(fsys)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("invalid embedded project metadata: %w", err)
	}
	if err == nil && len(pf.Env[env].Recipients) > 0 {
		return true, nil
	}
	// A standalone seal without its metadata must never fall back to a raw key.
	name := path.Join(seal.Dir, "keys", env)
	if err != nil {
		name = path.Join(seal.Dir, "keys")
	}
	if _, e := fs.Stat(fsys, name); e == nil {
		return false, errors.New("embedded standalone keys require matching esec.toml recipient metadata")
	} else if !errors.Is(e, fs.ErrNotExist) {
		return false, e
	}
	return false, nil
}

// embeddedProject reads the esec.toml embedded in fsys.
func embeddedProject(fsys fs.FS) (*projectfile.File, error) {
	data, err := fs.ReadFile(fsys, projectfile.ProjectFileName)
	if err != nil {
		return nil, err
	}
	return projectfile.Parse(data)
}

// sniffEmbeddedSeal names the environment when no ESEC_PRIVATE_KEY* says
// it: the one environment whose embedded seal the age identity opens.
func sniffEmbeddedSeal(fsys fs.FS) (string, error) {
	if pf, err := embeddedProject(fsys); err == nil {
		var names []string
		for _, env := range pf.Envs() {
			if len(pf.Env[env].Recipients) > 0 {
				names = append(names, env)
			}
		}
		if len(names) == 1 {
			return names[0], nil
		}
		if len(names) > 1 {
			return "", errors.New("multiple standalone environments embedded; set DecryptFromEmbedConfig.EnvName explicitly")
		}
	}
	entries, err := fs.ReadDir(fsys, seal.Dir)
	if err != nil {
		return "", errors.New("no sealed keys embedded")
	}
	ids, err := seal.EnvIdentities()
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("no %s to open the embedded sealed keys with", seal.EnvIdentity)
	}
	var opens []string
	for _, e := range entries {
		env, ok := strings.CutSuffix(e.Name(), ".age")
		if !ok || e.IsDir() {
			continue
		}
		data, err := fs.ReadFile(fsys, path.Join(seal.Dir, e.Name()))
		if err != nil {
			continue
		}
		if p, err := seal.Peek(data, ids...); err == nil && p.Env == env {
			opens = append(opens, env)
		}
	}
	sort.Strings(opens)
	switch len(opens) {
	case 0:
		return "", fmt.Errorf("%s opens none of the embedded sealed keys", seal.EnvIdentity)
	case 1:
		return opens[0], nil
	default:
		return "", fmt.Errorf("%s opens the sealed keys of %s: name the environment", seal.EnvIdentity, strings.Join(opens, ", "))
	}
}

// checkEmbeddedPolicy binds current standalone generations to their public
// record and authenticated policy. Pre-record seals remain readable.
func checkEmbeddedPolicy(fsys fs.FS, env, name string, sealed []byte, payload *seal.Payload) error {
	pf, err := embeddedProject(fsys)
	if err != nil {
		return err
	}
	want := pf.Env[env]
	public, err := payload.Public()
	if err != nil || public != want.Key {
		return errors.New("embedded key differs from project metadata")
	}
	data, err := fs.ReadFile(fsys, name+".json")
	if errors.Is(err, fs.ErrNotExist) {
		return (*seal.AccessRecord)(nil).CheckPayload(payload)
	}
	if err != nil {
		return errors.New("cannot read embedded access record")
	}
	var record seal.AccessRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return errors.New("invalid embedded access record")
	}
	if record.Version != 1 || record.Project != pf.Project || record.Environment != env || record.PublicKey != public || record.SealHash != seal.Hash(sealed) || !record.Matches(want.Access, want.Recipients) {
		return errors.New("embedded access record differs from project metadata or sealed key")
	}
	return record.CheckPayload(payload)
}
