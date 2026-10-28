package esec

import (
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
	sealed, err := fs.ReadFile(fsys, path.Join(seal.Dir, env+".age"))
	if err != nil {
		return key, notFound
	}
	ids, err := seal.EnvIdentities()
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
	return parseResolvedKey(p.Private, seal.EnvIdentity, &pub, nil)
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
