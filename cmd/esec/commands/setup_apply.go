package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/projectfile"
)

func applySetup(ctx *cliCtx, sc *setupContext, p setupPlan) error {
	useVault, err := p.route(sc)
	if err != nil {
		return err
	}
	if keyringExists(p.Project) && !p.Add {
		return fmt.Errorf("this machine already has a keyring for %s (%s)", p.Project, keyringPath(p.Project))
	}
	if useVault {
		return applyVault(ctx, sc, p)
	}
	return applyLocal(ctx, sc, p)
}

func applyLocal(ctx *cliCtx, sc *setupContext, p setupPlan) error {
	keys, notes, err := buildLocal(sc, p)
	if err != nil {
		return err
	}
	stored := make([]projectKey, len(keys))
	for i, k := range keys {
		stored[i] = projectKey{env: k.env, pub: k.pub, priv: k.priv}
	}
	if err := saveProjectKeys(p.Project, stored); err != nil {
		return err
	}
	wrote := make([]string, 0, len(keys))
	for _, k := range keys {
		if err := writeNewFile(k.path, k.body); err != nil {
			return fmt.Errorf("wrote keys for %s to %s, then failed: %w", p.Project, keyringPath(p.Project), err)
		}
		wrote = append(wrote, k.file)
	}
	if err := writeProject(sc, p, keys); err != nil {
		return fmt.Errorf("wrote keys and files, then failed on esec.toml: %w", err)
	}
	if added, ignored, err := ensureGitignore(sc.Dir, p.Format); err != nil {
		say(ctx, "could not update .gitignore: %s", err.Error())
	} else {
		if added {
			notes = append(notes, "added .esec-keyring to .gitignore")
		}
		if ignored {
			notes = append(notes, "gitignore ignores .env files; add an exception for the encrypted files you want to commit")
		}
	}
	notifyVault()
	say(ctx, "wrote esec.toml")
	for _, file := range wrote {
		say(ctx, "wrote %s", file)
	}
	say(ctx, "stored private keys in %s", keyringPath(p.Project))
	say(ctx, "the name was not reserved; keys are only on this machine")
	for _, note := range notes {
		say(ctx, "%s", note)
	}
	return nil
}

type localKey struct {
	env, pub, priv, file, path string
	body                       []byte
}

func buildLocal(sc *setupContext, p setupPlan) ([]localKey, []string, error) {
	var keys []localKey
	var notes []string
	for _, env := range p.Envs {
		pub, priv, err := esec.GenerateKeypair()
		if err != nil {
			return nil, nil, err
		}
		file, err := p.filename(env, sc)
		if err != nil {
			return nil, nil, err
		}
		path := filepath.Join(sc.Dir, file)
		if err := within(sc.Dir, path); err != nil {
			return nil, nil, err
		}
		if _, err := os.Lstat(path); err == nil {
			return nil, nil, fmt.Errorf("secrets file %s already exists; not overwritten", file)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, err
		}
		body, note, err := materialize(sc, p.Format, pub, env)
		if err != nil {
			return nil, nil, err
		}
		if note != "" {
			notes = append(notes, note)
		}
		keys = append(keys, localKey{env: env, pub: pub, priv: priv, file: file, path: path, body: body})
	}
	return keys, notes, nil
}

func writeProject(sc *setupContext, p setupPlan, keys []localKey) error {
	f := sc.File
	if f == nil {
		f = &projectfile.File{}
	}
	f.Project = p.Project
	if !p.Add || f.Files.Format == "" {
		f.Files.Format = p.Format
	}
	name, err := p.storedName(sc)
	if err != nil {
		return err
	}
	if !p.Add || f.Files.Name == "" {
		f.Files.Name = name
	}
	for _, k := range keys {
		f.SetEnv(k.env, k.pub)
	}
	if err := f.Validate(); err != nil {
		return err
	}
	return f.Save(sc.Dir)
}

func materialize(sc *setupContext, format, pub, env string) ([]byte, string, error) {
	name, body, ok := findTemplate(sc.Dir, format, sc.Config)
	if !ok {
		return []byte(skeleton(format, pub)), "", nil
	}
	with, err := withPublicKey(format, body, pub)
	if err != nil {
		return templateSkipped(format, pub, name, env)
	}
	var buf bytes.Buffer
	if _, err := esec.Encrypt(bytes.NewReader(with), &buf, esec.FileFormat("."+format)); err != nil {
		return nil, "", fmt.Errorf("encrypt %s for %s: %w", name, env, err)
	}
	out := buf.Bytes()
	if len(out) == 0 || out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return out, "", nil
}

func templateSkipped(format, pub, name, env string) ([]byte, string, error) {
	return []byte(skeleton(format, pub)), fmt.Sprintf("%s could not be used; wrote a public-key skeleton for %s", name, env), nil
}

func findTemplate(dir, format string, cfg config.Config) (string, []byte, bool) {
	patterns := cfg.Files.Templates
	if len(patterns) == 0 {
		patterns = []string{"example.{format}", ".{format}.example"}
	}
	token := strings.TrimPrefix(format, ".")
	for _, pat := range patterns {
		name := strings.NewReplacer("{format}", token, "{env}", "example").Replace(pat)
		if strings.ContainsAny(name, "{}") || !filepath.IsLocal(name) {
			continue
		}
		path := filepath.Join(dir, name)
		if err := within(dir, path); err != nil {
			continue
		}
		b, err := os.ReadFile(path) //nolint:gosec // path is a relative template name inside the project directory
		if err != nil {
			continue
		}
		return name, b, true
	}
	return "", nil, false
}

func skeleton(format, pub string) string {
	switch format {
	case "ejson":
		return "{\n  \"_ESEC_PUBLIC_KEY\": \"" + pub + "\"\n}\n"
	case "eyaml", "eyml":
		return "_ESEC_PUBLIC_KEY: " + pub + "\n"
	case "etoml":
		return "_ESEC_PUBLIC_KEY = \"" + pub + "\"\n"
	default:
		return "ESEC_PUBLIC_KEY=" + pub + "\n"
	}
}

func withPublicKey(format string, body []byte, pub string) ([]byte, error) {
	switch format {
	case "ejson":
		return insertJSONKey(body, pub)
	case "eyaml", "eyml":
		return insertPrefixedKey(body, "_ESEC_PUBLIC_KEY: "+pub, "_ESEC_PUBLIC_KEY:", "ESEC_PUBLIC_KEY:"), nil
	case "etoml":
		return insertPrefixedKey(body, "_ESEC_PUBLIC_KEY = \""+pub+"\"", "_ESEC_PUBLIC_KEY", "ESEC_PUBLIC_KEY"), nil
	default:
		return insertPrefixedKey(body, "ESEC_PUBLIC_KEY="+pub, "ESEC_PUBLIC_KEY=", "_ESEC_PUBLIC_KEY="), nil
	}
}

func insertJSONKey(body []byte, pub string) ([]byte, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		body = []byte("{}")
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, err
	}
	delete(obj, "ESEC_PUBLIC_KEY")
	obj["_ESEC_PUBLIC_KEY"] = pub
	out, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func insertPrefixedKey(body []byte, line string, prefixes ...string) []byte {
	s := string(body)
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	var out []string
	found := false
	for _, l := range strings.Split(s, "\n") {
		trim := strings.TrimSpace(l)
		match := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(trim, prefix) {
				match = true
				break
			}
		}
		if match {
			if !found {
				out = append(out, line)
				found = true
			}
			continue
		}
		out = append(out, l)
	}
	if !found {
		out = append([]string{line}, out...)
	}
	res := strings.Join(out, "\n")
	if !strings.HasSuffix(res, "\n") {
		res += "\n"
	}
	return []byte(res)
}

func writeNewFile(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // encrypted secrets files are committed
	if err != nil {
		return err
	}
	_, werr := f.Write(body)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

func within(dir, path string) error {
	rel, err := filepath.Rel(dir, path)
	if err != nil || !filepath.IsLocal(rel) {
		return fmt.Errorf("refusing to write %s", path)
	}
	return nil
}

func keyringPath(project string) string {
	dir := esec.GlobalKeyringDir()
	if dir == "" {
		return projectfile.KeyringName(project)
	}
	return filepath.Join(dir, projectfile.KeyringName(project))
}

func keyringExists(project string) bool {
	_, err := os.Lstat(keyringPath(project))
	return err == nil
}

func ensureGitignore(dir, format string) (added, envIgnored bool, err error) {
	path := filepath.Join(dir, ".gitignore")
	data, rerr := os.ReadFile(path) //nolint:gosec // the project's own gitignore
	if errors.Is(rerr, os.ErrNotExist) {
		if werr := os.WriteFile(path, []byte(".esec-keyring\n"), 0o644); werr != nil { //nolint:gosec // gitignore is not secret
			return false, false, werr
		}
		return true, false, nil
	}
	if rerr != nil {
		return false, false, rerr
	}
	envIgnored = format == "env" && gitignoreEnv(data)
	if gitignoreHas(data, ".esec-keyring") {
		return false, envIgnored, nil
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	data = append(data, ".esec-keyring\n"...)
	mode := os.FileMode(0o644)
	if info, serr := os.Stat(path); serr == nil {
		mode = info.Mode().Perm()
	}
	if werr := os.WriteFile(path, data, mode); werr != nil { //nolint:gosec // preserves the existing mode
		return false, envIgnored, werr
	}
	return true, envIgnored, nil
}

func gitignoreHas(data []byte, want string) bool {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == want {
			return true
		}
	}
	return false
}

func gitignoreEnv(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch line {
		case ".env", ".env.*", ".env*", "*.env":
			return true
		}
		if strings.HasPrefix(line, ".env.") {
			return true
		}
	}
	return false
}

func say(ctx *cliCtx, format string, args ...any) {
	if ctx != nil && ctx.Quiet {
		return
	}
	fmt.Fprintf(os.Stderr, "esec: "+format+"\n", args...)
}
