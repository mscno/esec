// Package secretfile reads and edits esec secrets files without their
// private keys: key names are plain in them, and each value is encrypted
// on its own to the file's public key. So a value can be replaced in
// place, by anyone who may change the repository, and every other value
// keeps its ciphertext, which keeps diffs to the one line.
//
// Formats: dotenv (.env), JSON (.ejson), TOML (.etoml) and YAML (.eyaml,
// .eyml). Paths name nested keys with dots: db.password.
package secretfile

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/joho/godotenv"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/format"
	esecjson "github.com/mscno/esec/pkg/json"
	"github.com/mscno/esec/pkg/projectfile"
	esectoml "github.com/mscno/esec/pkg/toml"
	esecyaml "github.com/mscno/esec/pkg/yaml"
	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
	"gopkg.in/yaml.v3"

	"github.com/mscno/esec/pkg/dotenv"
)

// maxFileSize skips files too large to be secrets files.
const maxFileSize = 10 << 20

// skipDirs are never searched.
var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv": true, ".esec": true, ".build": true, ".worktrees": true, "target": true, "dist": true}

// File is a secrets file.
type File struct {
	Path   string `json:"path"`
	Format string `json:"format"`
	// Env is the environment its name gives ("" for the default one).
	Env string `json:"env"`
	// Project is the project of the nearest esec.toml, Root the
	// directory it is in ("" when there is none).
	Project string `json:"project,omitempty"`
	Root    string `json:"root,omitempty"`
	// PublicKey is the key its values are encrypted to.
	PublicKey string `json:"public_key"`
	// Keys are the paths of its values; Plain those whose value should be
	// encrypted and is not.
	Keys  []string `json:"keys"`
	Plain []string `json:"plain,omitempty"`
}

// EnvOf returns the environment a secrets file's name gives: ".env.prod"
// is prod, ".ejson" the default environment.
func EnvOf(name string) (string, fileutils.FileFormat, error) {
	f, err := fileutils.ParseFormat(filepath.Base(name))
	if err != nil {
		return "", "", err
	}
	base := filepath.Base(name)
	if base != string(f) && strings.HasSuffix(base, string(f)) {
		return strings.TrimSuffix(base, string(f)), f, nil
	}
	rest := strings.TrimPrefix(base, string(f))
	if rest != "" && !strings.HasPrefix(rest, ".") {
		return "", "", fmt.Errorf("%s is not a secrets file name", name)
	}
	return strings.TrimPrefix(rest, "."), f, nil
}

// Scan finds the secrets files under root, with their projects.
func Scan(root string) ([]File, error) {
	var out []File
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if _, _, err := EnvOf(d.Name()); err != nil {
			return nil //nolint:nilerr // not a secrets file name
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize {
			return err
		}
		f, err := Read(path)
		if err != nil {
			return nil //nolint:nilerr // a file named like one that is not one
		}
		out = append(out, *f)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, err
}

// Read describes one secrets file.
func Read(path string) (*File, error) {
	data, err := os.ReadFile(path) //nolint:gosec // a secrets file the caller named or found
	if err != nil {
		return nil, err
	}
	return Parse(path, data)
}

// Parse describes a secrets file at path with content data, which need not
// be what is on disk (a staged version, say). It fails for content without
// a public key.
func Parse(path string, data []byte) (*File, error) {
	env, f, err := EnvOf(path)
	if err != nil {
		return nil, err
	}
	pub, err := esec.ExtractPublicKey(data, esec.FileFormat(f))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := &File{Path: path, Format: string(f), Env: env, PublicKey: hex.EncodeToString(pub[:])}
	if out.Keys, err = Keys(data, f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if out.Plain, err = Plain(data, f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if project, marker, err := projectfile.FindProjectFile(filepath.Dir(path)); err == nil {
		out.Project, out.Root = project, filepath.Dir(marker)
		// A custom name such as secrets/app.{env}.etoml takes precedence
		// over the generic suffix when identifying its environment/guard.
		if pf, err := projectfile.Load(out.Root); err == nil && pf.Files.Name != "" {
			if rel, err := filepath.Rel(out.Root, path); err == nil {
				prefix, suffix, _ := strings.Cut(pf.Files.Name, "{env}")
				if strings.HasPrefix(rel, prefix) && strings.HasSuffix(rel, suffix) && len(rel) >= len(prefix)+len(suffix) {
					out.Env = rel[len(prefix) : len(rel)-len(suffix)]
				}
			}
		}
	}
	return out, nil
}

// Has reports whether f holds a value at path.
func (f *File) Has(path string) bool {
	for _, k := range f.Keys {
		if k == path {
			return true
		}
	}
	return false
}

func handler(f fileutils.FileFormat) (format.Handler, error) {
	switch f {
	case fileutils.Env:
		return &dotenv.Formatter{}, nil
	case fileutils.Ejson:
		return &esecjson.Formatter{}, nil
	case fileutils.Etoml:
		return &esectoml.Formatter{}, nil
	case fileutils.Eyaml, fileutils.Eyml:
		return &esecyaml.Formatter{}, nil
	}
	return nil, fmt.Errorf("unsupported format %s", f)
}

// HasEncrypted reports whether any value needs a private key to be read.
// A public-key header alone (often in old templates) does not establish that.
func HasEncrypted(data []byte, f fileutils.FileFormat) (bool, error) {
	h, err := handler(f)
	if err != nil {
		return false, err
	}
	var found atomic.Bool
	_, err = h.TransformScalarValues(data, func(v []byte) ([]byte, error) {
		if crypto.IsBoxedMessage(v) {
			found.Store(true)
		}
		return v, nil
	})
	return found.Load(), err
}

// Plain lists the paths of values that should be encrypted and are not: a
// secret written in the clear.
func Plain(data []byte, f fileutils.FileFormat) ([]string, error) {
	h, err := handler(f)
	if err != nil {
		return nil, err
	}
	// The handler visits each value it would encrypt, in order; mark the
	// clear ones, then find which keys they are.
	const mark = "esec-plain-marker"
	var n atomic.Int64
	marked, err := h.TransformScalarValues(data, func(v []byte) ([]byte, error) {
		if crypto.IsBoxedMessage(v) {
			return v, nil
		}
		n.Add(1)
		return []byte(mark), nil
	})
	if err != nil || n.Load() == 0 {
		return nil, err
	}
	vals, err := values(marked, f)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, k := range sortedKeys(vals) {
		if vals[k] == mark {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		// Inside arrays: no key of its own.
		out = append(out, fmt.Sprintf("%d value(s)", n.Load()))
	}
	return out, nil
}

// Keys lists the paths of a file's values, but its public key.
func Keys(data []byte, f fileutils.FileFormat) ([]string, error) {
	vals, err := values(data, f)
	if err != nil {
		return nil, err
	}
	return sortedKeys(vals), nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != format.PublicKeyField && k != format.UnderscoredPublicKeyField {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// values maps the paths of a document's scalar values to their text.
func values(data []byte, f fileutils.FileFormat) (map[string]string, error) {
	out := map[string]string{}
	switch f {
	case fileutils.Env:
		m, err := godotenv.Parse(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		return m, nil
	case fileutils.Ejson:
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, err
		}
		flatten("", doc, out)
	case fileutils.Etoml:
		var doc map[string]any
		if err := unmarshalTOML(data, &doc); err != nil {
			return nil, err
		}
		flatten("", doc, out)
	case fileutils.Eyaml, fileutils.Eyml:
		var doc any
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, err
		}
		flatten("", doc, out)
	default:
		return nil, fmt.Errorf("unsupported format %s", f)
	}
	return out, nil
}

func flatten(prefix string, v any, out map[string]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			flatten(join(prefix, k), c, out)
		}
	case []any:
		// Array elements have no key to name them by.
	case nil:
		out[prefix] = ""
	default:
		out[prefix] = fmt.Sprint(x)
	}
}

func join(prefix, k string) string {
	if prefix == "" {
		return k
	}
	return prefix + "." + k
}

// ErrNotFound is returned by Set for a path a file does not have.
var ErrNotFound = errors.New("no such key in the file")

// Set replaces the value at path with value, encrypted to the file's
// public key, and leaves every other value as it is. With create, a
// missing top-level key is added. The value must
// be one esec encrypts: not the public key, nor a key starting with _.
func Set(data []byte, f fileutils.FileFormat, path, value string, create bool) ([]byte, error) {
	last := path[strings.LastIndex(path, ".")+1:]
	if path == "" || last == format.PublicKeyField || last == format.UnderscoredPublicKeyField {
		return nil, errors.New("not a key that holds a secret")
	}
	if f != fileutils.Env && strings.HasPrefix(last, "_") {
		return nil, fmt.Errorf("%s starts with _, so esec does not encrypt it: it is not for secrets", path)
	}
	if strings.Contains(value, "ESEC[") {
		return nil, errors.New("the value looks encrypted already: give the plain value")
	}
	var plain []byte
	var err error
	switch f {
	case fileutils.Env:
		plain, err = setEnv(data, path, value, create)
	case fileutils.Ejson:
		plain, err = setJSON(data, path, value)
		if create && errors.Is(err, ErrNotFound) {
			plain, err = addTopLevel(data, f, path, value)
		}
	case fileutils.Etoml:
		plain, err = setTOML(data, path, value)
		if create && errors.Is(err, ErrNotFound) {
			plain, err = addTopLevel(data, f, path, value)
		}
	case fileutils.Eyaml, fileutils.Eyml:
		plain, err = setYAML(data, path, value, create)
	default:
		err = fmt.Errorf("unsupported format %s", f)
	}
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if _, err := esec.Encrypt(bytes.NewReader(plain), &out, esec.FileFormat(f)); err != nil {
		return nil, err
	}
	// The value must now be encrypted; nothing must be left in the clear
	// that was not before.
	vals, err := values(out.Bytes(), f)
	if err != nil {
		return nil, err
	}
	if !crypto.IsBoxedMessage([]byte(vals[path])) {
		return nil, fmt.Errorf("%s did not end up encrypted; nothing was written", path)
	}
	return out.Bytes(), nil
}

// Check decrypts data with priv and returns the value at path, to confirm a
// change.
func Check(data []byte, f fileutils.FileFormat, path, priv string) (string, error) {
	var out bytes.Buffer
	if _, err := esec.Decrypt(bytes.NewReader(data), &out, "", esec.FileFormat(f), "", priv); err != nil {
		return "", err
	}
	vals, err := values(out.Bytes(), f)
	if err != nil {
		return "", err
	}
	v, ok := vals[path]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

// ---- dotenv ----

func envQuote(v string) string {
	if v != "" && !strings.ContainsAny(v, " \t\n\r\"'#$\\`=") {
		return v
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "$", `\$`)
	return `"` + r.Replace(v) + `"`
}

func setEnv(data []byte, key, value string, create bool) ([]byte, error) {
	var out bytes.Buffer
	found := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), maxFileSize)
	for sc.Scan() {
		line := sc.Text()
		t := strings.TrimSpace(line)
		k, _, ok := strings.Cut(t, "=")
		if ok && !strings.HasPrefix(t, "#") && strings.TrimSpace(strings.TrimPrefix(k, "export ")) == key {
			if found {
				return nil, fmt.Errorf("%s is set twice in the file", key)
			}
			found = true
			line = key + "=" + envQuote(value)
		}
		out.WriteString(line + "\n")
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !found {
		if !create {
			return nil, ErrNotFound
		}
		out.WriteString(key + "=" + envQuote(value) + "\n")
	}
	return out.Bytes(), nil
}

// ---- JSON ----

// setJSON replaces the string at path, found by walking the tokens.
func setJSON(data []byte, path, value string) ([]byte, error) { //nolint:gocyclo // one token walk
	dec := json.NewDecoder(bytes.NewReader(data))
	want := strings.Split(path, ".")
	type frame struct {
		object bool
		key    string
		expect bool // in an object, the next token is a key
	}
	var stack []frame
	keys := func() []string {
		var out []string
		for _, f := range stack {
			if f.object {
				out = append(out, f.key)
			}
		}
		return out
	}
	for {
		before := dec.InputOffset()
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].expect {
			if s, ok := tok.(string); ok {
				stack[n-1].key, stack[n-1].expect = s, false
				continue
			}
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, frame{object: true, expect: true})
			continue
		case json.Delim('['):
			stack = append(stack, frame{})
			continue
		case json.Delim('}'), json.Delim(']'):
			stack = stack[:len(stack)-1]
		default:
			if _, ok := tok.(string); ok && equalPath(keys(), want) && len(stack) > 0 && stack[len(stack)-1].object {
				end := int(dec.InputOffset())
				start := int(before)
				for start < end && data[start] != '"' {
					start++
				}
				quoted, err := json.Marshal(value)
				if err != nil {
					return nil, err
				}
				return append(append(append([]byte{}, data[:start]...), quoted...), data[end:]...), nil
			} else if equalPath(keys(), want) {
				return nil, fmt.Errorf("%s is not a string", path)
			}
		}
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expect = true
		}
	}
}

func equalPath(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---- TOML ----

func unmarshalTOML(data []byte, v any) error {
	return toml.Unmarshal(data, v)
}

// setTOML replaces the string at path, found with the TOML parser, in
// place.
func setTOML(data []byte, path, value string) ([]byte, error) {
	var p unstable.Parser
	p.KeepComments = true
	p.Reset(data)
	var table []string
	for p.NextExpression() {
		expr := p.Expression()
		if expr == nil {
			continue
		}
		switch expr.Kind { //nolint:exhaustive // tables and key/values only
		case unstable.Table, unstable.ArrayTable:
			table = nil
			for it := expr.Key(); it.Next(); {
				table = append(table, string(it.Node().Data))
			}
		case unstable.KeyValue:
			var key []string
			for it := expr.Key(); it.Next(); {
				key = append(key, string(it.Node().Data))
			}
			if strings.Join(append(append([]string{}, table...), key...), ".") != path {
				continue
			}
			v := expr.Value()
			if v == nil || v.Kind != unstable.String {
				return nil, fmt.Errorf("%s is not a string", path)
			}
			start, end := int(v.Raw.Offset), int(v.Raw.Offset)+int(v.Raw.Length)
			return append(append(append([]byte{}, data[:start]...), tomlQuote(value)...), data[end:]...), nil
		}
	}
	if err := p.Error(); err != nil {
		return nil, err
	}
	return nil, ErrNotFound
}

func tomlQuote(v string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range v {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ---- YAML ----

// setYAML replaces the scalar at path; esec writes YAML out again in its
// own layout when it encrypts, so the same happens here.
func setYAML(data []byte, path, value string, create bool) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("the YAML document is not a mapping")
	}
	node := doc.Content[0]
	parts := strings.Split(path, ".")
	for i, part := range parts {
		var next *yaml.Node
		for j := 0; j+1 < len(node.Content); j += 2 {
			if node.Content[j].Value == part {
				next = node.Content[j+1]
			}
		}
		if next == nil {
			if !create || i != len(parts)-1 || len(parts) != 1 {
				return nil, ErrNotFound
			}
			node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: part}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
			return encodeYAML(&doc)
		}
		node = next
	}
	if node.Kind != yaml.ScalarNode {
		return nil, fmt.Errorf("%s is not a single value", path)
	}
	node.Value, node.Tag, node.Style = value, "!!str", 0
	return encodeYAML(&doc)
}

func encodeYAML(doc *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(4)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
