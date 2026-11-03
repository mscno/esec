package secretfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/format"
	"gopkg.in/yaml.v3"
)

// Value is one displayed scalar. Structured paths that Set cannot address
// unambiguously (including array elements) are explicitly read-only.
type Value struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Editable bool   `json:"editable"`
}

// Document exists only in memory and on the private CLI pipes.
type Document struct {
	Revision string  `json:"revision"`
	Values   []Value `json:"values"`
}

// Revision identifies the exact ciphertext read by the viewer.
func Revision(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// DocumentValues reads all scalars, including nested objects and arrays.
// Parser errors intentionally omit input snippets, which may contain secrets.
func DocumentValues(data []byte, f fileutils.FileFormat) ([]Value, error) {
	out := []Value{}
	var doc any
	var err error
	switch f {
	case fileutils.Env:
		var vals map[string]string
		vals, err = godotenv.Parse(bytes.NewReader(data))
		if err == nil {
			for _, k := range sortedKeys(vals) {
				out = append(out, Value{Key: k, Value: vals[k], Editable: true})
			}
			return out, nil
		}
	case fileutils.Ejson:
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		err = dec.Decode(&doc)
	case fileutils.Etoml:
		var m map[string]any
		err = unmarshalTOML(data, &m)
		doc = m
	case fileutils.Eyaml, fileutils.Eyml:
		err = yaml.Unmarshal(data, &doc)
	default:
		return nil, fmt.Errorf("unsupported format %s", f)
	}
	if err != nil {
		return nil, fmt.Errorf("could not read %s values", f)
	}
	walkDocumentValues("", doc, true, &out)
	return out, nil
}

func walkDocumentValues(path string, value any, editable bool, out *[]Value) {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if path == "" && (k == format.PublicKeyField || k == format.UnderscoredPublicKeyField) {
				continue
			}
			simple := k != "" && !strings.ContainsAny(k, ".[]\"\\\n\r")
			next := join(path, k)
			if !simple {
				next = path + "[" + strconv.Quote(k) + "]"
			}
			walkDocumentValues(next, v[k], editable && simple && !strings.HasPrefix(k, "_"), out)
		}
	case []any:
		for i, item := range v {
			walkDocumentValues(fmt.Sprintf("%s[%d]", path, i), item, false, out)
		}
	default:
		text := fmt.Sprint(v)
		if v == nil {
			text = "null"
		}
		_, isString := v.(string)
		*out = append(*out, Value{Key: path, Value: text, Editable: editable && isString})
	}
}
