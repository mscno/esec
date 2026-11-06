package secretfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/mscno/esec/pkg/fileutils"
)

// Add a simple root string without reserializing existing numbers or ciphertext.
// Encrypt parses the resulting document and rejects duplicate or conflicting keys.
func addTopLevel(data []byte, f fileutils.FileFormat, key, value string) ([]byte, error) {
	if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`).MatchString(key) {
		return nil, errors.New("new keys must be simple top-level names")
	}
	if f == fileutils.Etoml {
		return append([]byte(key+" = "+tomlQuote(value)+"\n"), data...), nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil || root == nil {
		return nil, errors.New("expected a JSON object")
	}
	if _, exists := root[key]; exists {
		return nil, errors.New("key already exists")
	}
	quoted, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	end := bytes.LastIndexByte(data, '}')
	addition := "\n"
	if len(root) > 0 {
		addition = ",\n"
	}
	out := append([]byte{}, data[:end]...)
	out = append(out, []byte(addition+`"`+key+`": `)...)
	out = append(out, quoted...)
	out = append(out, '\n')
	return append(out, data[end:]...), nil
}
