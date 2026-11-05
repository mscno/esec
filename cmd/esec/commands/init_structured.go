package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/mscno/esec/pkg/format"
	ejson "github.com/mscno/esec/pkg/json"
	etoml "github.com/mscno/esec/pkg/toml"
	eyaml "github.com/mscno/esec/pkg/yaml"
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// Decode into native values, replace only root key metadata, then canonicalize
// string quoting with the same transformer used by encryption/decryption.
// This preserves integers, arrays and maps and permits exact round-trip checks.
func normalizeInitStructured(kind string, data []byte, public string) ([]byte, error) {
	var values map[string]any
	var handler format.Handler
	var marshal func(any) ([]byte, error)
	var err error
	switch kind {
	case "ejson":
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		err = decoder.Decode(&values)
		if err == nil && decoder.Decode(new(any)) != io.EOF {
			err = errors.New("trailing JSON document")
		}
		handler = &ejson.Formatter{}
		marshal = func(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }
	case "etoml":
		err = toml.Unmarshal(data, &values)
		handler, marshal = &etoml.Formatter{}, toml.Marshal
	case "eyaml", "eyml":
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		err = decoder.Decode(&values)
		if err == nil && decoder.Decode(new(any)) != io.EOF {
			err = errors.New("multiple YAML documents")
		}
		handler, marshal = &eyaml.Formatter{}, yaml.Marshal
	default:
		return nil, errors.New("unsupported initialization format")
	}
	if err != nil || values == nil {
		return nil, errors.New("invalid structured secrets document; existing file was not changed")
	}
	delete(values, format.PublicKeyField)
	values[format.UnderscoredPublicKeyField] = public
	encoded, err := marshal(values)
	if err != nil {
		return nil, errors.New("could not normalize secrets document; existing file was not changed")
	}
	canonical, err := handler.TransformScalarValues(encoded, func(v []byte) ([]byte, error) { return v, nil })
	if err != nil {
		return nil, errors.New("could not normalize secrets document; existing file was not changed")
	}
	return canonical, nil
}
