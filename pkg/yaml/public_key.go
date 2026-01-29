package yaml

import (
	"fmt"

	"github.com/mscno/esec/pkg/format"
	"gopkg.in/yaml.v3"
)

// ExtractPublicKey parses the YAML data and returns the ESEC_PUBLIC_KEY value.
// It looks for either "_ESEC_PUBLIC_KEY" (preferred) or "ESEC_PUBLIC_KEY" fields
// at the top level of the YAML document.
func (f *YamlFormatter) ExtractPublicKey(data []byte) ([32]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return [32]byte{}, fmt.Errorf("invalid yaml: %v", err)
	}

	// Empty document
	if root.Kind == 0 || len(root.Content) == 0 {
		return [32]byte{}, fmt.Errorf("invalid yaml: empty document")
	}

	// The root node should be a document containing a mapping
	doc := &root
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return [32]byte{}, fmt.Errorf("invalid yaml: empty document")
		}
		doc = doc.Content[0]
	}

	if doc.Kind != yaml.MappingNode {
		return [32]byte{}, fmt.Errorf("invalid yaml: top level must be a mapping, got %v", doc.Kind)
	}

	// Search for the public key in the mapping
	for i := 0; i < len(doc.Content); i += 2 {
		keyNode := doc.Content[i]
		valueNode := doc.Content[i+1]

		if keyNode.Kind != yaml.ScalarNode {
			continue
		}

		if keyNode.Value == format.UnderscoredPublicKeyField || keyNode.Value == format.PublicKeyField {
			if valueNode.Kind != yaml.ScalarNode {
				return [32]byte{}, fmt.Errorf("%w: public key is not a string", format.ErrPublicKeyInvalid)
			}
			key, err := format.ParseKey(valueNode.Value)
			if err != nil {
				return [32]byte{}, fmt.Errorf("%w: %v", format.ErrPublicKeyInvalid, err)
			}
			return key, nil
		}
	}

	return [32]byte{}, format.ErrPublicKeyMissing
}
