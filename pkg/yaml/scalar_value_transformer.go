package yaml

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/mscno/esec/pkg/format"
	"gopkg.in/yaml.v3"
)

// TransformScalarValues walks a YAML document, replacing all actionable nodes
// with the result of calling the passed-in `action` parameter with the content
// of the node. A node is actionable if it's a string scalar value (not a key),
// and its referencing key doesn't begin with an underscore. For each actionable
// node, the contents are replaced with the result of action. Everything else is
// unchanged, and document structure, comments, and formatting are preserved.
//
// Note that the underscore-to-disable-encryption syntax does not propagate
// down the hierarchy to children.
// That is:
//   - In {_a: b}, action will not be run at all.
//   - In {a: b}, action will be run with "b", and the return value will replace "b".
//   - In {k: {a: [b]}}, action will run on "b".
//   - In {_k: {a: [b]}}, action will run on "b".
//   - In {k: {_a: [b]}}, action will not run.
//
// YAML anchors and aliases are rejected as they break authentication.
// Top-level arrays are rejected as a mapping is required for the public key.
func (f *YamlFormatter) TransformScalarValues(
	data []byte,
	action func([]byte) ([]byte, error),
) ([]byte, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var documents []*yaml.Node

	// Parse all documents in the stream
	for {
		var node yaml.Node
		err := decoder.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid yaml: %v", err)
		}
		documents = append(documents, &node)
	}

	if len(documents) == 0 {
		return nil, fmt.Errorf("invalid yaml: empty document")
	}

	// Transform each document
	for _, doc := range documents {
		if err := walkNode(doc, action, false); err != nil {
			return nil, err
		}
	}

	// Encode back to YAML
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(4) // SOPS default

	for _, doc := range documents {
		if err := encoder.Encode(doc); err != nil {
			return nil, fmt.Errorf("failed to encode yaml: %v", err)
		}
	}

	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("failed to close yaml encoder: %v", err)
	}

	return buf.Bytes(), nil
}

// walkNode recursively walks the YAML node tree and applies the action function
// to actionable string scalar values.
func walkNode(node *yaml.Node, action func([]byte) ([]byte, error), parentKeyIsComment bool) error {
	switch node.Kind {
	case yaml.DocumentNode:
		// Validate that the document contains a mapping at the top level
		if len(node.Content) > 0 && node.Content[0].Kind == yaml.SequenceNode {
			return fmt.Errorf("invalid yaml: top-level arrays are not supported, a mapping with public key is required")
		}
		for _, child := range node.Content {
			if err := walkNode(child, action, false); err != nil {
				return err
			}
		}

	case yaml.MappingNode:
		// Process key-value pairs
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			// Skip public key fields entirely
			if keyNode.Kind == yaml.ScalarNode {
				if keyNode.Value == format.PublicKeyField || keyNode.Value == format.UnderscoredPublicKeyField {
					continue
				}
			}

			// Check if this key starts with underscore (comment)
			isComment := keyNode.Kind == yaml.ScalarNode && strings.HasPrefix(keyNode.Value, "_")

			// Recurse into the value
			if err := walkNode(valueNode, action, isComment); err != nil {
				return err
			}
		}

	case yaml.SequenceNode:
		// Process array elements
		for _, child := range node.Content {
			if err := walkNode(child, action, parentKeyIsComment); err != nil {
				return err
			}
		}

	case yaml.ScalarNode:
		// Only transform string scalars that are not under a comment key
		if !parentKeyIsComment && node.Tag == "!!str" {
			transformed, err := action([]byte(node.Value))
			if err != nil {
				return err
			}
			node.Value = string(transformed)
			// Use double-quoted style for encrypted values to handle special characters
			node.Style = yaml.DoubleQuotedStyle
		}

	case yaml.AliasNode:
		return fmt.Errorf("invalid yaml: anchors and aliases are not supported (breaks authentication)")
	}

	return nil
}
