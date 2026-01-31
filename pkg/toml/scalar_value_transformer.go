package toml

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/mscno/esec/pkg/format"
	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

// replacement tracks a string value replacement
type replacement struct {
	start int
	end   int
	value []byte
}

// TransformScalarValues walks a TOML document, replacing all actionable string values
// with the result of calling the passed-in `action` parameter with the content
// of the value. A value is actionable if it's a string scalar value (not a key),
// and its referencing key doesn't begin with an underscore. For each actionable
// value, the contents are replaced with the result of action. Everything else is
// unchanged, and document structure, comments, and formatting are preserved.
//
// Note that the underscore-to-disable-encryption syntax does not propagate
// down the hierarchy to children.
// That is:
//   - In {_a = "b"}, action will not be run at all.
//   - In {a = "b"}, action will be run with "b", and the return value will replace "b".
//   - In {k = {a = ["b"]}}, action will run on "b".
//   - In {_k = {a = ["b"]}}, action will run on "b".
//   - In {k = {_a = ["b"]}}, action will not run.
//
// Top-level arrays are rejected as a table is required for the public key.
func (f *Formatter) TransformScalarValues(
	data []byte,
	action func([]byte) ([]byte, error),
) ([]byte, error) {
	// First, verify the document is valid TOML
	var doc map[string]interface{}
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid toml: %v", err)
	}

	if len(doc) == 0 {
		return nil, fmt.Errorf("invalid toml: empty document")
	}

	// Use the unstable parser to find string values and their positions
	var p unstable.Parser
	p.KeepComments = true
	p.Reset(data)

	// Collect all replacements to make
	var replacements []replacement

	for p.NextExpression() {
		expr := p.Expression()
		if expr == nil {
			continue
		}

		switch expr.Kind { //nolint:exhaustive // We only care about Table, ArrayTable, and KeyValue
		case unstable.Table, unstable.ArrayTable:
			// Table headers are processed but their string values (the header itself) are not encrypted
			continue

		case unstable.KeyValue:
			// Get the key
			var keyParts []string
			for it := expr.Key(); it.Next(); {
				keyParts = append(keyParts, string(it.Node().Data))
			}

			// Check if the immediate key starts with underscore
			immediateKey := ""
			if len(keyParts) > 0 {
				immediateKey = keyParts[len(keyParts)-1]
			}

			// Skip public key fields entirely
			if immediateKey == format.PublicKeyField || immediateKey == format.UnderscoredPublicKeyField {
				continue
			}

			// Check if this key starts with underscore (should not encrypt its direct value)
			isComment := strings.HasPrefix(immediateKey, "_")

			// Get the value
			valueNode := expr.Value()
			if valueNode == nil {
				continue
			}

			// Collect string values to replace
			repls, err := collectStringReplacements(valueNode, action, isComment)
			if err != nil {
				return nil, err
			}
			replacements = append(replacements, repls...)
		}
	}

	if err := p.Error(); err != nil {
		return nil, fmt.Errorf("invalid toml: %v", err)
	}

	// Sort replacements by start position descending so we can apply them from end to start
	sort.Slice(replacements, func(i, j int) bool {
		return replacements[i].start > replacements[j].start
	})

	// Apply replacements
	result := make([]byte, len(data))
	copy(result, data)

	for _, r := range replacements {
		// Validate replacement bounds to prevent panic
		if r.start < 0 || r.end < 0 || r.start > len(result) || r.end > len(result) || r.start > r.end {
			return nil, fmt.Errorf("invalid replacement bounds: start=%d, end=%d, len=%d", r.start, r.end, len(result))
		}
		// Build new content with proper quoting
		quoted := quoteTomlString(string(r.value))
		newContent := make([]byte, 0, len(result)-r.end+r.start+len(quoted))
		newContent = append(newContent, result[:r.start]...)
		newContent = append(newContent, []byte(quoted)...)
		newContent = append(newContent, result[r.end:]...)
		result = newContent
	}

	return result, nil
}

// collectStringReplacements recursively collects replacements for string values in arrays and inline tables
func collectStringReplacements(
	node *unstable.Node,
	action func([]byte) ([]byte, error),
	parentKeyIsComment bool,
) ([]replacement, error) {
	var replacements []replacement

	switch node.Kind { //nolint:exhaustive // We only handle String, Array, and InlineTable values
	case unstable.String:
		if !parentKeyIsComment {
			// Get the unquoted string value
			strValue := string(node.Data)

			// Transform the value
			transformed, err := action([]byte(strValue))
			if err != nil {
				return nil, err
			}

			// Record the replacement
			replacements = append(replacements, replacement{
				start: int(node.Raw.Offset),
				end:   int(node.Raw.Offset) + int(node.Raw.Length),
				value: transformed,
			})
		}

	case unstable.Array:
		// Process array elements
		for it := node.Children(); it.Next(); {
			child := it.Node()
			repls, err := collectStringReplacements(child, action, parentKeyIsComment)
			if err != nil {
				return nil, err
			}
			replacements = append(replacements, repls...)
		}

	case unstable.InlineTable:
		// Process inline table key-value pairs
		for it := node.Children(); it.Next(); {
			child := it.Node()
			if child.Kind == unstable.KeyValue {
				// Get the key for this inline table entry
				var keyParts []string
				for keyIt := child.Key(); keyIt.Next(); {
					keyParts = append(keyParts, string(keyIt.Node().Data))
				}

				immediateKey := ""
				if len(keyParts) > 0 {
					immediateKey = keyParts[len(keyParts)-1]
				}

				// Skip public key fields
				if immediateKey == format.PublicKeyField || immediateKey == format.UnderscoredPublicKeyField {
					continue
				}

				// Check if this nested key starts with underscore
				isComment := strings.HasPrefix(immediateKey, "_")

				valueNode := child.Value()
				if valueNode != nil {
					repls, err := collectStringReplacements(valueNode, action, isComment)
					if err != nil {
						return nil, err
					}
					replacements = append(replacements, repls...)
				}
			}
		}
	}

	return replacements, nil
}

// quoteTomlString properly quotes a string for TOML output
func quoteTomlString(s string) string {
	var buf bytes.Buffer
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\b':
			buf.WriteString("\\b")
		case '\t':
			buf.WriteString("\\t")
		case '\n':
			buf.WriteString("\\n")
		case '\f':
			buf.WriteString("\\f")
		case '\r':
			buf.WriteString("\\r")
		case '"':
			buf.WriteString("\\\"")
		case '\\':
			buf.WriteString("\\\\")
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
	return buf.String()
}
