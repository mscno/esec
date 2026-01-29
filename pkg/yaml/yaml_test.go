package yaml

import (
	"reflect"
	"strings"
	"testing"
)

func TestKeyExtraction(t *testing.T) {
	fh := YamlFormatter{}
	in := `_ESEC_PUBLIC_KEY: 6d79b7e50073e5e66a4581ed08bf1d9a03806cc4648cffeb6df71b5775e5eb08`
	expected := [32]byte{109, 121, 183, 229, 0, 115, 229, 230, 106, 69, 129, 237, 8, 191, 29, 154, 3, 128, 108, 196, 100, 140, 255, 235, 109, 247, 27, 87, 117, 229, 235, 8}
	key, err := fh.ExtractPublicKey([]byte(in))
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(key, expected) {
		t.Errorf("unexpected key: %#v", key)
	}
}

func TestKeyExtractionWithoutUnderscore(t *testing.T) {
	fh := YamlFormatter{}
	in := `ESEC_PUBLIC_KEY: 6d79b7e50073e5e66a4581ed08bf1d9a03806cc4648cffeb6df71b5775e5eb08`
	expected := [32]byte{109, 121, 183, 229, 0, 115, 229, 230, 106, 69, 129, 237, 8, 191, 29, 154, 3, 128, 108, 196, 100, 140, 255, 235, 109, 247, 27, 87, 117, 229, 235, 8}
	key, err := fh.ExtractPublicKey([]byte(in))
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(key, expected) {
		t.Errorf("unexpected key: %#v", key)
	}
}

func TestKeyExtractionMissing(t *testing.T) {
	fh := YamlFormatter{}
	in := `some_key: some_value`
	_, err := fh.ExtractPublicKey([]byte(in))
	if err == nil {
		t.Error("expected error for missing public key")
	}
}

func TestKeyExtractionInvalidYaml(t *testing.T) {
	fh := YamlFormatter{}
	in := `{invalid yaml`
	_, err := fh.ExtractPublicKey([]byte(in))
	if err == nil {
		t.Error("expected error for invalid yaml")
	}
}

func TestKeyExtractionEmptyDocument(t *testing.T) {
	fh := YamlFormatter{}
	in := ``
	_, err := fh.ExtractPublicKey([]byte(in))
	if err == nil {
		t.Error("expected error for empty document")
	}
}

func TestKeyExtractionTopLevelArray(t *testing.T) {
	fh := YamlFormatter{}
	in := `- item1
- item2`
	_, err := fh.ExtractPublicKey([]byte(in))
	if err == nil {
		t.Error("expected error for top-level array")
	}
}

func TestScalarValueTransformer(t *testing.T) {
	action := func(a []byte) ([]byte, error) {
		return []byte("E"), nil
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fh := &YamlFormatter{}
			act, err := fh.TransformScalarValues([]byte(tc.in), action)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			// Normalize whitespace for comparison
			actNorm := strings.TrimSpace(string(act))
			outNorm := strings.TrimSpace(tc.out)
			if actNorm != outNorm {
				t.Errorf("unexpected output:\ngot:  '%s'\nwant: '%s'", actNorm, outNorm)
			}
		})
	}
}

type testCase struct {
	name        string
	in          string
	out         string
	expectError bool
}

// "E" means encrypted.
var testCases = []testCase{
	{
		name: "simple encryption",
		in:   `a: b`,
		out:  `a: "E"`,
	},
	{
		name: "commenting with underscore",
		in:   `_a: b`,
		out:  `_a: b`,
	},
	{
		name: "multiple keys",
		in: `a: b
c: d`,
		out: `a: "E"
c: "E"`,
	},
	{
		name: "numbers not encrypted",
		in:   `a: 1`,
		out:  `a: 1`,
	},
	{
		name: "booleans not encrypted",
		in:   `a: true`,
		out:  `a: true`,
	},
	{
		name: "null not encrypted",
		in:   `a: null`,
		out:  `a: null`,
	},
	{
		name: "array elements encrypted",
		in:   `a: [b, c]`,
		out:  `a: ["E", "E"]`,
	},
	{
		name: "commenting arrays",
		in:   `_a: [b, c]`,
		out:  `_a: [b, c]`,
	},
	{
		name: "nested objects",
		in: `a:
  b: c`,
		out: `a:
    b: "E"`,
	},
	{
		name: "nested comment",
		in: `a:
  _b: c`,
		out: `a:
    _b: c`,
	},
	{
		name: "comments dont inherit",
		in: `_a:
  b: c`,
		out: `_a:
    b: "E"`,
	},
	{
		name: "public key skipped",
		in: `_ESEC_PUBLIC_KEY: abc123
secret: value`,
		out: `_ESEC_PUBLIC_KEY: abc123
secret: "E"`,
	},
	{
		name: "public key without underscore skipped",
		in: `ESEC_PUBLIC_KEY: abc123
secret: value`,
		out: `ESEC_PUBLIC_KEY: abc123
secret: "E"`,
	},
	{
		name: "deeply nested",
		in: `level1:
  level2:
    level3:
      secret: value`,
		out: `level1:
    level2:
        level3:
            secret: "E"`,
	},
	{
		name: "mixed types",
		in: `string: value
number: 42
bool: true
nested:
  inner: secret`,
		out: `string: "E"
number: 42
bool: true
nested:
    inner: "E"`,
	},
	{
		name:        "top level array rejected",
		in:          `- item1`,
		out:         ``,
		expectError: true,
	},
	{
		name:        "empty document",
		in:          ``,
		out:         ``,
		expectError: true,
	},
}

func TestPreservesComments(t *testing.T) {
	action := func(a []byte) ([]byte, error) {
		return []byte("E"), nil
	}

	in := `# File comment
_ESEC_PUBLIC_KEY: abc123  # inline comment
# Section comment
database:
    # Connection string
    password: secret  # sensitive`

	fh := &YamlFormatter{}
	act, err := fh.TransformScalarValues([]byte(in), action)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	result := string(act)
	// Verify comments are preserved
	if !strings.Contains(result, "# File comment") {
		t.Error("file comment not preserved")
	}
	if !strings.Contains(result, "# inline comment") {
		t.Error("inline comment not preserved")
	}
	if !strings.Contains(result, "# Section comment") {
		t.Error("section comment not preserved")
	}
	if !strings.Contains(result, "# Connection string") {
		t.Error("nested comment not preserved")
	}
	if !strings.Contains(result, "# sensitive") {
		t.Error("inline nested comment not preserved")
	}
}

func TestAnchorAliasRejected(t *testing.T) {
	action := func(a []byte) ([]byte, error) {
		return []byte("E"), nil
	}

	in := `defaults: &defaults
  adapter: postgres
development:
  <<: *defaults
  database: dev_db`

	fh := &YamlFormatter{}
	_, err := fh.TransformScalarValues([]byte(in), action)
	if err == nil {
		t.Error("expected error for anchors/aliases")
	}
	if !strings.Contains(err.Error(), "anchors and aliases") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestMultipleDocuments(t *testing.T) {
	action := func(a []byte) ([]byte, error) {
		return []byte("E"), nil
	}

	in := `---
doc1: value1
---
doc2: value2`

	fh := &YamlFormatter{}
	act, err := fh.TransformScalarValues([]byte(in), action)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	result := string(act)
	if !strings.Contains(result, `doc1: "E"`) {
		t.Error("first document not transformed")
	}
	if !strings.Contains(result, `doc2: "E"`) {
		t.Error("second document not transformed")
	}
}

func TestQuotedStrings(t *testing.T) {
	action := func(a []byte) ([]byte, error) {
		return []byte("E"), nil
	}

	in := `single_quoted: 'value'
double_quoted: "value"
unquoted: value`

	fh := &YamlFormatter{}
	act, err := fh.TransformScalarValues([]byte(in), action)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	result := string(act)
	// All should be transformed to double-quoted "E"
	if !strings.Contains(result, `single_quoted: "E"`) {
		t.Error("single quoted string not transformed correctly")
	}
	if !strings.Contains(result, `double_quoted: "E"`) {
		t.Error("double quoted string not transformed correctly")
	}
	if !strings.Contains(result, `unquoted: "E"`) {
		t.Error("unquoted string not transformed correctly")
	}
}

func TestMultilineStrings(t *testing.T) {
	action := func(a []byte) ([]byte, error) {
		// Return something that needs escaping
		return []byte("ENC[line1\nline2]"), nil
	}

	in := `multiline: |
  line1
  line2`

	fh := &YamlFormatter{}
	act, err := fh.TransformScalarValues([]byte(in), action)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	// Result should use double-quoted style with escaped newline
	result := string(act)
	if !strings.Contains(result, `multiline: "ENC[line1\nline2]"`) {
		t.Errorf("multiline string not transformed correctly: %s", result)
	}
}

func TestFloatNotEncrypted(t *testing.T) {
	action := func(a []byte) ([]byte, error) {
		return []byte("E"), nil
	}

	in := `float: 3.14
scientific: 1.0e10`

	fh := &YamlFormatter{}
	act, err := fh.TransformScalarValues([]byte(in), action)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	result := string(act)
	// Floats should not be encrypted
	if strings.Contains(result, `float: "E"`) {
		t.Error("float was incorrectly encrypted")
	}
	if strings.Contains(result, `scientific: "E"`) {
		t.Error("scientific notation was incorrectly encrypted")
	}
}
