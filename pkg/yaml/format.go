// Package yaml provides a FormatHandler implementation for .eyaml (encrypted YAML) files.
package yaml

// YamlFormatter implements format.FormatHandler for .eyaml (encrypted YAML) files.
// It handles encryption and decryption of string values in YAML documents while
// preserving the document structure, comments, formatting, and non-string values.
type YamlFormatter struct{}
