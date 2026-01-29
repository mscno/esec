// Package yaml provides a Handler implementation for .eyaml (encrypted YAML) files.
package yaml

// Formatter implements format.Handler for .eyaml (encrypted YAML) files.
// It handles encryption and decryption of string values in YAML documents while
// preserving the document structure, comments, formatting, and non-string values.
type Formatter struct{}
