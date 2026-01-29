// Package toml provides a FormatHandler implementation for .etoml (encrypted TOML) files.
package toml

// Formatter implements format.FormatHandler for .etoml (encrypted TOML) files.
// It handles encryption and decryption of string values in TOML documents while
// preserving the document structure, comments, formatting, and non-string values.
type Formatter struct{}
