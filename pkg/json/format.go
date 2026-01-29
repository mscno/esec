// Package json provides a FormatHandler implementation for .ejson (encrypted JSON) files.
package json

// JsonFormatter implements format.FormatHandler for .ejson (encrypted JSON) files.
// It handles encryption and decryption of string values in JSON documents while
// preserving the document structure, formatting, and non-string values.
type JsonFormatter struct{}
