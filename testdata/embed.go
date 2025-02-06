package testdata

import "embed"

//go:embed .ejson*
var TestEmbed embed.FS
