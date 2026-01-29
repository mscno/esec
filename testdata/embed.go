package testdata

import "embed"

//go:embed .ejson* .eyaml*
var TestEmbed embed.FS
