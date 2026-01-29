package testdata

import "embed"

//go:embed .ejson* .eyaml* .etoml*
var TestEmbed embed.FS
