package commands

import (
	"strings"

	"github.com/mscno/esec/pkg/projectfile"
)

// checkRequires refuses to run command when the project here (its
// esec.toml, from the current directory up) requires a newer esec than
// version. Commands that do not touch a project, and a directory with no
// readable project file, are not checked: the command reports the latter.
func checkRequires(command, version string) error {
	if name, _, _ := strings.Cut(command, " "); name == "capabilities" || name == "help" {
		return nil
	}
	f, _, err := projectfile.Find(".")
	if err != nil {
		return nil //nolint:nilerr // no project file, or one the command reports itself
	}
	return f.CheckRequires(version)
}
