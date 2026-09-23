package main

import (
	"fmt"
	"runtime/debug"
)

// Version is the version of the esec CLI tool, set at build time via ldflags.
// If not set, it attempts to read the version from Go module info (for go install).
var Version = buildVersion()

// These are set via ldflags, e.g.: -X main.version=x.y.z -X main.commit=abc123 -X main.date=2026-01-01
var (
	version string
	commit  string
	date    string
)

func buildVersion() string {
	v := version
	if v == "" {
		// Fall back to Go module version (go install)
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
			v = info.Main.Version
		} else {
			v = "dev"
		}
	}
	if commit != "" && date != "" {
		return fmt.Sprintf("%s (commit: %s, built: %s)", v, commit, date)
	}
	if commit != "" {
		return fmt.Sprintf("%s (commit: %s)", v, commit)
	}
	return v
}
