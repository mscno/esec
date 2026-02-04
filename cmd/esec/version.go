package main

import "runtime/debug"

// Version is the version of the esec CLI tool, set at build time via ldflags.
// If not set, it attempts to read the version from Go module info (for go install).
var Version = getVersion()

func getVersion() string {
	// Check if version was set via ldflags (goreleaser)
	if version != "" {
		return version
	}
	// Fall back to Go module version (go install)
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "dev"
}

// version is set via ldflags: -X main.version=x.y.z
var version string
