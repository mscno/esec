package esec

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
)

// ReadInspection reports local metadata only. It never opens a key or a seal.
type ReadInspection struct {
	*ReadTarget

	Route    string      `json:"route"`
	Key      string      `json:"key_availability"`
	Hardware string      `json:"hardware"`
	Blockers []ReadError `json:"blockers"`
}

// InspectLocalRead does not access keychain entries, plugins, or services.
func InspectLocalRead(t *ReadTarget, o ReadOptions) *ReadInspection {
	i := &ReadInspection{ReadTarget: t, Route: t.Route(), Key: "absent", Hardware: "not_required", Blockers: []ReadError{}}
	if t.Standalone {
		i.Key = "age_sealed_unverified"
		if t.Access == "production" {
			i.Hardware = "depends_on_recipient"
		}
		return i
	}
	if i.Route == "blocked" {
		i.Key = "legacy_guarded"
		i.Hardware = "not_verified"
		i.Blockers = append(i.Blockers, *legacyGuardError())
		return i
	}
	if i.Route == "workload_identity" || i.Route == "workload_key" {
		i.Key = "explicit_credential_unverified"
		return i
	}
	for _, path := range resolveKeyringCandidates(readKeyDirectory(t, o.KeyDir)) {
		if _, err := os.Stat(path); err == nil {
			i.Key = "present_unverified"
		}
	}
	if _, _, ok := ResolveKey(envMap(), KeySuffixes(t.Environment), nil); ok {
		i.Key = "configured_unverified"
	}
	if o.PrivateKey != "" {
		i.Key = "explicit_key_unverified"
	}
	if t.Seal != "" && i.Key == "absent" {
		i.Key = "sealed_identity_unverified"
	}
	if i.Key == "absent" {
		i.Blockers = append(i.Blockers, ReadError{"key_unavailable", "no local key or sealed identity was found; provide the existing key or recover an age identity"})
	}
	return i
}

// InspectRead is a metadata-only local inspection on every platform.
func InspectRead(t *ReadTarget, o ReadOptions) *ReadInspection { return InspectLocalRead(t, o) }

// WriteInspection renders public metadata, never ciphertext or credentials.
func WriteInspection(w io.Writer, i *ReadInspection) error {
	_, err := fmt.Fprintf(w, "Project       %s\nEnvironment   %s\nFile          %s\nPublic key    %s\nKey           %s\nSeal          %s\nGuard         %s\nRoute         %s\nHardware      %s\n", safeInspection(i.Project), safeInspection(i.Environment), safeInspection(i.Path), i.PublicKey, i.Key, i.SealStatus, i.Guard, i.Route, i.Hardware)
	if err != nil {
		return err
	}
	for _, b := range i.Blockers {
		if _, err := fmt.Fprintf(w, "Blocked       %s: %s\n", b.Code, safeInspection(b.Detail)); err != nil {
			return err
		}
	}
	return nil
}

func safeInspection(s string) string {
	return strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, s)
}
