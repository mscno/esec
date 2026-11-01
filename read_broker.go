package esec

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/mscno/esec/pkg/secretstore"
)

// ReadInspection reports metadata only. Unknown states never claim a read is usable.
type ReadInspection struct {
	*ReadTarget

	Route    string      `json:"route"`
	Key      string      `json:"key_availability"`
	Reader   string      `json:"reader"`
	Broker   string      `json:"broker"`
	Consent  string      `json:"consent"`
	Hardware string      `json:"hardware"`
	Blockers []ReadError `json:"blockers"`
}

// ReadSocket is shared with the vault daemon, without depending on esec-vault.
func ReadSocket() string {
	if p := os.Getenv("ESEC_VAULT_SOCK"); p != "" {
		return p
	}
	return filepath.Join(secretstore.Home(), "run", "agent.sock")
}

type readRequest struct {
	Op      string `json:"op"`
	Project string `json:"project"`
	Env     string `json:"env"`
	Path    string `json:"path"`
	Format  string `json:"format"`
	Digest  string `json:"digest,omitempty"`
	Session string `json:"session,omitempty"`
	Content []byte `json:"content,omitempty"`
	Seal    []byte `json:"seal,omitempty"`
	Host    string `json:"host,omitempty"`
}
type readResponse struct {
	OK         bool            `json:"ok"`
	Error      string          `json:"error"`
	Code       string          `json:"code"`
	Document   []byte          `json:"document"`
	Inspection *ReadInspection `json:"inspection"`
}

func brokerCall(t *ReadTarget, o ReadOptions, op string) (*readResponse, error) {
	req, sock, err := prepareReadRequest(t, o, op)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return nil, &ReadError{"daemon_unavailable", "start or install the service with esec vault setup: " + err.Error()}
	}
	defer conn.Close()
	timeout := 4 * time.Minute
	if op == "inspect_read" {
		timeout = 2 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var response readResponse
	if err := json.NewDecoder(io.LimitReader(conn, 32<<20)).Decode(&response); err != nil {
		return nil, err
	}
	if !response.OK {
		code := response.Code
		if code == "" {
			code = "broker_read_failed"
		}
		if strings.HasPrefix(response.Error, "unknown op") {
			return nil, &ReadError{"daemon_upgrade_required", "install esec-vault v0.28.0 or later and run esec vault daemon upgrade"}
		}
		return nil, &ReadError{code, response.Error}
	}
	return &response, nil
}
func readBroker(t *ReadTarget, o ReadOptions) ([]byte, error) {
	response, err := brokerCall(t, o, "read_document")
	if err != nil {
		return nil, err
	}
	if response.Document == nil {
		return nil, &ReadError{"daemon_upgrade_required", "run esec vault daemon upgrade; the service must support document reads"}
	}
	pub, err := ExtractPublicKey(response.Document, t.Format)
	if err != nil || !strings.EqualFold(hex.EncodeToString(pub[:]), t.PublicKey) {
		return nil, &ReadError{"invalid_broker_response", "the returned document is not the resolved file's key and format"}
	}
	return response.Document, nil
}

// InspectLocalRead never reads secret-store entries, opens seals, or requests consent.
func InspectLocalRead(t *ReadTarget, o ReadOptions) *ReadInspection {
	i := &ReadInspection{ReadTarget: t, Route: t.Route(), Key: "absent", Reader: "not_verified", Broker: "not_required", Consent: "not_required", Hardware: "not_required", Blockers: []ReadError{}}
	dir := readKeyDirectory(t, o.KeyDir)
	for _, path := range resolveKeyringCandidates(dir) {
		if _, err := os.Stat(path); err == nil {
			i.Key = "present_unverified"
		}
	}
	if _, _, ok := ResolveKey(envMap(), KeySuffixes(t.Environment), nil); ok {
		i.Key = "configured_unverified"
	}
	if t.Seal != "" && i.Key == "absent" {
		i.Key = "sealed_identity_unverified"
	}
	if i.Route == "daemon" {
		i.Key = "hardware_protected"
		i.Consent = "required"
		i.Hardware = "not_verified"
	}
	if i.Route == "workload_identity" || i.Route == "workload_key" {
		i.Key = "identity_configured_unverified"
	}
	if o.PrivateKey != "" && t.Guard == "none" {
		i.Key = "explicit_key_unverified"
	}
	if i.Route == "direct" && o.PrivateKey == "" {
		_, idErr := os.Stat(filepath.Join(secretstore.Home(), "identity.esec"))
		if i.Key == "absent" || (i.Key == "sealed_identity_unverified" && idErr != nil && !hasReadIdentity()) {
			if t.Project != "" {
				i.Route = "daemon"
				i.Consent = "required"
			} else {
				i.Blockers = append(i.Blockers, ReadError{"key_unavailable", "no local key or sealed identity was found"})
			}
		}
	}
	return i
}

// InspectRead enriches the local plan with non-interactive daemon metadata.
func InspectRead(t *ReadTarget, o ReadOptions) *ReadInspection {
	i := InspectLocalRead(t, o)
	if o.Socket == "" && os.Getenv("ESEC_VAULT_FORWARD") != "" {
		if i.Route == "daemon" {
			i.Broker = "forwarded"
			i.Consent = "remote_approval_required"
			i.Hardware = "remote_not_verified"
			i.Blockers = append(i.Blockers, ReadError{"hardware_approval_required", "the desktop hosting the forwarded broker must approve this read"})
		}
		return i
	}
	// Broker inspection is optional for a direct read and cannot trigger dialogs.
	response, err := brokerCall(t, o, "inspect_read")
	if err == nil && response.Inspection != nil {
		remote := response.Inspection
		i.Reader = remote.Reader
		i.Broker = remote.Broker
		if i.Route == "daemon" {
			i.Consent = remote.Consent
			i.Hardware = remote.Hardware
			i.Blockers = remote.Blockers
		}
		return i
	}
	if i.Route == "daemon" {
		i.Broker = "unavailable"
		var re *ReadError
		if errors.As(err, &re) {
			i.Blockers = append(i.Blockers, *re)
		} else {
			i.Blockers = append(i.Blockers, ReadError{"daemon_unavailable", "run esec vault setup, or upgrade the existing service"})
		}
	}
	return i
}

// WriteInspection renders the same public metadata as --json, never ciphertext.
func WriteInspection(w io.Writer, i *ReadInspection) error {
	_, err := fmt.Fprintf(w, "Project       %s\nEnvironment   %s\nFile          %s\nPublic key    %s\nReader        %s\nKey           %s\nSeal          %s\nGuard         %s\nRoute         %s\nBroker        %s\nConsent       %s\nHardware      %s\n", safeInspection(i.Project), safeInspection(i.Environment), safeInspection(i.Path), i.PublicKey, safeInspection(i.Reader), i.Key, i.SealStatus, i.Guard, i.Route, i.Broker, i.Consent, i.Hardware)
	if err != nil {
		return err
	}
	for _, b := range i.Blockers {
		if _, err = fmt.Fprintf(w, "Blocked       %s: %s\n", b.Code, safeInspection(b.Detail)); err != nil {
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

func prepareReadRequest(t *ReadTarget, o ReadOptions, op string) (readRequest, string, error) {
	sock := o.Socket
	if sock == "" {
		sock = ReadSocket()
	}
	var forwardedSeal []byte
	forwarded := o.Socket == "" && os.Getenv("ESEC_VAULT_FORWARD") != ""
	if forwarded {
		if op == "inspect_read" {
			return readRequest{}, "", &ReadError{"inspection_unavailable", "forwarded inspection is metadata-only on this machine"}
		}
		if t.Guard == "none" {
			return readRequest{}, "", &ReadError{"forward_guard_required", "forwarded reads require a guarded environment"}
		}
		if t.KeyEnvironment != t.Environment {
			return readRequest{}, "", &ReadError{"environment_ambiguous", "forward the exact environment holding the sealed key: " + t.KeyEnvironment}
		}
		var err error
		forwardedSeal, err = os.ReadFile(t.Seal)
		if err != nil {
			return readRequest{}, "", err
		}
		sock = os.Getenv("ESEC_VAULT_FORWARD")
	}
	req := readRequest{Op: op, Project: t.Project, Env: t.Environment, Path: t.Path, Format: string(t.Format), Digest: t.Digest, Session: o.Session}
	if forwarded {
		req.Content = t.Content
		req.Seal = forwardedSeal
		req.Host, _ = os.Hostname()
	}

	return req, sock, nil
}
