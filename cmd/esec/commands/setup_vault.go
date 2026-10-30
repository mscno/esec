package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	vaultProbeTimeout = 8 * time.Second
	vaultApplyTimeout = 2 * time.Minute
)

// vaultInfo is what esec can learn by running esec-vault. It holds no secret.
type vaultInfo struct {
	Installed        bool
	SignedIn         bool
	Server           string
	Login            string
	Identity         string
	Personal         string
	Namespaces       []vaultNamespace
	HasSecurityKey   bool
	KeysKnown        bool
	CheckUnsupported bool
	StatusErr        string
}

// vaultNamespace is a tenant the signed-in user may create projects in.
type vaultNamespace struct {
	Name         string
	Kind         string
	YouMayCreate bool
	Reason       string
}

func (v *vaultInfo) summary() string {
	if v == nil || !v.Installed {
		return "esec-vault is not installed. The name will not be reserved, and keys stay on this machine, unless you cancel and install it (" + vaultInstall + ")."
	}
	if !v.SignedIn {
		msg := "esec-vault is installed but not signed in."
		if v.StatusErr != "" {
			msg += " " + v.StatusErr
		}
		return msg + " Run esec vault login, or continue to keep keys on this machine only."
	}
	who := v.Identity
	if who == "" {
		who = v.Login
	}
	if who == "" {
		who = "your account"
	}
	s := "Signed in as " + who
	if v.Server != "" {
		s += " at " + v.Server
	}
	s += "."
	if !v.KeysKnown {
		s += " Security keys could not be listed."
	} else if !v.HasSecurityKey {
		s += " No security key is enrolled (esec vault security-keys add)."
	}
	return s
}

// projectCheck is the read-only result of `esec vault project check ID --json`.
// The command creates nothing and prints no secret. relation is available,
// yours, taken, reserved, legacy, system or alias.
type projectCheck struct {
	Project      string
	Available    bool
	Relation     string
	Namespace    *vaultNamespace
	MayCreate    *bool
	LocalKeyring bool
	Error        string
	known        bool
}

// lookVault finds esec-vault. Tests replace it.
var lookVault = func() (string, error) { return exec.LookPath("esec-vault") }

// runVault runs esec-vault and returns its output. It never receives a
// private key. Tests replace it.
var runVault = execVault

func execVault(dir string, timeout time.Duration, args ...string) (stdout, stderr []byte, code int, err error) {
	bin, err := lookVault()
	if err != nil {
		return nil, nil, 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) // binary is esec-vault from PATH; arguments are constructed here
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	runErr := cmd.Run()
	if runErr == nil {
		return out.Bytes(), errb.Bytes(), 0, nil
	}
	var ee *exec.ExitError
	if errors.As(runErr, &ee) {
		return out.Bytes(), errb.Bytes(), ee.ExitCode(), nil
	}
	if ctx.Err() != nil {
		return out.Bytes(), errb.Bytes(), -1, fmt.Errorf("esec-vault timed out")
	}
	return out.Bytes(), errb.Bytes(), -1, runErr
}

func loadVault(dir string) *vaultInfo {
	v := &vaultInfo{}
	if _, err := lookVault(); err != nil {
		return v
	}
	v.Installed = true
	stdout, stderr, code, err := runVault(dir, vaultProbeTimeout, "status", "--json")
	if err != nil || code != 0 {
		v.StatusErr = clip(stderr)
		if v.StatusErr == "" && err != nil {
			v.StatusErr = err.Error()
		}
		return v
	}
	parseStatus(v, stdout)
	if len(v.Namespaces) == 0 {
		if out, _, c, e := runVault(dir, vaultProbeTimeout, "org", "--json"); e == nil && c == 0 {
			v.Namespaces = parseNamespaces(out)
		}
	}
	out, se, c, e := runVault(dir, vaultProbeTimeout, "security-keys", "list", "--json")
	switch {
	case e == nil && c == 0:
		v.KeysKnown = true
		v.HasSecurityKey = jsonHasItems(out)
	case vaultUnknown(c, se):
		v.KeysKnown = false
	default:
		v.KeysKnown = true
	}
	return v
}

func parseStatus(v *vaultInfo, data []byte) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil {
		return
	}
	v.Server = jsonString(raw, "server", "url")
	v.Login = jsonString(raw, "login", "github", "user", "username")
	if nested, ok := raw["vault_server"]; ok {
		var inner map[string]json.RawMessage
		if json.Unmarshal(nested, &inner) == nil {
			v.Server = firstNonEmpty(v.Server, jsonString(inner, "server", "url"))
			v.Login = firstNonEmpty(v.Login, jsonString(inner, "login", "user"))
		}
	}
	v.Personal = jsonString(raw, "personal", "personal_namespace")
	// status.identity is a fingerprint. reader is the person.
	v.Identity = jsonString(raw, "reader")
	if id := jsonInt(raw, "github_id"); v.Identity == "" && v.Login != "" && id != 0 {
		v.Identity = fmt.Sprintf("%s (gh:%d)", v.Login, id)
	}
	if b, ok := jsonBool(raw, "signed_in", "logged_in", "authenticated"); ok {
		v.SignedIn = b
	} else {
		v.SignedIn = v.Server != "" && (v.Login != "" || v.Identity != "")
	}
	v.Namespaces = parseNamespaces(data)
	if v.Personal != "" && !hasNamespace(v.Namespaces, v.Personal) {
		v.Namespaces = append([]vaultNamespace{{
			Name: v.Personal, Kind: "personal", YouMayCreate: true,
		}}, v.Namespaces...)
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func hasNamespace(list []vaultNamespace, name string) bool {
	for _, n := range list {
		if strings.EqualFold(n.Name, name) {
			return true
		}
	}
	return false
}

func parseNamespaces(data []byte) []vaultNamespace {
	var found []vaultNamespace
	var walk func(json.RawMessage)
	walk = func(raw json.RawMessage) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			return
		}
		switch raw[0] {
		case '[':
			var arr []json.RawMessage
			if json.Unmarshal(raw, &arr) != nil {
				return
			}
			for _, item := range arr {
				item = bytes.TrimSpace(item)
				if len(item) > 0 && item[0] == '"' {
					var name string
					if json.Unmarshal(item, &name) == nil && name != "" && !hasNamespace(found, name) {
						found = append(found, vaultNamespace{Name: name, YouMayCreate: true})
					}
					continue
				}
				walk(item)
			}
		case '{':
			var obj map[string]json.RawMessage
			if json.Unmarshal(raw, &obj) != nil {
				return
			}
			if name := jsonString(obj, "name", "handle"); name != "" {
				if kind := jsonString(obj, "kind", "type"); kind != "" || jsonString(obj, "you_may_create") != "" || hasKey(obj, "you_may_create") {
					ns := vaultNamespace{Name: name, Kind: kind, YouMayCreate: true}
					if b, ok := jsonBool(obj, "you_may_create"); ok {
						ns.YouMayCreate = b
					}
					ns.Reason = jsonString(obj, "reason")
					if !hasNamespace(found, name) {
						found = append(found, ns)
					}
				}
			}
			for _, key := range []string{"orgs", "organisations", "organizations", "namespaces", "tenants"} {
				if raw, ok := obj[key]; ok {
					walk(raw)
				}
			}
		}
	}
	walk(data)
	return found
}

func hasKey(obj map[string]json.RawMessage, key string) bool {
	_, ok := obj[key]
	return ok
}

// vaultProjectCheck runs the read-only name check. unsupported is true when
// this esec-vault does not have the command. A taken name is not an error
// here; the caller reads the result.
func vaultProjectCheck(dir, project string) (projectCheck, bool, error) {
	stdout, stderr, code, err := runVault(dir, vaultProbeTimeout, "project", "check", project, "--json")
	if err != nil {
		return projectCheck{}, false, err
	}
	if vaultUnknown(code, stderr) {
		return projectCheck{}, true, nil
	}
	if code != 0 {
		msg := clip(stderr)
		if msg == "" {
			msg = clip(stdout)
		}
		if msg == "" {
			msg = fmt.Sprintf("exit %d", code)
		}
		return projectCheck{}, false, fmt.Errorf("vault check failed: %s", msg)
	}
	chk, err := parseProjectCheck(stdout)
	if err != nil {
		return projectCheck{}, false, fmt.Errorf("vault check returned invalid JSON")
	}
	return chk, false, nil
}

func parseProjectCheck(data []byte) (projectCheck, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return projectCheck{}, err
	}
	var c projectCheck
	_, c.known = raw["relation"]
	if _, ok := raw["available"]; ok {
		c.known = true
	}
	c.Project = jsonString(raw, "project")
	if b, ok := jsonBool(raw, "available"); ok {
		c.Available = b
	}
	c.Relation = jsonString(raw, "relation")
	c.Error = jsonString(raw, "error")
	if b, ok := jsonBool(raw, "local_keyring"); ok {
		c.LocalKeyring = b
	}
	if nsRaw, ok := raw["namespace"]; ok {
		var ns map[string]json.RawMessage
		if json.Unmarshal(nsRaw, &ns) == nil {
			n := &vaultNamespace{
				Name:         jsonString(ns, "name"),
				Kind:         jsonString(ns, "kind"),
				Reason:       jsonString(ns, "reason"),
				YouMayCreate: true,
			}
			if b, ok := jsonBool(ns, "you_may_create"); ok {
				n.YouMayCreate = b
				c.MayCreate = &b
			}
			c.Namespace = n
		}
	}
	return c, nil
}

// allows reports whether this check permits creating or adding.
func (c projectCheck) allows(add bool) error {
	if !c.known {
		return fmt.Errorf("vault check did not say whether the name is free")
	}
	if c.Error != "" {
		return fmt.Errorf("%s", c.Error)
	}
	if c.MayCreate != nil && !*c.MayCreate {
		if c.Namespace != nil && c.Namespace.Reason != "" {
			return fmt.Errorf("%s", c.Namespace.Reason)
		}
		name := ""
		if c.Namespace != nil {
			name = c.Namespace.Name
		}
		return fmt.Errorf("you cannot create projects in %s", name)
	}
	rel := c.Relation
	if rel == "" {
		if c.Available {
			rel = "available"
		} else {
			rel = "taken"
		}
	}
	switch rel {
	case "available":
		return nil
	case "yours":
		if add {
			return nil
		}
		return fmt.Errorf("project %s already exists on the vault server; use that checkout, or pick another name", c.Project)
	case "taken", "reserved", "legacy", "system", "alias":
		msg := fmt.Sprintf("project %s is %s", c.Project, rel)
		if c.Namespace != nil && c.Namespace.Reason != "" {
			msg += ": " + c.Namespace.Reason
		}
		return fmt.Errorf("%s", msg)
	default:
		return fmt.Errorf("vault check for %s did not say whether the name is free", c.Project)
	}
}

func (p setupPlan) checkName(sc *setupContext) error {
	if p.Local || sc == nil || sc.Vault == nil || !sc.Vault.Installed || !sc.Vault.SignedIn {
		return nil
	}
	chk, unsupported, err := vaultProjectCheck(sc.Dir, p.Project)
	if unsupported {
		sc.Vault.CheckUnsupported = true
		return fail("this esec-vault cannot check whether a project name is free", "upgrade esec-vault, or pass --local to keep keys on this machine only")
	}
	if err != nil {
		return fail(err.Error(), "fix the vault connection, or pass --local to keep keys on this machine only")
	}
	sc.Check = &chk
	if err := chk.allows(p.Add); err != nil {
		hint := "pick another name"
		if chk.Namespace != nil && !chk.Namespace.YouMayCreate {
			hint = "create the tenant first: esec vault org create, or esec vault personal choose"
		}
		return fail(err.Error(), hint)
	}
	if chk.LocalKeyring && !p.Add {
		return fmt.Errorf("this machine already has a keyring for %s", p.Project)
	}
	return nil
}

func (p setupPlan) route(sc *setupContext) (bool, error) {
	if err := p.validate(sc); err != nil {
		return false, err
	}
	if p.Local {
		if p.needsVault() {
			return false, fail("guard and readers need esec vault; omit --local, or drop --guard and --with", "esec vault login, then run esec setup again")
		}
		return false, nil
	}
	v := sc.Vault
	if v == nil || !v.Installed {
		return false, fail("esec-vault is not installed, so the name cannot be reserved", "install it ("+vaultInstall+"), or pass --local to keep keys on this machine only")
	}
	if !v.SignedIn {
		return false, fail("esec vault is not signed in, so the name cannot be reserved", "esec vault login, or pass --local to keep keys on this machine only")
	}
	if err := p.checkName(sc); err != nil {
		return false, err
	}
	if v.CheckUnsupported {
		return false, fail("this esec-vault cannot check whether a project name is free", "upgrade esec-vault, or pass --local to keep keys on this machine only")
	}
	return true, nil
}

type vaultInitResult struct {
	Synced *bool `json:"synced"`
	Pushed *bool `json:"pushed"`
}

func applyVault(ctx *cliCtx, sc *setupContext, p setupPlan) error {
	args := []string{"project", "init", p.Project, "--env", strings.Join(p.Envs, ","), "--format", p.Format, "--dir", sc.Dir, "--json"}
	for _, env := range p.Envs {
		level := p.Guard[env]
		if level != "" && level != projectfileGuardNone() {
			args = append(args, "--guard", env+"="+level)
		}
	}
	stdout, stderr, code, err := runVault(sc.Dir, vaultApplyTimeout, args...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("esec vault project init: %s", clip(stderr))
	}
	say(ctx, "created %s through esec vault", p.Project)
	for _, env := range p.Envs {
		file, ferr := p.filename(env, sc)
		if ferr == nil {
			say(ctx, "environment %s (%s)", env, file)
		}
	}
	if needsSync(stdout) {
		_, se, c, serr := runVault(sc.Dir, vaultApplyTimeout, "sync")
		if serr != nil {
			return fmt.Errorf("esec vault sync: %w", serr)
		}
		if c != 0 {
			return fmt.Errorf("esec vault sync: %s", clip(se))
		}
		say(ctx, "synced keys")
	}
	for _, reader := range p.With {
		sargs := []string{"share", strings.Join(p.Envs, ","), "--with", reader, "--project", p.Project, "--yes"}
		_, se, c, serr := runVault(sc.Dir, vaultApplyTimeout, sargs...)
		if serr != nil {
			return fmt.Errorf("esec vault share --with %s: %w", reader, serr)
		}
		if c != 0 {
			return fmt.Errorf("esec vault share --with %s: %s", reader, clip(se))
		}
		say(ctx, "shared %s with %s", strings.Join(p.Envs, ", "), reader)
	}
	return nil
}

func projectfileGuardNone() string { return "none" }

func needsSync(stdout []byte) bool {
	var res vaultInitResult
	if json.Unmarshal(bytes.TrimSpace(stdout), &res) != nil {
		return false
	}
	if res.Synced != nil && !*res.Synced {
		return true
	}
	if res.Pushed != nil && !*res.Pushed {
		return true
	}
	return false
}

func vaultUnknown(code int, stderr []byte) bool {
	if code != 80 {
		return false
	}
	s := strings.ToLower(string(stderr))
	return strings.Contains(s, "unexpected") || strings.Contains(s, "unknown") || strings.Contains(s, "usage")
}

func jsonString(obj map[string]json.RawMessage, keys ...string) string {
	for _, key := range keys {
		raw, ok := obj[key]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return s
		}
	}
	return ""
}

func jsonBool(obj map[string]json.RawMessage, keys ...string) (bool, bool) {
	for _, key := range keys {
		raw, ok := obj[key]
		if !ok {
			continue
		}
		var b bool
		if json.Unmarshal(raw, &b) == nil {
			return b, true
		}
	}
	return false, false
}

func jsonInt(obj map[string]json.RawMessage, keys ...string) int64 {
	for _, key := range keys {
		raw, ok := obj[key]
		if !ok {
			continue
		}
		var n int64
		if json.Unmarshal(raw, &n) == nil {
			return n
		}
	}
	return 0
}

func jsonHasItems(data []byte) bool {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return false
	}
	var arr []json.RawMessage
	if json.Unmarshal(data, &arr) == nil {
		return len(arr) > 0
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) != nil {
		return false
	}
	for _, key := range []string{"keys", "security_keys", "items"} {
		raw, ok := obj[key]
		if !ok {
			continue
		}
		var inner []json.RawMessage
		if json.Unmarshal(raw, &inner) == nil {
			return len(inner) > 0
		}
	}
	return false
}

func clip(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 400 {
		s = s[:400]
	}
	return s
}
