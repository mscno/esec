package commands

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/projectfile"
	"golang.org/x/term"
)

// Setup presets. Names are stored as typed: production is not rewritten to prod.
var (
	setupPresets     = []string{"dev", "staging", "test", "production", "ops"}
	setupDefaultEnvs = []string{"dev", "staging", "production"}
)

// usageError is a bad invocation. It exits 80, the same code kong uses.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }
func (e *usageError) ExitCode() int { return 80 }

func usagef(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

// setupError is a failure that has a next step.
type setupError struct {
	msg, hint string
}

func (e *setupError) Error() string { return e.msg }
func (e *setupError) Hint() string  { return e.hint }

func fail(msg, hint string) error {
	return &setupError{msg: msg, hint: hint}
}

var errSetupAborted = errors.New("setup cancelled")

// SetupCmd creates a project, or adds environments to the one already here.
// A terminal with no --yes opens a wizard. Scripts pass flags and --yes.
// This is not "esec vault setup", which creates a personal identity.
type SetupCmd struct {
	Project string   `help:"Project id (org/repo[/path]). The first part is the vault tenant."`
	Env     string   `help:"Environments to create, comma-separated. Presets: dev, staging, test, production, ops."`
	Format  string   `help:"Secrets file format: env, ejson, eyaml, eyml or etoml."`
	Name    string   `help:"Filename pattern with {env}, such as .env.{env}. Default comes from config."`
	Guard   []string `help:"Guard for one new environment: production=touch. Level is none, session or touch."`
	With    []string `help:"Share the new environments with a GitHub login or \"group org/name\". Needs esec vault."`
	Add     bool     `help:"Add environments to the esec.toml already in this directory."`
	Dir     string   `help:"Directory to write into." default:"."`
	Local   bool     `help:"Write files and keys on this machine only. Do not reserve the name or sync."`
	Yes     bool     `help:"Write without asking. Required when there is no terminal."`
}

// setupPlan is what will be written. It holds no private key.
type setupPlan struct {
	Dir      string
	Project  string
	Add      bool
	Format   string
	Name     string
	Envs     []string
	Existing []string
	Guard    map[string]string
	With     []string
	Local    bool
}

// setupContext is the directory and vault state the wizard starts from.
type setupContext struct {
	Dir     string
	File    *projectfile.File
	Config  config.Config
	Vault   *vaultInfo
	Nearest string
	Check   *projectCheck
}

// setupInteractive reports whether a wizard can run. Tests replace it.
var setupInteractive = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// Run creates the project, or adds environments.
func (c *SetupCmd) Run(ctx *cliCtx) error {
	sc, plan, err := c.prepare()
	if err != nil {
		return err
	}
	if !c.Yes && setupInteractive() {
		plan, err = runSetupTUI(sc, plan)
		if err != nil {
			if errors.Is(err, errSetupAborted) {
				fmt.Fprintln(os.Stderr, "setup cancelled")
				return &ExitError{Code: 1}
			}
			return err
		}
	} else {
		if err := plan.complete(sc); err != nil {
			return err
		}
		if !c.Yes {
			return usagef("no terminal: pass --yes to write without asking")
		}
	}
	return applySetup(ctx, sc, plan)
}

func (c *SetupCmd) prepare() (*setupContext, setupPlan, error) {
	dir := c.Dir
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, setupPlan{}, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, setupPlan{}, fmt.Errorf("directory %s: %w", dir, err)
	}
	if !st.IsDir() {
		return nil, setupPlan{}, fmt.Errorf("%s is not a directory", dir)
	}
	cfg, err := config.Load()
	if err != nil {
		return nil, setupPlan{}, err
	}
	sc := &setupContext{Dir: abs, Config: cfg, Vault: &vaultInfo{}}
	f, err := projectfile.Load(abs)
	if err == nil {
		sc.File = f
	} else if !errors.Is(err, projectfile.ErrNotFound) {
		return nil, setupPlan{}, err
	} else if _, path, nerr := projectfile.Find(abs); nerr == nil {
		sc.Nearest = path
	}
	if !c.Local {
		sc.Vault = loadVault(abs)
	}
	plan, err := c.seed(sc)
	if err != nil {
		return nil, setupPlan{}, err
	}
	return sc, plan, nil
}

func (c *SetupCmd) seed(sc *setupContext) (setupPlan, error) {
	format, err := normalizeFormat(c.Format)
	if err != nil {
		return setupPlan{}, err
	}
	envs, err := parseEnvList(c.Env)
	if err != nil {
		return setupPlan{}, err
	}
	guards, err := parseGuards(c.Guard)
	if err != nil {
		return setupPlan{}, err
	}
	readers, err := parseReaders(c.With)
	if err != nil {
		return setupPlan{}, err
	}
	p := setupPlan{
		Dir:    sc.Dir,
		Format: format,
		Name:   c.Name,
		Envs:   envs,
		Guard:  guards,
		With:   readers,
		Local:  c.Local,
		Add:    c.Add,
	}
	if sc.File != nil {
		p.Project = sc.File.Project
		p.Existing = sc.File.Envs()
		if p.Format == "" {
			p.Format = sc.File.FilesFormat()
		}
		if p.Name == "" {
			p.Name = sc.File.Files.Name
		}
		if !c.Add {
			if c.Yes || !setupInteractive() {
				return setupPlan{}, usagef("esec.toml already exists; pass --add to add environments")
			}
			p.Add = true
		}
		if c.Project != "" && c.Project != sc.File.Project {
			return setupPlan{}, fmt.Errorf("project %s does not match esec.toml (%s)", c.Project, sc.File.Project)
		}
	} else if c.Add {
		msg := fmt.Sprintf("no esec.toml in %s", sc.Dir)
		if sc.Nearest != "" {
			msg += "; the nearest is " + sc.Nearest
		}
		return setupPlan{}, usagef("%s; omit --add to create one here", msg)
	}
	if c.Project != "" && p.Project == "" {
		if err := projectfile.ValidateOrgRepo(c.Project); err != nil {
			return setupPlan{}, err
		}
		p.Project = c.Project
	}
	return p, nil
}

// complete checks a non-interactive plan names every required flag.
func (p setupPlan) complete(sc *setupContext) error {
	if p.Project == "" {
		return usagef("pass --project")
	}
	if len(p.Envs) == 0 {
		return usagef("pass --env")
	}
	if p.Format == "" {
		return usagef("pass --format")
	}
	return p.validate(sc)
}

// validate checks values, not whether a terminal is attached.
func (p setupPlan) validate(sc *setupContext) error {
	if err := projectfile.ValidateOrgRepo(p.Project); err != nil {
		return err
	}
	format, err := p.validateFormat(sc)
	if err != nil {
		return err
	}
	if err := p.validateEnvs(sc, format); err != nil {
		return err
	}
	return p.validateAccess()
}

func (p setupPlan) validateFormat(sc *setupContext) (string, error) {
	format, err := normalizeFormat(p.Format)
	if err != nil {
		return "", err
	}
	if format == "" {
		return "", usagef("pass --format")
	}
	if sc != nil && sc.File != nil {
		if got := sc.File.FilesFormat(); got != "" && got != format {
			return "", usagef("format is already %s; it is not changed when adding environments", got)
		}
		if name := sc.File.Files.Name; name != "" && p.Name != "" && p.Name != name {
			return "", usagef("filename pattern is already %s; it is not changed when adding environments", name)
		}
	}
	if p.Name != "" {
		if err := validateName(format, p.Name); err != nil {
			return "", err
		}
	} else if sc != nil {
		if _, err := derivedName(format, sc.Config.Files.Create, ""); err != nil {
			return "", err
		}
	}
	return format, nil
}

func (p setupPlan) validateEnvs(sc *setupContext, format string) error {
	if len(p.Envs) == 0 {
		return usagef("pass --env")
	}
	seen := map[string]string{}
	for _, env := range p.Envs {
		if slices.Contains(p.Existing, env) {
			return fmt.Errorf("environment %s already exists", env)
		}
		trial := p
		trial.Format = format
		file, err := trial.filename(env, sc)
		if err != nil {
			return err
		}
		if prev, ok := seen[file]; ok {
			return fmt.Errorf("%s and %s would both write %s", prev, env, file)
		}
		seen[file] = env
	}
	return nil
}

func (p setupPlan) validateAccess() error {
	for env, level := range p.Guard {
		if !slices.Contains(p.Envs, env) {
			return usagef("--guard %s=%s names an environment that is not being created", env, level)
		}
		if err := projectfile.ValidateGuard(level); err != nil {
			return err
		}
	}
	for _, r := range p.With {
		if err := validReader(r); err != nil {
			return err
		}
	}
	return nil
}

func (p setupPlan) needsVault() bool {
	if len(p.With) > 0 {
		return true
	}
	for _, level := range p.Guard {
		if level != "" && level != projectfile.GuardNone {
			return true
		}
	}
	return false
}

func (p setupPlan) filename(env string, sc *setupContext) (string, error) {
	pattern := p.Name
	create := ".{format}.{env}"
	if sc != nil && sc.Config.Files.Create != "" {
		create = sc.Config.Files.Create
	}
	if pattern == "" {
		var err error
		pattern, err = derivedName(p.Format, create, "")
		if err != nil {
			return "", err
		}
	}
	return config.Expand(pattern, env, p.Format)
}

func (p setupPlan) storedName(sc *setupContext) (string, error) {
	if p.Add && sc != nil && sc.File != nil && sc.File.Files.Name != "" {
		return sc.File.Files.Name, nil
	}
	create := ".{format}.{env}"
	if sc != nil && sc.Config.Files.Create != "" {
		create = sc.Config.Files.Create
	}
	return derivedName(p.Format, create, p.Name)
}

func normalizeFormat(s string) (string, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), ".")
	switch s {
	case "", "env", "ejson", "eyaml", "eyml", "etoml":
		return s, nil
	default:
		return "", usagef("invalid format %q: use env, ejson, eyaml, eyml or etoml", s)
	}
}

func parseEnvList(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		if err := config.ValidateEnvironment(name); err != nil {
			return nil, err
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out, nil
}

func parseGuards(items []string) (map[string]string, error) {
	out := map[string]string{}
	for _, item := range items {
		for _, part := range strings.Split(item, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			env, level, ok := strings.Cut(part, "=")
			if !ok {
				return nil, usagef("pass --guard as production=touch (none, session or touch)")
			}
			env = strings.TrimSpace(env)
			level = strings.TrimSpace(level)
			if err := config.ValidateEnvironment(env); err != nil {
				return nil, err
			}
			if err := projectfile.ValidateGuard(level); err != nil {
				return nil, err
			}
			if level == "" {
				level = projectfile.GuardNone
			}
			out[env] = level
		}
	}
	return out, nil
}

func parseReaders(items []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, item := range items {
		for _, part := range splitReaders(item) {
			if seen[part] {
				continue
			}
			if err := validReader(part); err != nil {
				return nil, err
			}
			seen[part] = true
			out = append(out, part)
		}
	}
	return out, nil
}

// splitReaders splits on commas that are not inside a group name.
// Group ids contain no comma, so a plain split is enough.
func splitReaders(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func validReader(s string) error {
	if rest, ok := strings.CutPrefix(s, "group "); ok {
		if err := projectfile.ValidateOrgRepo(rest); err != nil {
			return fmt.Errorf("reader %q: use group org/name", s)
		}
		return nil
	}
	if strings.Contains(s, " ") || strings.Contains(s, "/") {
		return fmt.Errorf("reader %q: a GitHub login, or group org/name", s)
	}
	if !validLogin(s) {
		return fmt.Errorf("reader %q: a GitHub login, or group org/name", s)
	}
	return nil
}

func validLogin(s string) bool {
	if s == "" || len(s) > 39 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func validateName(format, name string) error {
	f := &projectfile.File{Project: "acme/store", Files: projectfile.Files{Format: format, Name: name}}
	return f.Validate()
}

func derivedName(format, create, explicit string) (string, error) {
	if explicit != "" {
		if err := validateName(format, explicit); err != nil {
			return "", err
		}
		return explicit, nil
	}
	name := strings.ReplaceAll(create, "{format}", strings.TrimPrefix(format, "."))
	if err := validateName(format, name); err != nil {
		return "", fmt.Errorf("filename pattern %q is not valid for %s: %w", name, format, err)
	}
	return name, nil
}

func (sc *setupContext) vaultReady() bool {
	return sc != nil && sc.Vault != nil && sc.Vault.Installed && sc.Vault.SignedIn && !sc.Vault.CheckUnsupported
}

func (sc *setupContext) banner() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Directory: %s\n", sc.Dir)
	if sc.File != nil {
		fmt.Fprintf(&b, "Project: %s. Adding environments; the id, format and filename pattern stay as they are.\n", sc.File.Project)
		if len(sc.File.Envs()) > 0 {
			fmt.Fprintf(&b, "Already here: %s\n", strings.Join(sc.File.Envs(), ", "))
		}
	} else if sc.Nearest != "" {
		fmt.Fprintf(&b, "No esec.toml here. The nearest is %s. This command writes in this directory only.\n", sc.Nearest)
	}
	b.WriteString(sc.Vault.summary())
	b.WriteString("\nIdentity and server login are \"esec vault setup\", not this command.")
	return b.String()
}

func suggestRepo(dir string) string {
	base := strings.ToLower(filepath.Base(dir))
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		}
	}
	s := strings.Trim(b.String(), ".-_")
	if s == "" || s == "." || s == ".." {
		return ""
	}
	return s
}

func suggestProject(dir, personal string) string {
	name := suggestRepo(dir)
	if name == "" {
		return ""
	}
	if personal != "" {
		return personal + "/" + name
	}
	return name
}
