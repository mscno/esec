package commands

import (
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/mscno/esec/pkg/projectfile"
)

func runSetupTUI(sc *setupContext, seed setupPlan) (setupPlan, error) {
	p := seed
	if sc.File != nil {
		p.Add = true
		p.Project = sc.File.Project
		p.Existing = sc.File.Envs()
		if p.Format == "" {
			p.Format = sc.File.FilesFormat()
		}
		if p.Name == "" {
			p.Name = sc.File.Files.Name
		}
	}
	if err := runForm("esec setup", sc.banner(), huh.NewNote().
		Title("Before anything is written").
		Description("Esc cancels. Nothing is reserved or written until the last step.").
		Next(true).NextLabel("Continue")); err != nil {
		return p, err
	}
	if !p.Add {
		if err := tuiProject(sc, &p); err != nil {
			return p, err
		}
	}
	if err := tuiEnvs(&p); err != nil {
		return p, err
	}
	if !p.Add || p.Format == "" {
		if err := tuiFormat(sc, &p); err != nil {
			return p, err
		}
	}
	if p.Local || !sc.vaultReady() {
		p.Local = true
		p.Guard = map[string]string{}
		p.With = nil
	} else {
		if err := tuiGuard(sc, &p); err != nil {
			return p, err
		}
		if err := tuiReaders(sc, &p); err != nil {
			return p, err
		}
	}
	if err := tuiReview(sc, &p); err != nil {
		return p, err
	}
	return p, nil
}

func runForm(title, description string, fields ...huh.Field) error {
	if len(fields) == 0 {
		return nil
	}
	err := huh.NewForm(huh.NewGroup(fields...).Title(title).Description(description)).Run()
	if errors.Is(err, huh.ErrUserAborted) {
		return errSetupAborted
	}
	return err
}

func tuiProject(sc *setupContext, p *setupPlan) error {
	if p.Project == "" {
		p.Project = suggestProject(sc.Dir, sc.Vault.Personal)
	}
	owners := ownerNote(sc)
	project := p.Project
	err := runForm("Project", owners, huh.NewInput().
		Title("Project id").
		Description("org/repo, or org/repo/path. The first part is the tenant that owns it, not a GitHub organisation claim.").
		Placeholder("acme/store").
		Value(&project).
		Validate(func(s string) error {
			s = strings.TrimSpace(s)
			if err := projectfile.ValidateOrgRepo(s); err != nil {
				return err
			}
			trial := *p
			trial.Project = s
			if trial.Local || !sc.Vault.Installed || !sc.Vault.SignedIn {
				return nil
			}
			return trial.checkName(sc)
		}))
	if err != nil {
		return err
	}
	p.Project = strings.TrimSpace(project)
	return nil
}

func ownerNote(sc *setupContext) string {
	if sc.Vault == nil || len(sc.Vault.Namespaces) == 0 {
		return "The owner is the tenant in the project id. A vault check, when you are signed in, says whether you may use it."
	}
	var parts []string
	for _, ns := range sc.Vault.Namespaces {
		if !ns.YouMayCreate && ns.Kind != "" {
			continue
		}
		label := ns.Name
		if ns.Kind != "" {
			label += " (" + ns.Kind + ")"
		}
		parts = append(parts, label)
	}
	if len(parts) == 0 {
		return "No tenant you can create in was listed. The name check will say why."
	}
	return "Tenants you can create in: " + strings.Join(parts, ", ") + "."
}

func tuiEnvs(p *setupPlan) error {
	selected := without(p.Envs, p.Existing)
	if len(selected) == 0 {
		for _, env := range setupDefaultEnvs {
			if !contains(p.Existing, env) {
				selected = append(selected, env)
			}
		}
	}
	var custom string
	opts := make([]huh.Option[string], 0, len(setupPresets))
	for _, env := range setupPresets {
		if contains(p.Existing, env) {
			continue
		}
		opt := huh.NewOption(env, env)
		if contains(selected, env) {
			opt = opt.Selected(true)
		}
		opts = append(opts, opt)
	}
	desc := "Space toggles, enter continues. Names are stored as typed: production is not rewritten to prod."
	if len(p.Existing) > 0 {
		desc = "Already here, and left as they are: " + strings.Join(p.Existing, ", ") + ". " + desc
	}
	fields := []huh.Field{}
	if len(opts) > 0 {
		fields = append(fields, huh.NewMultiSelect[string]().
			Title("Environments").
			Description(desc).
			Options(opts...).
			Value(&selected))
	}
	fields = append(fields, huh.NewInput().
		Title("Other environments").
		Description("Optional. Comma-separated. Lowercase letters and digits; dots separate parts.").
		Placeholder("api.production").
		Value(&custom))
	if err := runForm("Environments", "", fields...); err != nil {
		return err
	}
	extra, err := parseEnvList(custom)
	if err != nil {
		return err
	}
	merged := append([]string{}, selected...)
	for _, env := range extra {
		if contains(p.Existing, env) {
			return fmt.Errorf("environment %s already exists", env)
		}
		if !contains(merged, env) {
			merged = append(merged, env)
		}
	}
	if len(merged) == 0 {
		return usagef("choose at least one environment")
	}
	p.Envs = merged
	return nil
}

func tuiFormat(sc *setupContext, p *setupPlan) error {
	if p.Format == "" {
		p.Format = strings.TrimPrefix(sc.Config.DefaultFormat, ".")
	}
	if p.Format == "" {
		p.Format = "env"
	}
	format := p.Format
	preview := filenamePreview(sc, *p)
	err := runForm("Format", preview, huh.NewSelect[string]().
		Title("Secrets file format").
		Options(
			huh.NewOption("env", "env"),
			huh.NewOption("ejson", "ejson"),
			huh.NewOption("eyaml", "eyaml"),
			huh.NewOption("eyml", "eyml"),
			huh.NewOption("etoml", "etoml"),
		).
		Value(&format),
		huh.NewInput().
			Title("Filename pattern").
			Description("Leave empty to use the pattern above. It must contain {env} and show the format, such as .env.{env} or {env}.etoml.").
			Placeholder(placeholderName(format, sc)).
			Value(&p.Name).
			Validate(func(s string) error {
				s = strings.TrimSpace(s)
				if s == "" {
					return nil
				}
				return validateName(format, s)
			}))
	if err != nil {
		return err
	}
	p.Format = format
	p.Name = strings.TrimSpace(p.Name)
	return nil
}

func tuiGuard(sc *setupContext, p *setupPlan) error {
	if p.Guard == nil {
		p.Guard = map[string]string{}
	}
	keys := sc.Vault != nil && sc.Vault.KeysKnown && sc.Vault.HasSecurityKey
	levels := make([]string, len(p.Envs))
	fields := make([]huh.Field, 0, len(p.Envs))
	for i, env := range p.Envs {
		def := p.Guard[env]
		if def == "" {
			def = projectfile.GuardNone
			if env == "production" && keys {
				def = projectfile.GuardTouch
			}
		}
		levels[i] = def
		fields = append(fields, guardField(env, &levels[i], keys))
	}
	desc := "none keeps the key in the keyring. session and touch seal it so a security key opens it."
	if !keys {
		desc = "session and touch need a security key: esec vault security-keys add. They are not offered until one is enrolled."
	}
	if err := runForm("Guard", desc, fields...); err != nil {
		return err
	}
	for i, env := range p.Envs {
		if levels[i] == "" || levels[i] == projectfile.GuardNone {
			delete(p.Guard, env)
			continue
		}
		p.Guard[env] = levels[i]
	}
	return nil
}

func guardField(env string, dest *string, keys bool) huh.Field {
	opts := []huh.Option[string]{
		huh.NewOption("none — key stays in the keyring", projectfile.GuardNone),
	}
	if keys {
		opts = append(opts,
			huh.NewOption("session — one touch unlocks it", projectfile.GuardSession),
			huh.NewOption("touch — every read needs a touch", projectfile.GuardTouch),
		)
	}
	s := huh.NewSelect[string]().Title(env).Value(dest).Options(opts...)
	return s
}

func tuiReaders(sc *setupContext, p *setupPlan) error {
	who := "you"
	if sc.Vault != nil && sc.Vault.Identity != "" {
		who = sc.Vault.Identity
	} else if sc.Vault != nil && sc.Vault.Login != "" {
		who = sc.Vault.Login
	}
	var extra string
	if len(p.With) > 0 {
		extra = strings.Join(p.With, ", ")
	}
	err := runForm("Readers", who+" is the first reader. Vault writes that into esec.toml and seals the key. Extra people are shared after create.",
		huh.NewInput().
			Title("Also share with").
			Description("Optional. GitHub logins or group org/name, comma-separated. Leave empty to keep the keys to yourself.").
			Placeholder("alice, group acme/backend").
			Value(&extra).
			Validate(func(s string) error {
				_, err := parseReaders([]string{s})
				return err
			}))
	if err != nil {
		return err
	}
	readers, err := parseReaders([]string{extra})
	if err != nil {
		return err
	}
	p.With = readers
	return nil
}

func tuiReview(sc *setupContext, p *setupPlan) error {
	var ok bool
	title := "Create this project?"
	if p.Add {
		title = "Add these environments?"
	}
	err := runForm("Review", "", huh.NewConfirm().
		Title(title).
		Description(reviewText(sc, *p)).
		Affirmative("Create").
		Negative("Cancel").
		Value(&ok))
	if err != nil {
		return err
	}
	if !ok {
		return errSetupAborted
	}
	return nil
}

func reviewText(sc *setupContext, p setupPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Project: %s\n", p.Project)
	fmt.Fprintf(&b, "Format: %s\n", p.Format)
	for _, env := range p.Envs {
		file, err := p.filename(env, sc)
		if err != nil {
			file = env
		}
		level := p.Guard[env]
		if level == "" {
			level = "none"
		}
		fmt.Fprintf(&b, "  %s  %s  guard %s\n", env, file, level)
	}
	if len(p.With) > 0 {
		fmt.Fprintf(&b, "Also share with: %s\n", strings.Join(p.With, ", "))
	}
	if p.Local || !sc.vaultReady() {
		b.WriteString("\nKeys stay on this machine. The name is not reserved, and guard and readers are not recorded.")
	} else {
		b.WriteString("\nThe name is checked with the vault server. Keys are stored and synced through esec vault.")
	}
	return b.String()
}

func filenamePreview(sc *setupContext, p setupPlan) string {
	if len(p.Envs) == 0 {
		return ""
	}
	var files []string
	for _, env := range p.Envs {
		trial := p
		if trial.Format == "" {
			trial.Format = "env"
		}
		file, err := trial.filename(env, sc)
		if err != nil {
			continue
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		return ""
	}
	return "Files: " + strings.Join(files, ", ")
}

func placeholderName(format string, sc *setupContext) string {
	create := ".{format}.{env}"
	if sc != nil && sc.Config.Files.Create != "" {
		create = sc.Config.Files.Create
	}
	name, err := derivedName(format, create, "")
	if err != nil {
		return ".env.{env}"
	}
	return name
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func without(list, drop []string) []string {
	var out []string
	for _, item := range list {
		if !contains(drop, item) {
			out = append(out, item)
		}
	}
	return out
}
