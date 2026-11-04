package commands

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/seal"
)

// MachineSetupCmd configures this machine, never a project or cloud account.
type MachineSetupCmd struct {
	GenerateDev       bool     `help:"Generate a developer identity if none is configured"`
	DeveloperIdentity string   `type:"path" help:"Existing native age developer identity file"`
	YubikeyIdentity   string   `type:"path" help:"Existing age-plugin-yubikey identity file (a hardware reference)"`
	YubikeyRecipient  []string `help:"Public age recipient of that YubiKey slot; must use always-touch"`
	RecoveryRecipient []string `help:"Default offline recovery recipients for new environments, including production (public keys only)"`
	Yes               bool     `help:"Use the supplied choices without prompting"`
}

// Run configures public recipients and optional local developer identity.
func (c *MachineSetupCmd) Run(ctx *cliCtx) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := c.completeChoices(cfg); err != nil {
		return err
	}
	var hardwarePath string
	if c.YubikeyIdentity != "" {
		hardwarePath, err = absoluteIdentity(c.YubikeyIdentity)
		if err != nil {
			return err
		}
		if err := validateHardwareReferenceFile(hardwarePath); err != nil {
			return err
		}
	}
	if err := c.verifyRecipients(ctx); err != nil {
		return err
	}

	for _, r := range c.RecoveryRecipient {
		if _, err := seal.ParseRecipient(r); err != nil {
			return err
		}
	}
	if err := c.configureDeveloper(ctx, &cfg); err != nil {
		return err
	}
	if hardwarePath != "" {
		cfg.Age.IdentityFiles = appendUnique(cfg.Age.IdentityFiles, hardwarePath)
	}
	for _, r := range c.YubikeyRecipient {
		cfg.Age.YubiKeyRecipients = appendUnique(cfg.Age.YubiKeyRecipients, r)
	}
	for _, r := range c.RecoveryRecipient {
		cfg.Age.RecoveryRecipients = appendUnique(cfg.Age.RecoveryRecipients, r)
	}
	if cfg.Age.DeveloperRecipient == "" && len(cfg.Age.YubiKeyRecipients) == 0 {
		return errors.New("configure a developer identity or paste a YubiKey recipient")
	}
	if err := cfg.SaveAge(); err != nil {
		return err
	}
	say(ctx, "Configured this machine. No server, daemon, or account is needed.")
	if len(cfg.Age.YubiKeyRecipients) == 0 {
		say(ctx, "YubiKey is not configured yet; production initialization will be refused.")
	}
	return nil
}

func absoluteIdentity(p string) (string, error) {
	if strings.HasPrefix(p, "~/") {
		return config.IdentityPath(p)
	}
	return filepath.Abs(p)
}
func appendUnique(xs []string, s string) []string {
	if !slices.Contains(xs, s) {
		return append(xs, s)
	}
	return xs
}

func requireAlwaysTouch(list, recipient string) error {
	policy := ""
	for _, line := range strings.Split(list, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Touch policy:") {
			policy = line
		}
		if line == recipient {
			if !strings.Contains(policy, "Touch policy: Always") {
				return fmt.Errorf("YubiKey recipient does not require every touch (%s); create a new slot with age-plugin-yubikey --generate --touch-policy always; existing slots are not changed", policy)
			}
			return nil
		}
	}
	return errors.New("recipient not found on a connected YubiKey")
}

// IdentityCmd groups independent machine identity commands.
type IdentityCmd struct {
	Create IdentityCreateCmd `cmd:"" help:"Create an independent software age identity for a machine or offline recovery"`
	List   IdentityListCmd   `cmd:"" help:"Show this machine's configured public recipients; no private keys"`
}

// IdentityListCmd prints only public machine defaults for sharing with a repo.
type IdentityListCmd struct {
	JSON bool `help:"Print configured public recipients as JSON"`
}

// Run reads public configuration without opening identity files or hardware.
func (c *IdentityListCmd) Run(_ *cliCtx) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if c.JSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"developer": cfg.Age.DeveloperRecipient, "yubikey": cfg.Age.YubiKeyRecipients, "recovery": cfg.Age.RecoveryRecipients})
	}
	if cfg.Age.DeveloperRecipient != "" {
		fmt.Printf("developer  %s\n", cfg.Age.DeveloperRecipient)
	}
	for _, r := range cfg.Age.YubiKeyRecipients {
		fmt.Printf("yubikey    %s\n", r)
	}
	for _, r := range cfg.Age.RecoveryRecipients {
		fmt.Printf("recovery   %s\n", r)
	}
	return nil
}

// IdentityCreateCmd writes a new software age identity without granting access.
type IdentityCreateCmd struct {
	Out string `required:"" type:"path" help:"New private identity file; never overwritten or automatically configured locally"`
}

// Run creates an identity and prints its public recipient only.
func (c *IdentityCreateCmd) Run(ctx *cliCtx) error {
	p, err := filepath.Abs(c.Out)
	if err != nil {
		return err
	}
	recipient, err := createAgeIdentity(p)
	if err != nil {
		return err
	}
	fmt.Println(recipient)
	say(ctx, "Private identity written to %s (0600). For deployment, transfer it to the deployment secret store; keep its private key off developer machines.", p)
	return nil
}
func createAgeIdentity(p string) (string, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) //nolint:gosec // explicitly chosen destination, exclusively created
	if err != nil {
		return "", err
	}
	good := false
	defer func() {
		f.Close()
		if !good {
			os.Remove(p)
		}
	}()
	if _, err = fmt.Fprintf(f, "# public key: %s\n%s\n", id.Recipient(), id.String()); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	good = true
	return id.Recipient().String(), nil
}

func (c *MachineSetupCmd) completeChoices(cfg config.Config) error {
	if !c.Yes && !setupInteractive() {
		return errors.New("no terminal: supply setup options and --yes")
	}
	if !c.Yes {
		in := bufio.NewReader(os.Stdin)
		ask := func(prompt string) (string, error) {
			fmt.Fprint(os.Stderr, prompt)
			s, e := in.ReadString('\n')
			return strings.TrimSpace(s), e
		}
		if cfg.Age.DeveloperRecipient == "" && c.DeveloperIdentity == "" && !c.GenerateDev {
			answer, e := ask("Create a software age identity for dev/test/staging on this machine? [Y/n] ")
			if e != nil {
				return e
			}
			if answer == "" || strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes") {
				c.GenerateDev = true
			}
		}
		if len(cfg.Age.YubiKeyRecipients) == 0 && len(c.YubikeyRecipient) == 0 {
			s, e := ask("Paste public age/rage YubiKey recipients for production and recovery (space/comma separated; Enter to add later): ")
			if e != nil {
				return e
			}
			c.YubikeyRecipient = strings.Fields(strings.ReplaceAll(s, ",", " "))
		}
	}

	return nil
}

func validateHardwareReferenceFile(hardwarePath string) error {
	b, e := os.ReadFile(hardwarePath) //nolint:gosec // explicit hardware reference path
	if e != nil {
		return e
	}
	count := 0
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, _, e := plugin.ParseIdentity(line)
		if e != nil || name != "yubikey" {
			return errors.New("YubiKey identity file must contain only age-plugin-yubikey references")
		}
		count++
	}
	if count == 0 {
		return errors.New("empty YubiKey identity file")
	}
	return nil
}

func (c *MachineSetupCmd) verifyRecipients(ctx *cliCtx) error {
	for _, r := range c.YubikeyRecipient {
		name, _, e := plugin.ParseRecipient(r)
		if e != nil || name != "yubikey" {
			return errors.New("expected an age1yubikey1... public recipient, not a private identity or software recipient")
		}
		if _, e = seal.ParseRecipient(r); e != nil {
			return e
		}
		// Pasting a public key works without hardware. Verification is optional
		// here and mandatory when discovering that YubiKey for decryption.
		probe, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		output, e := exec.CommandContext(probe, "age-plugin-yubikey", "--list").Output()
		cancel()
		if e == nil && strings.Contains(string(output), r) {
			if e = requireAlwaysTouch(string(output), r); e != nil {
				return e
			}
			say(ctx, "Verified an always-touch YubiKey recipient.")
		} else {
			say(ctx, "Saved public YubiKey recipient; touch policy will be verified when the key is connected.")
		}
	}

	return nil
}

func (c *MachineSetupCmd) configureDeveloper(ctx *cliCtx, cfg *config.Config) error {
	if c.DeveloperIdentity != "" && c.GenerateDev {
		return errors.New("choose --generate-dev or --developer-identity")
	}
	if c.DeveloperIdentity != "" {
		p, e := absoluteIdentity(c.DeveloperIdentity)
		if e != nil {
			return e
		}
		b, e := os.ReadFile(p) //nolint:gosec // explicitly selected native identity file
		if e != nil {
			return e
		}
		ids, e := age.ParseIdentities(strings.NewReader(string(b)))
		if e != nil {
			return e
		}
		if len(ids) != 1 {
			return errors.New("developer identity file must contain exactly one native age identity")
		}
		id, ok := ids[0].(*age.X25519Identity)
		if !ok {
			return errors.New("developer identity must be a native X25519 age identity")
		}
		cfg.Age.DeveloperRecipient = id.Recipient().String()
		cfg.Age.IdentityFiles = appendUnique(cfg.Age.IdentityFiles, p)
	} else if c.GenerateDev && cfg.Age.DeveloperRecipient == "" {
		cp, e := config.Path()
		if e != nil {
			return e
		}
		p := filepath.Join(filepath.Dir(cp), "identities", "developer.age")
		recipient, e := createAgeIdentity(p)
		if e != nil {
			return e
		}
		cfg.Age.DeveloperRecipient = recipient
		cfg.Age.IdentityFiles = appendUnique(cfg.Age.IdentityFiles, p)
		say(ctx, "Created developer identity %s; keep a protected backup.", p)
	}

	return nil
}
