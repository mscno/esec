package commands

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/recovery"
)

// RecoveryCmd manages offline phrase identities without a keyring or service.
type RecoveryCmd struct {
	Create    RecoveryCreateCmd    `cmd:"" help:"Generate and confirm a 24-word recovery identity; save only its public recipient as a default"`
	Import    RecoveryImportCmd    `cmd:"" help:"Register an existing phrase's public recovery recipient as a default"`
	Recipient RecoveryRecipientCmd `cmd:"" help:"Derive and print only a public recipient from hidden phrase/passphrase input"`
	Verify    RecoveryVerifyCmd    `cmd:"" help:"Test phrase access to a file in memory without displaying its secrets"`
	Export    RecoveryExportCmd    `cmd:"" help:"Explicitly export a recovery age identity to a new private file"`
}

// RecoveryCreateCmd deliberately has no phrase, passphrase, or unattended flags.
type RecoveryCreateCmd struct{}

// Run displays a fresh phrase only on the controlling terminal and confirms its backup.
func (*RecoveryCreateCmd) Run(_ *cliCtx) error {
	t, err := openRecoveryTerminal()
	if err != nil {
		return err
	}
	defer t.Close()
	phrase, err := recovery.Generate()
	if err != nil {
		return err
	}
	pass, err := t.Secret("Optional recovery passphrase (Enter for none): ")
	if err != nil {
		return err
	}
	if pass != "" {
		again, err := t.Secret("Confirm recovery passphrase: ")
		if err != nil {
			return err
		}
		if again != pass {
			return errors.New("passphrases did not match; no configuration changed")
		}
	}
	id, err := recovery.Derive(phrase, pass, recovery.Format)
	if err != nil {
		return err
	}
	if err := t.Write(fmt.Sprintf("\nOffline recovery backup — format: %s\n%s\nPublic recipient: %s\nStore these words offline. If set, the passphrase is also required. Neither is saved by Esec.\n\n", recovery.Format, phrase, id.Recipient())); err != nil {
		return err
	}
	confirmation, err := t.Secret("Re-enter all 24 words to confirm your backup: ")
	if err != nil {
		return err
	}
	if recovery.Normalize(confirmation) != phrase {
		return errors.New("recovery phrase did not match; no configuration changed")
	}
	return registerRecovery(t, id)
}

// RecoveryImportCmd registers public defaults, never a private identity.
type RecoveryImportCmd struct {
	ExpectRecipient string `help:"Optional public recovery recipient from an existing backup; reject a phrase/passphrase/format mismatch"`
	Format          string `default:"esec-v1" enum:"esec-v1,vault-v2" help:"Derivation format recorded with the recovery backup"`
}

// Run confirms a recovered public recipient before adding it to defaults.
func (c *RecoveryImportCmd) Run(_ *cliCtx) error {
	t, err := openRecoveryTerminal()
	if err != nil {
		return err
	}
	defer t.Close()
	id, err := readPhraseIdentity(t, c.Format, true)
	if err != nil {
		return err
	}
	if c.ExpectRecipient != "" && id.Recipient().String() != c.ExpectRecipient {
		return errors.New("recovery recipient mismatch; configuration unchanged")
	}
	return registerRecovery(t, id)
}

func registerRecovery(t recoveryTerminal, id *age.X25519Identity) error {
	recipient := id.Recipient().String()
	if err := t.Write(fmt.Sprintf("Public recovery recipient: %s\nNew environments, including production, will include this default. The phrase can decrypt without a YubiKey. Existing projects are unchanged; esec.toml controls their recipients.\n", recipient)); err != nil {
		return err
	}
	answer, err := t.Secret("Type 'add recovery' to register this public default: ")
	if err != nil {
		return err
	}
	if answer != "add recovery" {
		return errors.New("cancelled; configuration unchanged")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if recipient == cfg.Age.DeveloperRecipient {
		return errors.New("the everyday developer identity cannot also be the offline recovery default")
	}
	cfg.Age.RecoveryRecipients = appendUnique(cfg.Age.RecoveryRecipients, recipient)
	if err := cfg.SaveAge(); err != nil {
		return err
	}
	fmt.Println(recipient)
	return nil
}

// RecoveryRecipientCmd prints a public recipient without changing configuration.
type RecoveryRecipientCmd struct {
	Format string `default:"esec-v1" enum:"esec-v1,vault-v2" help:"Recovery derivation format"`
}

// Run derives an identity transiently and prints only its public recipient.
func (c *RecoveryRecipientCmd) Run(_ *cliCtx) error {
	id, err := promptRecoveryIdentity(c.Format)
	if err != nil {
		return err
	}
	fmt.Println(id.Recipient())
	return nil
}

// RecoveryVerifyCmd verifies a real file, never just a phrase checksum.
type RecoveryVerifyCmd struct {
	File   string `arg:"" help:"Encrypted environment or file to verify"`
	Format string `default:"esec-v1" enum:"esec-v1,vault-v2" help:"Recovery derivation format"`
}

// Run decrypts only in memory and prints no secret values.
func (c *RecoveryVerifyCmd) Run(ctx *cliCtx) error {
	data, err := readRecoveryDocument(c.File, "", c.Format)
	if err != nil {
		return err
	}
	clear(data)
	say(ctx, "Recovery verified for %q. File and local identities unchanged.", c.File)
	return nil
}

// RecoveryExportCmd is an explicit escape hatch; normal recovery stays in memory.
type RecoveryExportCmd struct {
	Out             string `required:"" type:"path" help:"New private age identity file (0600); never overwritten or automatically configured"`
	ExpectRecipient string `required:"" help:"Expected public age recipient from your backup or esec.toml; rejects a wrong passphrase/format"`
	Format          string `default:"esec-v1" enum:"esec-v1,vault-v2" help:"Recovery derivation format"`
}

// Run requires both a matching public recipient and explicit export confirmation.
func (c *RecoveryExportCmd) Run(ctx *cliCtx) error {
	if _, err := age.ParseX25519Recipient(c.ExpectRecipient); err != nil {
		return errors.New("--expect-recipient must be the complete public recovery age recipient")
	}
	t, err := openRecoveryTerminal()
	if err != nil {
		return err
	}
	defer t.Close()
	id, err := readRecoveryIdentity(t, c.Format)
	if err != nil {
		return err
	}
	if id.Recipient().String() != c.ExpectRecipient {
		return errors.New("recovery recipient mismatch; check phrase, passphrase, and format; nothing written")
	}
	if err := t.Write("Export writes a plaintext private age identity. Anyone who reads it can decrypt its environments without the phrase, passphrase, or YubiKey.\n"); err != nil {
		return err
	}
	answer, err := t.Secret("Type 'export recovery' to write the private identity: ")
	if err != nil {
		return err
	}
	if answer != "export recovery" {
		return errors.New("cancelled; nothing written")
	}
	if err := writeRecoveryIdentity(c.Out, id, c.Format); err != nil {
		return err
	}
	say(ctx, "Wrote the private recovery identity to %s (0600). It was not added to local identity discovery.", c.Out)
	return nil
}

func writeRecoveryIdentity(path string, id *age.X25519Identity, format string) error {
	p, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) //nolint:gosec // explicit export destination, exclusively created
	if err != nil {
		return err
	}
	good := false
	defer func() {
		f.Close()
		if !good {
			os.Remove(p)
		}
	}()
	if _, err := fmt.Fprintf(f, "# Esec recovery format: %s\n# public key: %s\n%s\n", format, id.Recipient(), id); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	good = true
	return nil
}

func promptRecoveryIdentity(format string) (*age.X25519Identity, error) {
	t, err := openRecoveryTerminal()
	if err != nil {
		return nil, err
	}
	defer t.Close()
	return readRecoveryIdentity(t, format)
}

func readRecoveryIdentity(t recoveryTerminal, format string) (*age.X25519Identity, error) {
	return readPhraseIdentity(t, format, false)
}

func readPhraseIdentity(t recoveryTerminal, format string, confirmPassphrase bool) (*age.X25519Identity, error) {
	if format == "" {
		format = recovery.Format
	}
	phrase, err := t.Secret("Recovery phrase (24 words; input hidden): ")
	if err != nil {
		return nil, err
	}
	pass, err := t.Secret("Recovery passphrase (Enter only if none was set): ")
	if err != nil {
		return nil, err
	}
	if confirmPassphrase && pass != "" {
		again, err := t.Secret("Confirm recovery passphrase: ")
		if err != nil {
			return nil, err
		}
		if again != pass {
			return nil, errors.New("passphrases did not match; configuration unchanged")
		}
	}
	return recovery.Derive(phrase, pass, format)
}

func readRecoveryDocument(file, fileFormat, recoveryFormat string) ([]byte, error) {
	target, err := esec.ResolveRead(".", file, fileFormat)
	if err != nil {
		return nil, err
	}
	if target.Seal == "" {
		return nil, errors.New("this file has no age-sealed environment key; recover its legacy key and migrate it first")
	}
	id, err := promptRecoveryIdentity(recoveryFormat)
	if err != nil {
		return nil, err
	}
	data, err := esec.ReadDocument(target, esec.ReadOptions{AgeIdentities: []age.Identity{id}})
	if err != nil {
		return nil, fmt.Errorf("recovery did not open the file; check the phrase, passphrase, derivation format, and granted recipients: %w", err)
	}
	return data, nil
}
