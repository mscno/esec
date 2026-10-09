package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/filelock"
	"github.com/mscno/esec/pkg/projectfile"
)

// KeygenCmd generates a new keypair for encryption.
type KeygenCmd struct {
	Save    bool   `help:"Store the private key in the global project keyring; print only its public key"`
	Env     string `help:"Environment for --save (e.g. dev or registry.prod)"`
	Project string `help:"Project id for --save (default: nearest .esec-project)"`
}

// Run executes the keygen command.
func (c *KeygenCmd) Run(ctx *cliCtx) error {
	if !c.Save && (c.Env != "" || c.Project != "") {
		return fmt.Errorf("--env and --project require --save")
	}
	ctx.Logger.Debug("generating new keypair")

	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		ctx.Logger.Debug("keypair generation failed", "error", err)
		return err
	}

	ctx.Logger.Debug("keypair generated successfully")
	if c.Save {
		if err := c.save(pub, priv); err != nil {
			return err
		}
		notifyVault()
		fmt.Printf("ESEC_PUBLIC_KEY=%s\n", pub)
		return nil
	}
	fmt.Printf("Public Key:\n%s\nPrivate Key:\n%s\n", pub, priv)

	return nil
}

// Notification is a wake-up hint only. The daemon also reconciles persisted
// keyrings, so missing/failed IPC never loses a key mutation or blocks keygen.
func notifyVault() {
	home := os.Getenv("ESEC_VAULT_HOME")
	if home == "" {
		base := os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			user, err := os.UserHomeDir()
			if err != nil {
				return
			}
			base = filepath.Join(user, ".config")
		}
		home = filepath.Join(base, "esec")
	}
	conn, err := net.DialTimeout("unix", filepath.Join(home, "run", "control.sock"), 100*time.Millisecond) //nolint:gosec // local Unix socket under configured vault home, never an HTTP request
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
	if err := json.NewEncoder(conn).Encode(map[string]any{"version": 1, "op": "changed"}); err != nil {
		return
	}
}

func (c *KeygenCmd) save(pub, priv string) error {
	project := c.Project
	if project == "" {
		p, _, err := projectfile.FindProjectFile(".")
		if err != nil {
			return fmt.Errorf("--save needs .esec-project or --project: %w", err)
		}
		project = p
	}
	if err := projectfile.ValidateOrgRepo(project); err != nil {
		return err
	}
	if c.Env != "" {
		if _, err := processFileOrEnv(c.Env, ".ejson"); err != nil || strings.HasPrefix(c.Env, ".") || strings.ContainsAny(c.Env, "/\\") {
			return fmt.Errorf("invalid environment %q", c.Env)
		}
	}
	dir := esec.GlobalKeyringDir()
	if dir == "" {
		return fmt.Errorf("global keyring directory unavailable")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	unlock, err := filelock.Acquire(dir)
	if err != nil {
		return err
	}
	defer unlock()
	p := filepath.Join(dir, projectfile.KeyringName(project))
	entries, err := readSavedKeyring(p, project)
	if err != nil {
		return err
	}
	if c.Env != "" {
		name := esec.EsecPrivateKey + "_" + strings.ToUpper(strings.ReplaceAll(c.Env, ".", "_"))
		if _, ok := entries[name]; ok {
			return fmt.Errorf("environment %q already has a key", c.Env)
		}
		entries[name] = priv
	}
	entries[esec.EsecPrivateKey+"_"+strings.ToUpper(pub)] = priv
	return writeSavedKeyring(dir, p, project, entries)
}

func readSavedKeyring(p, project string) (map[string]string, error) {
	entries := map[string]string{}
	if info, err := os.Lstat(p); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing keyring symlink")
		}
		data, err := os.ReadFile(p) //nolint:gosec // constructed from a validated project id inside configured keyring dir
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if owner, ok := strings.CutPrefix(line, "# ESEC_PROJECT="); ok && owner != project {
				return nil, fmt.Errorf("keyring belongs to a different project")
			}
		}
		entries, err = godotenv.Unmarshal(string(data))
		if err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return entries, nil
}

func writeSavedKeyring(dir, p, project string, entries map[string]string) error {
	data, err := godotenv.Marshal(entries)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".keygen-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := fmt.Fprintf(f, "# ESEC_PROJECT=%s\n%s\n", project, data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), p)
}
