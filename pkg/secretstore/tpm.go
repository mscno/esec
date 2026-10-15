package secretstore

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// systemdCreds is the systemd-creds executable used by the TPM backend.
var systemdCreds = "systemd-creds"

// tpmStore seals each secret with `systemd-creds --with-key=tpm2` into
// <dir>/<name>.cred. The credential is bound to this machine's TPM, so a copy
// of the disk cannot be decrypted elsewhere. The credential name is embedded
// and checked on decrypt, so one file cannot be swapped for another.
type tpmStore struct {
	dir string
	bin string
}

func newTPM(dir, bin string) (Store, error) {
	if runtime.GOOS != "linux" && bin == systemdCreds {
		return nil, fmt.Errorf("%w: TPM store requires Linux", ErrUnavailable)
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, fmt.Errorf("%w: %s not found", ErrUnavailable, bin)
	}
	return &tpmStore{dir: dir, bin: path}, nil
}

func (t *tpmStore) Backend() string     { return BackendTPM }
func (t *tpmStore) HardwareBound() bool { return true }

func credName(name string) string { return Service + "-" + name }

func (t *tpmStore) Get(name string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	p := t.file(name)
	info, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("refusing credential that is not a regular file: %s", p)
	}
	out, err := t.run(nil, "decrypt", "--name="+credName(name), p, "-")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (t *tpmStore) Set(name, value string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if err := os.MkdirAll(t.dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(t.dir, ".cred-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpName)
	if _, err := t.run([]byte(value), "encrypt", "--with-key=tpm2", "--name="+credName(name), "-", tmpName); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		return err
	}
	return os.Rename(tmpName, t.file(name))
}

func (t *tpmStore) Delete(name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if err := os.Remove(t.file(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (t *tpmStore) run(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(t.bin, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("systemd-creds %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (t *tpmStore) file(name string) string { return filepath.Join(t.dir, name+".cred") }
