package secretstore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/pelletier/go-toml/v2"

	"github.com/mscno/esec/pkg/filelock"
)

// FileStore keeps secrets in one 0600 TOML file. It survives reboots and has
// the same protection as an SSH private key on disk: file permissions only.
type FileStore struct {
	Path string
}

// NewFile returns a file-backed store at path.
func NewFile(path string) *FileStore { return &FileStore{Path: path} }

// Backend implements Store.
func (f *FileStore) Backend() string { return BackendFile }

// HardwareBound implements Store.
func (f *FileStore) HardwareBound() bool { return false }

type fileContent struct {
	Secrets map[string]string `toml:"secrets"`
}

// Get implements Store.
func (f *FileStore) Get(name string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	m, err := f.read()
	if err != nil {
		return "", err
	}
	v, ok := m[name]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

// Set implements Store.
func (f *FileStore) Set(name, value string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	return f.update(func(m map[string]string) { m[name] = value })
}

// Delete implements Store.
func (f *FileStore) Delete(name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	return f.update(func(m map[string]string) { delete(m, name) })
}

func (f *FileStore) read() (map[string]string, error) {
	info, err := os.Lstat(f.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing secret store that is not a regular file: %s", f.Path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("secret store %s is readable by other users (mode %04o); run: chmod 600 %s", f.Path, info.Mode().Perm(), f.Path)
	}
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, err
	}
	var c fileContent
	if err := toml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("invalid secret store %s: %w", f.Path, err)
	}
	if c.Secrets == nil {
		c.Secrets = map[string]string{}
	}
	return c.Secrets, nil
}

func (f *FileStore) update(fn func(map[string]string)) error {
	unlock, err := filelock.Acquire(filepath.Dir(f.Path))
	if err != nil {
		return err
	}
	defer unlock()
	m, err := f.read()
	if err != nil {
		return err
	}
	fn(m)
	data, err := toml.Marshal(fileContent{Secrets: m})
	if err != nil {
		return err
	}
	return writePrivate(f.Path, data)
}
