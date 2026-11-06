package commands

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/mscno/esec/pkg/config"
	"github.com/pelletier/go-toml/v2"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/filelock"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/secretfile"
)

// FilesCmd discovers ciphertext and key names without decrypting values.
type FilesCmd struct {
	Registered bool   `help:"List remembered checkout paths from local migration metadata"`
	Dir        string `default:"." type:"path" help:"Directory to search recursively"`
	JSON       bool   `help:"Print JSON (the default)"`
}

// Run prints public local file metadata only.
func (c *FilesCmd) Run(_ *cliCtx) error {
	if c.Registered {
		return registeredCheckoutPaths()
	}
	root, err := filepath.Abs(c.Dir)
	if err != nil {
		return err
	}
	files, err := secretfile.Scan(root)
	if err != nil {
		return err
	}
	if files == nil {
		files = []secretfile.File{}
	}
	return json.NewEncoder(os.Stdout).Encode(files)
}

// SecretsCmd exposes the local document interface used by native editors.
type SecretsCmd struct {
	Show   SecretsShowCmd   `cmd:"" help:"Decrypt one file in memory to JSON; never contacts a broker"`
	Update SecretsUpdateCmd `cmd:"" help:"Encrypt a revision-checked edit from JSON stdin"`
}

// SecretsShowCmd opens a document using Esec's local key resolution.
type SecretsShowCmd struct {
	File string `required:"" type:"existingfile" help:"Exact secrets file"`
	JSON bool   `help:"Print JSON (the default)"`
	GUI  bool   `help:"Use JSON-lines hardware prompts and a result frame over stdin/stdout"`
}
type secretDocumentView struct {
	secretfile.Document

	File       *secretfile.File `json:"file"`
	Decryption esec.ReadInfo    `json:"decryption"`
}

// Run emits a document only after successful local decryption.
func (c *SecretsShowCmd) Run(_ *cliCtx) error {
	options := esec.ReadOptions{}
	if c.GUI {
		options.AgeUI = newGUIProtocol(os.Stdin, os.Stdout).ui()
	}
	doc, err := c.document(options)
	if err != nil {
		return err
	}
	if c.GUI {
		return json.NewEncoder(os.Stdout).Encode(struct {
			Type     string              `json:"type"`
			Document *secretDocumentView `json:"document"`
		}{"result", doc})
	}
	return json.NewEncoder(os.Stdout).Encode(doc)
}
func (c *SecretsShowCmd) document(options esec.ReadOptions) (*secretDocumentView, error) {
	target, err := esec.ResolveRead(".", c.File, "")
	if err != nil {
		return nil, err
	}
	file, err := secretfile.Parse(target.Path, target.Content)
	if err != nil {
		return nil, errors.New("could not read file metadata")
	}
	file.Env = target.Environment
	plain, info, err := esec.ReadDocumentWithInfo(target, options)
	if err != nil {
		return nil, err
	}
	values, err := secretfile.DocumentValues(plain, fileutils.FileFormat(file.Format))
	if err != nil {
		return nil, err
	}
	return &secretDocumentView{File: file, Decryption: info, Document: secretfile.Document{Revision: target.Digest, Values: values}}, nil
}

// SecretsUpdateCmd accepts only a JSON stdin payload, keeping values out of argv.
type SecretsUpdateCmd struct {
	File string `required:"" type:"existingfile" help:"Exact secrets file"`
}
type secretUpdate struct {
	Revision string  `json:"revision"`
	Key      string  `json:"key"`
	Value    *string `json:"value"`
	Create   bool    `json:"create"`
}

// Run encrypts an edit and prints its new ciphertext revision.
func (c *SecretsUpdateCmd) Run(_ *cliCtx) error {
	var update secretUpdate
	dec := json.NewDecoder(io.LimitReader(os.Stdin, 10<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&update); err != nil {
		return errors.New("expected revision, key and value in JSON stdin")
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("expected one JSON update")
	}
	revision, err := updateSecretDocument(c.File, update)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Revision string `json:"revision"`
	}{revision})
}
func updateSecretDocument(path string, update secretUpdate) (string, error) {
	if len(update.Revision) != 64 || update.Key == "" || update.Value == nil {
		return "", errors.New("revision, key and value are required")
	}
	target, err := esec.ResolveRead(".", path, "")
	if err != nil {
		return "", err
	}
	root := target.Root
	if root == "" {
		root = filepath.Dir(target.Path)
	}
	if err := safeProjectPath(root, filepath.Join(root, ".esec")); err != nil {
		return "", err
	}
	unlock, err := filelock.Acquire(filepath.Join(root, ".esec"))
	if err != nil {
		return "", err
	}
	defer unlock()
	before, err := snapshot(target.Path)
	if err != nil {
		return "", err
	}
	if before.Hash != update.Revision || target.Digest != update.Revision {
		return "", errors.New("this file changed on disk; reload it before saving")
	}
	expected, err := documentSnapshots(target, root, before)
	if err != nil {
		return "", err
	}
	file, err := secretfile.Parse(target.Path, target.Content)
	if err != nil {
		return "", errors.New("could not read file metadata")
	}
	if len(file.Plain) > 0 {
		return "", errors.New("the file contains unencrypted values; encrypt them before editing in the app")
	}
	if err := validateSecretEdit(target.Content, file, update); err != nil {
		return "", err
	}
	next, err := secretfile.Set(target.Content, fileutils.FileFormat(file.Format), update.Key, *update.Value, update.Create)
	if err != nil {
		return "", errors.New("could not encrypt this value; check its key and format (nothing was saved)")
	}
	if err := applyCiphertextChanges(root, map[string][]byte{target.Path: next}, expected); err != nil {
		return "", err
	}
	return secretfile.Revision(next), nil
}
func validateSecretEdit(data []byte, f *secretfile.File, update secretUpdate) error {
	values, err := secretfile.DocumentValues(data, fileutils.FileFormat(f.Format))
	if err != nil {
		return err
	}
	found := false
	for _, entry := range values {
		if entry.Key != update.Key {
			continue
		}
		found = true
		if update.Create {
			return errors.New("this key already exists; edit its value instead")
		}
		if !entry.Editable {
			return errors.New("this value is read-only in the editor")
		}
	}
	if !found {
		if !update.Create {
			return secretfile.ErrNotFound
		}
		if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`).MatchString(update.Key) {
			return errors.New("use a key name starting with a letter, followed by letters, digits or underscores")
		}
	}
	return nil
}

// registeredCheckoutPaths imports only local folder names, never Vault keys.
func registeredCheckoutPaths() error {
	p, err := config.Path()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(p), "projects.toml"))
	var paths = []string{}
	if errors.Is(err, os.ErrNotExist) {
		return json.NewEncoder(os.Stdout).Encode(paths)
	}
	if err != nil {
		return err
	}
	var registry struct {
		Checkouts []struct {
			Path string `toml:"path"`
		} `toml:"checkout"`
	}
	if err := toml.Unmarshal(data, &registry); err != nil {
		return errors.New("could not read remembered local checkout paths")
	}
	for _, c := range registry.Checkouts {
		if filepath.IsAbs(c.Path) {
			paths = appendUnique(paths, filepath.Clean(c.Path))
		}
	}
	return json.NewEncoder(os.Stdout).Encode(paths)
}

func documentSnapshots(target *esec.ReadTarget, root string, before sourceSnapshot) (map[string]sourceSnapshot, error) {
	expected := map[string]sourceSnapshot{target.Path: before}
	if target.Root != "" {
		marker := filepath.Join(root, "esec.toml")
		markerBefore, e := snapshot(marker)
		if e != nil {
			return nil, e
		}
		expected[marker] = markerBefore
		fresh, e := esec.ResolveRead(root, target.Path, "")
		if e != nil {
			return nil, e
		}
		if fresh.PublicKey != target.PublicKey || fresh.Digest != target.Digest {
			return nil, errors.New("file or key changed; reload before saving")
		}
	}

	return expected, nil
}
