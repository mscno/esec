package commands

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kong"

	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/workspace"
)

func storeDirectory(dir string) (string, error) {
	f, err := projectfile.Load(dir)
	if err == nil && f.Workspace != nil {
		return "", projectfile.ErrWorkspace
	}
	return filepath.Abs(dir)
}

// Resolve only store inputs. Never chdir: imports, exports and child processes
// keep the caller's working directory and all ordinary relative path semantics.
func (c *cli) selectMember(parsed *kong.Context) error { //nolint:gocyclo // explicit allowlist of store operations
	words := strings.Fields(parsed.Command())
	if len(words) == 0 {
		return nil
	}
	name := words[0]
	if c.Member == "" {
		return nil
	}

	if c.Check.Workspace || c.Plan.Workspace || c.Status.Workspace || c.Files.Workspace {
		return errors.New("--member and --workspace are mutually exclusive")
	}
	i, err := workspace.Find(".")
	if err != nil {
		return err
	}
	root, err := i.Store(c.Member)
	if err != nil {
		return err
	}
	directory := func(dir *string) error {
		for _, node := range parsed.Path {
			if node.Flag != nil && node.Flag.Name == "dir" {
				return errors.New("--member cannot be combined with an explicit --dir")
			}
		}
		*dir = root
		return nil
	}
	file := func(input *string, format string, keyDir *string) error {
		if strings.HasPrefix(*input, "~/") {
			*input = kong.ExpandPath(*input)
		}
		path, _, err := fileutils.Resolve(root, *input, format)
		if err != nil {
			return errors.New("cannot resolve file in selected member")
		}
		if err := safeProjectPath(root, path); err != nil {
			return err
		}
		_, marker, err := projectfile.Find(filepath.Dir(path))
		if err != nil || filepath.Dir(marker) != root {
			return errors.New("selected file belongs to a different store")
		}
		*input = path
		if keyDir != nil && (*keyDir == "." || *keyDir == "") {
			*keyDir = root
		}
		return nil
	}
	switch name {
	case "check":
		return directory(&c.Check.Dir)
	case "plan":
		return directory(&c.Plan.Dir)
	case "status":
		return directory(&c.Status.Dir)
	case "apply":
		return directory(&c.Apply.Dir)
	case "init":
		return directory(&c.Init.Dir)
	case "repair":
		return directory(&c.Repair.Dir)
	case "files":
		if c.Files.Registered {
			return errors.New("--member cannot be combined with --registered")
		}
		c.Files.storeRoot = root
		return directory(&c.Files.Dir)
	case "encrypt":
		return file(&c.Encrypt.File, c.Encrypt.Format, nil)
	case "decrypt":
		return file(&c.Decrypt.File, c.Decrypt.Format, &c.Decrypt.KeyDir)
	case "get":
		return file(&c.Get.File, c.Get.Format, &c.Get.KeyDir)
	case "export":
		return file(&c.Export.File, c.Export.Format, &c.Export.KeyDir)
	case "run":
		return file(&c.Run.File, c.Run.Format, &c.Run.KeyDir)
	case "set":
		return file(&c.Set.File, "", nil)
	case "inspect":
		return file(&c.Inspect.File, c.Inspect.Format, &c.Inspect.KeyDir)
	case "recipients":
		return file(&c.Recipients.File, "", nil)
	case "rotate":
		return file(&c.Rotate.File, "", nil)
	case "adopt":
		return file(&c.Adopt.File, "", nil)
	case "diff":
		for n := range c.Diff.Files {
			if err := file(&c.Diff.Files[n], "", nil); err != nil {
				return err
			}
		}
		return nil
	case "blob":
		if len(words) > 1 {
			switch words[1] {
			case "set":
				return file(&c.Blob.Set.Environment, "", nil)
			case "get":
				return file(&c.Blob.Get.Environment, "", nil)
			case "run":
				return file(&c.Blob.Run.Environment, "", nil)
			}
		}
	case "secrets":
		if len(words) > 1 {
			switch words[1] {
			case "show":
				return file(&c.Secrets.Show.File, "", nil)
			case "update":
				return file(&c.Secrets.Update.File, "", nil)
			}
		}
	case "recovery":
		if len(words) > 1 && words[1] == "verify" {
			return file(&c.Recovery.Verify.File, "", nil)
		}
	}
	return errors.New("--member is supported only for store operations; machine identities and setup are independent of workspaces")
}
