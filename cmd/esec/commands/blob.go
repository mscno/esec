package commands

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/blob"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/secretfile"
)

// BlobCmd manages exact file bytes inside ordinary encrypted secret values.
type BlobCmd struct {
	Set BlobSetCmd `cmd:"" help:"Encrypt a file or stdin as a versioned blob value"`
	Get BlobGetCmd `cmd:"" help:"Decode a blob to stdout or a new private file"`
	Run BlobRunCmd `cmd:"" help:"Run a command with selected blobs in private temporary files"`
}

// BlobSetCmd never accepts secret content in command arguments.
type BlobSetCmd struct {
	Environment string `arg:"" help:"Exact environment or secrets file"`
	Key         string `arg:"" help:"Secret key or existing dotted field path"`
	From        string `help:"Read bytes from this regular file" xor:"source"`
	Stdin       bool   `help:"Read exact bytes from stdin" xor:"source"`
	Create      bool   `help:"Explicitly add a missing simple top-level key"`
}

// Run snapshots the destination before reading input and writes only ciphertext.
func (c *BlobSetCmd) Run(ctx *cliCtx) error {
	if (c.From != "") == c.Stdin {
		return errors.New("choose exactly one of --from FILE or --stdin")
	}
	target, err := esec.ResolveRead(".", c.Environment, "")
	if err != nil {
		return errors.New("cannot resolve secrets file or access metadata; use esec check")
	}
	var input io.Reader = os.Stdin
	if c.From != "" {
		file, err := openBlobInput(c.From)
		if err != nil {
			return errors.New("could not open blob input")
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > blob.MaxSize {
			return errors.New("blob input must be a readable regular file no larger than 1 MiB")
		}
		input = file
	}
	data, err := io.ReadAll(io.LimitReader(input, blob.MaxSize+1))
	defer clear(data)
	if err != nil {
		return errors.New("could not read blob input")
	}
	value, err := blob.Encode(data)
	if err != nil {
		return err
	}
	_, err = updateSecretDocument(target.Path, secretUpdate{Revision: target.Digest, Key: c.Key, Value: &value, Create: c.Create})
	if err != nil {
		return err
	}
	say(ctx, "Saved encrypted blob %s in %s.", c.Key, target.Environment)
	return nil
}

// BlobGetCmd writes byte-accurate data and refuses to overwrite any existing path.
type BlobGetCmd struct {
	Environment string `arg:"" help:"Exact environment or secrets file"`
	Key         string `arg:"" help:"Blob key or dotted field path"`
	Out         string `help:"Create a new 0600 file instead of writing to stdout (Unix only)"`
}

// Run decrypts and validates the blob before producing any output.
func (c *BlobGetCmd) Run(_ *cliCtx) error {
	if c.Out != "" {
		if err := blobDiskSupported(); err != nil {
			return err
		}
	}
	values, err := readBlobValues(c.Environment)
	if err != nil {
		return err
	}
	data, err := decodeBlobValue(values, c.Key)
	if err != nil {
		return err
	}
	defer clear(data)
	if c.Out == "" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return writeBlobFile(c.Out, data)
}

func readBlobValues(environment string) ([]secretfile.Value, error) {
	target, err := esec.ResolveRead(".", environment, "")
	if err != nil {
		return nil, err
	}
	encrypted, err := secretfile.DocumentValues(target.Content, fileutils.FileFormat(target.Format))
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, v := range encrypted {
		allowed[v.Key] = v.Editable && crypto.IsBoxedMessage([]byte(v.Value))
	}
	plain, err := esec.ReadDocument(target, esec.ReadOptions{})
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	values, err := secretfile.DocumentValues(plain, fileutils.FileFormat(target.Format))
	if err != nil {
		return nil, err
	}
	for i := range values {
		values[i].Editable = values[i].Editable && allowed[values[i].Key]
	}
	return values, nil
}

func decodeBlobValue(values []secretfile.Value, key string) ([]byte, error) {
	for _, v := range values {
		if v.Key == key && v.Editable {
			return blob.Decode(v.Value)
		}
	}
	return nil, errors.New("blob key not found or not an encrypted string field")
}

func writeBlobFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) //nolint:gosec // exclusive creation prevents symlink following or overwrite
	if err != nil {
		return errors.New("cannot create blob output; the path must not already exist")
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("blob write failed and partial output could not be removed: %w", err)
		}
		return errors.New("could not write blob output; partial file removed")
	}
	return nil
}
