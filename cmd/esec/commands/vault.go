package commands

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/mscno/esec"
)

func readDocument(file, format, keyDir, key string) ([]byte, error) {
	target, err := esec.ResolveRead(".", file, format)
	if err != nil {
		return nil, err
	}
	return esec.ReadDocument(target, esec.ReadOptions{KeyDir: keyDir, PrivateKey: key, Session: os.Getenv("ESEC_VAULT_SESSION")})
}

// InspectCmd explains the exact read plan without opening a key or asking consent.
type InspectCmd struct {
	File   string `arg:"" help:"Exact environment or filename"`
	Format string `short:"f" env:"ESEC_FORMAT" help:"File format filter"`
	KeyDir string `short:"d" default:"." env:"ESEC_KEY_DIR" help:"Local keyring directory"`
	JSON   bool   `help:"Print public inspection metadata as JSON"`
}

// Run prints the public read plan without unlocking it.
func (c *InspectCmd) Run(_ *cliCtx) error {
	target, err := esec.ResolveRead(".", c.File, c.Format)
	if err != nil {
		if c.JSON {
			failure := esec.ReadError{Code: "inspection_failed", Detail: err.Error()}
			var re *esec.ReadError
			if errors.As(err, &re) {
				failure = *re
			}
			if encodeErr := json.NewEncoder(os.Stdout).Encode(&esec.ReadInspection{Route: "blocked", Key: "unknown", Reader: "not_verified", Blockers: []esec.ReadError{failure}}); encodeErr != nil {
				return encodeErr
			}
		}
		return err
	}
	result := esec.InspectRead(target, esec.ReadOptions{KeyDir: c.KeyDir})
	if c.JSON {
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	return esec.WriteInspection(os.Stdout, result)
}
