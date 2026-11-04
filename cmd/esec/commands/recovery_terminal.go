package commands

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/term"
)

// A controlling terminal keeps phrases out of pipes, redirected stdout, argv,
// environment variables, and logs. Tests supply a synthetic terminal.
type recoveryTerminal interface {
	Secret(label string) (string, error)
	Write(text string) error
	Close() error
}

var openRecoveryTerminal = newRecoveryTerminal

type privateTerminal struct{ input, output *os.File }

func newRecoveryTerminal() (recoveryTerminal, error) {
	input, output := "/dev/tty", "/dev/tty"
	if runtime.GOOS == "windows" {
		input, output = "CONIN$", "CONOUT$"
	}
	in, err := os.OpenFile(input, os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("recovery requires your local interactive terminal; run this command there (never put the phrase in arguments or chat)")
	}
	out, err := os.OpenFile(output, os.O_WRONLY, 0)
	if err != nil {
		in.Close()
		return nil, err
	}
	if !term.IsTerminal(int(in.Fd())) {
		in.Close()
		out.Close()
		return nil, errors.New("recovery input must be a terminal")
	}
	return &privateTerminal{input: in, output: out}, nil
}
func (t *privateTerminal) Secret(label string) (string, error) {
	if err := t.Write(label); err != nil {
		return "", err
	}
	b, err := term.ReadPassword(int(t.input.Fd()))
	defer clear(b)
	newlineErr := t.Write("\n")
	if err != nil {
		return "", errors.New("recovery input was interrupted")
	}
	if newlineErr != nil {
		return "", newlineErr
	}
	return string(b), nil
}
func (t *privateTerminal) Write(text string) error { _, err := fmt.Fprint(t.output, text); return err }
func (t *privateTerminal) Close() error            { return errors.Join(t.input.Close(), t.output.Close()) }
