package seal

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// localYubiKey discovers hardware only after the software identities failed.
// Discovery reads public slot metadata; the plugin itself asks for PIN/touch.
// There is no key cache, persistent process, or hardware private-key export.
type localYubiKey struct {
	recipients []string
	identities []string
	ui         *plugin.ClientUI
}

func (y *localYubiKey) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "age-plugin-yubikey", "--identity").Output()
	if err != nil {
		return nil, fmt.Errorf("discover YubiKey: %w (connect the key and install age-plugin-yubikey)", err)
	}
	refs, err := yubiKeyReferences(string(output), y.recipients, y.identities)
	if err != nil {
		return nil, err
	}
	for _, ref := range refs {
		ui := y.ui
		if ui == nil {
			ui = plugin.NewTerminalUI(func(string, ...any) {}, func(string, ...any) {})
		}
		id, err := plugin.NewIdentity(ref, ui)
		if err != nil {
			return nil, err
		}
		key, err := id.Unwrap(stanzas)
		if err == nil {
			return key, nil
		}
		if !errors.Is(err, age.ErrIncorrectIdentity) {
			return nil, err
		}
	}
	return nil, age.ErrIncorrectIdentity
}

// YubiKeyReferences selects only configured recipients with actual always-touch
// slot metadata. A public recipient alone does not attest the slot's policy.
func YubiKeyReferences(output string, recipients []string) ([]string, error) {
	return yubiKeyReferences(output, recipients, nil)
}

func yubiKeyReferences(output string, recipients, identities []string) ([]string, error) {
	var refs []string
	recipient, policy := "", ""
	cached := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			field := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if v, ok := strings.CutPrefix(field, "Touch policy:"); ok {
				policy = strings.TrimSpace(v)
			}
			if v, ok := strings.CutPrefix(field, "Recipient:"); ok {
				recipient = strings.TrimSpace(v)
			}
			continue
		}
		if strings.HasPrefix(line, "AGE-PLUGIN-YUBIKEY-") {
			if slices.Contains(recipients, recipient) || slices.Contains(identities, line) {
				if policy == "Always" || strings.HasPrefix(policy, "Always ") {
					name, _, err := plugin.ParseIdentity(line)
					if err != nil || name != "yubikey" {
						return nil, errors.New("invalid YubiKey reference")
					}
					refs = append(refs, line)
				} else {
					cached = true
				}
			}
			recipient, policy = "", ""
		}
	}
	if len(refs) == 0 && cached {
		return nil, errors.New("configured YubiKey slot does not require every touch; use an always-touch slot")
	}
	if len(refs) == 0 {
		return nil, errors.New("no configured always-touch YubiKey is connected")
	}
	return refs, nil
}
