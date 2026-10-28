package seal

import (
	"filippo.io/age"
	"filippo.io/age/agessh"
)

// parseSSHRecipient parses an ssh-ed25519 or ssh-rsa public key, such as
// one of github.com/USER.keys.
func parseSSHRecipient(s string) (age.Recipient, error) { return agessh.ParseRecipient(s) }
