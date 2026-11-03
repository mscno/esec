package seal

import (
	"strings"
	"testing"

	"filippo.io/age/plugin"
)

func TestYubiKeyDiscoveryRejectsCachedTouchAndOtherRecipients(t *testing.T) {
	r := plugin.EncodeRecipient("yubikey", []byte("synthetic-test-recipient"))
	ref := plugin.EncodeIdentity("yubikey", []byte("synthetic-test-reference"))
	output := "# Touch policy: Always (A physical touch is required for every decryption)\n# Recipient: " + r + "\n" + ref + "\n"
	ids, err := YubiKeyReferences(output, []string{r})
	if err != nil || len(ids) != 1 || ids[0] != ref {
		t.Fatal("always-touch discovery failed", err)
	}
	if _, err := YubiKeyReferences(strings.Replace(output, "Always", "Cached", 1), []string{r}); err == nil {
		t.Fatal("cached touch accepted")
	}
	if _, err := YubiKeyReferences(output, []string{"other"}); err == nil {
		t.Fatal("unconfigured hardware accepted")
	}
}

func TestExplicitYubiKeyIdentitiesVerifyPolicy(t *testing.T) {
	ref := plugin.EncodeIdentity("yubikey", []byte("synthetic-test-reference"))
	recipient := plugin.EncodeRecipient("yubikey", []byte("synthetic-test-recipient"))
	output := "# Touch policy: Cached (15 seconds)\n# Recipient: " + recipient + "\n" + ref + "\n"
	if _, err := yubiKeyReferences(output, nil, []string{ref}); err == nil {
		t.Fatal("explicit cached-touch identity accepted")
	}
	ids, err := parseLocalIdentities(ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatal("missing identity")
	}
	if _, ok := ids[0].(*localYubiKey); !ok {
		t.Fatal("explicit reference bypassed hardware verifier")
	}
	if _, err := yubiKeyReferences(strings.Replace(output, "Cached (15 seconds)", "Always", 1), nil, []string{ref}); err != nil {
		t.Fatal(err)
	}
}
