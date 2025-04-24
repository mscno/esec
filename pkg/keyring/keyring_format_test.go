package keyring

import (
	"strings"
	"testing"
)

func TestFormatKeyringFile(t *testing.T) {
	input := map[string]string{
		"ESEC_ACTIVE_ENVIRONMENT": "dev",
		"ESEC_ACTIVE_KEY":         "HelloDev",
		"ESEC_PRIVATE_KEY_DEV":    "HelloDev",
		"ESEC_PRIVATE_KEY_PROD":   "HelloProd",
		"OTHER":                   "shouldnotshow",
	}
	got := FormatKeyringFile(input)

	expectedSections := []string{`###########################################################
### Private key file - Do not commit to version control ###
###########################################################

### Active Key
ESEC_ACTIVE_ENVIRONMENT=dev
ESEC_ACTIVE_KEY=HelloDev

### Private Keys
ESEC_PRIVATE_KEY_DEV=HelloDev
ESEC_PRIVATE_KEY_PROD=HelloProd
`,
	}
	for _, section := range expectedSections {
		if !strings.Contains(got, section) {
			t.Errorf("Missing section:\n%s\nGot:\n%s", section, got)
		}
	}
	if strings.Contains(got, "OTHER=") {
		t.Errorf("Should not include non-active/non-private keys, got: %s", got)
	}
}
