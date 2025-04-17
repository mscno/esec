package dotenv

import (
	"fmt"
	"sort"
	"strings"
)

// FormatKeyringFile takes a map of key-value pairs and returns a formatted string for .esec-keyring
func FormatKeyringFile(envMap map[string]string) string {
	var b strings.Builder
	b.WriteString("###########################################################\n### Private key file - Do not commit to version control ###\n###########################################################\n\n")

	// Collect and write active keys
	activeKeys := []string{}
	for k := range envMap {
		if strings.HasPrefix(k, "ESEC_ACTIVE") {
			activeKeys = append(activeKeys, k)
		}
	}
	sort.Strings(activeKeys)
	if len(activeKeys) > 0 {
		b.WriteString("### Active Key\n")
		for _, k := range activeKeys {
			b.WriteString(fmt.Sprintf("%s=%s\n", k, envMap[k]))
		}
		b.WriteString("\n")
	}

	// Collect and write private keys
	privateKeys := []string{}
	for k := range envMap {
		if strings.HasPrefix(k, "ESEC_PRIVATE_KEY") {
			privateKeys = append(privateKeys, k)
		}
	}
	sort.Strings(privateKeys)
	if len(privateKeys) > 0 {
		b.WriteString("### Private Keys\n")
		for _, k := range privateKeys {
			b.WriteString(fmt.Sprintf("%s=%s\n", k, envMap[k]))
		}
	}

	return b.String()
}
