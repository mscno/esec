package commands

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/joho/godotenv"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/format"
)

func normalizeInitDotenv(data []byte) ([]byte, bool, error) {
	values, err := godotenv.Unmarshal(string(data))
	if err != nil {
		return nil, false, errors.New("invalid dotenv")
	}
	lines := strings.Split(string(data), "\n")
	normalize := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "export ") {
			lines[i] = strings.TrimSpace(strings.TrimPrefix(trimmed, "export "))
		}
		parsed, err := godotenv.Unmarshal(line)
		if err != nil || !strings.Contains(line, "=") {
			normalize = true
		}
		for _, value := range parsed {
			if crypto.IsBoxedMessage([]byte(value)) && strings.ContainsAny(line, "\"'") {
				normalize = true
			}
		}
	}
	if !normalize {
		return []byte(strings.Join(lines, "\n")), false, nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	quote := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "$", `\$`)
	var out strings.Builder
	for _, key := range keys {
		value := values[key]
		if key != format.PublicKeyField && key != format.UnderscoredPublicKeyField && !crypto.IsBoxedMessage([]byte(value)) {
			value = `"` + quote.Replace(value) + `"`
		}
		fmt.Fprintf(&out, "%s=%s\n", key, value)
	}
	return []byte(out.String()), true, nil
}
