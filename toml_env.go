package esec

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// TomlToEnv flattens tables with __ separators. Top-level names retain case;
// nested paths are uppercased. Scalars are strings, numbers or booleans.
// Arrays and date/time values require explicit application-level parsing.
func TomlToEnv(data []byte) (map[string]string, error) {
	var doc map[string]any
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid TOML")
	}
	out := map[string]string{}
	var walk func(map[string]any, []string) error
	walk = func(m map[string]any, prefix []string) error {
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if len(prefix) == 0 && (k == "ESEC_PUBLIC_KEY" || k == "_ESEC_PUBLIC_KEY") {
				continue
			}
			if !validIdentifierPattern.MatchString(k) {
				return fmt.Errorf("invalid TOML environment key %q", k)
			}
			parts := append(append([]string{}, prefix...), k)
			v := m[k]
			if child, ok := v.(map[string]any); ok {
				if err := walk(child, parts); err != nil {
					return err
				}
				continue
			}
			name := strings.Join(parts, "__")
			if len(parts) > 1 {
				name = strings.ToUpper(name)
			}
			if _, exists := out[name]; exists {
				return fmt.Errorf("TOML environment key collision at %q", name)
			}
			var value string
			switch v := v.(type) {
			case string:
				value = v
			case bool:
				value = strconv.FormatBool(v)
			case int64:
				value = strconv.FormatInt(v, 10)
			case float64:
				value = strconv.FormatFloat(v, 'g', -1, 64)
			default:
				return fmt.Errorf("unsupported TOML value for %q: run supports scalar strings, numbers, booleans and nested tables", name)
			}
			out[name] = value
		}
		return nil
	}
	if err := walk(doc, nil); err != nil {
		return nil, err
	}
	return out, nil
}
