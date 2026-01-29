package toml

import (
	"fmt"

	"github.com/mscno/esec/pkg/format"
	"github.com/pelletier/go-toml/v2"
)

// ExtractPublicKey parses the TOML data and returns the ESEC_PUBLIC_KEY value.
// It looks for either "_ESEC_PUBLIC_KEY" (preferred) or "ESEC_PUBLIC_KEY" fields
// at the top level of the TOML document.
func (f *Formatter) ExtractPublicKey(data []byte) ([32]byte, error) {
	var doc map[string]interface{}
	if err := toml.Unmarshal(data, &doc); err != nil {
		return [32]byte{}, fmt.Errorf("invalid toml: %v", err)
	}

	// Empty document
	if len(doc) == 0 {
		return [32]byte{}, fmt.Errorf("invalid toml: empty document")
	}

	// Search for the public key in the document
	for _, keyName := range []string{format.UnderscoredPublicKeyField, format.PublicKeyField} {
		if value, ok := doc[keyName]; ok {
			strValue, ok := value.(string)
			if !ok {
				return [32]byte{}, fmt.Errorf("%w: public key is not a string", format.ErrPublicKeyInvalid)
			}
			key, err := format.ParseKey(strValue)
			if err != nil {
				return [32]byte{}, fmt.Errorf("%w: %v", format.ErrPublicKeyInvalid, err)
			}
			return key, nil
		}
	}

	return [32]byte{}, format.ErrPublicKeyMissing
}
