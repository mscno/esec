package json

import (
	"encoding/json"
	"fmt"
	"github.com/mscno/esec/pkg/format"
)

// ExtractPublicKey parses the JSON data and returns the ESEC_PUBLIC_KEY value.
// It looks for either "_ESEC_PUBLIC_KEY" (preferred) or "ESEC_PUBLIC_KEY" fields
// at the top level of the JSON document.
func (f *JsonFormatter) ExtractPublicKey(data []byte) ([32]byte, error) {
	// Unmarshal JSON to map structure
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return [32]byte{}, fmt.Errorf("invalid json: %v", err)
	}

	return format.ExtractPublicKeyHelper(obj)
}
