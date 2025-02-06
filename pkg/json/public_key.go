package json

import (
	"encoding/json"
	"fmt"
	"github.com/mscno/esec/pkg/format"
)

func (f *JsonFormatter) ExtractPublicKey(data []byte) ([32]byte, error) {
	// Unmarshal JSON to map structure
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return [32]byte{}, fmt.Errorf("invalid json: %v", err)
	}

	return format.ExtractPublicKeyHelper(obj)
}
