package secretfile

import (
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/fileutils"
)

// ValidateCiphertext checks encrypted envelope syntax without opening a key.
// Authentication and recipient access still require an actual decryption.
func ValidateCiphertext(data []byte, format fileutils.FileFormat) error {
	h, err := handler(format)
	if err != nil {
		return err
	}
	_, err = h.TransformScalarValues(data, func(value []byte) ([]byte, error) {
		if crypto.IsBoxedMessage(value) {
			if err := crypto.ValidateBoxedMessage(value); err != nil {
				return nil, err
			}
		}
		return value, nil
	})
	return err
}
