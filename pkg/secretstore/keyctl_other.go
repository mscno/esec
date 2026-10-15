//go:build !linux

package secretstore

import "fmt"

func newKeyctl() (Store, error) {
	return nil, fmt.Errorf("%w: the kernel keyring store requires Linux", ErrUnavailable)
}
