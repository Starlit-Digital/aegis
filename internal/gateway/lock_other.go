//go:build !darwin && !linux

package gateway

import (
	"errors"
	"os"
)

func lockSpool(string) (*os.File, error) {
	return nil, errors.New("aegis currently supports macOS and Linux")
}
