//go:build !unix

package aegis_test

import (
	"testing"
)

func fence[T []byte | string](_ *testing.T, s T) []byte {
	return []byte(s)
}
