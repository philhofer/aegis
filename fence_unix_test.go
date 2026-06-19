//go:build unix

package aegis_test

import (
	"syscall"
	"testing"
)

// fence constructs a byte slice that ends at a page boundary,
// and guarantees that the subsequent page is mapped PROT_NONE
func fence[T []byte | string](t *testing.T, s T) []byte {
	t.Helper()
	pgsize := syscall.Getpagesize()
	spgsize := (len(s) + pgsize - 1) &^ (pgsize - 1)
	size := pgsize + spgsize
	buf, err := syscall.Mmap(-1, 0, size, syscall.PROT_NONE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		syscall.Munmap(buf)
	})
	if spgsize > 0 {
		err = syscall.Mprotect(buf[:spgsize], syscall.PROT_READ|syscall.PROT_WRITE)
		if err != nil {
			t.Fatal(err)
		}
	}
	offset := spgsize - len(s)
	copy(buf[offset:], s)
	return buf[offset : offset+len(s) : offset+len(s)]
}
