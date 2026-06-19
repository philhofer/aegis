package aegis_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/philhofer/aegis"
	"github.com/philhofer/aegis/internal/ref"
)

func Fuzz128L(f *testing.F) {
	testFuzz(f, aegis.KeySize128L, aegis.NonceSize128L)
}

func Fuzz256(f *testing.F) {
	testFuzz(f, aegis.KeySize256, aegis.NonceSize256)
}

func testFuzz(f *testing.F, keySize, nonceSize int) {
	key := make([]byte, keySize)
	nonce := make([]byte, nonceSize)
	rand.Read(key)
	rand.Read(nonce)

	f.Add("", "")
	f.Add("plaintext", "ad")
	f.Add("a very longer plaintext string w/o ad", "")
	f.Add("", "just ad")
	f.Fuzz(func(t *testing.T, plaintext, ad string) {
		refcrypt, err := ref.New(key)
		if err != nil {
			t.Fatal(err)
		}
		ourcrypt, err := aegis.New(key)
		if err != nil {
			t.Fatal(err)
		}
		pt := []byte(plaintext)
		at := []byte(ad)

		wantCt := refcrypt.Seal(nil, nonce, pt, at)
		gotCt := ourcrypt.Seal(nil, nonce, pt, at)
		if !bytes.Equal(wantCt, gotCt) {
			t.Fatal("didn't get identical ciphertext")
		}
		wantPt, err := refcrypt.Open(nil, nonce, wantCt, at)
		if err != nil {
			t.Fatal(err)
		}
		gotPt, err := ourcrypt.Open(nil, nonce, gotCt, at)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(wantPt, gotPt) {
			t.Fatal("didn't get identitcal output plaintext")
		}
		if !bytes.Equal(gotPt, pt) {
			t.Fatal("didn't round-trip plaintext")
		}
	})
}
