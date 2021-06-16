// Package md5crypt provides low-level access to MD5 crypt functions.
package md5crypt

import (
	"crypto/md5"
	"hash"

	"github.com/sergeymakinen/go-crypt/internal/cryptoutil"
)

// Permutation table for final digest.
var permFinal = [16]byte{
	12, 6, 0, 13,
	7, 1, 14, 8,
	2, 15, 9, 3,
	5, 10, 4, 11,
}

// Encrypt performs raw MD5 crypt calculation.
func Encrypt(password, salt, prefix []byte) []byte {
	h := newHash(password, prefix, salt)
	d := sum(password, salt, password)
	for i := len(password); i > 0; i -= md5.Size {
		if i > md5.Size {
			h.Write(d)
		} else {
			h.Write(d[:i])
		}
	}
	for i := len(password); i > 0; i >>= 1 {
		if i&1 != 0 {
			h.Write([]byte{0})
		} else {
			h.Write(password[:1])
		}
	}
	d = h.Sum(nil)
	for i := 0; i < 1000; i++ {
		h1 := newHash()
		if i&1 != 0 {
			h1.Write(password)
		} else {
			h1.Write(d)
		}
		if i%3 != 0 {
			h1.Write(salt)
		}
		if i%7 != 0 {
			h1.Write(password)
		}
		if i&1 != 0 {
			h1.Write(d)
		} else {
			h1.Write(password)
		}
		d = h1.Sum(nil)
	}
	return cryptoutil.Permute(d, permFinal[:])
}

func newHash(bytes ...[]byte) hash.Hash {
	h := md5.New()
	for _, b := range bytes {
		h.Write(b)
	}
	return h
}

func sum(bytes ...[]byte) []byte {
	return newHash(bytes...).Sum(nil)
}
