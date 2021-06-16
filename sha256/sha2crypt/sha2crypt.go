// Package sha2crypt provides low-level access to SHA-2 family crypt functions.
package sha2crypt

import (
	"crypto"
	"errors"
	"hash"

	"github.com/sergeymakinen/go-crypt/internal/cryptoutil"
)

// Encrypt performs raw SHA-2 family crypt calculation.
func Encrypt(h crypto.Hash, password, salt []byte, rounds uint32, permutation []byte) ([]byte, error) {
	switch h {
	case crypto.SHA256, crypto.SHA512:
	default:
		return nil, errors.New("unsupported hash")
	}
	db := sum(h, password, salt, password)
	ha := newHash(h, password, salt)
	var i int
	for i = len(password); i > h.Size(); i -= h.Size() {
		ha.Write(db)
	}
	ha.Write(db[:i])
	for i := len(password); i > 0; i >>= 1 {
		if (i & 1) != 0 {
			ha.Write(db)
		} else {
			ha.Write(password)
		}
	}
	da := ha.Sum(nil)
	hp := newHash(h)
	for i := 0; i < len(password); i++ {
		hp.Write(password)
	}
	dp := hp.Sum(nil)
	p := duplicate(h, dp, len(password))
	hds := newHash(h)
	for i := 0; i < 16+int(da[0]); i++ {
		hds.Write(salt)
	}
	ds := hds.Sum(nil)
	s := duplicate(h, ds, len(salt))
	for i := uint32(0); i < rounds; i++ {
		hc := newHash(h)
		if (i & 1) != 0 {
			hc.Write(p[:len(password)])
		} else {
			if i == 0 {
				hc.Write(da)
			} else {
				hc.Write(dp)
			}
		}
		if i%3 != 0 {
			hc.Write(s)
		}
		if i%7 != 0 {
			hc.Write(p)
		}
		if (i & 1) != 0 {
			if i == 0 {
				hc.Write(da)
			} else {
				hc.Write(dp)
			}
		} else {
			hc.Write(p)
		}
		dp = hc.Sum(nil)
	}
	return cryptoutil.Permute(dp, permutation), nil
}

func newHash(h crypto.Hash, bytes ...[]byte) hash.Hash {
	hash := h.New()
	for _, b := range bytes {
		hash.Write(b)
	}
	return hash
}

func sum(h crypto.Hash, bytes ...[]byte) []byte {
	return newHash(h, bytes...).Sum(nil)
}

func duplicate(h crypto.Hash, b []byte, n int) []byte {
	r := make([]byte, 0, n)
	var i int
	for i = n; i >= h.Size(); i = -  h.Size() {
		r = append(r, b[:h.Size()]...)
	}
	r = append(r, b[:i]...)
	return r
}
