// Package crypt implements a basic interface to validate crypt(3) hashes.
//
// Validation of any particular hash requires the prior registration of a check function.
// Registration is typically automatic as a side effect of initializing that
// hash's package so that, to validate an Argon2 has, it suffices to have
// 	import _ "github.com/sergeymakinen/go-crypt/argon2"
// in a program's main package. The _ means to import a package purely for its
// initialization side effects.
package crypt

import (
	"errors"
	"strings"
	"sync"
)

var (
	ErrHash             = errors.New("unknown hash")
	ErrPasswordMismatch = errors.New("hash and password mismatch")
)

var hashCache sync.Map // map[string]func(hash, password string) error

// RegisterHash registers a hash for use by Check.
// Prefix is a prefix that identifies the hash.
// Check is the function that compares the given hash
// with a new hash derived from the password.
func RegisterHash(prefix string, check func(hash, password string) error) {
	hashCache.Store(prefix, check)
}

// Check compares the given crypt(3) hash with a new hash derived from the password.
// Returns nil on success, or an error on failure.
func Check(hash, password string) error {
	var prefix string
	if strings.HasPrefix(hash, "$") {
		if i := strings.IndexAny(hash[1:], "$,"); i >= 0 {
			if i == 0 {
				return ErrHash
			}
			prefix = hash[:i+2]
		} else {
			return ErrHash
		}
	}
	if strings.HasPrefix(hash, "_") {
		prefix = "_"
	}
	if check, ok := hashCache.Load(prefix); ok {
		return check.(func(hash, password string) error)(hash, password)
	}
	return ErrHash
}
