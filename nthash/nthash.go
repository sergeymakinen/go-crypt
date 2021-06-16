// Package nthash implements the NT Hash hashing algorithm for crypt(3).
package nthash

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"unicode/utf16"

	"github.com/sergeymakinen/go-crypt"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"golang.org/x/crypto/md4"
)

const MaxPasswordLength = 256

// InvalidPasswordLengthError values describe errors resulting from an invalid length of a password.
type InvalidPasswordLengthError int

func (e InvalidPasswordLengthError) Error() string {
	return fmt.Sprintf("invalid password length %d", int(e))
}

// Key returns a NT Hash key derived from the password and salt.
func Key(password []byte) ([]byte, error) {
	if n := len(password); n%2 != 0 || n > MaxPasswordLength {
		return nil, InvalidPasswordLengthError(n)
	}
	h := md4.New()
	h.Write(password)
	return h.Sum(nil), nil
}

const Prefix = "$3$"

// UnsupportedPrefixError values describe errors resulting from an unsupported prefix string.
type UnsupportedPrefixError string

func (e UnsupportedPrefixError) Error() string {
	return "unsupported prefix " + strconv.Quote(string(e))
}

type hashPrefix string

func (h *hashPrefix) UnmarshalText(text []byte) error {
	if s := string(text); s != Prefix {
		return UnsupportedPrefixError(s)
	}
	*h = Prefix
	return nil
}

const sumLength = 32

type scheme struct {
	HashPrefix hashPrefix
	Empty      [0]byte
	Sum        [sumLength]byte
}

func encodePassword(s string) []byte {
	a := utf16.Encode([]rune(s))
	b := make([]byte, len(a)*2)
	for i, r := range a {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

// NewHash returns the crypt(3) NT Hash hash of the password.
func NewHash(password string) (string, error) {
	b, err := Key(encodePassword(password))
	if err != nil {
		return "", err
	}
	scheme := scheme{HashPrefix: Prefix}
	hex.Encode(scheme.Sum[:], b)
	return crypthash.Marshal(scheme)
}

// Check compares the given crypt(3) NT Hash hash with a new hash derived from the password.
// Returns nil on success, or an error on failure.
func Check(hash, password string) error {
	var scheme scheme
	if err := crypthash.Unmarshal(hash, &scheme); err != nil {
		return err
	}
	key, err := Key(encodePassword(password))
	if err != nil {
		return err
	}
	var b [sumLength]byte
	hex.Encode(b[:], key)
	if subtle.ConstantTimeCompare(b[:], scheme.Sum[:]) == 0 {
		return crypt.ErrPasswordMismatch
	}
	return nil
}

func init() {
	crypt.RegisterHash(Prefix, Check)
}
