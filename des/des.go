// Package des implements the DES hashing algorithm for crypt(3).
package des

import (
	"crypto/subtle"
	"encoding/binary"
	"strconv"

	"github.com/sergeymakinen/go-crypt"
	"github.com/sergeymakinen/go-crypt/des/descrypt"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/internal/hashutil"
)

const MaxPasswordLength = 8

// InvalidPasswordLengthError values describe errors resulting from an invalid length of a password.
type InvalidPasswordLengthError int

func (e InvalidPasswordLengthError) Error() string {
	return "invalid password length " + strconv.FormatInt(int64(e), 10)
}

const SaltLength = 2

// InvalidSaltLengthError values describe errors resulting from an invalid length of a salt.
type InvalidSaltLengthError int

func (e InvalidSaltLengthError) Error() string {
	return "invalid salt length " + strconv.FormatInt(int64(e), 10)
}

// InvalidSaltError values describe errors resulting from an invalid character in a hash string.
type InvalidSaltError byte

func (e InvalidSaltError) Error() string {
	return "invalid character " + strconv.QuoteRuneToASCII(rune(e)) + " in salt"
}

// Key returns a DES key derived from the password and salt.
func Key(password, salt []byte) ([]byte, error) {
	if n := len(password); n > MaxPasswordLength {
		return nil, InvalidPasswordLengthError(n)
	}
	if n := len(salt); n != SaltLength {
		return nil, InvalidSaltLengthError(n)
	}
	if i := hashutil.HashEncoding.IndexAnyInvalid(salt); i >= 0 {
		return nil, InvalidSaltError(salt[i])
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], descrypt.Encrypt(descrypt.Key(password), 0, descrypt.DecodeInt(salt), 25))
	return b[:], nil
}

const Prefix = ""

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

const sumLength = 11

type scheme struct {
	HashPrefix hashPrefix `hash:"omitempty"`
	Salt       []byte     `hash:"length:2,inline"`
	Sum        [sumLength]byte
}

// NewHash returns the crypt(3) DES hash of the password.
func NewHash(password string) string {
	scheme := scheme{
		HashPrefix: Prefix,
		Salt:       hashutil.HashEncoding.Rand(SaltLength),
	}
	key, _ := Key([]byte(password), scheme.Salt)
	crypthash.BigEndianEncoding.Encode(scheme.Sum[:], key)
	s, _ := crypthash.Marshal(scheme)
	return s
}

// Salt returns the hashing salt used to create
// the given crypt(3) DES hash.
func Salt(hash string) (salt []byte, err error) {
	var scheme scheme
	if err = crypthash.Unmarshal(hash, &scheme); err != nil {
		return
	}
	return scheme.Salt, nil
}

// Check compares the given crypt(3) DES hash with a new hash derived from the password.
// Returns nil on success, or an error on failure.
func Check(hash, password string) error {
	var scheme scheme
	if err := crypthash.Unmarshal(hash, &scheme); err != nil {
		return err
	}
	key, err := Key([]byte(password), scheme.Salt)
	if err != nil {
		return err
	}
	var b [sumLength]byte
	crypthash.BigEndianEncoding.Encode(b[:], key)
	if subtle.ConstantTimeCompare(b[:], scheme.Sum[:]) == 0 {
		return crypt.ErrPasswordMismatch
	}
	return nil
}

func init() {
	crypt.RegisterHash(Prefix, Check)
}
