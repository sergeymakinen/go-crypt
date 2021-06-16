// Package md5 implements the MD5 hashing algorithm for crypt(3).
package md5

import (
	"crypto/subtle"
	"strconv"

	"github.com/sergeymakinen/go-crypt"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/internal/hashutil"
	"github.com/sergeymakinen/go-crypt/md5/md5crypt"
)

const (
	MaxSaltLength     = 8
	DefaultSaltLength = MaxSaltLength
)

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

const Prefix = "$1$"

var prefixBytes = []byte(Prefix)

// Key returns a MD5 key derived from the password and salt.
func Key(password, salt []byte) ([]byte, error) {
	if n := len(salt); n > MaxSaltLength {
		return nil, InvalidSaltLengthError(n)
	}
	if i := hashutil.HashEncoding.IndexAnyInvalid(salt); i >= 0 {
		return nil, InvalidSaltError(salt[i])
	}
	return md5crypt.Encrypt(password, salt, prefixBytes), nil
}

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

type scheme struct {
	HashPrefix hashPrefix
	Salt       []byte
	Sum        []byte `hash:"length:22"`
}

const sumLength = 22

// NewHash returns the crypt(3) MD5 hash of the password.
func NewHash(password string) string {
	scheme := scheme{
		HashPrefix: Prefix,
		Salt:       hashutil.HashEncoding.Rand(DefaultSaltLength),
		Sum:        make([]byte, sumLength),
	}
	key, _ := Key([]byte(password), scheme.Salt)
	crypthash.LittleEndianEncoding.Encode(scheme.Sum, key)
	s, _ := crypthash.Marshal(scheme)
	return s
}

// Salt returns the hashing salt used to create
// the given crypt(3) MD5 hash.
func Salt(hash string) (salt []byte, err error) {
	var scheme scheme
	if err = crypthash.Unmarshal(hash, &scheme); err != nil {
		return
	}
	return scheme.Salt, nil
}

// Check compares the given crypt(3) MD5 hash with a new hash derived from the password.
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
	crypthash.LittleEndianEncoding.Encode(b[:], key)
	if subtle.ConstantTimeCompare(b[:], scheme.Sum) == 0 {
		return crypt.ErrPasswordMismatch
	}
	return nil
}

func init() {
	crypt.RegisterHash(Prefix, Check)
}
