// Package bcrypt implements the bcrypt hashing algorithm for crypt(3).
package bcrypt

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"

	"github.com/sergeymakinen/go-crypt"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/internal/cryptoutil"
	"github.com/sergeymakinen/go-crypt/internal/hashutil"
	"golang.org/x/crypto/blowfish"
)

const encoder = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// Encoding is the unpadded base64 encoding, defined by a 64-character alphabet used by bcrypt.
var Encoding = base64.NewEncoding(encoder).WithPadding(base64.NoPadding)

const SaltLength = 22

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

const (
	MinCost     = 4
	MaxCost     = 31
	DefaultCost = 12
)

// InvalidCostError values describe errors resulting from an invalid cost.
type InvalidCostError uint8

func (e InvalidCostError) Error() string {
	return "invalid cost " + strconv.FormatUint(uint64(e), 10)
}

const (
	Prefix2  = "$2$"  // the original bcrypt specification
	Prefix2a = "$2a$" // requires the string must be UTF-8 encoded and the null terminator must be included
	Prefix2b = "$2b$" // fixing bug with storing the string length in an unsigned char
)

// UnsupportedPrefixError values describe errors resulting from an unsupported prefix string.
type UnsupportedPrefixError string

func (e UnsupportedPrefixError) Error() string {
	return "unsupported prefix " + strconv.Quote(string(e))
}

// CompatibilityOptions are the key derivation parameters required to produce keys from old/non-standard hashes.
type CompatibilityOptions struct {
	Prefix string
}

// Key returns a bcrypt key derived from the password, salt, cost and compatibility options.
//
// The opts parameter is optional. If nil, default options are used.
func Key(password, salt []byte, cost uint8, opts *CompatibilityOptions) ([]byte, error) {
	if opts == nil {
		opts = &CompatibilityOptions{Prefix: Prefix2b}
	}
	switch opts.Prefix {
	case Prefix2, Prefix2a, Prefix2b:
	default:
		return nil, UnsupportedPrefixError(opts.Prefix)
	}
	n := len(password)
	if opts.Prefix == Prefix2b && n > 72 {
		// BUG: if the version is 2b and the string length is greater than 72,
		// only first 72 characters will be used.
		// It's intentional to emulate the old behavior.
		password = password[:72]
	} else if n >= 254 {
		// BUG: if the version is older than 2b and the string length is greater than or equal to 254,
		// 72 zero digits will be used instead.
		// It's intentional to emulate the old behavior.
		password = bytes.Repeat([]byte{'0'}, 72)
	}
	if n := len(salt); n != SaltLength {
		return nil, InvalidSaltLengthError(n)
	}
	if i := hashutil.HashEncoding.IndexAnyInvalid(salt); i >= 0 {
		return nil, InvalidSaltError(salt[i])
	}
	decSalt := make([]byte, Encoding.DecodedLen(len(salt)))
	Encoding.Decode(decSalt, salt)
	if cost < MinCost || cost > MaxCost {
		return nil, InvalidCostError(cost)
	}
	return encode(password, decSalt, cost, opts.Prefix)
}

func encode(key, salt []byte, rounds uint8, prefix string) ([]byte, error) {
	b := []byte("OrpheanBeholderScryDoubt")
	c, err := setup(key, salt, rounds, prefix)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 24; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(b[i:i+8], b[i:i+8])
		}
	}
	return b[:23], nil
}

func setup(key, salt []byte, cost uint8, prefix string) (*blowfish.Cipher, error) {
	if prefix != Prefix2 {
		// BUG: if the version is 2, no zero byte is appended to the key.
		// It's intentional to emulate the old behavior.
		key = append(key, 0)
	}
	c, err := blowfish.NewSaltedCipher(key, salt)
	if err != nil {
		return nil, errors.New("failed to create blowfish cipher: " + err.Error())
	}
	for i, n := 0, 1<<cost; i < n; i++ {
		blowfish.ExpandKey(key, c)
		blowfish.ExpandKey(salt, c)
	}
	return c, nil
}

type hashPrefix string

func (h *hashPrefix) UnmarshalText(text []byte) error {
	switch s := hashPrefix(text); s {
	case Prefix2, Prefix2a, Prefix2b:
		*h = s
		return nil
	default:
		return UnsupportedPrefixError(s)
	}
}

type hashCost uint8

func (h hashCost) MarshalText() ([]byte, error) {
	b := make([]byte, 0, 2)
	if h < 10 {
		b = strconv.AppendUint(append(b, '0'), uint64(h), 10)
	} else {
		b = strconv.AppendUint(b, uint64(h), 10)
	}
	return b, nil
}

const sumLength = 31

type scheme struct {
	HashPrefix hashPrefix
	Cost       hashCost `hash:"length:2"`
	Salt       []byte   `hash:"length:22,inline"`
	Sum        [sumLength]byte
}

// NewHash returns the crypt(3) bcrypt hash of the password at the given cost.
func NewHash(password string, cost uint8) (string, error) {
	scheme := scheme{
		HashPrefix: Prefix2b,
		Cost:       hashCost(cost),
		Salt:       make([]byte, SaltLength),
	}
	Encoding.Encode(scheme.Salt, cryptoutil.Rand(Encoding.DecodedLen(SaltLength)))
	key, err := Key([]byte(password), scheme.Salt, uint8(scheme.Cost), &CompatibilityOptions{Prefix: string(scheme.HashPrefix)})
	if err != nil {
		return "", err
	}
	Encoding.Encode(scheme.Sum[:], key)
	return crypthash.Marshal(scheme)
}

// Params returns the hashing salt, cost, version and compatibility options used to create
// the given crypt(3) bcrypt hash.
func Params(hash string) (salt []byte, cost uint8, opts *CompatibilityOptions, err error) {
	var scheme scheme
	if err = crypthash.Unmarshal(hash, &scheme); err != nil {
		return
	}
	return scheme.Salt, uint8(scheme.Cost), &CompatibilityOptions{Prefix: string(scheme.HashPrefix)}, nil
}

// Check compares the given crypt(3) bcrypt hash with a new hash derived from the password.
// Returns nil on success, or an error on failure.
func Check(hash, password string) error {
	var scheme scheme
	if err := crypthash.Unmarshal(hash, &scheme); err != nil {
		return err
	}
	key, err := Key([]byte(password), scheme.Salt, uint8(scheme.Cost), &CompatibilityOptions{Prefix: string(scheme.HashPrefix)})
	if err != nil {
		return err
	}
	var b [sumLength]byte
	Encoding.Encode(b[:], key)
	if subtle.ConstantTimeCompare(b[:], scheme.Sum[:]) == 0 {
		return crypt.ErrPasswordMismatch
	}
	return nil
}

func init() {
	crypt.RegisterHash(Prefix2, Check)
	crypt.RegisterHash(Prefix2a, Check)
	crypt.RegisterHash(Prefix2b, Check)
}
