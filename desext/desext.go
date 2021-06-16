// Package desext implements the DES Extended hashing algorithm for crypt(3).
package desext

import (
	"crypto/subtle"
	"encoding/binary"
	"strconv"

	"github.com/sergeymakinen/go-crypt"
	"github.com/sergeymakinen/go-crypt/des/descrypt"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/internal/hashutil"
)

const SaltLength = 4

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
	MinRounds     = 1
	MaxRounds     = 1<<24 - 1
	DefaultRounds = 5001
)

// InvalidRoundsError values describe errors resulting from an invalid round count.
type InvalidRoundsError uint32

func (e InvalidRoundsError) Error() string {
	return "invalid round count " + strconv.FormatUint(uint64(e), 10)
}

// Key returns a DES Extended key derived from the password, salt and rounds.
func Key(password, salt []byte, rounds uint32) ([]byte, error) {
	if n := len(salt); n != SaltLength {
		return nil, InvalidSaltLengthError(n)
	}
	if i := hashutil.HashEncoding.IndexAnyInvalid(salt); i >= 0 {
		return nil, InvalidSaltError(salt[i])
	}
	if rounds < MinRounds || rounds > MaxRounds {
		return nil, InvalidRoundsError(rounds)
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], descrypt.Encrypt(key(password), 0, descrypt.DecodeInt(salt), rounds))
	return b[:], nil
}

// key converts password to DES key used by the Key function.
func key(password []byte) uint64 {
	keyValue := descrypt.Key(password[:min(len(password), 8)])
	for i := 8; i < len(password); i += 8 {
		t := descrypt.Key(password[i:min(i+8, len(password))])
		keyValue = descrypt.Encrypt(keyValue, keyValue, 0, 1) ^ t
	}
	return keyValue
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

const Prefix = "_"

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

type hashRounds uint32

func (r hashRounds) MarshalText() ([]byte, error) {
	return descrypt.EncodeInt(uint32(r)), nil
}

func (r *hashRounds) UnmarshalText(text []byte) error {
	*r = hashRounds(descrypt.DecodeInt(text))
	return nil
}

const sumLength = 11

type scheme struct {
	HashPrefix hashPrefix
	Rounds     hashRounds `hash:"length:4,inline"`
	Salt       []byte     `hash:"length:4,inline"`
	Sum        [sumLength]byte
}

// NewHash returns the crypt(3) DES Extended hash of the password with the given rounds.
func NewHash(password string, rounds uint32) (string, error) {
	scheme := scheme{
		HashPrefix: Prefix,
		Rounds:     hashRounds(rounds),
		Salt:       hashutil.HashEncoding.Rand(SaltLength),
	}
	key, err := Key([]byte(password), scheme.Salt, uint32(scheme.Rounds))
	if err != nil {
		return "", err
	}
	crypthash.BigEndianEncoding.Encode(scheme.Sum[:], key)
	return crypthash.Marshal(scheme)
}

// Params returns the hashing salt and rounds used to create
// the given crypt(3) DES Extended hash.
func Params(hash string) (salt []byte, rounds uint32, err error) {
	var scheme scheme
	if err = crypthash.Unmarshal(hash, &scheme); err != nil {
		return
	}
	return scheme.Salt, uint32(scheme.Rounds), nil
}

// Check compares the given crypt(3) DES Extended hash with a new hash derived from the password.
// Returns nil on success, or an error on failure.
func Check(hash, password string) error {
	var scheme scheme
	if err := crypthash.Unmarshal(hash, &scheme); err != nil {
		return err
	}
	key, err := Key([]byte(password), scheme.Salt, uint32(scheme.Rounds))
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
