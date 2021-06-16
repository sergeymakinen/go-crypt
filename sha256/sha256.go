// Package sha256 implements the SHA-256 hashing algorithm for crypt(3).
package sha256

import (
	"crypto"
	_ "crypto/sha256"
	"crypto/subtle"
	"strconv"

	"github.com/sergeymakinen/go-crypt"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/internal/hashutil"
	"github.com/sergeymakinen/go-crypt/sha256/sha2crypt"
)

const (
	MaxSaltLength     = 16
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

const (
	MinRounds      = 1000
	MaxRounds      = 999999999
	DefaultRounds  = 535000
	ImplicitRounds = 5000 // the value if the rounds parameter is omitted from the hash string
)

// InvalidRoundsError values describe errors resulting from an invalid round count.
type InvalidRoundsError uint32

func (e InvalidRoundsError) Error() string {
	return "invalid round count " + strconv.FormatUint(uint64(e), 10)
}

// Permutation table for final digest.
var permFinal = [32]byte{
	20, 10, 0, 11,
	1, 21, 2, 22,
	12, 23, 13, 3,
	14, 4, 24, 5,
	25, 15, 26, 16,
	6, 17, 7, 27,
	8, 28, 18, 29,
	19, 9, 30, 31,
}

// Key returns a SHA-256 key derived from the password, salt and rounds.
func Key(password, salt []byte, rounds uint32) ([]byte, error) {
	if n := len(salt); n > MaxSaltLength {
		return nil, InvalidSaltLengthError(n)
	}
	if i := hashutil.HashEncoding.IndexAnyInvalid(salt); i >= 0 {
		return nil, InvalidSaltError(salt[i])
	}
	if rounds < MinRounds || rounds > MaxRounds {
		return nil, InvalidRoundsError(rounds)
	}
	return sha2crypt.Encrypt(crypto.SHA256, password, salt, rounds, permFinal[:])
}

const Prefix = "$5$"

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

const sumLength = 43

type scheme struct {
	HashPrefix hashPrefix
	Rounds     uint32 `hash:"param:rounds,omitempty"`
	Salt       []byte
	Sum        [sumLength]byte
}

// NewHash returns the crypt(3) SHA-256 hash of the password with the given rounds.
func NewHash(password string, rounds uint32) (string, error) {
	scheme := scheme{
		HashPrefix: Prefix,
		Rounds:     rounds,
		Salt:       hashutil.HashEncoding.Rand(DefaultSaltLength),
	}
	key, err := Key([]byte(password), scheme.Salt, scheme.Rounds)
	if err != nil {
		return "", err
	}
	crypthash.LittleEndianEncoding.Encode(scheme.Sum[:], key)
	return crypthash.Marshal(scheme)
}

// Params returns the hashing salt and rounds used to create
// the given crypt(3) SHA-256 hash.
func Params(hash string) (salt []byte, rounds uint32, err error) {
	var scheme scheme
	if err = crypthash.Unmarshal(hash, &scheme); err != nil {
		return
	}
	if scheme.Rounds == 0 {
		scheme.Rounds = ImplicitRounds
	}
	return scheme.Salt, scheme.Rounds, nil
}

// Check compares the given crypt(3) SHA-256 hash with a new hash derived from the password.
// Returns nil on success, or an error on failure.
func Check(hash, password string) error {
	var scheme scheme
	if err := crypthash.Unmarshal(hash, &scheme); err != nil {
		return err
	}
	if scheme.Rounds == 0 {
		scheme.Rounds = ImplicitRounds
	}
	key, err := Key([]byte(password), scheme.Salt, scheme.Rounds)
	if err != nil {
		return err
	}
	var b [sumLength]byte
	crypthash.LittleEndianEncoding.Encode(b[:], key)
	if subtle.ConstantTimeCompare(b[:], scheme.Sum[:]) == 0 {
		return crypt.ErrPasswordMismatch
	}
	return nil
}

func init() {
	crypt.RegisterHash(Prefix, Check)
}
