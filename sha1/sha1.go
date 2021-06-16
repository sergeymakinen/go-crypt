// Package sha1 implements the SHA-1 hashing algorithm for crypt(3).
package sha1

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"strconv"

	"github.com/sergeymakinen/go-crypt"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/internal/cryptoutil"
	"github.com/sergeymakinen/go-crypt/internal/hashutil"
)

const (
	MaxSaltLength     = 64
	DefaultSaltLength = 8
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
	MinRounds     = 1
	RandomRounds  = 1<<32 - 1
	DefaultRounds = RandomRounds
)

// InvalidRoundsError values describe errors resulting from an invalid round count.
type InvalidRoundsError uint32

func (e InvalidRoundsError) Error() string {
	return "invalid round count " + strconv.FormatUint(uint64(e), 10)
}

// Permutation table for final digest.
var permFinal = [21]byte{
	2, 1, 0, 5,
	4, 3, 8, 7,
	6, 11, 10, 9,
	14, 13, 12, 17,
	16, 15, 0, 19,
	18,
}

const randomHint = 24680

func randRounds() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return randomHint - (binary.BigEndian.Uint32(b[:]) % (randomHint / 4))
}

const Prefix = "$sha1$"

var prefixBytes = []byte(Prefix)

// Key returns a SHA-1 key derived from the password, salt and rounds.
func Key(password, salt []byte, rounds uint32) ([]byte, error) {
	if n := len(salt); n > MaxSaltLength {
		return nil, InvalidSaltLengthError(n)
	}
	if i := hashutil.HashEncoding.IndexAnyInvalid(salt); i >= 0 {
		return nil, InvalidSaltError(salt[i])
	}
	if rounds == RandomRounds {
		rounds = randRounds()
	}
	if rounds < MinRounds {
		return nil, InvalidRoundsError(rounds)
	}
	h := hmac.New(sha1.New, password)
	h.Write(salt)
	h.Write(prefixBytes)
	h.Write([]byte(strconv.FormatUint(uint64(rounds), 10)))
	var b [sha1.Size]byte
	h.Sum(b[:0])
	for rounds--; rounds > 0; rounds-- {
		h.Reset()
		h.Write(b[:])
		h.Sum(b[:0])
	}
	return cryptoutil.Permute(b[:], permFinal[:]), nil
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

const sumLength = 28

type scheme struct {
	HashPrefix hashPrefix
	Rounds     uint32
	Salt       []byte
	Sum        [sumLength]byte
}

// NewHash returns the crypt(3) SHA-1 hash of the password with the given rounds.
func NewHash(password string, rounds uint32) (string, error) {
	if rounds == RandomRounds {
		rounds = randRounds()
	}
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
// the given crypt(3) SHA-1 hash.
func Params(hash string) (salt []byte, rounds uint32, err error) {
	var scheme scheme
	if err = crypthash.Unmarshal(hash, &scheme); err != nil {
		return
	}
	return scheme.Salt, scheme.Rounds, nil
}

// Check compares the given crypt(3) SHA-1 hash with a new hash derived from the password.
// Returns nil on success, or an error on failure.
func Check(hash, password string) error {
	var scheme scheme
	if err := crypthash.Unmarshal(hash, &scheme); err != nil {
		return err
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
