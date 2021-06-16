// Package argon2 implements the Argon2 hashing algorithm for crypt(3).
package argon2

import (
	"crypto/subtle"
	"encoding/base64"
	"strconv"

	"github.com/sergeymakinen/go-crypt"
	"github.com/sergeymakinen/go-crypt/argon2/argon2crypto"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/internal/cryptoutil"
	"github.com/sergeymakinen/go-crypt/internal/hashutil"
)

const (
	MinSaltLength     = 11
	DefaultSaltLength = MinSaltLength
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
	MinTime     = 1
	DefaultTime = 3
)

// InvalidTimeError values describe errors resulting from an invalid time cost.
type InvalidTimeError uint32

func (e InvalidTimeError) Error() string {
	return "invalid time cost " + strconv.FormatUint(uint64(e), 10)
}

const (
	MinMemory     = 8
	DefaultMemory = 1 << 12
)

// InvalidMemoryError values describe errors resulting from an invalid memory cost.
type InvalidMemoryError uint32

func (e InvalidMemoryError) Error() string {
	return "invalid memory cost " + strconv.FormatUint(uint64(e), 10)
}

const (
	MinThreads     = 1
	DefaultThreads = MinThreads
)

// InvalidThreadsError values describe errors resulting from an invalid thread count
type InvalidThreadsError uint32

func (e InvalidThreadsError) Error() string {
	return "invalid thread count " + strconv.FormatUint(uint64(e), 10)
}

const (
	Prefix2d  = "$argon2d$"
	Prefix2i  = "$argon2i$"
	Prefix2id = "$argon2id$"
)

// UnsupportedPrefixError values describe errors resulting from an unsupported prefix string.
type UnsupportedPrefixError string

func (e UnsupportedPrefixError) Error() string {
	return "unsupported prefix " + strconv.Quote(string(e))
}

const (
	Version10 = 0x10
	Version13 = 0x13
)

// UnsupportedVersionError values describe errors resulting from an unsupported version.
type UnsupportedVersionError int

func (e UnsupportedVersionError) Error() string {
	return "unsupported version 0x" + strconv.FormatUint(uint64(e), 16)
}

// CompatibilityOptions are the key derivation parameters required to produce keys from old/non-standard hashes.
type CompatibilityOptions struct {
	Prefix  string
	Version int
}

const keyLen = 32

// Key returns an Argon2 key derived from the password, salt, memory and time costs,
// threads and compatibility options.
//
// The opts parameter is optional. If nil, default options are used.
func Key(password, salt []byte, memory, time uint32, threads uint8, opts *CompatibilityOptions) ([]byte, error) {
	if opts == nil {
		opts = &CompatibilityOptions{
			Prefix:  Prefix2id,
			Version: Version13,
		}
	}
	var mode int
	switch opts.Prefix {
	case Prefix2d:
		mode = argon2crypto.Argon2d
	case Prefix2i:
		mode = argon2crypto.Argon2i
	case Prefix2id:
		mode = argon2crypto.Argon2id
	default:
		return nil, UnsupportedPrefixError(opts.Prefix)
	}
	var version int
	switch opts.Version {
	case Version10:
		version = argon2crypto.Version10
	case Version13:
		version = argon2crypto.Version13
	default:
		return nil, UnsupportedVersionError(opts.Version)
	}
	if n := len(salt); n < MinSaltLength {
		return nil, InvalidSaltLengthError(n)
	}
	if i := hashutil.Base64Encoding.IndexAnyInvalid(salt); i >= 0 {
		return nil, InvalidSaltError(salt[i])
	}
	decSalt := make([]byte, base64.RawStdEncoding.DecodedLen(len(salt)))
	base64.RawStdEncoding.Decode(decSalt, salt)
	if memory < MinMemory {
		return nil, InvalidMemoryError(memory)
	}
	if time < MinTime {
		return nil, InvalidTimeError(time)
	}
	if threads < MinThreads {
		return nil, InvalidThreadsError(threads)
	}
	return argon2crypto.Key(mode, version, password, decSalt, time, memory, threads, keyLen), nil
}

type hashPrefix string

func (h *hashPrefix) UnmarshalText(text []byte) error {
	switch s := hashPrefix(text); s {
	case Prefix2d, Prefix2i, Prefix2id:
		*h = s
		return nil
	default:
		return UnsupportedPrefixError(s)
	}
}

type scheme struct {
	HashPrefix hashPrefix
	Version    uint8  `hash:"param:v,omitempty"`
	Memory     uint32 `hash:"param:m,group"`
	Time       uint32 `hash:"param:t,group"`
	Threads    uint8  `hash:"param:p,group"`
	Salt       []byte `hash:"enc:base64"`
	Sum        []byte `hash:"enc:base64"`
}

// NewHash returns the crypt(3) Argon2 hash of the password, memory and time costs.
func NewHash(password string, memory, time uint32) (string, error) {
	scheme := scheme{
		HashPrefix: Prefix2id,
		Version:    Version13,
		Memory:     memory,
		Time:       time,
		Threads:    DefaultThreads,
		Salt:       make([]byte, DefaultSaltLength),
	}
	base64.RawStdEncoding.Encode(scheme.Salt, cryptoutil.Rand(base64.RawStdEncoding.DecodedLen(DefaultSaltLength)))
	key, err := Key([]byte(password), scheme.Salt, scheme.Memory, scheme.Time, scheme.Threads, &CompatibilityOptions{
		Prefix:  string(scheme.HashPrefix),
		Version: int(scheme.Version),
	})
	if err != nil {
		return "", err
	}
	scheme.Sum = make([]byte, base64.RawStdEncoding.EncodedLen(len(key)))
	base64.RawStdEncoding.Encode(scheme.Sum, key)
	return crypthash.Marshal(scheme)
}

// Params returns the hashing salt, memory and time costs, threads and compatibility options
// used to create the given crypt(3) Argon2 hash.
func Params(hash string) (salt []byte, memory, time uint32, threads uint8, opts *CompatibilityOptions, err error) {
	var scheme scheme
	if err = crypthash.Unmarshal(hash, &scheme); err != nil {
		return
	}
	if scheme.Version == 0 {
		scheme.Version = Version10
	}
	return scheme.Salt, scheme.Memory, scheme.Time, scheme.Threads, &CompatibilityOptions{
		Prefix:  string(scheme.HashPrefix),
		Version: int(scheme.Version),
	}, nil
}

// Check compares the given crypt(3) Argon2 hash with a new hash derived from the password.
// Returns nil on success, or an error on failure.
func Check(hash, password string) error {
	var scheme scheme
	if err := crypthash.Unmarshal(hash, &scheme); err != nil {
		return err
	}
	if scheme.Version == 0 {
		scheme.Version = Version10
	}
	key, err := Key([]byte(password), scheme.Salt, scheme.Memory, scheme.Time, scheme.Threads, &CompatibilityOptions{
		Prefix:  string(scheme.HashPrefix),
		Version: int(scheme.Version),
	})
	if err != nil {
		return err
	}
	b := make([]byte, base64.RawStdEncoding.EncodedLen(len(key)))
	base64.RawStdEncoding.Encode(b[:], key)
	if subtle.ConstantTimeCompare(b[:], scheme.Sum) == 0 {
		return crypt.ErrPasswordMismatch
	}
	return nil
}

func init() {
	crypt.RegisterHash(Prefix2d, Check)
	crypt.RegisterHash(Prefix2i, Check)
	crypt.RegisterHash(Prefix2id, Check)
}
