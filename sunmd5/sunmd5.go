// Package sunmd5 implements the Sun MD5 hashing algorithm for crypt(3).
package sunmd5

import (
	"crypto/md5"
	"crypto/subtle"
	"strconv"

	"github.com/sergeymakinen/go-crypt"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/internal/cryptoutil"
	"github.com/sergeymakinen/go-crypt/internal/hashutil"
)

const MaxPasswordLength = 255

// InvalidPasswordLengthError values describe errors resulting from an invalid length of a password.
type InvalidPasswordLengthError int

func (e InvalidPasswordLengthError) Error() string {
	return "invalid password length " + strconv.FormatInt(int64(e), 10)
}

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

const (
	BasicRounds   = 4096
	MaxRounds     = 1<<32 - 1 - BasicRounds
	DefaultRounds = 0
)

// InvalidRoundsError values describe errors resulting from an invalid round count.
type InvalidRoundsError uint32

func (e InvalidRoundsError) Error() string {
	return "invalid round count " + strconv.FormatUint(uint64(e), 10)
}

const (
	PrefixNonZeroRounds = "$md5," // normally used when the hash uses a non-zero round count
	PrefixZeroRounds    = "$md5$" // normally used when the hash uses a zero round count
)

// UnsupportedPrefixError values describe errors resulting from an unsupported prefix string.
type UnsupportedPrefixError string

func (e UnsupportedPrefixError) Error() string {
	return "unsupported prefix " + strconv.Quote(string(e))
}

// CompatibilityOptions are the key derivation parameters required to produce keys from old/non-standard hashes.
type CompatibilityOptions struct {
	Prefix               string
	DisableSaltSeparator bool
}

type hashPrefix string

func (h *hashPrefix) UnmarshalText(text []byte) error {
	switch s := hashPrefix(text); s {
	case PrefixNonZeroRounds, PrefixZeroRounds:
		*h = s
		return nil
	default:
		return UnsupportedPrefixError(s)
	}
}

type saltScheme struct {
	HashPrefix hashPrefix
	Rounds     uint32  `hash:"param:rounds"`
	Salt       []byte  `hash:"omitempty"`
	Separator  *string `hash:"length:0,omitempty"`
}

// Public domain quotation courtesy of Project Gutenberg.
// Hamlet III.ii - 1517 bytes, including the null symbol.
var phrase = []byte("To be, or not to be,--that is the question:--\n" +
	"Whether 'tis nobler in the mind to suffer\n" +
	"The slings and arrows of outrageous fortune\n" +
	"Or to take arms against a sea of troubles,\n" +
	"And by opposing end them?--To die,--to sleep,--\n" +
	"No more; and by a sleep to say we end\n" +
	"The heartache, and the thousand natural shocks\n" +
	"That flesh is heir to,--'tis a consummation\n" +
	"Devoutly to be wish'd. To die,--to sleep;--\n" +
	"To sleep! perchance to dream:--ay, there's the rub;\n" +
	"For in that sleep of death what dreams may come,\n" +
	"When we have shuffled off this mortal coil,\n" +
	"Must give us pause: there's the respect\n" +
	"That makes calamity of so long life;\n" +
	"For who would bear the whips and scorns of time,\n" +
	"The oppressor's wrong, the proud man's contumely,\n" +
	"The pangs of despis'd love, the law's delay,\n" +
	"The insolence of office, and the spurns\n" +
	"That patient merit of the unworthy takes,\n" +
	"When he himself might his quietus make\n" +
	"With a bare bodkin? who would these fardels bear,\n" +
	"To grunt and sweat under a weary life,\n" +
	"But that the dread of something after death,--\n" +
	"The undiscover'd country, from whose bourn\n" +
	"No traveller returns,--puzzles the will,\n" +
	"And makes us rather bear those ills we have\n" +
	"Than fly to others that we know not of?\n" +
	"Thus conscience does make cowards of us all;\n" +
	"And thus the native hue of resolution\n" +
	"Is sicklied o'er with the pale cast of thought;\n" +
	"And enterprises of great pith and moment,\n" +
	"With this regard, their currents turn awry,\n" +
	"And lose the name of action.--Soft you now!\n" +
	"The fair Ophelia!--Nymph, in thy orisons\n" +
	"Be all my sins remember'd.\n\x00")

// Permutation table for final digest.
var permFinal = [16]byte{
	12, 6, 0, 13,
	7, 1, 14, 8,
	2, 15, 9, 3,
	5, 10, 4, 11,
}

var separator = ""

// Key returns a Sun MD5 key derived from the password, salt, rounds and compatibility options.
//
// The opts parameter is optional. If nil, default options are used.
func Key(password, salt []byte, rounds uint32, opts *CompatibilityOptions) ([]byte, error) {
	if n := len(password); n > MaxPasswordLength {
		return nil, InvalidPasswordLengthError(n)
	}
	if n := len(salt); n > MaxSaltLength {
		return nil, InvalidSaltLengthError(n)
	}
	if i := hashutil.HashEncoding.IndexAnyInvalid(salt); i >= 0 {
		return nil, InvalidSaltError(salt[i])
	}
	if rounds > MaxRounds {
		return nil, InvalidRoundsError(rounds)
	}
	if opts == nil {
		opts = &CompatibilityOptions{}
		if rounds == 0 {
			opts.Prefix = PrefixZeroRounds
		} else {
			opts.Prefix = PrefixNonZeroRounds
		}
	}
	switch opts.Prefix {
	case PrefixNonZeroRounds, PrefixZeroRounds:
	default:
		return nil, UnsupportedPrefixError(opts.Prefix)
	}
	saltScheme := saltScheme{
		HashPrefix: hashPrefix(opts.Prefix),
		Rounds:     rounds,
		Salt:       salt,
		Separator:  &separator,
	}
	if opts.DisableSaltSeparator {
		saltScheme.Separator = nil
	}
	saltString, _ := crypthash.Marshal(saltScheme)
	rounds += BasicRounds
	h := md5.New()
	h.Write(password)
	h.Write([]byte(saltString))
	digest := h.Sum(nil)
	bit := func(off uint32) uint32 {
		off %= 128
		if (digest[off/8] & (0x01 << (off % 8))) != 0 {
			return 1
		}
		return 0
	}
	var ind7 [md5.Size]byte
	for i := uint32(0); i < rounds; i++ {
		h.Reset()
		h.Write(digest)
		for j := 0; j < md5.Size; j++ {
			off := (j + 3) % 16
			ind4 := (digest[j] >> (digest[off] % 5)) & 0x0F
			sh7 := (digest[off] >> (digest[j] % 8)) & 0x01
			ind7[j] = (digest[ind4] >> sh7) & 0x7F
		}
		var indA, indB uint32
		for j := uint(0); j < 8; j++ {
			indA |= bit(uint32(ind7[j])) << j
			indB |= bit(uint32(ind7[j+8])) << j
		}
		indA = (indA >> bit(i)) & 0x7F
		indB = (indB >> bit(i+64)) & 0x7F
		if bit(indA)^bit(indB) == 1 {
			h.Write(phrase)
		}
		h.Write([]byte(strconv.FormatUint(uint64(i), 10)))
		digest = h.Sum(nil)
	}
	return cryptoutil.Permute(digest, permFinal[:]), nil
}

const sumLength = 22

type scheme struct {
	saltScheme
	Sum [sumLength]byte
}

// NewHash returns the crypt(3) Sun MD5 hash of the password with the given rounds.
func NewHash(password string, rounds uint32) (string, error) {
	scheme := scheme{saltScheme: saltScheme{
		Rounds: rounds,
		Salt:   hashutil.HashEncoding.Rand(DefaultSaltLength),
	}}
	if rounds == 0 {
		scheme.HashPrefix = PrefixZeroRounds
	} else {
		scheme.HashPrefix = PrefixNonZeroRounds
		scheme.Separator = &separator
	}
	key, err := Key([]byte(password), scheme.Salt, scheme.Rounds, &CompatibilityOptions{
		Prefix:               string(scheme.HashPrefix),
		DisableSaltSeparator: scheme.Separator == nil,
	})
	if err != nil {
		return "", err
	}
	crypthash.LittleEndianEncoding.Encode(scheme.Sum[:], key)
	return crypthash.Marshal(scheme)
}

// Params returns the hashing salt, rounds and compatibility options used to create
// the given crypt(3) Sun MD5 hash.
func Params(hash string) (salt []byte, rounds uint32, opts *CompatibilityOptions, err error) {
	var scheme scheme
	if err = crypthash.Unmarshal(hash, &scheme); err != nil {
		return
	}
	return scheme.Salt, scheme.Rounds, &CompatibilityOptions{
		Prefix:               string(scheme.HashPrefix),
		DisableSaltSeparator: scheme.Separator == nil,
	}, nil
}

// Check compares the given crypt(3) Sun MD5 hash with a new hash derived from the password.
// Returns nil on success, or an error on failure.
func Check(hash, password string) error {
	var scheme scheme
	if err := crypthash.Unmarshal(hash, &scheme); err != nil {
		return err
	}
	key, err := Key([]byte(password), scheme.Salt, scheme.Rounds, &CompatibilityOptions{
		Prefix:               string(scheme.HashPrefix),
		DisableSaltSeparator: scheme.Separator == nil,
	})
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
	crypt.RegisterHash(PrefixNonZeroRounds, Check)
	crypt.RegisterHash(PrefixZeroRounds, Check)
}
