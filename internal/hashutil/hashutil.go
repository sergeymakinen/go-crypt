package hashutil

import (
	"crypto/rand"
	"math/big"
)

const encoderHash = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Encoding implements alphabet-specific actions useful to hashes.
type Encoding struct {
	encoder   string
	encMax    *big.Int
	decodeMap [256]byte
}

// Rand returns a string consisting of n cryptographically secure
// random characters from the e alphabet.
func (enc Encoding) Rand(n int) []byte {
	buf := make([]byte, n)
	for i := 0; i < len(buf); i++ {
		n, err := rand.Int(rand.Reader, enc.encMax)
		if err != nil {
			panic(err)
		}
		buf[i] = enc.encoder[n.Uint64()]
	}
	return buf
}

// Encode returns the character representing the c index of the e alphabet
// or 0xFF if the c index is not present in the e alphabet.
func (enc Encoding) Encode(c byte) byte {
	if int(c) >= len(enc.encoder) {
		return 0xFF
	}
	return enc.encoder[c]
}

// Decode returns the index of c in the e alphabet,
// or 0xFF if c is not present in the e alphabet.
func (enc Encoding) Decode(c byte) byte {
	return enc.decodeMap[c]
}

// IndexAnyInvalid returns the byte index of the first occurrence in b of any byte
// not from the e alphabet.
// It returns -1 if there is no invalid byte in b.
func (enc Encoding) IndexAnyInvalid(b []byte) int {
	for i := 0; i < len(b); i++ {
		if enc.decodeMap[b[i]] == 0xFF {
			return i
		}
	}
	return -1
}

// NewEncoding returns a new Encoding defined by the given alphabet.
func NewEncoding(encoder string) *Encoding {
	e := &Encoding{
		encoder: encoder,
		encMax:  big.NewInt(int64(len(encoder))),
	}
	for i := 0; i < len(e.decodeMap); i++ {
		e.decodeMap[i] = 0xFF
	}
	for i := 0; i < len(encoder); i++ {
		e.decodeMap[encoder[i]] = byte(i)
	}
	return e
}

const encoderBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

var (
	HashEncoding   = NewEncoding(encoderHash)
	Base64Encoding = NewEncoding(encoderBase64)
)
