// Package hash implements encoding and decoding of crypt(3) hashes.
//
// The mapping between hashes and Go is described
// in the documentation for the Marshal and Unmarshal functions.
package hash

import (
	"encoding/base64"

	"github.com/sergeymakinen/go-crypt/hash/base64le"
)

const encoder = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// LittleEndianEncoding is the unpadded little-endian base64 encoding, defined by
// the 64-character alphabet used by crypt(3).
var LittleEndianEncoding = base64le.NewEncoding(encoder).WithPadding(base64le.NoPadding)

// BigEndianEncoding is the unpadded big-endian base64 encoding, defined by
// the 64-character alphabet used by crypt(3).
var BigEndianEncoding = base64.NewEncoding(encoder).WithPadding(base64.NoPadding)
