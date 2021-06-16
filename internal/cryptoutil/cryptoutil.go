package cryptoutil

import "crypto/rand"

// Permute returns rearranged b elements in a order defined by t.
func Permute(b, t []byte) []byte {
	buf := make([]byte, len(t))
	for i, j := range t {
		buf[i] = b[j]
	}
	return buf
}

// Rand returns n cryptographically secure random bytes.
func Rand(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
