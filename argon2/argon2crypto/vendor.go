package argon2crypto

import (
	_ "unsafe"

	_ "golang.org/x/crypto/argon2"
)

//go:linkname blake2bHash golang.org/x/crypto/argon2.blake2bHash
func blake2bHash(out []byte, in []byte)

//go:linkname processBlock golang.org/x/crypto/argon2.processBlock
func processBlock(out, in1, in2 *block)

//go:linkname processBlockXOR golang.org/x/crypto/argon2.processBlockXOR
func processBlockXOR(out, in1, in2 *block)
