// Copyright 2017 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//   * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package argon2crypto

import (
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/blake2b"
)

// blake2bHash computes an arbitrary long hash value of in
// and writes the hash to out.
func blake2bHash(out []byte, in []byte) {
	var b2 hash.Hash
	if n := len(out); n < blake2b.Size {
		b2, _ = blake2b.New(n, nil)
	} else {
		b2, _ = blake2b.New512(nil)
	}

	var buffer [blake2b.Size]byte
	binary.LittleEndian.PutUint32(buffer[:4], uint32(len(out)))
	b2.Write(buffer[:4])
	b2.Write(in)

	if len(out) <= blake2b.Size {
		b2.Sum(out[:0])
		return
	}

	outLen := len(out)
	b2.Sum(buffer[:0])
	b2.Reset()
	copy(out, buffer[:32])
	out = out[32:]
	for len(out) > blake2b.Size {
		b2.Write(buffer[:])
		b2.Sum(buffer[:0])
		copy(out, buffer[:32])
		out = out[32:]
		b2.Reset()
	}

	if outLen%blake2b.Size > 0 { // outLen > 64
		r := ((outLen + 31) / 32) - 2 // ⌈τ /32⌉-2
		b2, _ = blake2b.New(outLen-32*r, nil)
	}
	b2.Write(buffer[:])
	b2.Sum(out[:0])
}
