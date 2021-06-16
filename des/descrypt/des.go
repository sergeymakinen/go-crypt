// Derived from Passlib which is licensed as follows:
//
// Passlib
// Copyright (c) 2008-2020 Assurance Technologies, LLC.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// * Neither the name of Assurance Technologies, nor the names of the
//   contributors may be used to endorse or promote products derived
//   from this software without specific prior written permission.
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

// Package descrypt provides low-level access to DES crypt functions.
package descrypt

import (
	"github.com/sergeymakinen/go-crypt/internal/hashutil"
)

// permute816 returns the permutation of the given 64-bit code with
// the specified 8x16 permutation table.
func permute816(c uint64, p [8][16]uint64) uint64 {
	var v uint64
	for _, r := range p {
		v |= r[c&0x0F]
		c >>= 4
	}
	return v
}

// permute1616 returns the permutation of the given 64-bit code with
// the specified 16x16 permutation table.
func permute1616(c uint64, p [16][16]uint64) uint64 {
	var v uint64
	for _, r := range p {
		v |= r[c&0x0F]
		c >>= 4
	}
	return v
}

// Encrypt encrypts single block of data using DES, operates on 64-bit integers.
func Encrypt(key, input uint64, salt uint32, rounds uint32) uint64 {
	kss := keySchedules(key)
	// Expand 24 bit salt -> 32 bit per DES & BSDi
	salt = ((salt & 0x00003F) << 26) |
		((salt & 0x000FC0) << 12) |
		((salt & 0x03F000) >> 2) |
		((salt & 0xFC0000) >> 16)
	// Init l & r
	var l, r uint64
	if input != 0 {
		l = ((input >> 31) & 0xAAAAAAAA) | (input & 0x55555555)
		l = permute816(l, ie3264)

		r = ((input >> 32) & 0xAAAAAAAA) | ((input >> 1) & 0x55555555)
		r = permute816(r, ie3264)
	}
	// Main DES loop - run for specified number of rounds
	for ; rounds > 0; rounds-- {
		// Run over each part of the schedule, 2 parts at a time
		for _, ks := range kss {
			ksEven, ksOdd := ks[0], ks[1]
			k := ((r >> 32) ^ r) & uint64(salt) // use the salt to flip specific bits
			b := (k << 32) ^ k ^ r ^ ksEven
			l ^= spe[0][(b>>58)&0x3F] ^ spe[1][(b>>50)&0x3F] ^
				spe[2][(b>>42)&0x3F] ^ spe[3][(b>>34)&0x3F] ^
				spe[4][(b>>26)&0x3F] ^ spe[5][(b>>18)&0x3F] ^
				spe[6][(b>>10)&0x3F] ^ spe[7][(b>>2)&0x3F]
			k = ((l >> 32) ^ l) & uint64(salt) // use the salt to flip specific bits
			b = (k << 32) ^ k ^ l ^ ksOdd
			r ^= spe[0][(b>>58)&0x3F] ^ spe[1][(b>>50)&0x3F] ^
				spe[2][(b>>42)&0x3F] ^ spe[3][(b>>34)&0x3F] ^
				spe[4][(b>>26)&0x3F] ^ spe[5][(b>>18)&0x3F] ^
				spe[6][(b>>10)&0x3F] ^ spe[7][(b>>2)&0x3F]
		}
		// Swap l and r
		l, r = r, l
	}
	// Return final result
	c := ((l >> 3) & 0x0F0F0F0F00000000) |
		((l << 33) & 0xF0F0F0F000000000) |
		((r >> 35) & 0x000000000F0F0F0F) |
		((r << 1) & 0x00000000F0F0F0F0)
	return permute1616(c, cf6464)
}

// Mask used to setup key schedule.
var ksMask uint64 = 0xFCFCFCFCFFFFFFFF

// Given 64-bit key, iterates over the 8 (even,odd) key schedule pairs generate key schedule.
// Note: generation was modified to output two elements at a time,
// so that per-round loop could do two passes at once
func keySchedules(ksOdd uint64) [8][2]uint64 {
	var b [8][2]uint64
	var ksEven uint64
	for i, p := range pcxRot {
		pEven, pOdd := p[0], p[1]
		ksEven = permute1616(ksOdd, pEven)
		ksOdd = permute1616(ksEven, pOdd)
		b[i][0] = ksEven & ksMask
		b[i][1] = ksOdd & ksMask
	}
	return b
}

// Key converts up to a maximum of 8 bytes from password to a 56-bit DES key.
// Only 7 lowest bits of each byte of password is used.
func Key(password []byte) uint64 {
	var v uint64
	for i := 0; i < len(password) && i < 8; i++ {
		v += uint64(password[i]&0x7F) << uint(57-i*8)
	}
	return v
}

// EncodeInt converts the 24-bit number from val up to a maximum of 4 bytes
// consisting of the hash alphabet.
func EncodeInt(val uint32) []byte {
	var b [4]byte
	for i := 0; i < 4; i++ {
		b[i] = hashutil.HashEncoding.Encode(byte((val >> uint(i*6)) & 0x3F))
	}
	return b[:]
}

// DecodeInt converts up to a maximum of 4 bytes from b consisting of the hash alphabet
// to a 24-bit number.
func DecodeInt(b []byte) uint32 {
	var v uint32
	for i := 0; i < len(b) && i < 4; i++ {
		v += uint32(hashutil.HashEncoding.Decode(b[i])) << uint(i*6)
	}
	return v
}
