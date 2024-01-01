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

//go:build amd64 && gc && !purego

package argon2crypto

import "golang.org/x/sys/cpu"

func init() {
	useSSE4 = cpu.X86.HasSSE41
}

//go:noescape
func mixBlocksSSE2(out, a, b, c *block)

//go:noescape
func xorBlocksSSE2(out, a, b, c *block)

//go:noescape
func blamkaSSE4(b *block)

func processBlockSSE(out, in1, in2 *block, xor bool) {
	var t block
	mixBlocksSSE2(&t, in1, in2, &t)
	if useSSE4 {
		blamkaSSE4(&t)
	} else {
		for i := 0; i < blockLength; i += 16 {
			blamkaGeneric(
				&t[i+0], &t[i+1], &t[i+2], &t[i+3],
				&t[i+4], &t[i+5], &t[i+6], &t[i+7],
				&t[i+8], &t[i+9], &t[i+10], &t[i+11],
				&t[i+12], &t[i+13], &t[i+14], &t[i+15],
			)
		}
		for i := 0; i < blockLength/8; i += 2 {
			blamkaGeneric(
				&t[i], &t[i+1], &t[16+i], &t[16+i+1],
				&t[32+i], &t[32+i+1], &t[48+i], &t[48+i+1],
				&t[64+i], &t[64+i+1], &t[80+i], &t[80+i+1],
				&t[96+i], &t[96+i+1], &t[112+i], &t[112+i+1],
			)
		}
	}
	if xor {
		xorBlocksSSE2(out, in1, in2, &t)
	} else {
		mixBlocksSSE2(out, in1, in2, &t)
	}
}

func processBlock(out, in1, in2 *block) {
	processBlockSSE(out, in1, in2, false)
}

func processBlockXOR(out, in1, in2 *block) {
	processBlockSSE(out, in1, in2, true)
}
