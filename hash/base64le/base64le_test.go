// Derived from Go which is licensed as follows:
//
// Copyright (c) 2009 The Go Authors. All rights reserved.
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

package base64le_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/hash/base64le"
)

type testpair struct {
	decoded, encoded string
}

var pairs = []testpair{
	// RFC 3548 examples
	{"\x14\xfb\x9c\x03\xd9\x7e", "IgDb1YhT"},
	{"\x14\xfb\x9c\x03\xd9", "IgDb1YB="},
	{"\x14\xfb\x9c\x03", "IgDb1.=="},

	// RFC 4648 examples
	{"", ""},
	{"f", "a/=="},
	{"fo", "ax4="},
	{"foo", "axqP"},
	{"foob", "axqPW/=="},
	{"fooba", "axqPW34="},
	{"foobar", "axqPW3aQ"},

	// Wikipedia examples
	{"sure.", "nJbQZt0="},
	{"sure", "nJbQZ/=="},
	{"sur", "nJbQ"},
	{"su", "nJ5="},
	{"leasure.", "gJKMnJbQZt0="},
	{"easure.", "Z3qQp7LNi.=="},
	{"asure.", "VBLRmJa9"},
	{"sure.", "nJbQZt0="},
}

func leRef(ref string) string {
	return strings.TrimRight(ref, "=")
}

// A nonstandard encoding with a padding, for testing
var padEncoding = hash.LittleEndianEncoding.WithPadding(base64le.StdPadding)

func padRef(ref string) string {
	return ref
}

// A nonstandard encoding with a funny padding character, for testing
var funnyEncoding = hash.LittleEndianEncoding.WithPadding('@')

func funnyRef(ref string) string {
	return strings.ReplaceAll(ref, "=", "@")
}

type encodingTest struct {
	enc  *base64le.Encoding  // Encoding to test
	conv func(string) string // Reference string converter
}

var encodingTests = []encodingTest{
	{hash.LittleEndianEncoding, leRef},
	{padEncoding, padRef},
	{funnyEncoding, funnyRef},
	{hash.LittleEndianEncoding.Strict(), leRef},
	{padEncoding.Strict(), padRef},
	{funnyEncoding.Strict(), funnyRef},
}

var bigtest = testpair{
	"Twas brillig, and the slithy toves",
	"IRLMn/WMmZ4PgZqNg.GMiF46oVKNUA5PdF5Ot/0RjNLNn/==",
}

func testEqual(t *testing.T, msg string, args ...interface{}) bool {
	t.Helper()
	if args[len(args)-2] != args[len(args)-1] {
		t.Errorf(msg, args...)
		return false
	}
	return true
}

func TestEncode(t *testing.T) {
	for _, p := range pairs {
		for _, tt := range encodingTests {
			got := tt.enc.EncodeToString([]byte(p.decoded))
			testEqual(t, "Encode(%q) = %q, want %q", p.decoded,
				got, tt.conv(p.encoded))
		}
	}
}

func TestEncoder(t *testing.T) {
	for _, p := range pairs {
		bb := &bytes.Buffer{}
		encoder := base64le.NewEncoder(padEncoding, bb)
		encoder.Write([]byte(p.decoded))
		encoder.Close()
		testEqual(t, "Encode(%q) = %q, want %q", p.decoded, bb.String(), p.encoded)
	}
}

func TestEncoderBuffering(t *testing.T) {
	input := []byte(bigtest.decoded)
	for bs := 1; bs <= 12; bs++ {
		bb := &bytes.Buffer{}
		encoder := base64le.NewEncoder(padEncoding, bb)
		for pos := 0; pos < len(input); pos += bs {
			end := pos + bs
			if end > len(input) {
				end = len(input)
			}
			n, err := encoder.Write(input[pos:end])
			testEqual(t, "Write(%q) gave error %v, want %v", input[pos:end], err, error(nil))
			testEqual(t, "Write(%q) gave length %v, want %v", input[pos:end], n, end-pos)
		}
		err := encoder.Close()
		testEqual(t, "Close gave error %v, want %v", err, error(nil))
		testEqual(t, "Encoding/%d of %q = %q, want %q", bs, bigtest.decoded, bb.String(), bigtest.encoded)
	}
}

func TestDecode(t *testing.T) {
	for _, p := range pairs {
		for _, tt := range encodingTests {
			encoded := tt.conv(p.encoded)
			dbuf := make([]byte, tt.enc.DecodedLen(len(encoded)))
			count, err := tt.enc.Decode(dbuf, []byte(encoded))
			testEqual(t, "Decode(%q) = error %v, want %v", encoded, err, error(nil))
			testEqual(t, "Decode(%q) = length %v, want %v", encoded, count, len(p.decoded))
			testEqual(t, "Decode(%q) = %q, want %q", encoded, string(dbuf[0:count]), p.decoded)

			dbuf, err = tt.enc.DecodeString(encoded)
			testEqual(t, "DecodeString(%q) = error %v, want %v", encoded, err, error(nil))
			testEqual(t, "DecodeString(%q) = %q, want %q", encoded, string(dbuf), p.decoded)
		}
	}
}

func TestDecoder(t *testing.T) {
	for _, p := range pairs {
		decoder := base64le.NewDecoder(padEncoding, strings.NewReader(p.encoded))
		dbuf := make([]byte, padEncoding.DecodedLen(len(p.encoded)))
		count, err := decoder.Read(dbuf)
		if err != nil && err != io.EOF {
			t.Fatal("Read failed", err)
		}
		testEqual(t, "Read from %q = length %v, want %v", p.encoded, count, len(p.decoded))
		testEqual(t, "Decoding of %q = %q, want %q", p.encoded, string(dbuf[0:count]), p.decoded)
		if err != io.EOF {
			_, err = decoder.Read(dbuf)
		}
		testEqual(t, "Read from %q = %v, want %v", p.encoded, err, io.EOF)
	}
}

func TestDecoderBuffering(t *testing.T) {
	for bs := 1; bs <= 12; bs++ {
		decoder := base64le.NewDecoder(padEncoding, strings.NewReader(bigtest.encoded))
		buf := make([]byte, len(bigtest.decoded)+12)
		var total int
		var n int
		var err error
		for total = 0; total < len(bigtest.decoded) && err == nil; {
			n, err = decoder.Read(buf[total : total+bs])
			total += n
		}
		if err != nil && err != io.EOF {
			t.Errorf("Read from %q at pos %d = %d, unexpected error %v", bigtest.encoded, total, n, err)
		}
		testEqual(t, "Decoding/%d of %q = %q, want %q", bs, bigtest.encoded, string(buf[0:total]), bigtest.decoded)
	}
}

func TestDecodeCorrupt(t *testing.T) {
	testCases := []struct {
		input  string
		offset int // -1 means no corruption.
	}{
		{"", -1},
		{"\n", -1},
		{"AAA=\n", -1},
		{"AAAA\n", -1},
		{"!!!!", 0},
		{"====", 0},
		{"x===", 1},
		{"=AAA", 0},
		{"A=AA", 1},
		{"AA=A", 2},
		{"AA==A", 4},
		{"AAA=AAAA", 4},
		{"AAAAA", 4},
		{"AAAAAA", 4},
		{"A=", 1},
		{"A==", 1},
		{"AA=", 3},
		{"AA==", -1},
		{"AAA=", -1},
		{"AAAA", -1},
		{"AAAAAA=", 7},
		{"YWJjZA=====", 8},
		{"A!\n", 1},
		{"A=\n", 1},
	}
	for _, tc := range testCases {
		dbuf := make([]byte, padEncoding.DecodedLen(len(tc.input)))
		_, err := padEncoding.Decode(dbuf, []byte(tc.input))
		if tc.offset == -1 {
			if err != nil {
				t.Error("Decoder wrongly detected corruption in", tc.input)
			}
			continue
		}
		switch err := err.(type) {
		case base64le.CorruptInputError:
			testEqual(t, "Corruption in %q at offset %v, want %v", tc.input, int(err), tc.offset)
		default:
			t.Error("Decoder failed to detect corruption in", tc)
		}
	}
}

func TestDecodeBounds(t *testing.T) {
	var buf [32]byte
	s := hash.LittleEndianEncoding.EncodeToString(buf[:])
	defer func() {
		if err := recover(); err != nil {
			t.Fatalf("Decode panicked unexpectedly: %v\n%s", err, debug.Stack())
		}
	}()
	n, err := hash.LittleEndianEncoding.Decode(buf[:], []byte(s))
	if n != len(buf) || err != nil {
		t.Fatalf("hash.LittleEndianEncoding.Decode = %d, %v, want %d, nil", n, err, len(buf))
	}
}

func TestEncodedLen(t *testing.T) {
	for _, tt := range []struct {
		enc  *base64le.Encoding
		n    int
		want int
	}{
		{padEncoding, 0, 0},
		{padEncoding, 1, 4},
		{padEncoding, 2, 4},
		{padEncoding, 3, 4},
		{padEncoding, 4, 8},
		{padEncoding, 7, 12},
		{hash.LittleEndianEncoding, 0, 0},
		{hash.LittleEndianEncoding, 1, 2},
		{hash.LittleEndianEncoding, 2, 3},
		{hash.LittleEndianEncoding, 3, 4},
		{hash.LittleEndianEncoding, 7, 10},
	} {
		if got := tt.enc.EncodedLen(tt.n); got != tt.want {
			t.Errorf("EncodedLen(%d): got %d, want %d", tt.n, got, tt.want)
		}
	}
}

func TestDecodedLen(t *testing.T) {
	for _, tt := range []struct {
		enc  *base64le.Encoding
		n    int
		want int
	}{
		{padEncoding, 0, 0},
		{padEncoding, 4, 3},
		{padEncoding, 8, 6},
		{hash.LittleEndianEncoding, 0, 0},
		{hash.LittleEndianEncoding, 2, 1},
		{hash.LittleEndianEncoding, 3, 2},
		{hash.LittleEndianEncoding, 4, 3},
		{hash.LittleEndianEncoding, 10, 7},
	} {
		if got := tt.enc.DecodedLen(tt.n); got != tt.want {
			t.Errorf("DecodedLen(%d): got %d, want %d", tt.n, got, tt.want)
		}
	}
}

func TestBig(t *testing.T) {
	n := 3*1000 + 1
	raw := make([]byte, n)
	const alpha = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for i := 0; i < n; i++ {
		raw[i] = alpha[i%len(alpha)]
	}
	encoded := new(bytes.Buffer)
	w := base64le.NewEncoder(hash.LittleEndianEncoding, encoded)
	nn, err := w.Write(raw)
	if nn != n || err != nil {
		t.Fatalf("Encoder.Write(raw) = %d, %v want %d, nil", nn, err, n)
	}
	err = w.Close()
	if err != nil {
		t.Fatalf("Encoder.Close() = %v want nil", err)
	}
	decoded, err := ioutil.ReadAll(base64le.NewDecoder(hash.LittleEndianEncoding, encoded))
	if err != nil {
		t.Fatalf("io.ReadAll(NewDecoder(...)): %v", err)
	}

	if !bytes.Equal(raw, decoded) {
		var i int
		for i = 0; i < len(decoded) && i < len(raw); i++ {
			if decoded[i] != raw[i] {
				break
			}
		}
		t.Errorf("Decode(Encode(%d-byte string)) failed at offset %d", n, i)
	}
}

func TestNewLineCharacters(t *testing.T) {
	// Each of these should decode to the string "sure", without errors.
	const expected = "sure"
	examples := []string{
		"nJbQZ/==",
		"nJbQZ/==\r",
		"nJbQZ/==\n",
		"nJbQZ/==\r\n",
		"nJbQZ\r\n/==",
		"nJbQ\rZ\n/==",
		"nJbQ\nZ\r/==",
		"nJbQZ\n/==",
		"nJbQZ/\n==",
		"nJbQZ/=\n=",
		"nJbQZ/=\r\n\r\n=",
	}
	for _, e := range examples {
		buf, err := padEncoding.DecodeString(e)
		if err != nil {
			t.Errorf("Decode(%q) failed: %v", e, err)
			continue
		}
		if s := string(buf); s != expected {
			t.Errorf("Decode(%q) = %q, want %q", e, s, expected)
		}
	}
}

type nextRead struct {
	n   int   // bytes to return
	err error // error to return
}

// faultInjectReader returns data from source, rate-limited
// and with the errors as written to nextc.
type faultInjectReader struct {
	source string
	nextc  <-chan nextRead
}

func (r *faultInjectReader) Read(p []byte) (int, error) {
	nr := <-r.nextc
	if len(p) > nr.n {
		p = p[:nr.n]
	}
	n := copy(p, r.source)
	r.source = r.source[n:]
	return n, nr.err
}

// tests that we don't ignore errors from our underlying reader
func TestDecoderIssue3577(t *testing.T) {
	next := make(chan nextRead, 10)
	wantErr := errors.New("my error")
	next <- nextRead{5, nil}
	next <- nextRead{10, wantErr}
	next <- nextRead{0, wantErr}
	d := base64le.NewDecoder(hash.LittleEndianEncoding, &faultInjectReader{
		source: "VHdhcyBicmlsbGlnLCBhbmQgdGhlIHNsaXRoeSB0b3Zlcw==", // twas brillig...
		nextc:  next,
	})
	errc := make(chan error, 1)
	go func() {
		_, err := ioutil.ReadAll(d)
		errc <- err
	}()
	select {
	case err := <-errc:
		if err != wantErr {
			t.Errorf("got error %v; want %v", err, wantErr)
		}
	case <-time.After(5 * time.Second):
		t.Errorf("timeout; Decoder blocked without returning an error")
	}
}

func BenchmarkEncodeToString(b *testing.B) {
	data := make([]byte, 8192)
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		hash.LittleEndianEncoding.EncodeToString(data)
	}
}

func BenchmarkDecodeString(b *testing.B) {
	sizes := []int{2, 4, 8, 64, 8192}
	benchFunc := func(b *testing.B, benchSize int) {
		data := hash.LittleEndianEncoding.EncodeToString(make([]byte, benchSize))
		b.SetBytes(int64(len(data)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			hash.LittleEndianEncoding.DecodeString(data)
		}
	}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			benchFunc(b, size)
		})
	}
}

func TestDecoderRaw(t *testing.T) {
	source := "......"
	want := []byte{0, 0, 0, 0}

	// Direct.
	dec1, err := hash.LittleEndianEncoding.DecodeString(source)
	if err != nil || !bytes.Equal(dec1, want) {
		t.Errorf("hash.LittleEndianEncoding.DecodeString(%q) = %x, %v, want %x, nil", source, dec1, err, want)
	}

	// Through reader. Used to fail.
	r := base64le.NewDecoder(hash.LittleEndianEncoding, bytes.NewReader([]byte(source)))
	dec2, err := ioutil.ReadAll(io.LimitReader(r, 100))
	if err != nil || !bytes.Equal(dec2, want) {
		t.Errorf("reading NewDecoder(hash.LittleEndianEncoding, %q) = %x, %v, want %x, nil", source, dec2, err, want)
	}

	// Should work with padding.
	r = base64le.NewDecoder(padEncoding, bytes.NewReader([]byte(source+"==")))
	dec3, err := ioutil.ReadAll(r)
	if err != nil || !bytes.Equal(dec3, want) {
		t.Errorf("reading NewDecoder(hash.LittleEndianEncoding, %q) = %x, %v, want %x, nil", source+"==", dec3, err, want)
	}
}
