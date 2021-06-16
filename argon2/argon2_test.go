package argon2

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/internal/testutil"
)

func TestParse(t *testing.T) {
	tests := []struct {
		hash         string
		password     string
		salt         []byte
		memory, time uint32
		threads      uint8
		opts         *CompatibilityOptions
	}{
		// Passlib
		{
			hash:     "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
			password: "password",
			salt:     []byte(base64.RawStdEncoding.EncodeToString([]byte("somesalt"))),
			memory:   65536,
			time:     2,
			threads:  1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2i,
				Version: Version10,
			},
		},
		{
			hash:     "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
			password: "password",
			salt:     []byte(base64.RawStdEncoding.EncodeToString([]byte("somesalt"))),
			memory:   65536,
			time:     2,
			threads:  1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2i,
				Version: Version13,
			},
		},
		{
			hash:     "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
			password: "password",
			salt:     []byte(base64.RawStdEncoding.EncodeToString([]byte("somesalt"))),
			memory:   65536,
			time:     2,
			threads:  1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2id,
				Version: Version13,
			},
		},
		{
			hash:     "$argon2i$m=65536,t=2,p=4$c29tZXNhbHQAAAAAAAAAAA$QWLzI4TY9HkL2ZTLc8g6SinwdhZewYrzz9zxCo0bkGY",
			password: "password",
			salt:     []byte(base64.RawStdEncoding.EncodeToString([]byte("somesalt\x00\x00\x00\x00\x00\x00\x00\x00"))),
			memory:   65536,
			time:     2,
			threads:  4,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2i,
				Version: Version10,
			},
		},
		{
			hash:     "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4",
			password: "password",
			salt:     []byte(base64.RawStdEncoding.EncodeToString([]byte("somesalt"))),
			memory:   65536,
			time:     2,
			threads:  4,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2i,
				Version: Version13,
			},
		},
		{
			hash:     "$argon2d$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$cZn5d+rFh+ZfuRhm2iGUGgcrW5YLeM6q7L3vBsdmFA0",
			password: "password",
			salt:     []byte(base64.RawStdEncoding.EncodeToString([]byte("somesalt"))),
			memory:   65536,
			time:     2,
			threads:  4,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2d,
				Version: Version13,
			},
		},
		{
			hash:     "$argon2id$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo",
			password: "password",
			salt:     []byte(base64.RawStdEncoding.EncodeToString([]byte("somesalt"))),
			memory:   65536,
			time:     2,
			threads:  4,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2id,
				Version: Version13,
			},
		},
		{
			hash:     "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$Vpzuc0v0SrP88LcVvmg+z5RoOYpMDKH/lt6O+CZabIQ",
			password: "password\x00",
			salt:     []byte(base64.RawStdEncoding.EncodeToString([]byte("somesalt"))),
			memory:   65536,
			time:     2,
			threads:  4,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2i,
				Version: Version13,
			},
		},

		// Other
		{
			hash:     "$argon2d$m=65536,t=2,p=1$aaaaaaaaaaa$XaFjw0YePzV0u+iQQPfVIKxR+/EkPPaNRWhamN6HWFw",
			password: "password",
			salt:     []byte("aaaaaaaaaaa"),
			memory:   65536,
			time:     2,
			threads:  1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2d,
				Version: Version10,
			},
		},
		{
			hash:     "$argon2i$m=65536,t=2,p=1$aaaaaaaaaaa$6l5VGPImlKbzbcyLoBDHTjlgJqE4B/t5gmsuIjZQ3y8",
			password: "password",
			salt:     []byte("aaaaaaaaaaa"),
			memory:   65536,
			time:     2,
			threads:  1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2i,
				Version: Version10,
			},
		},
		{
			hash:     "$argon2id$m=65536,t=2,p=1$aaaaaaaaaaa$Pfwf5vMdV8nbWskx+eHG3K6MgUrVKsoQ+/JpLvF5rNo",
			password: "password",
			salt:     []byte("aaaaaaaaaaa"),
			memory:   65536,
			time:     2,
			threads:  1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2id,
				Version: Version10,
			},
		},
		{
			hash:     "$argon2d$v=19$m=65536,t=2,p=1$aaaaaaaaaaa$J7PriH2ruyNR/iNVgFnKcy0+5ajsp4pT6ooc/uUPitU",
			password: "password",
			salt:     []byte("aaaaaaaaaaa"),
			memory:   65536,
			time:     2,
			threads:  1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2d,
				Version: Version13,
			},
		},
		{
			hash:     "$argon2i$v=19$m=65536,t=2,p=1$aaaaaaaaaaa$qGBmp2D8cyDPxZZ+xi34ZfSNZ148Ni3mxBvrvfFFAjc",
			password: "password",
			salt:     []byte("aaaaaaaaaaa"),
			memory:   65536,
			time:     2,
			threads:  1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2i,
				Version: Version13,
			},
		},
		{
			hash:     "$argon2id$v=19$m=65536,t=2,p=1$aaaaaaaaaaa$gr1YMQTv2aipnJeX6EhS4pMlK5cz2B/arFrAh0PV46w",
			password: "password",
			salt:     []byte("aaaaaaaaaaa"),
			memory:   65536,
			time:     2,
			threads:  1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2id,
				Version: Version13,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.hash, func(t *testing.T) {
			if err := Check(test.hash, test.password); err != nil {
				t.Errorf("Check() = %v; want nil", err)
			}
			salt, memory, time, threads, opts, err := Params(test.hash)
			if err != nil {
				t.Fatalf("Params() = _, _, _, _, _, %v; want nil", err)
			}
			if !bytes.Equal(salt, test.salt) {
				t.Errorf("Params() = %v, _, _, _, _, _; want %v", salt, test.salt)
			}
			if memory != test.memory {
				t.Errorf("Params() = _, %d, _, _, _, _; want %d", memory, test.memory)
			}
			if time != test.time {
				t.Errorf("Params() = _, _, %d, _, _, _; want %d", time, test.time)
			}
			if threads != test.threads {
				t.Errorf("Params() = _, _, _, %d, _, _; want %d", threads, test.threads)
			}
			if !reflect.DeepEqual(opts, test.opts) {
				t.Errorf("Params() = _, _, _, _, %v, _; want %v", opts, test.opts)
			}
		})
	}
}

func TestParseShouldFail(t *testing.T) {
	tests := []struct {
		hash string
		err  error
	}{
		{
			hash: "",
			err: &crypthash.UnmarshalTypeError{
				Value:  "EOF",
				Type:   testutil.FieldType(scheme{}, "HashPrefix"),
				Struct: "*argon2.scheme",
				Field:  "HashPrefix",
				Msg:    "prefix not found",
			},
		},
		{
			hash: "$argon2id@$v=19$m=512,t=3,p=1$qXMlAYBABLl$/OuG+qcZ1ntdTRfhUGFVp2YMcTPJ7aH3e4j7KIEnRho",
			err: &crypthash.UnmarshalTypeError{
				Value:  "prefix",
				Type:   testutil.FieldType(scheme{}, "HashPrefix"),
				Offset: 11,
				Struct: "*argon2.scheme",
				Field:  "HashPrefix",
				Msg:    `unsupported prefix "$argon2id@$"`,
			},
		},
		{
			hash: "$argon2id$v=1@$m=512,t=3,p=1$qXMlAYBABLl$/OuG+qcZ1ntdTRfhUGFVp2YMcTPJ7aH3e4j7KIEnRho",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Version"),
				Offset: 14,
				Struct: "*argon2.scheme",
				Field:  "Version",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$argon2id$v=19$m=512@,t=3,p=1$qXMlAYBABLl$/OuG+qcZ1ntdTRfhUGFVp2YMcTPJ7aH3e4j7KIEnRho",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Memory"),
				Offset: 21,
				Struct: "*argon2.scheme",
				Field:  "Memory",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$argon2id$v=19$m=512,t=3@,p=1$qXMlAYBABLl$/OuG+qcZ1ntdTRfhUGFVp2YMcTPJ7aH3e4j7KIEnRho",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Time"),
				Offset: 25,
				Struct: "*argon2.scheme",
				Field:  "Time",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$argon2id$v=19$m=512,t=3,p=1@$qXMlAYBABLl$/OuG+qcZ1ntdTRfhUGFVp2YMcTPJ7aH3e4j7KIEnRho",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Threads"),
				Offset: 29,
				Struct: "*argon2.scheme",
				Field:  "Threads",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$argon2id$v=19$m=512,t=3,p=1$qXMlAYBABL@$/OuG+qcZ1ntdTRfhUGFVp2YMcTPJ7aH3e4j7KIEnRho",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Salt"),
				Offset: 40,
				Struct: "*argon2.scheme",
				Field:  "Salt",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$argon2id$v=19$m=512,t=3,p=1$qXMlAYBABLl$/OuG+qcZ1ntdTRfhUGFVp2YMcTPJ7aH3e4j7KIEnRh@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 84,
				Struct: "*argon2.scheme",
				Field:  "Sum",
				Msg:    "invalid character '@'",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.hash, func(t *testing.T) {
			if err := Check(test.hash, "password"); !testutil.IsEqualError(err, test.err) {
				t.Errorf("Check() = %v; want %v", err, test.err)
			}
			if _, _, _, _, _, err := Params(test.hash); !testutil.IsEqualError(err, test.err) {
				t.Errorf("Params() = _, _, _, %v; want %v", err, test.err)
			}
		})
	}
}

func TestKey(t *testing.T) {
	tests := []struct {
		salt         []byte
		memory, time uint32
		threads      uint8
		opts         *CompatibilityOptions
		key          string
	}{
		{
			salt:    []byte("aaaaaaaaaaaY"),
			memory:  512,
			time:    3,
			threads: 1,
			opts:    nil,
			key:     "RoNwJ8EXTG+RwuhSwzXmSPCTBZXREHE1AbIE86Z2wcU",
		},
		{
			salt:    []byte("aaaaaaaaaac"),
			memory:  512,
			time:    3,
			threads: 1,
			opts:    nil,
			key:     "BBYFdyEIR3/VOqi+QIg92ZJwB5j6TyfZG/955wU8+kU",
		},
		{
			salt:    []byte("aaaaaaaaaaaY"),
			memory:  513,
			time:    3,
			threads: 1,
			opts:    nil,
			key:     "mciF8mEYX1aoc0QnzRaQO0QgxZGDEakfvJFnYsODp5U",
		},
		{
			salt:    []byte("aaaaaaaaaaaY"),
			memory:  512,
			time:    4,
			threads: 1,
			opts:    nil,
			key:     "3FWioROzveOOYfwgTicGZgxAZrUAchZL4zQ6e7hDQ1k",
		},
		{
			salt:    []byte("aaaaaaaaaaaY"),
			memory:  512,
			time:    3,
			threads: 2,
			opts:    nil,
			key:     "PqrOHHYW1PdJQpHxIqWkl9kAYlRZgdWbJCJGrciAY0M",
		},
		{
			salt:    []byte("aaaaaaaaaaaY"),
			memory:  512,
			time:    3,
			threads: 1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2d,
				Version: Version10,
			},
			key: "dbutN85uTg8lvDXP9jgv1rPSvq0QB2zbXwv0a1kMRv8",
		},
		{
			salt:    []byte("aaaaaaaaaaaY"),
			memory:  512,
			time:    3,
			threads: 1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2i,
				Version: Version10,
			},
			key: "CLvHYcpuMTTC4fEJETHuiBLx2Wt23IKZIlajp+G3jMg",
		},
		{
			salt:    []byte("aaaaaaaaaaaY"),
			memory:  512,
			time:    3,
			threads: 1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2id,
				Version: Version10,
			},
			key: "kcDVTmB7LDJkhIt0ep4+C+/2OO1NQqkHMtgfQCfn2Z4",
		},
		{
			salt:    []byte("aaaaaaaaaaaY"),
			memory:  512,
			time:    3,
			threads: 1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2d,
				Version: Version13,
			},
			key: "AZiWtk8pWk1RZet8bkGS4NeymYHrLw+bGAUx21lHOZQ",
		},
		{
			salt:    []byte("aaaaaaaaaaaY"),
			memory:  512,
			time:    3,
			threads: 1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2i,
				Version: Version13,
			},
			key: "7b9fHBHs4ZNqn8s26cGUh/4aKAON9F6znj2CeSfNYHQ",
		},
		{
			salt:    []byte("aaaaaaaaaaaY"),
			memory:  512,
			time:    3,
			threads: 1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2id,
				Version: Version13,
			},
			key: "RoNwJ8EXTG+RwuhSwzXmSPCTBZXREHE1AbIE86Z2wcU",
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("salt=%s;memory=%d;time=%d;threads=%d;opts=%v", test.salt, test.memory, test.time, test.threads, test.opts), func(t *testing.T) {
			key, err := Key([]byte("password"), test.salt, test.memory, test.time, test.threads, test.opts)
			if err != nil {
				t.Fatalf("Key() = _, %v; want nil", err)
			}
			if encKey := base64.RawStdEncoding.EncodeToString(key); encKey != test.key {
				t.Errorf("Key() = %q, _; want %q", encKey, test.key)
			}
		})
	}
}

func TestKeyShouldFail(t *testing.T) {
	tests := []struct {
		salt         []byte
		memory, time uint32
		threads      uint8
		opts         *CompatibilityOptions
		err          error
	}{
		{
			salt:    bytes.Repeat([]byte{'a'}, MinSaltLength-1),
			memory:  512,
			time:    3,
			threads: 1,
			opts:    nil,
			err:     InvalidSaltLengthError(MinSaltLength - 1),
		},
		{
			salt:    []byte("aaaaaaaaaa@"),
			memory:  512,
			time:    3,
			threads: 1,
			opts:    nil,
			err:     InvalidSaltError('@'),
		},
		{
			salt:    []byte("aaaaaaaaaaa"),
			memory:  MinMemory - 1,
			time:    3,
			threads: 1,
			opts:    nil,
			err:     InvalidMemoryError(MinMemory - 1),
		},
		{
			salt:    []byte("aaaaaaaaaaa"),
			memory:  512,
			time:    MinTime - 1,
			threads: 1,
			opts:    nil,
			err:     InvalidTimeError(MinTime - 1),
		},
		{
			salt:    []byte("aaaaaaaaaaa"),
			memory:  512,
			time:    3,
			threads: MinThreads - 1,
			opts:    nil,
			err:     InvalidThreadsError(MinThreads - 1),
		},
		{
			salt:    []byte("aaaaaaaaaaa"),
			memory:  512,
			time:    3,
			threads: 1,
			opts:    &CompatibilityOptions{Prefix: "aaa"},
			err:     UnsupportedPrefixError("aaa"),
		},
		{
			salt:    []byte("aaaaaaaaaaa"),
			memory:  512,
			time:    3,
			threads: 1,
			opts: &CompatibilityOptions{
				Prefix:  Prefix2id,
				Version: 0x8,
			},
			err: UnsupportedVersionError(0x8),
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("salt=%s;memory=%d;time=%d;threads=%d;opts=%v", test.salt, test.memory, test.time, test.threads, test.opts), func(t *testing.T) {
			if _, err := Key([]byte("password"), test.salt, test.memory, test.time, test.threads, test.opts); !testutil.IsEqualError(err, test.err) {
				t.Errorf("Key() = _, %v; want %v", err, test.err)
			}
		})
	}
}

func TestNewHash(t *testing.T) {
	tests := []struct {
		password     string
		memory, time uint32
		scheme       scheme
	}{
		{
			password: "password",
			memory:   DefaultMemory,
			time:     DefaultTime,
			scheme: scheme{
				HashPrefix: Prefix2id,
				Version:    Version13,
				Memory:     DefaultMemory,
				Time:       DefaultTime,
				Threads:    DefaultThreads,
			},
		},
		{
			password: "password",
			memory:   512,
			time:     DefaultTime,
			scheme: scheme{
				HashPrefix: Prefix2id,
				Version:    Version13,
				Memory:     512,
				Time:       DefaultTime,
				Threads:    DefaultThreads,
			},
		},
		{
			password: "password",
			memory:   DefaultMemory,
			time:     1,
			scheme: scheme{
				HashPrefix: Prefix2id,
				Version:    Version13,
				Memory:     DefaultMemory,
				Time:       1,
				Threads:    DefaultThreads,
			},
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("password=%s;memory=%d;time=%d", test.password, test.memory, test.time), func(t *testing.T) {
			hash, err := NewHash(test.password, test.memory, test.time)
			if err != nil {
				t.Fatalf("NewHash() = _, %v; want nil", err)
			}
			if err := Check(hash, test.password); err != nil {
				t.Errorf("Check() = %v; want nil", err)
			}
			var schema scheme
			if err := crypthash.Unmarshal(hash, &schema); err != nil {
				t.Fatalf("crypthash.Unmarshal() = %v; want nil", err)
			}
			if diff := cmp.Diff(test.scheme, schema, cmp.Comparer(func(x, y scheme) bool {
				return x.HashPrefix == y.HashPrefix && x.Memory == y.Memory && x.Time == y.Time && x.Threads == y.Threads
			})); diff != "" {
				t.Errorf("crypthash.Unmarshal() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
