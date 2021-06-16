package sunmd5

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/internal/testutil"
)

func TestParse(t *testing.T) {
	// Tested on Solaris 11
	tests := []struct {
		hash   string
		salt   []byte
		rounds uint32
		opts   *CompatibilityOptions
	}{
		{
			hash:   "$md5,rounds=5000$z3L69cPJTnwjRDTAFtqGE.",
			rounds: 5000,
			opts: &CompatibilityOptions{
				Prefix:               PrefixNonZeroRounds,
				DisableSaltSeparator: true,
			},
		},
		{
			hash:   "$md5,rounds=5000$aaa$$abAU9NFKS6nog0MbB4WmM.",
			salt:   []byte("aaa"),
			rounds: 5000,
			opts: &CompatibilityOptions{
				Prefix:               PrefixNonZeroRounds,
				DisableSaltSeparator: false,
			},
		},
		{
			hash:   "$md5,rounds=5000$aaa$GNArD84Syd52XPjlSDxuX/",
			salt:   []byte("aaa"),
			rounds: 5000,
			opts: &CompatibilityOptions{
				Prefix:               PrefixNonZeroRounds,
				DisableSaltSeparator: true,
			},
		},
		{
			hash:   "$md5$rounds=5000$kuxX9vDbwOHLHi7y6cIrR0",
			rounds: 5000,
			opts: &CompatibilityOptions{
				Prefix:               PrefixZeroRounds,
				DisableSaltSeparator: true,
			},
		},
		{
			hash:   "$md5$rounds=5000$aaa$$LvUyweN9Tdadr7cv.RmQn.",
			salt:   []byte("aaa"),
			rounds: 5000,
			opts: &CompatibilityOptions{
				Prefix:               PrefixZeroRounds,
				DisableSaltSeparator: false,
			},
		},
		{
			hash:   "$md5$rounds=5000$aaa$NaTj.65AER50nLcHV9aKI/",
			salt:   []byte("aaa"),
			rounds: 5000,
			opts: &CompatibilityOptions{
				Prefix:               PrefixZeroRounds,
				DisableSaltSeparator: true,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.hash, func(t *testing.T) {
			if err := Check(test.hash, "password"); err != nil {
				t.Errorf("Check() = %v; want nil", err)
			}
			salt, rounds, opts, err := Params(test.hash)
			if err != nil {
				t.Fatalf("Params() = _, _, _, %v; want nil", err)
			}
			if !bytes.Equal(salt, test.salt) {
				t.Errorf("Params() = %v, _, _, _; want %v", salt, test.salt)
			}
			if rounds != test.rounds {
				t.Errorf("Params() = _, %d, _, _; want %d", rounds, test.rounds)
			}
			if !reflect.DeepEqual(opts, test.opts) {
				t.Errorf("Params() = _, _, %v, _; want %v", opts, test.opts)
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
				Struct: "*sunmd5.scheme",
				Field:  "HashPrefix",
				Msg:    "prefix not found",
			},
		},
		{
			hash: "$md5@,rounds=5000$aaa$$abAU9NFKS6nog0MbB4WmM.",
			err: &crypthash.UnmarshalTypeError{
				Value:  "prefix",
				Type:   testutil.FieldType(scheme{}, "HashPrefix"),
				Offset: 6,
				Struct: "*sunmd5.scheme",
				Field:  "HashPrefix",
				Msg:    `unsupported prefix "$md5@,"`,
			},
		},
		{
			hash: "$md5,rounds=5000@$aaa$$abAU9NFKS6nog0MbB4WmM.",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Rounds"),
				Offset: 17,
				Struct: "*sunmd5.scheme",
				Field:  "Rounds",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$md5,rounds=5000$aaa@$$abAU9NFKS6nog0MbB4WmM.",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Salt"),
				Offset: 21,
				Struct: "*sunmd5.scheme",
				Field:  "Salt",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$md5,rounds=5000$aaa$$abAU9NFKS6nog0MbB4WmM@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 44,
				Struct: "*sunmd5.scheme",
				Field:  "Sum",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$md5,rounds=5000$aaa$$abAU9NFKS6nog0MbB4WmM.@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 45,
				Struct: "*sunmd5.scheme",
				Field:  "Sum",
				Msg:    "length mismatch",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.hash, func(t *testing.T) {
			if err := Check(test.hash, "password"); !testutil.IsEqualError(err, test.err) {
				t.Errorf("Check() = %v; want %v", err, test.err)
			}
			if _, _, _, err := Params(test.hash); !testutil.IsEqualError(err, test.err) {
				t.Errorf("Params() = _, _, _, %v; want %v", err, test.err)
			}
		})
	}
}

func TestKey(t *testing.T) {
	tests := []struct {
		salt   []byte
		rounds uint32
		opts   *CompatibilityOptions
		key    string
	}{
		{
			salt:   []byte("aaa"),
			rounds: DefaultRounds,
			opts:   nil,
			key:    "4hpwvO8R7Vz0smS5.6r5T/",
		},
		{
			salt:   []byte("aaa"),
			rounds: 5000,
			opts:   nil,
			key:    "abAU9NFKS6nog0MbB4WmM.",
		},
		{
			salt:   []byte("aab"),
			rounds: 5000,
			opts:   nil,
			key:    "Vmh99peF3k1z6VfnQxmoH1",
		},
		{
			salt:   []byte("aaa"),
			rounds: 5001,
			opts:   nil,
			key:    ".CG9cGPNrgBrOXmpPKoTC/",
		},
		{
			salt:   []byte("aaa"),
			rounds: 5000,
			opts: &CompatibilityOptions{
				Prefix:               PrefixNonZeroRounds,
				DisableSaltSeparator: false,
			},
			key: "abAU9NFKS6nog0MbB4WmM.",
		},
		{
			salt:   []byte("aaa"),
			rounds: 5000,
			opts: &CompatibilityOptions{
				Prefix:               PrefixZeroRounds,
				DisableSaltSeparator: false,
			},
			key: "LvUyweN9Tdadr7cv.RmQn.",
		},
		{
			salt:   []byte("aaa"),
			rounds: 5000,
			opts: &CompatibilityOptions{
				Prefix:               PrefixNonZeroRounds,
				DisableSaltSeparator: true,
			},
			key: "GNArD84Syd52XPjlSDxuX/",
		},
		{
			salt:   []byte("aaa"),
			rounds: 5000,
			opts: &CompatibilityOptions{
				Prefix:               PrefixZeroRounds,
				DisableSaltSeparator: true,
			},
			key: "NaTj.65AER50nLcHV9aKI/",
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("salt=%s;rounds=%d;opts=%v", test.salt, test.rounds, test.opts), func(t *testing.T) {
			key, err := Key([]byte("password"), test.salt, test.rounds, test.opts)
			if err != nil {
				t.Fatalf("Key() = _, %v; want nil", err)
			}
			if encKey := crypthash.LittleEndianEncoding.EncodeToString(key); encKey != test.key {
				t.Errorf("Key() = %q, _; want %q", encKey, test.key)
			}
		})
	}
}

func TestKeyShouldFail(t *testing.T) {
	tests := []struct {
		password, salt []byte
		rounds         uint32
		opts           *CompatibilityOptions
		err            error
	}{
		{
			password: bytes.Repeat([]byte{'p'}, MaxPasswordLength+1),
			salt:     []byte("aaa"),
			rounds:   5000,
			opts:     nil,
			err:      InvalidPasswordLengthError(MaxPasswordLength + 1),
		},
		{
			password: []byte("password"),
			salt:     bytes.Repeat([]byte{'a'}, MaxSaltLength+1),
			rounds:   5000,
			opts:     nil,
			err:      InvalidSaltLengthError(MaxSaltLength + 1),
		},
		{
			password: []byte("password"),
			salt:     []byte("aaa@"),
			rounds:   5000,
			opts:     nil,
			err:      InvalidSaltError('@'),
		},
		{
			password: []byte("password"),
			salt:     []byte("aaa"),
			rounds:   MaxRounds + 1,
			opts:     nil,
			err:      InvalidRoundsError(MaxRounds + 1),
		},
		{
			password: []byte("password"),
			salt:     []byte("aaa"),
			rounds:   5000,
			opts: &CompatibilityOptions{
				Prefix:               "aaa",
				DisableSaltSeparator: false,
			},
			err: UnsupportedPrefixError("aaa"),
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("password=%s;salt=%s;rounds=%d;opts=%v", test.password, test.salt, test.rounds, test.opts), func(t *testing.T) {
			if _, err := Key(test.password, test.salt, test.rounds, test.opts); !testutil.IsEqualError(err, test.err) {
				t.Errorf("Key() = _, %v; want %v", err, test.err)
			}
		})
	}
}

func TestNewHash(t *testing.T) {
	tests := []struct {
		password string
		rounds   uint32
		scheme   scheme
	}{
		{
			password: "password",
			rounds:   DefaultRounds,
			scheme: scheme{
				saltScheme: saltScheme{
					HashPrefix: PrefixZeroRounds,
					Rounds:     DefaultRounds,
				},
			},
		},
		{
			password: "password",
			rounds:   5000,
			scheme: scheme{
				saltScheme: saltScheme{
					HashPrefix: PrefixNonZeroRounds,
					Rounds:     5000,
					Separator:  &separator,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("password=%s;rounds=%d", test.password, test.rounds), func(t *testing.T) {
			hash, err := NewHash(test.password, test.rounds)
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
				return x.HashPrefix == y.HashPrefix && x.Rounds == y.Rounds && reflect.DeepEqual(x.Separator, y.Separator)
			})); diff != "" {
				t.Errorf("crypthash.Unmarshal() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
