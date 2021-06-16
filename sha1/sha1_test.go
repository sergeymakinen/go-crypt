package sha1

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/internal/testutil"
)

func TestParse(t *testing.T) {
	tests := []struct {
		hash   string
		salt   []byte
		rounds uint32
	}{
		{
			hash:   "$sha1$40000$aaa$RgfGsUx52n.yarrkcZHeaI7X8pQo",
			salt:   []byte("aaa"),
			rounds: 40000,
		},
		{
			hash:   "$sha1$50000$aaa$dkLSBxcx.iZ8aCZqe23WLT/3t/GA",
			salt:   []byte("aaa"),
			rounds: 50000,
		},
	}
	for _, test := range tests {
		t.Run(test.hash, func(t *testing.T) {
			if err := Check(test.hash, "password"); err != nil {
				t.Errorf("Check() = %v; want nil", err)
			}
			salt, rounds, err := Params(test.hash)
			if err != nil {
				t.Fatalf("Params() = _, _, %v; want nil", err)
			}
			if !bytes.Equal(salt, test.salt) {
				t.Errorf("Params() = %v, _, _; want %v", salt, test.salt)
			}
			if rounds != test.rounds {
				t.Errorf("Params() = _, %d, _, _; want %d", rounds, test.rounds)
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
				Struct: "*sha1.scheme",
				Field:  "HashPrefix",
				Msg:    "prefix not found",
			},
		},
		{
			hash: "$sha1@$48000$mHh0IIOQ$YS/Lw0PKCThSEBBYqP37zXySQ3cC",
			err: &crypthash.UnmarshalTypeError{
				Value:  "prefix",
				Type:   testutil.FieldType(scheme{}, "HashPrefix"),
				Offset: 7,
				Struct: "*sha1.scheme",
				Field:  "HashPrefix",
				Msg:    `unsupported prefix "$sha1@$"`,
			},
		},
		{
			hash: "$sha1$48000@$mHh0IIOQ$YS/Lw0PKCThSEBBYqP37zXySQ3cC",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Rounds"),
				Offset: 12,
				Struct: "*sha1.scheme",
				Field:  "Rounds",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$sha1$48000$mHh0IIO@$YS/Lw0PKCThSEBBYqP37zXySQ3cC",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Salt"),
				Offset: 20,
				Struct: "*sha1.scheme",
				Field:  "Salt",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$sha1$48000$mHh0IIOQ$YS/Lw0PKCThSEBBYqP37zXySQ3c@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 49,
				Struct: "*sha1.scheme",
				Field:  "Sum",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$sha1$48000$mHh0IIOQ$YS/Lw0PKCThSEBBYqP37zXySQ3cC@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 50,
				Struct: "*sha1.scheme",
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
			if _, _, err := Params(test.hash); !testutil.IsEqualError(err, test.err) {
				t.Errorf("Params() = _, _, %v; want %v", err, test.err)
			}
		})
	}
}

func TestKey(t *testing.T) {
	tests := []struct {
		salt   []byte
		rounds uint32
		key    string
	}{
		{
			salt:   []byte("aaa"),
			rounds: 40000,
			key:    "RgfGsUx52n.yarrkcZHeaI7X8pQo",
		},
		{
			salt:   []byte("aab"),
			rounds: 40000,
			key:    "s78HpiTYM6n8QjeLYw7Rw1PvA3nw",
		},
		{
			salt:   []byte("aaa"),
			rounds: 50000,
			key:    "dkLSBxcx.iZ8aCZqe23WLT/3t/GA",
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("salt=%s;rounds=%d", test.salt, test.rounds), func(t *testing.T) {
			key, err := Key([]byte("password"), test.salt, test.rounds)
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
		err            error
	}{
		{
			password: []byte("password"),
			salt:     bytes.Repeat([]byte{'a'}, MaxSaltLength+1),
			rounds:   505000,
			err:      InvalidSaltLengthError(MaxSaltLength + 1),
		},
		{
			password: []byte("password"),
			salt:     []byte("aaa@"),
			rounds:   505000,
			err:      InvalidSaltError('@'),
		},
		{
			password: []byte("password"),
			salt:     []byte("aaa"),
			rounds:   MinRounds - 1,
			err:      InvalidRoundsError(MinRounds - 1),
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("password=%s;salt=%s;rounds=%d", test.password, test.salt, test.rounds), func(t *testing.T) {
			if _, err := Key(test.password, test.salt, test.rounds); !testutil.IsEqualError(err, test.err) {
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
				HashPrefix: Prefix,
				Rounds:     DefaultRounds,
			},
		},
		{
			password: "password",
			rounds:   40000,
			scheme: scheme{
				HashPrefix: Prefix,
				Rounds:     40000,
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
			var comparer func(x, y scheme) bool
			if test.rounds == RandomRounds {
				comparer = func(x, y scheme) bool {
					return x.HashPrefix == y.HashPrefix
				}
			} else {
				comparer = func(x, y scheme) bool {
					return x.HashPrefix == y.HashPrefix && x.Rounds == y.Rounds
				}
			}
			if diff := cmp.Diff(test.scheme, schema, cmp.Comparer(comparer)); diff != "" {
				t.Errorf("crypthash.Unmarshal() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
