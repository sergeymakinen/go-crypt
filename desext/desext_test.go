package desext

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/internal/testutil"
)

func TestParse(t *testing.T) {
	hash := "_1111aaaa5FiuKrpisKM"
	if err := Check(hash, "password"); err != nil {
		t.Errorf("Check() = %v; want nil", err)
	}
	salt, rounds, err := Params(hash)
	if err != nil {
		t.Fatalf("Params() = _, _, %v; want nil", err)
	}
	if expected := []byte("aaaa"); !bytes.Equal(salt, expected) {
		t.Errorf("Params() = %v, _, _; want %v", salt, expected)
	}
	if expected := uint32(798915); rounds != expected {
		t.Errorf("Params() = _, %d, _; want %d", rounds, expected)
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
				Struct: "*desext.scheme",
				Field:  "HashPrefix",
				Msg:    "prefix not found",
			},
		},
		{
			hash: "$1$6C/.yaiu.qYIjNR7X.s",
			err: &crypthash.UnmarshalTypeError{
				Value:  "prefix",
				Type:   testutil.FieldType(scheme{}, "HashPrefix"),
				Offset: 3,
				Struct: "*desext.scheme",
				Field:  "HashPrefix",
				Msg:    `unsupported prefix "$1$"`,
			},
		},
		{
			hash: "_6C/@yaiu.qYIjNR7X.s",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Rounds"),
				Offset: 20,
				Struct: "*desext.scheme",
				Field:  "Rounds",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "_6C/.yai@.qYIjNR7X.s",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Salt"),
				Offset: 20,
				Struct: "*desext.scheme",
				Field:  "Salt",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "_6C/.yaiu.qYIjNR7X.@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 20,
				Struct: "*desext.scheme",
				Field:  "Sum",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "_6C/.yaiu.qYIjNR7X.s@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 21,
				Struct: "*desext.scheme",
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
				t.Errorf("Params() = _, _, _, %v; want %v", err, test.err)
			}
		})
	}
}

func TestKey(t *testing.T) {
	tests := []struct {
		password, salt []byte
		rounds         uint32
		key            string
	}{
		{
			password: []byte("password"),
			salt:     []byte("aaaa"),
			rounds:   5000,
			key:      "oLVqmfE5o0U",
		},
		{
			password: []byte("password"),
			salt:     []byte("aaab"),
			rounds:   5000,
			key:      "1xnEpVh9j2k",
		},
		{
			password: []byte("password"),
			salt:     []byte("aaaa"),
			rounds:   5001,
			key:      "NbnICTD.rh2",
		},
		{
			password: []byte("passwordpassword"),
			salt:     []byte("aaaa"),
			rounds:   798915,
			key:      "vmtgH6mlBQk",
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("password=%s;salt=%s;rounds=%d", test.password, test.salt, test.rounds), func(t *testing.T) {
			key, err := Key(test.password, test.salt, test.rounds)
			if err != nil {
				t.Fatalf("Key() = _, %v; want nil", err)
			}
			if encKey := crypthash.BigEndianEncoding.EncodeToString(key); encKey != test.key {
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
			salt:     bytes.Repeat([]byte{'a'}, SaltLength+1),
			rounds:   5000,
			err:      InvalidSaltLengthError(SaltLength + 1),
		},
		{
			password: []byte("password"),
			salt:     []byte("aaa@"),
			rounds:   5000,
			err:      InvalidSaltError('@'),
		},
		{
			password: []byte("password"),
			salt:     []byte("aaaa"),
			rounds:   MinRounds - 1,
			err:      InvalidRoundsError(MinRounds - 1),
		},
		{
			password: []byte("password"),
			salt:     []byte("aaaa"),
			rounds:   MaxRounds + 1,
			err:      InvalidRoundsError(MaxRounds + 1),
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
			rounds:   5050,
			scheme: scheme{
				HashPrefix: Prefix,
				Rounds:     5050,
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
				return x.HashPrefix == y.HashPrefix && x.Rounds == y.Rounds
			})); diff != "" {
				t.Errorf("crypthash.Unmarshal() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
