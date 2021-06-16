package sha512

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
			hash:   "$6$rounds=5000$aaa$I4qE52homEnm0Oc9OlL/XVQbfwhe2/m3vmS0y/a/hkTq01TU4NpqoPGWHKmDCHBpUO/htAXPrpsYE6v2zZon/.",
			salt:   []byte("aaa"),
			rounds: 5000,
		},
		{
			hash:   "$6$aaa$I4qE52homEnm0Oc9OlL/XVQbfwhe2/m3vmS0y/a/hkTq01TU4NpqoPGWHKmDCHBpUO/htAXPrpsYE6v2zZon/.",
			salt:   []byte("aaa"),
			rounds: 5000,
		},
		{
			hash:   "$6$rounds=6000$aaa$aQGFJ.RGgUKrm8.ppuLyHU7aDfTgsmYaZNmk72xLl8JsKSBzhHai2gwD/m5d.R52wwn6eQ7Qoj6fxY3fpvnbw/",
			salt:   []byte("aaa"),
			rounds: 6000,
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
				t.Errorf("Params() = _, %d, _; want %d", rounds, test.rounds)
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
				Struct: "*sha512.scheme",
				Field:  "HashPrefix",
				Msg:    "prefix not found",
			},
		},
		{
			hash: "$6@$rounds=505000$69oRpYjidkp7hFdm$nbf4615NgTuG8kCnGYSjz/lXw4KrGMVR16cbCa9CSIHXK8UXwCK9bzCqDUw/I8hgb9Wstd1w5Bwgu5YG6Q.dm.",
			err: &crypthash.UnmarshalTypeError{
				Value:  "prefix",
				Type:   testutil.FieldType(scheme{}, "HashPrefix"),
				Offset: 4,
				Struct: "*sha512.scheme",
				Field:  "HashPrefix",
				Msg:    `unsupported prefix "$6@$"`,
			},
		},
		{
			hash: "$6$rounds=505000@$69oRpYjidkp7hFdm$nbf4615NgTuG8kCnGYSjz/lXw4KrGMVR16cbCa9CSIHXK8UXwCK9bzCqDUw/I8hgb9Wstd1w5Bwgu5YG6Q.dm.",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Rounds"),
				Offset: 17,
				Struct: "*sha512.scheme",
				Field:  "Rounds",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$6$rounds=505000$69oRpYjidkp7hFd@$nbf4615NgTuG8kCnGYSjz/lXw4KrGMVR16cbCa9CSIHXK8UXwCK9bzCqDUw/I8hgb9Wstd1w5Bwgu5YG6Q.dm.",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Salt"),
				Offset: 33,
				Struct: "*sha512.scheme",
				Field:  "Salt",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$6$rounds=505000$69oRpYjidkp7hFdm$nbf4615NgTuG8kCnGYSjz/lXw4KrGMVR16cbCa9CSIHXK8UXwCK9bzCqDUw/I8hgb9Wstd1w5Bwgu5YG6Q.dm@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 120,
				Struct: "*sha512.scheme",
				Field:  "Sum",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$6$rounds=505000$69oRpYjidkp7hFdm$nbf4615NgTuG8kCnGYSjz/lXw4KrGMVR16cbCa9CSIHXK8UXwCK9bzCqDUw/I8hgb9Wstd1w5Bwgu5YG6Q.dm.@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 121,
				Struct: "*sha512.scheme",
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
			rounds: 5050,
			key:    "60vWNtQXasFFizmEJXCLqg4l6.XOJzw8hYkWtUU.nj50nGl0D.IXiJOkMyfTKmZdR2QQI9PFCgfWZGf1Tp4Ac/",
		},
		{
			salt:   []byte("aab"),
			rounds: 5050,
			key:    "IpPADtGIldtiul9hghiMF2BdEx6xCHq.0n7O5Qc5m1lVfl.ng7ZOcZXfX8BGlMR.ImmKlB4MK/3re56rXELbc0",
		},
		{
			salt:   []byte("aaa"),
			rounds: 5051,
			key:    "abmRMTs29yFio/aBTwFPTw3zyVcg4NcxeKSDvk7/es4Rp15NB6tXdCxCpeWdggZkAD665fnCcKo7HKzJ4bUpj/",
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
		{
			password: []byte("password"),
			salt:     []byte("aaa"),
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
			rounds:   505000,
			scheme: scheme{
				HashPrefix: Prefix,
				Rounds:     505000,
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
