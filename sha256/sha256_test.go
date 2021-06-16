package sha256

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
			hash:   "$5$rounds=5000$aaa$KzSJfmMb9SO88yzOh42fPm3ckBI944gGvTRvr.psx20",
			salt:   []byte("aaa"),
			rounds: 5000,
		},
		{
			hash:   "$5$aaa$KzSJfmMb9SO88yzOh42fPm3ckBI944gGvTRvr.psx20",
			salt:   []byte("aaa"),
			rounds: 5000,
		},
		{
			hash:   "$5$rounds=6000$aaa$pUyBiWL.TGiYGXCdEJ5f8w/SMIHZxzAttBHlB61pke8",
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
				Struct: "*sha256.scheme",
				Field:  "HashPrefix",
				Msg:    "prefix not found",
			},
		},
		{
			hash: "$5@$rounds=505000$.HnFpd3anFzRwVj5$EdcK/Q9wfmq1XsG5OTKP0Ns.ZlN9DRHslblcgCLtXY5",
			err: &crypthash.UnmarshalTypeError{
				Value:  "prefix",
				Type:   testutil.FieldType(scheme{}, "HashPrefix"),
				Offset: 4,
				Struct: "*sha256.scheme",
				Field:  "HashPrefix",
				Msg:    `unsupported prefix "$5@$"`,
			},
		},
		{
			hash: "$5$rounds=505000@$.HnFpd3anFzRwVj5$EdcK/Q9wfmq1XsG5OTKP0Ns.ZlN9DRHslblcgCLtXY5",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Rounds"),
				Offset: 17,
				Struct: "*sha256.scheme",
				Field:  "Rounds",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$5$rounds=505000$.HnFpd3anFzRwVj@$EdcK/Q9wfmq1XsG5OTKP0Ns.ZlN9DRHslblcgCLtXY5",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Salt"),
				Offset: 33,
				Struct: "*sha256.scheme",
				Field:  "Salt",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$5$rounds=505000$.HnFpd3anFzRwVj5$EdcK/Q9wfmq1XsG5OTKP0Ns.ZlN9DRHslblcgCLtXY@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 77,
				Struct: "*sha256.scheme",
				Field:  "Sum",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$5$rounds=505000$.HnFpd3anFzRwVj5$EdcK/Q9wfmq1XsG5OTKP0Ns.ZlN9DRHslblcgCLtXY5@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 78,
				Struct: "*sha256.scheme",
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
			key:    "Uz6VT8T/P9YanfRrt7fT/Ut1Rlh1oRob3Ay4.3/.tH7",
		},
		{
			salt:   []byte("aab"),
			rounds: 5050,
			key:    "aRuZKyju5Coa7qmOvZWxwvn6pBxsAGCEtdlx9StYJO4",
		},
		{
			salt:   []byte("aaa"),
			rounds: 5051,
			key:    "MQjydXF/w2HydSfhjooE3/Ro4zHSElB9hkXLJtobyJ3",
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
