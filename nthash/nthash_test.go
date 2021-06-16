package nthash

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/internal/testutil"
)

func TestCheck(t *testing.T) {
	if err := Check("$3$$8846f7eaee8fb117ad06bdd830b7586c", "password"); err != nil {
		t.Errorf("Check() = %v; want nil", err)
	}
}

func TestCheckShouldFail(t *testing.T) {
	tests := []struct {
		hash string
		err  error
	}{
		{
			hash: "",
			err: &crypthash.UnmarshalTypeError{
				Value:  "EOF",
				Type:   testutil.FieldType(scheme{}, "HashPrefix"),
				Struct: "*nthash.scheme",
				Field:  "HashPrefix",
				Msg:    "prefix not found",
			},
		},
		{
			hash: "$3@$$8846f7eaee8fb117ad06bdd830b7586c",
			err: &crypthash.UnmarshalTypeError{
				Value:  "prefix",
				Type:   testutil.FieldType(scheme{}, "HashPrefix"),
				Offset: 4,
				Struct: "*nthash.scheme",
				Field:  "HashPrefix",
				Msg:    `unsupported prefix "$3@$"`,
			},
		},
		{
			hash: "$3$$8846f7eaee8fb117ad06bdd830b7586@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 36,
				Struct: "*nthash.scheme",
				Field:  "Sum",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$3$$8846f7eaee8fb117ad06bdd830b7586c@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 37,
				Struct: "*nthash.scheme",
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
		})
	}
}

func TestKey(t *testing.T) {
	key, err := Key(encodePassword("password"))
	if err != nil {
		t.Fatalf("Key() = _, %v; want nil", err)
	}
	if encKey, expected := hex.EncodeToString(key), "8846f7eaee8fb117ad06bdd830b7586c"; encKey != expected {
		t.Errorf("Key() = %q, _; want %q", encKey, expected)
	}
}

func TestKeyShouldFail(t *testing.T) {
	tests := []struct {
		password []byte
		err      error
	}{
		{
			password: []byte("passwor"),
			err:      InvalidPasswordLengthError(7),
		},
		{
			password: bytes.Repeat([]byte{'p'}, MaxPasswordLength+1),
			err:      InvalidPasswordLengthError(MaxPasswordLength + 1),
		},
	}
	for _, test := range tests {
		t.Run(string(test.password), func(t *testing.T) {
			if _, err := Key(test.password); !testutil.IsEqualError(err, test.err) {
				t.Errorf("Key() = _, %v; want %v", err, test.err)
			}
		})
	}
}

func TestNewHash(t *testing.T) {
	hash, err := NewHash("password")
	if err != nil {
		t.Fatalf("NewHash() = _, %v; want nil", err)
	}
	if err := Check(hash, "password"); err != nil {
		t.Errorf("Check() = %v; want nil", err)
	}
	var schema scheme
	if err := crypthash.Unmarshal(hash, &schema); err != nil {
		t.Fatalf("crypthash.Unmarshal() = %v; want nil", err)
	}
	expected := scheme{HashPrefix: "$3$"}
	copy(expected.Sum[:], "8846f7eaee8fb117ad06bdd830b7586c")
	if diff := cmp.Diff(expected, schema, cmp.AllowUnexported(scheme{})); diff != "" {
		t.Errorf("crypthash.Unmarshal() mismatch (-want +got):\n%s", diff)
	}
}
