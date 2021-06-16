package des

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/internal/testutil"
)

func TestParse(t *testing.T) {
	hash := "aajfMKNH1hTm2"
	if err := Check(hash, "password"); err != nil {
		t.Errorf("Check() = %v; want nil", err)
	}
	salt, err := Salt(hash)
	if err != nil {
		t.Fatalf("Salt() = _, %v; want nil", err)
	}
	if expected := []byte("aa"); !bytes.Equal(salt, expected) {
		t.Errorf("Salt() = %v, _; want %v", salt, expected)
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
				Type:   testutil.FieldType(scheme{}, "Salt"),
				Struct: "*des.scheme",
				Field:  "Salt",
				Msg:    "unexpected EOF",
			},
		},
		{
			hash: "_aajfMKNH1hTm2",
			err: &crypthash.UnmarshalTypeError{
				Value:  "prefix",
				Type:   testutil.FieldType(scheme{}, "HashPrefix"),
				Offset: 1,
				Struct: "*des.scheme",
				Field:  "HashPrefix",
				Msg:    `unsupported prefix "_"`,
			},
		},
		{
			hash: "a@jfMKNH1hTm2",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Salt"),
				Offset: 13,
				Struct: "*des.scheme",
				Field:  "Salt",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "aajfMKNH1hTm@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 13,
				Struct: "*des.scheme",
				Field:  "Sum",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "aajfMKNH1hTm2@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 14,
				Struct: "*des.scheme",
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
			if _, err := Salt(test.hash); !testutil.IsEqualError(err, test.err) {
				t.Errorf("Salt() = _, %v; want %v", err, test.err)
			}
		})
	}
}

func TestKey(t *testing.T) {
	tests := []struct {
		salt []byte
		key  string
	}{
		{
			salt: []byte("aa"),
			key:  "jfMKNH1hTm2",
		},
		{
			salt: []byte("ab"),
			key:  "JnggxhB/yWI",
		},
	}
	for _, test := range tests {
		t.Run(string(test.salt), func(t *testing.T) {
			key, err := Key([]byte("password"), test.salt)
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
		err            error
	}{
		{
			password: bytes.Repeat([]byte{'p'}, MaxPasswordLength+1),
			salt:     []byte("aa"),
			err:      InvalidPasswordLengthError(MaxPasswordLength + 1),
		},
		{
			password: []byte("password"),
			salt:     bytes.Repeat([]byte{'a'}, SaltLength+1),
			err:      InvalidSaltLengthError(SaltLength + 1),
		},
		{
			password: []byte("password"),
			salt:     []byte("a@"),
			err:      InvalidSaltError('@'),
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("password=%s;salt=%s", test.password, test.salt), func(t *testing.T) {
			if _, err := Key(test.password, test.salt); !testutil.IsEqualError(err, test.err) {
				t.Errorf("Key() = _, %v; want %v", err, test.err)
			}
		})
	}
}

func TestNewHash(t *testing.T) {
	hash := NewHash("password")
	if err := Check(hash, "password"); err != nil {
		t.Errorf("Check() = %v; want nil", err)
	}
	var schema scheme
	if err := crypthash.Unmarshal(hash, &schema); err != nil {
		t.Fatalf("crypthash.Unmarshal() = %v; want nil", err)
	}
	if diff := cmp.Diff(scheme{HashPrefix: Prefix}, schema, cmp.Comparer(func(x, y scheme) bool {
		return x.HashPrefix == y.HashPrefix
	})); diff != "" {
		t.Errorf("crypthash.Unmarshal() mismatch (-want +got):\n%s", diff)
	}
}
