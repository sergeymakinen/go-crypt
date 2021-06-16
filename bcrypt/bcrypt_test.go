package bcrypt

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/internal/testutil"
)

func TestParse(t *testing.T) {
	tests := []struct {
		hash     string
		password string
		salt     []byte
		cost     uint8
		opts     *CompatibilityOptions
	}{
		// Passlib
		{
			hash:     "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
			password: "U*U",
			salt:     []byte("CCCCCCCCCCCCCCCCCCCCC."),
			cost:     5,
			opts:     &CompatibilityOptions{Prefix: Prefix2a},
		},
		{
			hash:     "$2a$05$Otz9agnajgrAe0.kFVF9V.tzaStZ2s1s4ZWi/LY4sw2k/MTVFj/IO",
			password: "",
			salt:     []byte("Otz9agnajgrAe0.kFVF9V."),
			cost:     5,
			opts:     &CompatibilityOptions{Prefix: Prefix2a},
		},
		{
			hash:     "$2b$05$6bNw2HLQYeqHYyBfLMsv/OUcZd0LKP39b87nBw3.S2tVZSqiQX6eu",
			password: "\xD1\x91",
			salt:     []byte("6bNw2HLQYeqHYyBfLMsv/O"),
			cost:     5,
			opts:     &CompatibilityOptions{Prefix: Prefix2b},
		},
		{
			hash:     "$2a$04$R1lJ2gkNaoPGdafE.H.16.nVyh2niHsGJhayOHLMiXlI45o8/DU.6",
			password: strings.Repeat("0123456789", 26)[:254],
			salt:     []byte("R1lJ2gkNaoPGdafE.H.16."),
			cost:     4,
			opts:     &CompatibilityOptions{Prefix: Prefix2a},
		},
		{
			hash:     "$2a$04$R1lJ2gkNaoPGdafE.H.16.nVyh2niHsGJhayOHLMiXlI45o8/DU.6",
			password: strings.Repeat("0123456789", 26)[:255],
			salt:     []byte("R1lJ2gkNaoPGdafE.H.16."),
			cost:     4,
			opts:     &CompatibilityOptions{Prefix: Prefix2a},
		},
		{
			hash:     "$2a$04$R1lJ2gkNaoPGdafE.H.16.nVyh2niHsGJhayOHLMiXlI45o8/DU.6",
			password: strings.Repeat("0123456789", 26)[:256],
			salt:     []byte("R1lJ2gkNaoPGdafE.H.16."),
			cost:     4,
			opts:     &CompatibilityOptions{Prefix: Prefix2a},
		},
		{
			hash:     "$2a$04$R1lJ2gkNaoPGdafE.H.16.nVyh2niHsGJhayOHLMiXlI45o8/DU.6",
			password: strings.Repeat("0123456789", 26)[:257],
			salt:     []byte("R1lJ2gkNaoPGdafE.H.16."),
			cost:     4,
			opts:     &CompatibilityOptions{Prefix: Prefix2a},
		},
		{
			hash:     "$2$05$......................XuQjdH.wPVNUZ/bOfstdW/FqB8QSjte",
			password: "abc",
			salt:     []byte("......................"),
			cost:     5,
			opts:     &CompatibilityOptions{Prefix: Prefix2},
		},
		{
			hash:     "$2a$05$......................ev6gDwpVye3oMCUpLY85aTpfBNHD0Ga",
			password: "abc",
			salt:     []byte("......................"),
			cost:     5,
			opts:     &CompatibilityOptions{Prefix: Prefix2a},
		},

		// Other
		{
			hash:     "$2$10$aaaaaaaaaaaaaaaaaaaaa.wO.4ZI1cRE8ywyGfFyb.ruFKsqhl76W",
			password: "password",
			salt:     []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost:     10,
			opts:     &CompatibilityOptions{Prefix: Prefix2},
		},
		{
			hash:     "$2a$10$aaaaaaaaaaaaaaaaaaaaa.YyEInewbeNaLexYUjbnHaAt0H.Fq.Gi",
			password: "password",
			salt:     []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost:     10,
			opts:     &CompatibilityOptions{Prefix: Prefix2a},
		},
		{
			hash:     "$2b$10$aaaaaaaaaaaaaaaaaaaaa.YyEInewbeNaLexYUjbnHaAt0H.Fq.Gi",
			password: "password",
			salt:     []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost:     10,
			opts:     &CompatibilityOptions{Prefix: Prefix2b},
		},
		{
			hash:     "$2b$10$aaaaaaaaaaaaaaaaaaaaa.1Bx7.YgIFrRP5EQeMrjVPZ9VfOJzLvu",
			password: strings.Repeat("p", 72),
			salt:     []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost:     10,
			opts:     &CompatibilityOptions{Prefix: Prefix2b},
		},
		{
			hash:     "$2b$10$aaaaaaaaaaaaaaaaaaaaa.1Bx7.YgIFrRP5EQeMrjVPZ9VfOJzLvu",
			password: strings.Repeat("p", 254),
			salt:     []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost:     10,
			opts:     &CompatibilityOptions{Prefix: Prefix2b},
		},
		{
			hash:     "$2a$10$aaaaaaaaaaaaaaaaaaaaa.i7xIT/FobtzNkJzuI.imEyRZ5FbZHBe",
			password: strings.Repeat("p", 254),
			salt:     []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost:     10,
			opts:     &CompatibilityOptions{Prefix: Prefix2a},
		},
		{
			hash:     "$2$10$aaaaaaaaaaaaaaaaaaaaa.i7xIT/FobtzNkJzuI.imEyRZ5FbZHBe",
			password: strings.Repeat("p", 254),
			salt:     []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost:     10,
			opts:     &CompatibilityOptions{Prefix: Prefix2},
		},
	}
	for _, test := range tests {
		t.Run(test.hash, func(t *testing.T) {
			if err := Check(test.hash, test.password); err != nil {
				t.Errorf("Check() = %v; want nil", err)
			}
			salt, cost, opts, err := Params(test.hash)
			if err != nil {
				t.Fatalf("Params() = _, _, _, %v; want nil", err)
			}
			if !bytes.Equal(salt, test.salt) {
				t.Errorf("Params() = %v, _, _, _; want %v", salt, test.salt)
			}
			if cost != test.cost {
				t.Errorf("Params() = _, %d, _, _; want %d", cost, test.cost)
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
				Struct: "*bcrypt.scheme",
				Field:  "HashPrefix",
				Msg:    "prefix not found",
			},
		},
		{
			hash: "$2b@$10$UVjcf7m8L91VOpIRwEprguF4o9Inqj7aNhqvSzUElX4GWGyIkYLuG",
			err: &crypthash.UnmarshalTypeError{
				Value:  "prefix",
				Type:   testutil.FieldType(scheme{}, "HashPrefix"),
				Offset: 5,
				Struct: "*bcrypt.scheme",
				Field:  "HashPrefix",
				Msg:    `unsupported prefix "$2b@$"`,
			},
		},
		{
			hash: "$2b$1@$UVjcf7m8L91VOpIRwEprguF4o9Inqj7aNhqvSzUElX4GWGyIkYLuG",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Cost"),
				Offset: 6,
				Struct: "*bcrypt.scheme",
				Field:  "Cost",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$2b$10$UVjcf7m8L91VOpIRwEprg@F4o9Inqj7aNhqvSzUElX4GWGyIkYLuG",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Salt"),
				Offset: 60,
				Struct: "*bcrypt.scheme",
				Field:  "Salt",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$2b$10$UVjcf7m8L91VOpIRwEprguF4o9Inqj7aNhqvSzUElX4GWGyIkYLu@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 60,
				Struct: "*bcrypt.scheme",
				Field:  "Sum",
				Msg:    "invalid character '@'",
			},
		},
		{
			hash: "$2b$10$UVjcf7m8L91VOpIRwEprguF4o9Inqj7aNhqvSzUElX4GWGyIkYLuG@",
			err: &crypthash.UnmarshalTypeError{
				Value:  "value",
				Type:   testutil.FieldType(scheme{}, "Sum"),
				Offset: 61,
				Struct: "*bcrypt.scheme",
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
		salt []byte
		cost uint8
		opts *CompatibilityOptions
		key  string
	}{
		{
			salt: []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost: DefaultCost,
			opts: nil,
			key:  "OUGthP2850D.9QZX0BwzLEsRFxcALs1",
		},
		{
			salt: []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost: 10,
			opts: nil,
			key:  "f3YWamEb.ST11OXZJeRGkhWxY2.v.Y6",
		},
		{
			salt: []byte("aaaaaaaaaaaaaaaaaaaab."),
			cost: 10,
			opts: nil,
			key:  "Nm99MAAhNATMWF2alwaLO7OLJrWJII4",
		},
		{
			salt: []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost: 11,
			opts: nil,
			key:  "XM6KlyIdTxvLUn0gSVTCrbsUtG5OfT1",
		},
		{
			salt: []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost: 10,
			opts: &CompatibilityOptions{Prefix: Prefix2},
			key:  "71UCgperAx4h99I6TQ2Er4.nuWwtrPA",
		},
		{
			salt: []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost: 10,
			opts: &CompatibilityOptions{Prefix: Prefix2a},
			key:  "f3YWamEb.ST11OXZJeRGkhWxY2.v.Y6",
		},
		{
			salt: []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost: 10,
			opts: &CompatibilityOptions{Prefix: Prefix2b},
			key:  "f3YWamEb.ST11OXZJeRGkhWxY2.v.Y6",
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("salt=%s;cost=%d;opts=%v", test.salt, test.cost, test.opts), func(t *testing.T) {
			key, err := Key([]byte("password"), test.salt, test.cost, test.opts)
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
		cost           uint8
		opts           *CompatibilityOptions
		err            error
	}{
		{
			password: nil,
			salt:     []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost:     10,
			opts:     &CompatibilityOptions{Prefix: Prefix2},
			err:      errors.New("failed to create blowfish cipher: crypto/blowfish: invalid key size 0"),
		},
		{
			password: []byte("password"),
			salt:     bytes.Repeat([]byte{'a'}, SaltLength+1),
			cost:     10,
			opts:     nil,
			err:      InvalidSaltLengthError(SaltLength + 1),
		},
		{
			password: []byte("password"),
			salt:     []byte("aaaaaaaaaaaaaaaaaaaaa@"),
			cost:     10,
			opts:     nil,
			err:      InvalidSaltError('@'),
		},
		{
			password: []byte("password"),
			salt:     []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost:     MaxCost + 1,
			opts:     nil,
			err:      InvalidCostError(MaxCost + 1),
		},
		{
			password: []byte("password"),
			salt:     []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost:     MinCost - 1,
			opts:     nil,
			err:      InvalidCostError(MinCost - 1),
		},
		{
			password: []byte("password"),
			salt:     []byte("aaaaaaaaaaaaaaaaaaaaa."),
			cost:     10,
			opts:     &CompatibilityOptions{Prefix: "aaa"},
			err:      UnsupportedPrefixError("aaa"),
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("password=%s;salt=%s;cost=%d;opts=%v", test.password, test.salt, test.cost, test.opts), func(t *testing.T) {
			if _, err := Key(test.password, test.salt, test.cost, test.opts); !testutil.IsEqualError(err, test.err) {
				t.Errorf("Key() = _, %v; want %v", err, test.err)
			}
		})
	}
}

func TestNewHash(t *testing.T) {
	tests := []struct {
		password string
		cost     uint8
		scheme   scheme
	}{
		{
			password: "password",
			cost:     DefaultCost,
			scheme: scheme{
				HashPrefix: Prefix2b,
				Cost:       DefaultCost,
			},
		},
		{
			password: "password",
			cost:     10,
			scheme: scheme{
				HashPrefix: Prefix2b,
				Cost:       10,
			},
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("password=%s;cost=%d", test.password, test.cost), func(t *testing.T) {
			hash, err := NewHash(test.password, test.cost)
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
				return x.HashPrefix == y.HashPrefix && x.Cost == y.Cost
			})); diff != "" {
				t.Errorf("crypthash.Unmarshal() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
