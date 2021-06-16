package hash

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sergeymakinen/go-crypt/internal/testutil"
)

type testMarshal string

func (m testMarshal) MarshalText() (text []byte, err error) {
	text = []byte(m)
	if m != "ok" && m != "$ok$" {
		err = errors.New(string(m))
	}
	return
}

func (m *testMarshal) UnmarshalText(text []byte) error {
	*m = testMarshal(text)
	if bytes.Equal(text, []byte("ok")) || bytes.Equal(text, []byte("$ok$")) {
		return nil
	}
	return errors.New(string(text))
}

func TestMarshal(t *testing.T) {
	type inline struct {
		S string `hash:"param:s"`
	}
	m1 := testMarshal("$ok$")
	m2 := testMarshal("ok")
	tests := []struct {
		name          string
		v             interface{}
		s             string
		skipUnmarshal bool
	}{
		{
			name: "field override",
			v: struct {
				*inline

				S string `hash:"param:s"`
				I int
			}{
				inline: &inline{S: "foo"},
				S:      "bar",
			},
			s:             "s=bar$0",
			skipUnmarshal: true,
		},
		{
			name: "private fields",
			v: struct {
				S string
				s string
			}{
				S: "bar",
				s: "foo",
			},
			s:             "bar",
			skipUnmarshal: true,
		},
		{
			name: "length derived from array",
			v: struct {
				S1 [1]byte
			}{S1: [1]byte{'f'}},
			s: "f",
		},
		{
			name: "number base",
			v: struct {
				S1 int `hash:"base:16"`
			}{S1: 16},
			s: "10",
		},
		{
			name: "any character",
			v: struct {
				S1 string `hash:"enc:none"`
			}{S1: string([]byte{0, 32, 128, 255})},
			s: string([]byte{0, 32, 128, 255}),
		},
		{
			name: "marshaler of hash prefix",
			v: struct {
				HashPrefix testMarshal
			}{HashPrefix: "$ok$"},
			s: "$ok$",
		},
		{
			name: "ptr marshaler of hash prefix",
			v: struct {
				HashPrefix *testMarshal
			}{HashPrefix: &m1},
			s: "$ok$",
		},
		{
			name: "marshaler of field",
			v: struct {
				S testMarshal
			}{S: "ok"},
			s: "ok",
		},
		{
			name: "ptr marshaler of field",
			v: struct {
				S *testMarshal
			}{S: &m2},
			s: "ok",
		},
		{
			name: "field types",
			v: struct {
				I  int
				U  uint
				S  string
				B  [3]byte
				Sl []byte
			}{
				I:  123,
				U:  124,
				S:  "foo",
				B:  [3]byte{'b', 'a', 'r'},
				Sl: []byte("baz"),
			},
			s: "123$124$foo$bar$baz",
		},
		{
			name: "omit empty",
			v: struct {
				I  int
				U  uint
				S  string
				B  [3]byte
				Sl []byte

				EI  int     `hash:"omitempty"`
				EU  uint    `hash:"omitempty"`
				ES  string  `hash:"omitempty"`
				EB  [3]byte `hash:"omitempty"`
				ESl []byte  `hash:"omitempty"`
			}{
				B:  [3]byte{'f', 'o', 'o'},
				Sl: []byte{},
				EB: [3]byte{'b', 'a', 'r'},
			},
			s:             "0$0$$foo$$bar",
			skipUnmarshal: true,
		},
		{
			name: "omit unsupported struct field when nil",
			v: struct {
				B *bool `hash:"omitempty"`
			}{},
			s: "",
		},
		{
			name: "single param in group",
			v: struct {
				S1 string
				S2 string `hash:"param:x,group"`
				S3 string
				S4 string
			}{
				S1: "foo",
				S2: "bar",
				S3: "baz1",
				S4: "baz2",
			},
			s: "foo$x=bar$baz1$baz2",
		},
		{
			name: "inline fields",
			v: struct {
				S1 string `hash:"inline,length:3"`
				S2 string `hash:"length:3"`
			}{
				S1: "foo",
				S2: "bar",
			},
			s: "foobar",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := Marshal(test.v)
			if err != nil {
				t.Errorf("Marshal() = _, %v; want nil", err)
			}
			if s != test.s {
				t.Errorf("Marshal() = %q, _; want %q", s, test.s)
			}
			if test.skipUnmarshal {
				return
			}
			typ := reflect.TypeOf(test.v)
			if typ.Kind() == reflect.Ptr {
				typ = typ.Elem()
			}
			v := reflect.New(typ).Interface()
			if err := Unmarshal(s, v); err != nil {
				t.Errorf("Unmarshal() = %v; want nil", err)
			}
			if diff := cmp.Diff(test.v, reflect.ValueOf(v).Elem().Interface(), cmp.AllowUnexported(reflect.Zero(typ).Interface())); diff != "" {
				t.Errorf("Unmarshal() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMarshalShouldFail(t *testing.T) {
	b := true
	tests := []struct {
		name string
		v    interface{}
		err  error
	}{
		{
			name: "nil",
			v:    nil,
			err:  &UnsupportedTypeError{},
		},
		{
			name: "non-struct",
			v:    true,
			err:  &UnsupportedTypeError{},
		},
		{
			name: "unsupported hash prefix type",
			v: struct {
				HashPrefix int
			}{},
			err: &UnsupportedTypeError{Field: "HashPrefix"},
		},
		{
			name: "unsupported field type",
			v: struct {
				B bool
			}{},
			err: &UnsupportedTypeError{Field: "B"},
		},
		{
			name: "unsupported field type (error message)",
			v: &struct {
				B *bool
			}{B: &b},
			err: &UnsupportedTypeError{Field: "B"},
		},
		{
			name: "length mismatch",
			v: struct {
				S1 string `hash:"length:1"`
			}{S1: "foo"},
			err: &UnsupportedValueError{
				Field: "S1",
				Str:   "length mismatch",
			},
		},
		{
			name: "invalid character",
			v: struct {
				S1 string `hash:"enc:base64"`
			}{S1: "!@#"},
			err: &UnsupportedValueError{
				Field: "S1",
				Str:   "invalid character '!'",
			},
		},
		{
			name: "errored marshaler of hash prefix",
			v: struct {
				HashPrefix testMarshal
			}{HashPrefix: "error"},
			err: &UnsupportedValueError{
				Field: "HashPrefix",
				Str:   "error",
			},
		},
		{
			name: "errored marshaler of field",
			v: struct {
				M testMarshal
			}{M: "error"},
			err: &UnsupportedValueError{
				Field: "M",
				Str:   "error",
			},
		},
	}
	for _, test := range invalidTags {
		tests = append(tests, test)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			switch err := test.err.(type) {
			case *UnsupportedTypeError:
				if err.Type == nil {
					if err.Struct == "" && err.Field != "" {
						err.Struct = reflect.TypeOf(test.v).String()
					}
					if err.Struct != "" {
						err.Type = testutil.FieldType(test.v, err.Field)
					} else {
						err.Type = reflect.TypeOf(test.v)
					}
				}
			case *TagParamError:
				if err.Struct == nil {
					err.Struct = reflect.TypeOf(test.v)
				}
			case *UnsupportedValueError:
				if err.Struct == "" && err.Field != "" {
					err.Struct = reflect.TypeOf(test.v).String()
				}
				if err.Struct != "" {
					err.Value = indirect(reflect.ValueOf(test.v)).FieldByName(err.Field)
				} else {
					err.Value = reflect.ValueOf(test.v)
				}
			}
			if _, err := Marshal(test.v); !testutil.IsEqualError(err, test.err) {
				t.Errorf("Marshal() = _, %v; want %v", err, test.err)
			}
		})
	}
}
