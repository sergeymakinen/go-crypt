package hash

import (
	"errors"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sergeymakinen/go-crypt/hash/parse"
	"github.com/sergeymakinen/go-crypt/internal/testutil"
)

func BenchmarkUnmarshal(b *testing.B) {
	type hash struct {
		HashPrefix string
		Version    uint8  `hash:"param:v,base:16"`
		M          uint32 `hash:"param:m,group"`
		T          uint32 `hash:"param:t,group"`
		P          uint32 `hash:"param:p,group"`
		Data       string `hash:"param:data,group,omitempty"`
		Salt       string
		Hash       string `hash:"enc:base64"`

		R1     string `hash:"param:r1"`
		O1, O2 string `hash:"omitempty"`
		R2     string
		O3     string `hash:"omitempty"`
		R3     string
		O4     string `hash:"omitempty"`
	}
	data := "$test$v=1A$m=512,t=6235,p=90,data=abc$c29tZXNhbHQ$SqlVijFGiPG+935vDSGEsA$r1=val$o1$o2$r2$o3$r3"
	for i := 0; i < b.N; i++ {
		var h hash
		Unmarshal(data, &h)
	}
}

func TestUnmarshal(t *testing.T) {
	type inline struct {
		S string `hash:"param:s"`
	}
	m1 := testMarshal("$ok$")
	m2 := testMarshal("ok")
	type hash struct {
		HashPrefix string
		Version    uint8  `hash:"param:v,base:16"`
		M          uint32 `hash:"param:m,group"`
		T          uint32 `hash:"param:t,group"`
		P          uint32 `hash:"param:p,group"`
		Data       string `hash:"param:data,group,omitempty"`
		Salt       string
		Hash       string `hash:"enc:base64"`

		R1     string `hash:"param:r1"`
		O1, O2 string `hash:"omitempty"`
		R2     string
		O3     string `hash:"omitempty"`
		R3     string
		O4     string `hash:"omitempty"`
	}
	tests := []struct {
		name, hash string
		v          interface{}
	}{
		{
			name: "field override",
			hash: "s=bar$0",
			v: &struct {
				*inline

				S string `hash:"param:s"`
				I int
			}{
				S: "bar",
			},
		},
		{
			name: "private fields",
			hash: "bar",
			v: &struct {
				S string
				s string
			}{
				S: "bar",
			},
		},
		{
			name: "length derived from array",
			hash: "foo",
			v: &struct {
				S1 [3]byte
			}{S1: [3]byte{'f', 'o', 'o'}},
		},
		{
			name: "number base",
			hash: "10",
			v: &struct {
				S1 int `hash:"base:16"`
			}{S1: 16},
		},
		{
			name: "any character",
			hash: string([]byte{0, 32, 128, 255}),
			v: &struct {
				S1 string `hash:"enc:none"`
			}{S1: string([]byte{0, 32, 128, 255})},
		},
		{
			name: "unmarshaler of hash prefix",
			hash: "$ok$",
			v: &struct {
				HashPrefix testMarshal
			}{HashPrefix: "$ok$"},
		},
		{
			name: "ptr unmarshaler of hash prefix",
			hash: "$ok$",
			v: &struct {
				HashPrefix *testMarshal
			}{HashPrefix: &m1},
		},
		{
			name: "unmarshaler of field",
			hash: "ok",
			v: &struct {
				S testMarshal
			}{S: "ok"},
		},
		{
			name: "ptr unmarshaler of field",
			hash: "ok",
			v: &struct {
				S *testMarshal
			}{S: &m2},
		},
		{
			name: "field types",
			hash: "123$124$foo$bar$baz",
			v: &struct {
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
		},
		{
			name: "omit unsupported struct field when not used",
			hash: "",
			v: &struct {
				B *bool `hash:"omitempty"`
			}{},
		},
		{
			name: "inline fields",
			hash: "foobar",
			v: &struct {
				S1 string `hash:"inline,length:3"`
				S2 string `hash:"length:3"`
			}{
				S1: "foo",
				S2: "bar",
			},
		},
		{
			name: "optional fields",
			hash: "$test$a$b$c",
			v: &struct {
				HashPrefix string
				A          string
				O1         string `hash:"omitempty"`
				O2         string `hash:"omitempty"`
				B          string
				O3         string `hash:"omitempty"`
				C          string
				O4         string `hash:"omitempty"`
				O5         string `hash:"omitempty"`
				O6         string `hash:"omitempty"`
			}{
				HashPrefix: "$test$",
				A:          "a",
				B:          "b",
				C:          "c",
			},
		},
		{
			name: "complex",
			hash: "$test$v=1a$m=512,t=6235,p=90,data=abc$c29tZXNhbHQ$SqlVijFGiPG+935vDSGEsA$r1=val$o1$o2$r2$o3$r3",
			v: &hash{
				HashPrefix: "$test$",
				Version:    26,
				M:          512,
				T:          6235,
				P:          90,
				Data:       "abc",
				Salt:       "c29tZXNhbHQ",
				Hash:       "SqlVijFGiPG+935vDSGEsA",
				R1:         "val",
				O1:         "o1",
				O2:         "o2",
				R2:         "r2",
				O3:         "o3",
				R3:         "r3",
				O4:         "",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			typ := reflect.TypeOf(test.v).Elem()
			v := reflect.New(typ).Interface()
			if err := Unmarshal(test.hash, v); err != nil {
				t.Errorf("Unmarshal() = %v; want nil", err)
			}
			if diff := cmp.Diff(test.v, v, cmp.AllowUnexported(reflect.Zero(typ).Interface(), inline{})); diff != "" {
				t.Errorf("Unmarshal() mismatch (-want +got):\n%s", diff)
			}
			s, err := Marshal(test.v)
			if err != nil {
				t.Errorf("Marshal() = _, %v; want nil", err)
			}
			if s != test.hash {
				t.Errorf("Marshal() = %q, _; want %q", s, test.hash)
			}
		})
	}
}

var invalidTags = []struct {
	name string
	v    interface{}
	err  error
}{
	{
		name: "duplicated param name",
		v: &struct {
			S1 string `hash:"param:x"`
			S2 string `hash:"param:x"`
		}{},
		err: &TagParamError{
			Field1: "S2",
			Field2: "S1",
			Tag1:   "param:x",
			Tag2:   "param:x",
		},
	},
	{
		name: "inline with omit empty",
		v: &struct {
			S1 string `hash:"omitempty,inline"`
		}{},
		err: errors.New(`invalid tag in field *struct { S1 string "hash:\"omitempty,inline\"" }.S1: "omitempty,inline"`),
	},
	{
		name: "group without param",
		v: &struct {
			S1 string `hash:"group"`
		}{},
		err: errors.New(`invalid tag in field *struct { S1 string "hash:\"group\"" }.S1: "group"`),
	},
	{
		name: "param with hash prefix",
		v: &struct {
			HashPrefix string `hash:"param:x"`
		}{},
		err: errors.New(`invalid tag in field *struct { HashPrefix string "hash:\"param:x\"" }.HashPrefix: "param:x"`),
	},
	{
		name: "inline with hash prefix",
		v: &struct {
			HashPrefix string `hash:"inline"`
		}{},
		err: errors.New(`invalid tag in field *struct { HashPrefix string "hash:\"inline\"" }.HashPrefix: "inline"`),
	},
	{
		name: "inline without length",
		v: &struct {
			S1 string `hash:"inline"`
		}{},
		err: errors.New(`invalid tag in field *struct { S1 string "hash:\"inline\"" }.S1: "inline"`),
	},
	{
		name: "inline without length (type reporting)",
		v: &struct {
			S1 *string `hash:"inline"`
		}{},
		err: errors.New(`invalid tag in field *struct { S1 *string "hash:\"inline\"" }.S1: "inline"`),
	},
}

func TestUnmarshalShouldFail(t *testing.T) {
	b := true
	tests := []struct {
		name, hash string
		v          interface{}
		err        error
	}{
		{
			name: "nil",
			v:    nil,
			err:  &InvalidUnmarshalError{},
		},
		{
			name: "non-ptr",
			v:    true,
			err:  &InvalidUnmarshalError{},
		},
		{
			name: "non-struct",
			v:    &b,
			err:  &InvalidUnmarshalError{},
		},
		{
			name: "invalid hash",
			hash: "$foo",
			v: &struct {
				S string
			}{},
			err: &parse.SyntaxError{
				Offset: 4,
				Msg:    "missing prefix end",
			},
		},
		{
			name: "missing hash prefix",
			hash: "foo",
			v: &struct {
				HashPrefix string
			}{},
			err: &UnmarshalTypeError{
				Value:  "EOF",
				Offset: 3,
				Field:  "HashPrefix",
				Msg:    "prefix not found",
			},
		},
		{
			name: "invalid hash prefix",
			hash: "$foo$bar",
			v: &struct {
				HashPrefix string `hash:"length:10"`
				S          string
			}{},
			err: &UnmarshalTypeError{
				Value:  "prefix",
				Offset: 5,
				Field:  "HashPrefix",
				Msg:    "length mismatch",
			},
		},
		{
			name: "excessive fragment",
			hash: "foo$bar",
			v: &struct {
				S string
			}{},
			err: &UnmarshalTypeError{
				Value:  "value",
				Offset: 7,
				Msg:    "excessive fragment",
			},
		},
		{
			name: "unexpected EOF",
			hash: "foo$bar",
			v: &struct {
				S1, S2, S3 string
			}{},
			err: &UnmarshalTypeError{
				Value:  "EOF",
				Offset: 7,
				Field:  "S3",
				Msg:    "unexpected EOF",
			},
		},
		{
			name: "missing param",
			hash: "foo$bar",
			v: &struct {
				S string `hash:"param:x"`
			}{},
			err: &UnmarshalTypeError{
				Value:  "value",
				Offset: 3,
				Field:  "S",
				Msg:    "param not found",
			},
		},
		{
			name: "missing param in group",
			hash: "foo=bar,y=baz",
			v: &struct {
				S1 string `hash:"param:x,group"`
				S2 string `hash:"param:y,group"`
			}{},
			err: &UnmarshalTypeError{
				Value:  "group",
				Offset: 13,
				Field:  "S1",
				Msg:    "grouped param not found",
			},
		},
		{
			name: "excessive param in group",
			hash: "x=bar,y=baz,z=foo",
			v: &struct {
				S1 string `hash:"param:x,group"`
				S2 string `hash:"param:y,group"`
			}{},
			err: &UnmarshalTypeError{
				Value:  "group",
				Offset: 17,
				Msg:    "excessive fragment",
			},
		},
		{
			name: "missing group",
			hash: "foo$bar",
			v: &struct {
				S1 string `hash:"param:x,group"`
				S2 string `hash:"param:y,group"`
			}{},
			err: &UnmarshalTypeError{
				Value:  "value",
				Offset: 3,
				Field:  "S1",
				Msg:    "grouped param not found",
			},
		},
		{
			name: "group not end",
			hash: "x=foo,y=bar,z=baz",
			v: &struct {
				S1 string `hash:"param:x,group"`
				S2 string `hash:"param:y,group"`
				S3 string
			}{},
			err: &UnmarshalTypeError{
				Value:  "group",
				Offset: 17,
				Field:  "S3",
				Msg:    "excessive fragment",
			},
		},
		{
			name: "length mismatch",
			hash: "foo",
			v: &struct {
				S1 string `hash:"length:10"`
			}{},
			err: &UnmarshalTypeError{
				Value:  "value",
				Offset: 3,
				Field:  "S1",
				Msg:    "length mismatch",
			},
		},
		{
			name: "length derived from array mismatch",
			hash: "foo",
			v: &struct {
				S1 [1]byte
			}{},
			err: &UnmarshalTypeError{
				Value:  "value",
				Offset: 3,
				Field:  "S1",
				Msg:    "length mismatch",
			},
		},
		{
			name: "inline length mismatch",
			hash: "foo",
			v: &struct {
				S1 string `hash:"length:10,inline"`
				S2 string
			}{},
			err: &UnmarshalTypeError{
				Value:  "value",
				Offset: 3,
				Field:  "S1",
				Msg:    "length mismatch",
			},
		},
		{
			name: "invalid character in value",
			hash: "!@#",
			v: &struct {
				S1 string `hash:"enc:base64"`
			}{},
			err: &UnmarshalTypeError{
				Value:  "value",
				Offset: 3,
				Field:  "S1",
				Msg:    "invalid character '!'",
			},
		},
		{
			name: "invalid character in param",
			hash: "foo$x=!@#",
			v: &struct {
				S1 string
				S2 string `hash:"param:x,enc:base64"`
			}{},
			err: &UnmarshalTypeError{
				Value:  "value",
				Offset: 9,
				Field:  "S2",
				Msg:    "invalid character '!'",
			},
		},
		{
			name: "invalid character in grouped param",
			hash: "foo$x=!@#$baz1$baz2",
			v: &struct {
				S1 string
				S2 string `hash:"param:x,group,enc:base64"`
				S3 string
				S4 string
			}{},
			err: &UnmarshalTypeError{
				Value:  "value",
				Offset: 9,
				Field:  "S2",
				Msg:    "invalid character '!'",
			},
		},
		{
			name: "errored marshaler",
			hash: "error",
			v: &struct {
				M testMarshal
			}{},
			err: &UnmarshalTypeError{
				Value:  "value",
				Offset: 5,
				Field:  "M",
				Msg:    "error",
			},
		},
		{
			name: "unsupported hash prefix type",
			hash: "$foo$",
			v: &struct {
				HashPrefix int
			}{},
			err: &UnmarshalTypeError{
				Value:  "prefix",
				Offset: 5,
				Field:  "HashPrefix",
				Msg:    "unsupported type",
			},
		},
		{
			name: "unsupported field type",
			hash: "foo",
			v: &struct {
				B bool
			}{},
			err: &UnmarshalTypeError{
				Value:  "value",
				Offset: 3,
				Field:  "B",
				Msg:    "unsupported type",
			},
		},
		{
			name: "unsupported field type (error message)",
			hash: "foo",
			v: &struct {
				B *bool
			}{},
			err: &UnmarshalTypeError{
				Value:  "value",
				Offset: 3,
				Field:  "B",
				Msg:    "unsupported type",
			},
		},
		{
			name: "invalid int",
			hash: "abc",
			v: &struct {
				S1 int
			}{},
			err: &UnmarshalTypeError{
				Value:  "value",
				Offset: 3,
				Field:  "S1",
				Msg:    `strconv.ParseInt: parsing "abc": invalid syntax`,
			},
		},
		{
			name: "invalid uint",
			hash: "abc",
			v: &struct {
				S1 uint
			}{},
			err: &UnmarshalTypeError{
				Value:  "value",
				Offset: 3,
				Field:  "S1",
				Msg:    `strconv.ParseUint: parsing "abc": invalid syntax`,
			},
		},
	}
	for _, test := range invalidTags {
		v := test.v
		tests = append(tests, struct {
			name, hash string
			v          interface{}
			err        error
		}{
			name: test.name,
			hash: "",
			v:    v,
			err:  test.err,
		})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			switch err := test.err.(type) {
			case *InvalidUnmarshalError:
				if err.Type == nil {
					err.Type = reflect.TypeOf(test.v)
				}
			case *UnmarshalTypeError:
				if err.Struct == "" && err.Field != "" {
					err.Struct = reflect.TypeOf(test.v).String()
				}
				if err.Struct != "" {
					err.Type = testutil.FieldType(test.v, err.Field)
				} else {
					err.Type = reflect.TypeOf(test.v)
				}
			}
			if err := Unmarshal(test.hash, test.v); !testutil.IsEqualError(err, test.err) {
				t.Errorf("Unmarshal() = %v; want %v", err, test.err)
			}
		})
	}
}
