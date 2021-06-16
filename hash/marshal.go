package hash

import (
	"encoding"
	"reflect"
	"strconv"
	"strings"
)

var textMarshalerType = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()

// UnsupportedTypeError is returned by Marshal when attempting
// to encode an unsupported value type.
type UnsupportedTypeError struct {
	Type   reflect.Type // type of Go value could not be encoded
	Struct string       // name of the struct type containing the field
	Field  string       // the full path to the field
}

func (e *UnsupportedTypeError) Error() string {
	t := "nil"
	if e.Type != nil {
		t = e.Type.String()
	}
	if e.Struct != "" && e.Field != "" {
		return "unsupported type of Go struct field " + e.Struct + "." + e.Field + ": " + t
	}
	return "unsupported type: " + t
}

// UnsupportedValueError is returned by Marshal when attempting
// to encode an unsupported value.
type UnsupportedValueError struct {
	Value  reflect.Value
	Struct string // name of the struct type containing the field
	Field  string // the full path to the field
	Str    string
}

func (e *UnsupportedValueError) Error() string {
	if e.Struct != "" && e.Field != "" {
		return "unsupported value of Go struct field " + e.Struct + "." + e.Field + ": " + e.Str
	}
	return "unsupported value: " + e.Str
}

// Marshal returns the hash of the struct v.
//
// Each exported struct field becomes a fragment of the hash,
// unless the field is omitted for the reason given below.
//
// If the struct has a field named HashPrefix,
// Unmarshal records the hash prefix in that field (only strings are supported).
//
// The encoding of each struct field can be customized by the format string
// stored under the "hash" key in the struct field's tag.
// The format string contains the following comma-separated list of options:
//	omitempty  causes the field to be is omitted if the field value is empty
//	group      marks the field belonging to a param group
//	param:x    marks the field as a key-value param
//	enc:x      sets the encoding of the field (hash, base64 or none)
//	length:x   sets the length of the field value as a string
//	inline     causes the partial usage of the field up to length:x characters
//	base:x     sets the base for integer fields
//
// As a special case, if the field tag is "-", the field is always omitted.
//
// If an encountered value implements the encoding.TextMarshaler interface
// and is not a nil pointer, Marshal calls its MarshalText method.
//
// Otherwise, Marshal can encode the following types:
//	- byte arrays
//	- byte slices
//	- signed or unsigned integers
//	- strings
//
// Anonymous struct fields are marshaled as if their inner exported fields
// were fields in the outer struct, subject to the usual Go visibility rules.
//
// Pointer values encode as the value pointed to.
//
// Interface values encode as the value contained in the interface.
func Marshal(v interface{}) (string, error) {
	val := indirect(reflect.ValueOf(v))
	if !val.IsValid() || val.Kind() != reflect.Struct {
		return "", &UnsupportedTypeError{Type: reflect.TypeOf(v)}
	}
	t := reflect.TypeOf(v)
	info, err := getTypeInfo(t)
	if err != nil {
		return "", err
	}
	var buf strings.Builder
	if info.HashPrefix != nil {
		s, err := marshalValue(t, info.HashPrefix, indirect(val.FieldByIndex(info.HashPrefix.Index)))
		if err != nil {
			return "", err
		}
		buf.WriteString(s)
	}
	var prevFi *fieldInfo
	for _, fi := range info.Fields {
		fv := val.FieldByIndex(fi.Index)
		if fi.Opts.OmitEmpty && isEmpty(fv) {
			continue
		}
		fv = indirect(fv)
		s, err := marshalValue(t, fi, fv)
		if err != nil {
			return "", err
		}
		if prevFi != nil && !prevFi.Opts.Inline {
			if prevFi.Opts.Group && fi.Opts.Group {
				buf.WriteByte(',')
			} else {
				buf.WriteByte('$')
			}
		}
		if fi.Opts.Param != "" {
			buf.WriteString(fi.Opts.Param)
			buf.WriteByte('=')
		}
		buf.WriteString(s)
		prevFi = fi
	}
	return buf.String(), nil
}

func marshalValue(t reflect.Type, fi *fieldInfo, v reflect.Value) (string, error) {
	s, err := marshal(t, fi, v)
	if err != nil {
		return "", err
	}
	if fi.Opts.Length > 0 && len(s) != fi.Opts.Length {
		return "", &UnsupportedValueError{
			Value:  v,
			Struct: t.String(),
			Field:  fi.Name,
			Str:    "length mismatch",
		}
	}
	if fi.Opts.Encoding != nil {
		if i := fi.Opts.Encoding.IndexAnyInvalid([]byte(s)); i >= 0 {
			return "", &UnsupportedValueError{
				Value:  v,
				Struct: t.String(),
				Field:  fi.Name,
				Str:    "invalid character " + strconv.QuoteRuneToASCII(rune(s[i])),
			}
		}
	}
	return s, nil
}

func marshal(t reflect.Type, fi *fieldInfo, v reflect.Value) (string, error) {
	if !v.IsValid() {
		return "", nil
	}
	if v.CanInterface() && v.Type().Implements(textMarshalerType) {
		b, err := v.Interface().(encoding.TextMarshaler).MarshalText()
		if err != nil {
			return "", &UnsupportedValueError{
				Value:  v,
				Struct: t.String(),
				Field:  fi.Name,
				Str:    err.Error(),
			}
		}
		return string(b), nil
	}
	if fi.Opts.Prefix && v.Kind() != reflect.String {
		return "", &UnsupportedTypeError{
			Type:   fi.Type,
			Struct: t.String(),
			Field:  fi.Name,
		}
	}
	switch v.Kind() {
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := make([]byte, v.Len())
			reflect.Copy(reflect.ValueOf(b), v)
			return string(b), nil
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return string(v.Bytes()), nil
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), fi.Opts.Base), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), fi.Opts.Base), nil
	case reflect.String:
		return v.String(), nil
	}
	return "", &UnsupportedTypeError{
		Type:   fi.Type,
		Struct: t.String(),
		Field:  fi.Name,
	}
}

func indirect(v reflect.Value) reflect.Value {
	for {
		if !v.IsValid() {
			return reflect.Value{}
		}
		typ := v.Type()
		switch typ.Kind() {
		case reflect.Interface, reflect.Ptr:
			if v.IsNil() {
				return reflect.Value{}
			}
			v = v.Elem()
		default:
			return v
		}
	}
}

func isEmpty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return false
}
