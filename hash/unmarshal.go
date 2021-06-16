package hash

import (
	"encoding"
	"reflect"
	"strconv"
	"strings"

	"github.com/sergeymakinen/go-crypt/hash/parse"
)

var textUnmarshalerType = reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()

// UnmarshalTypeError describes a value that was
// not appropriate for a value of a specific Go type.
type UnmarshalTypeError struct {
	Value  string       // description of value - "EOF", "prefix", "group", "value"
	Type   reflect.Type // type of Go value it could not be assigned to
	Offset int          // error occurred after reading Offset bytes
	Struct string       // name of the struct type containing the field
	Field  string       // the full path to the field
	Msg    string       // description of error
}

func (e *UnmarshalTypeError) Error() string {
	if e.Struct != "" && e.Field != "" {
		return "cannot unmarshal " + e.Value + " into Go struct field " + e.Struct + "." + e.Field + " of type " + e.Type.String() + ": " + e.Msg
	}
	return "cannot unmarshal " + e.Value + " into Go value of type " + e.Type.String() + ": " + e.Msg
}

// InvalidUnmarshalError describes an invalid argument passed to Unmarshal.
// (The argument to Unmarshal must be a non-nil struct pointer.)
type InvalidUnmarshalError struct {
	Type reflect.Type
}

func (e *InvalidUnmarshalError) Error() string {
	if e.Type == nil {
		return "Unmarshal(nil)"
	}
	if e.Type.Kind() != reflect.Ptr {
		return "Unmarshal(non-pointer " + e.Type.String() + ")"
	}
	if e.Type.Kind() != reflect.Struct {
		return "Unmarshal(" + e.Type.String() + ")"
	}
	return "Unmarshal(nil " + e.Type.String() + ")"
}

// Unmarshal parses the hash and stores the result
// in the value pointed to by v. If v is nil or not a pointer,
// or not a struct, Unmarshal returns an error.
//
// Unmarshal uses the inverse of the rules that
// Marshal uses, allocating pointers as necessary.
//
// To unmarshal data into a pointer, Unmarshal unmarshals data into
// the value pointed at by the pointer. If the pointer is nil, Unmarshal
// allocates a new value for it to point to
func Unmarshal(hash string, v interface{}) error {
	val := reflect.ValueOf(v)
	if val.Kind() != reflect.Ptr || val.IsNil() {
		return &InvalidUnmarshalError{reflect.TypeOf(v)}
	}
	val = unmarshalIndirect(val)
	if val.Kind() != reflect.Struct {
		return &InvalidUnmarshalError{reflect.TypeOf(v)}
	}
	tree, err := parse.Parse(hash)
	if err != nil {
		return err
	}
	ti, err := getTypeInfo(reflect.TypeOf(v))
	if err != nil {
		return err
	}
	var (
		fragIdx, numGroupValues int
		group                   *parse.GroupNode
	)
	numValues := len(tree.Fragments)
	numReqValues := ti.NumReqValues
	if ti.HashPrefix != nil {
		// Prefix
		if tree.Prefix != nil {
			if err := unmarshal(tree.Prefix, ti, ti.HashPrefix, unmarshalIndirect(val.FieldByIndex(ti.HashPrefix.Index))); err != nil {
				return err
			}
		} else if !ti.HashPrefix.Opts.OmitEmpty {
			return &UnmarshalTypeError{
				Value:  "EOF",
				Type:   ti.HashPrefix.Type,
				Offset: len(hash),
				Struct: ti.Struct.String(),
				Field:  ti.HashPrefix.Name,
				Msg:    "prefix not found",
			}
		}
	}
	for _, fi := range ti.Fields {
		if !fi.Opts.Group && group != nil {
			// End of group
			if numGroupValues > 0 {
				return newUnmarshalError(group, ti, fi, "excessive fragment")
			}
			fragIdx++
			group = nil
		}
		if fragIdx >= len(tree.Fragments) {
			// No more fragments
			if fi.Opts.OmitEmpty {
				continue
			}
			return &UnmarshalTypeError{
				Value:  "EOF",
				Type:   fi.Type,
				Offset: len(hash),
				Struct: ti.Struct.String(),
				Field:  fi.Name,
				Msg:    "unexpected EOF",
			}
		}
		if fi.Opts.OmitEmpty && group == nil && numValues-numReqValues <= 0 {
			// Skip optional value if there are more values needed
			numValues--
			continue
		}
		frag := tree.Fragments[fragIdx]
		switch {
		case fi.Opts.Group && (frag.Type() == parse.NodeGroup || (frag.Type() == parse.NodeValue && !fi.Opts.OmitEmpty)):
			switch frag.Type() {
			case parse.NodeGroup:
				// Param group
				if group == nil {
					group = frag.(*parse.GroupNode)
					numGroupValues = len(group.Values)
				}
			case parse.NodeValue:
				// Single value is consumed when a grouped param is required
				group = &parse.GroupNode{Values: []*parse.ValueNode{frag.(*parse.ValueNode)}}
				numGroupValues = 1
			}
			match := false
			for _, value := range group.Values {
				if strings.HasPrefix(value.Value, fi.Opts.Param+"=") {
					if err := unmarshal(value, ti, fi, unmarshalIndirect(val.FieldByIndex(fi.Index))); err != nil {
						return err
					}
					numGroupValues--
					match = true
					break
				}
			}
			if !match && !fi.Opts.OmitEmpty {
				return newUnmarshalError(frag, ti, fi, fi.String()+" not found")
			}
		case !fi.Opts.Group && frag.Type() == parse.NodeValue:
			switch {
			case fi.Opts.Param != "" && strings.HasPrefix(frag.String(), fi.Opts.Param), fi.Opts.Param == "":
				// Param/value
				if err := unmarshal(frag, ti, fi, unmarshalIndirect(val.FieldByIndex(fi.Index))); err != nil {
					return err
				}
				numValues--
				if !fi.Opts.OmitEmpty {
					numReqValues--
				}
				if !fi.Opts.Inline {
					fragIdx++
				}
			case fi.Opts.OmitEmpty:
				continue
			default:
				return newUnmarshalError(frag, ti, fi, fi.String()+" not found")
			}
		case fi.Opts.OmitEmpty:
			continue
		default:
			return newUnmarshalError(frag, ti, fi, fi.String()+" not found")
		}
	}
	if group != nil {
		if numGroupValues > 0 {
			return &UnmarshalTypeError{
				Value:  group.Type().String(),
				Type:   reflect.TypeOf(v),
				Offset: int(group.End()),
				Msg:    "excessive fragment",
			}
		}
		fragIdx++
	}
	if fragIdx < len(tree.Fragments) {
		return &UnmarshalTypeError{
			Value:  tree.Fragments[fragIdx].Type().String(),
			Type:   reflect.TypeOf(v),
			Offset: int(tree.Fragments[fragIdx].End()),
			Msg:    "excessive fragment",
		}
	}
	return nil
}

func unmarshal(node parse.Node, ti *typeInfo, fi *fieldInfo, v reflect.Value) error {
	s := node.String()
	if fi.Opts.Param != "" {
		s = strings.TrimPrefix(s, fi.Opts.Param+"=")
	}
	if fi.Opts.Length > 0 {
		if fi.Opts.Inline {
			if len(s) < fi.Opts.Length {
				return newUnmarshalError(node, ti, fi, "length mismatch")
			}
			val := node.(*parse.ValueNode)
			s = val.Value[:fi.Opts.Length]
			defer func() {
				val.Value = val.Value[fi.Opts.Length:]
			}()
		} else if len(s) != fi.Opts.Length {
			return newUnmarshalError(node, ti, fi, "length mismatch")
		}
	}
	if fi.Opts.Encoding != nil {
		if i := fi.Opts.Encoding.IndexAnyInvalid([]byte(s)); i >= 0 {
			return newUnmarshalError(node, ti, fi, "invalid character "+strconv.QuoteRuneToASCII(rune(s[i])))
		}
	}
	ft := indirectType(fi.Type)
	if v.CanInterface() && ft.Implements(textUnmarshalerType) {
		if err := v.Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte(s)); err != nil {
			return newUnmarshalError(node, ti, fi, err.Error())
		}
		return nil
	}
	if v.CanAddr() {
		a := v.Addr()
		if a.CanInterface() && a.Type().Implements(textUnmarshalerType) {
			if err := a.Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte(s)); err != nil {
				return newUnmarshalError(node, ti, fi, err.Error())
			}
			return nil
		}
	}
	if fi.Opts.Prefix && ft.Kind() != reflect.String {
		return newUnmarshalError(node, ti, fi, "unsupported type")
	}
	switch ft.Kind() {
	case reflect.Array, reflect.Slice:
		if ft.Elem().Kind() == reflect.Uint8 {
			if v.Kind() == reflect.Slice {
				if len(s) >= v.Cap() {
					v.Set(reflect.MakeSlice(v.Type(), v.Len(), len(s)))
				}
				if len(s) != v.Len() {
					v.SetLen(len(s))
				}
			}
			for i := 0; i < len(s) && i < v.Len(); i++ {
				v.Index(i).SetUint(uint64(s[i]))
			}
			if len(s) == 0 && v.Kind() == reflect.Slice {
				v.Set(reflect.MakeSlice(v.Type(), 0, 0))
			}
			return nil
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		val, err := strconv.ParseInt(s, fi.Opts.Base, ft.Bits())
		if err != nil {
			return newUnmarshalError(node, ti, fi, err.Error())
		}
		v.SetInt(val)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		val, err := strconv.ParseUint(s, fi.Opts.Base, ft.Bits())
		if err != nil {
			return newUnmarshalError(node, ti, fi, err.Error())
		}
		v.SetUint(val)
		return nil
	case reflect.String:
		v.SetString(s)
		return nil
	}
	return newUnmarshalError(node, ti, fi, "unsupported type")
}

func newUnmarshalError(node parse.Node, ti *typeInfo, fi *fieldInfo, msg string) error {
	return &UnmarshalTypeError{
		Value:  node.Type().String(),
		Type:   fi.Type,
		Offset: int(node.End()),
		Struct: ti.Struct.String(),
		Field:  fi.Name,
		Msg:    msg,
	}
}

func unmarshalIndirect(v reflect.Value) reflect.Value {
	var done bool
	for !done {
		switch v.Kind() {
		case reflect.Interface:
			done = true
			if !v.IsNil() {
				e := v.Elem()
				if e.Kind() == reflect.Ptr && !e.IsNil() {
					v = e
					done = false
				}
			}
		case reflect.Ptr:
			if v.IsNil() {
				v.Set(reflect.New(v.Type().Elem()))
			}
			v = v.Elem()
		default:
			done = true
		}
	}
	return v
}
