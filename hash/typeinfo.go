package hash

import (
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/sergeymakinen/go-crypt/internal/hashutil"
)

const hashPrefix = "HashPrefix"

// TagParamError represents an error in the unmarshaling process
// caused by the use of field tags with conflicting parameter names.
type TagParamError struct {
	Struct         reflect.Type
	Field1, Field2 string
	Tag1, Tag2     string
}

func (e *TagParamError) Error() string {
	return e.Struct.String() + " field " + strconv.Quote(e.Field1) + " with tag " + strconv.Quote(e.Tag1) + " conflicts with field " + strconv.Quote(e.Field2) + " with tag " + strconv.Quote(e.Tag2)
}

type fieldOpts struct {
	Prefix    bool
	OmitEmpty bool
	Group     bool
	Param     string
	Encoding  *hashutil.Encoding
	Length    int
	Inline    bool
	Base      int
}

type fieldInfo struct {
	Index []int
	Name  string
	Type  reflect.Type
	Opts  fieldOpts
}

func (f fieldInfo) String() string {
	switch {
	case f.Opts.Group:
		return "grouped param"
	case f.Opts.Param != "":
		return "param"
	default:
		return "value"
	}
}

type typeInfo struct {
	Struct       reflect.Type
	Type         reflect.Type
	HashPrefix   *fieldInfo
	Fields       []*fieldInfo
	NumReqValues int
}

func (ti *typeInfo) field(param string) (*fieldInfo, error) {
	var fields []*fieldInfo
	for _, fi1 := range ti.Fields {
		if fi1.Opts.Param != param {
			continue
		}
		for _, fi2 := range fields {
			if len(fi1.Index) == len(fi2.Index) {
				return nil, &TagParamError{
					Struct: ti.Struct,
					Field1: fi1.Name,
					Tag1:   ti.Type.FieldByIndex(fi1.Index).Tag.Get("hash"),
					Field2: fi2.Name,
					Tag2:   ti.Type.FieldByIndex(fi2.Index).Tag.Get("hash"),
				}
			}
		}
		fields = append(fields, fi1)
	}
	sort.Slice(fields, func(i, j int) bool {
		// Like encoding.json does
		if len(fields[i].Index) != len(fields[j].Index) {
			return len(fields[i].Index) < len(fields[j].Index)
		}
		for k, v := range fields[i].Index {
			if k >= len(fields[j].Index) {
				return false
			}
			if v != fields[j].Index[k] {
				return v < fields[j].Index[k]
			}
		}
		return false
	})
	// Matches the Go field resolution on embedding
	return fields[0], nil
}

func (ti *typeInfo) normalize() error {
	var fields []*fieldInfo
	params := map[string]bool{}
	for _, f := range ti.Fields {
		isValid := true
		if f.Opts.OmitEmpty {
			isValid = isValid && !f.Opts.Inline
		}
		if f.Opts.Group {
			isValid = isValid && f.Opts.Param != ""
		}
		if f.Opts.Param != "" {
			isValid = isValid && !f.Opts.Prefix
		}
		if f.Opts.Inline {
			isValid = isValid && !f.Opts.Prefix && f.Opts.Length > 0
		}
		if !isValid {
			return errors.New("invalid tag in field " + ti.Struct.String() + "." + f.Name + ": " + strconv.Quote(ti.Type.FieldByIndex(f.Index).Tag.Get("hash")))
		}
		if f.Opts.Prefix {
			ti.HashPrefix = f
			continue
		}
		if !f.Opts.Group && !f.Opts.OmitEmpty && !f.Opts.Inline {
			ti.NumReqValues++
		}
		if f.Opts.Param == "" {
			fields = append(fields, f)
			continue
		}
		if _, ok := params[f.Opts.Param]; ok {
			continue
		}
		fi, err := ti.field(f.Opts.Param)
		if err != nil {
			return err
		}
		fields = append(fields, fi)
		params[f.Opts.Param] = true
	}
	ti.Fields = fields
	return nil
}

func getRawTypeInfo(t reflect.Type) *typeInfo {
	ti := &typeInfo{Type: t}
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		tag := sf.Tag.Get("hash")
		if (sf.PkgPath != "" && !sf.Anonymous) || tag == "-" {
			continue
		}
		if sf.Anonymous {
			st := sf.Type
			for st.Kind() == reflect.Ptr {
				st = st.Elem()
			}
			if st.Kind() == reflect.Struct {
				for _, fi := range getRawTypeInfo(st).Fields {
					fi.Index = append([]int{i}, fi.Index...)
					ti.Fields = append(ti.Fields, fi)
				}
				continue
			}
		}
		fi := &fieldInfo{
			Index: sf.Index,
			Name:  sf.Name,
			Type:  sf.Type,
			Opts: fieldOpts{
				Encoding: hashutil.HashEncoding,
				Base:     10,
			},
		}
		if fi.Name == hashPrefix {
			fi.Opts.Prefix = true
			fi.Opts.Encoding = nil
		}
		if st := indirectType(fi.Type); st.Kind() == reflect.Array && st.Elem().Kind() == reflect.Uint8 {
			fi.Opts.Length = st.Len()
		}
		var part string
		for tag != "" {
			i := strings.IndexByte(tag, ',')
			if i < 0 {
				part, tag = tag, ""
			} else {
				part, tag = tag[:i], tag[i+1:]
			}
			switch {
			case strings.HasPrefix(part, "param:"):
				fi.Opts.Param = part[6:]
			case part == "omitempty":
				fi.Opts.OmitEmpty = true
			case part == "group":
				fi.Opts.Group = true
			case strings.HasPrefix(part, "length:"):
				if v, err := strconv.ParseUint(part[7:], 10, 32); err == nil {
					if fi.Opts.Length == 0 || int(v) < fi.Opts.Length {
						fi.Opts.Length = int(v)
					}
				}
			case part == "inline":
				fi.Opts.Inline = true
			case strings.HasPrefix(part, "base:"):
				if i, err := strconv.ParseUint(part[5:], 10, 8); err == nil && i >= 2 && i <= 36 {
					fi.Opts.Base = int(i)
				}
			case strings.HasPrefix(part, "enc:"):
				switch part[4:] {
				case "base64":
					fi.Opts.Encoding = hashutil.Base64Encoding
				case "none":
					fi.Opts.Encoding = nil
				}
			}
		}
		ti.Fields = append(ti.Fields, fi)
	}
	return ti
}

var typeCache sync.Map // map[reflect.Type]*typeInfo

func getTypeInfo(t reflect.Type) (*typeInfo, error) {
	typ := indirectType(t)
	f, ok := typeCache.Load(typ)
	if !ok {
		info := getRawTypeInfo(typ)
		info.Struct = t
		if err := info.normalize(); err != nil {
			return nil, err
		}
		f, _ = typeCache.LoadOrStore(t, info)
	}
	ti := &(*f.(*typeInfo))
	ti.Struct = t
	return ti, nil
}

func indirectType(typ reflect.Type) reflect.Type {
	for {
		switch typ.Kind() {
		case reflect.Ptr:
			typ = typ.Elem()
		default:
			return typ
		}
	}
}
