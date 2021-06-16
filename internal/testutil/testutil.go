package testutil

import (
	"reflect"
	"strconv"
)

func FieldType(v interface{}, name string) reflect.Type {
	sf, ok := indirectType(reflect.TypeOf(v)).FieldByName(name)
	if !ok {
		panic("no struct field " + strconv.Quote(name))
	}
	return sf.Type
}

func IsEqualError(x, y error) bool {
	if x == nil && y == nil {
		return true
	}
	if (x == nil) != (y == nil) {
		return false
	}
	return reflect.DeepEqual(x, y) && x.Error() == y.Error()
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
