package nthash_test

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"unicode/utf16"

	"github.com/sergeymakinen/go-crypt/nthash"
)

func ExampleKey() {
	// UTF-8 to UTF-16 LE
	a := utf16.Encode([]rune("password"))
	b := make([]byte, len(a)*2)
	for i, r := range a {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}

	key, _ := nthash.Key(b)
	fmt.Println(hex.EncodeToString(key))
	// Output:
	// 8846f7eaee8fb117ad06bdd830b7586c
}

func ExampleCheck() {
	hash := "$3$$8846f7eaee8fb117ad06bdd830b7586c"
	fmt.Println(nthash.Check(hash, "password"))
	fmt.Println(nthash.Check(hash, "test"))
	// Output:
	// <nil>
	// hash and password mismatch
}
