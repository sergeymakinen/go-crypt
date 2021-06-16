package md5_test

import (
	"fmt"

	"github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/md5"
)

func ExampleSalt() {
	salt, _ := md5.Salt("$1$ip0xp41O$7DHwMihQRmDjn2tiJ17mw.")
	fmt.Println(string(salt))
	// Output:
	// ip0xp41O
}

func ExampleKey() {
	salt, _ := md5.Salt("$1$ip0xp41O$7DHwMihQRmDjn2tiJ17mw.")
	fmt.Println(string(salt))

	key, _ := md5.Key([]byte("password"), salt)
	fmt.Println(hash.LittleEndianEncoding.EncodeToString(key))
	// Output:
	// ip0xp41O
	// 7DHwMihQRmDjn2tiJ17mw.
}

func ExampleCheck() {
	hash := "$1$ip0xp41O$7DHwMihQRmDjn2tiJ17mw."
	fmt.Println(md5.Check(hash, "password"))
	fmt.Println(md5.Check(hash, "test"))
	// Output:
	// <nil>
	// hash and password mismatch
}
