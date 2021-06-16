package desext_test

import (
	"fmt"

	"github.com/sergeymakinen/go-crypt/desext"
	"github.com/sergeymakinen/go-crypt/hash"
)

func ExampleParams() {
	salt, rounds, _ := desext.Params("_6C/.yaiu.qYIjNR7X.s")
	fmt.Println(string(salt))
	fmt.Println(rounds)
	// Output:
	// yaiu
	// 5000
}

func ExampleKey() {
	salt, rounds, _ := desext.Params("_6C/.yaiu.qYIjNR7X.s")
	fmt.Println(string(salt))
	fmt.Println(rounds)

	key, _ := desext.Key([]byte("password"), salt, rounds)
	fmt.Println(hash.BigEndianEncoding.EncodeToString(key))
	// Output:
	// yaiu
	// 5000
	// .qYIjNR7X.s
}

func ExampleCheck() {
	hash := "_6C/.yaiu.qYIjNR7X.s"
	fmt.Println(desext.Check(hash, "password"))
	fmt.Println(desext.Check(hash, "test"))
	// Output:
	// <nil>
	// hash and password mismatch
}
