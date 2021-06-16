package sha1_test

import (
	"fmt"

	"github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/sha1"
)

func ExampleParams() {
	salt, rounds, _ := sha1.Params("$sha1$48000$mHh0IIOQ$YS/Lw0PKCThSEBBYqP37zXySQ3cC")
	fmt.Println(string(salt))
	fmt.Println(rounds)
	// Output:
	// mHh0IIOQ
	// 48000
}

func ExampleKey() {
	salt, rounds, _ := sha1.Params("$sha1$48000$mHh0IIOQ$YS/Lw0PKCThSEBBYqP37zXySQ3cC")
	fmt.Println(string(salt))
	fmt.Println(rounds)

	key, _ := sha1.Key([]byte("password"), salt, rounds)
	fmt.Println(hash.LittleEndianEncoding.EncodeToString(key))
	// Output:
	// mHh0IIOQ
	// 48000
	// YS/Lw0PKCThSEBBYqP37zXySQ3cC
}

func ExampleCheck() {
	hash := "$sha1$48000$mHh0IIOQ$YS/Lw0PKCThSEBBYqP37zXySQ3cC"
	fmt.Println(sha1.Check(hash, "password"))
	fmt.Println(sha1.Check(hash, "test"))
	// Output:
	// <nil>
	// hash and password mismatch
}
