package sha512_test

import (
	"fmt"

	"github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/sha512"
)

func ExampleParams() {
	salt, rounds, _ := sha512.Params("$6$rounds=505000$69oRpYjidkp7hFdm$nbf4615NgTuG8kCnGYSjz/lXw4KrGMVR16cbCa9CSIHXK8UXwCK9bzCqDUw/I8hgb9Wstd1w5Bwgu5YG6Q.dm.")
	fmt.Println(string(salt))
	fmt.Println(rounds)
	// Output:
	// 69oRpYjidkp7hFdm
	// 505000
}

func ExampleKey() {
	salt, rounds, _ := sha512.Params("$6$rounds=505000$69oRpYjidkp7hFdm$nbf4615NgTuG8kCnGYSjz/lXw4KrGMVR16cbCa9CSIHXK8UXwCK9bzCqDUw/I8hgb9Wstd1w5Bwgu5YG6Q.dm.")
	fmt.Println(string(salt))
	fmt.Println(rounds)

	key, _ := sha512.Key([]byte("password"), salt, rounds)
	fmt.Println(hash.LittleEndianEncoding.EncodeToString(key))
	// Output:
	// 69oRpYjidkp7hFdm
	// 505000
	// nbf4615NgTuG8kCnGYSjz/lXw4KrGMVR16cbCa9CSIHXK8UXwCK9bzCqDUw/I8hgb9Wstd1w5Bwgu5YG6Q.dm.
}

func ExampleCheck() {
	hash := "$6$rounds=505000$69oRpYjidkp7hFdm$nbf4615NgTuG8kCnGYSjz/lXw4KrGMVR16cbCa9CSIHXK8UXwCK9bzCqDUw/I8hgb9Wstd1w5Bwgu5YG6Q.dm."
	fmt.Println(sha512.Check(hash, "password"))
	fmt.Println(sha512.Check(hash, "test"))
	// Output:
	// <nil>
	// hash and password mismatch
}
