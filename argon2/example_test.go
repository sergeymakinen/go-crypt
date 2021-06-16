package argon2_test

import (
	"encoding/base64"
	"fmt"

	"github.com/sergeymakinen/go-crypt/argon2"
)

func ExampleParams() {
	salt, memory, time, threads, _, _ := argon2.Params("$argon2id$v=19$m=512,t=3,p=1$qXMlAYBABLl$/OuG+qcZ1ntdTRfhUGFVp2YMcTPJ7aH3e4j7KIEnRho")
	fmt.Println(string(salt))
	fmt.Println(memory)
	fmt.Println(time)
	fmt.Println(threads)
	// Output:
	// qXMlAYBABLl
	// 512
	// 3
	// 1
}

func ExampleKey() {
	salt, memory, time, threads, opts, _ := argon2.Params("$argon2id$v=19$m=512,t=3,p=1$qXMlAYBABLl$/OuG+qcZ1ntdTRfhUGFVp2YMcTPJ7aH3e4j7KIEnRho")
	fmt.Println(string(salt))
	fmt.Println(memory)
	fmt.Println(time)
	fmt.Println(threads)

	key, _ := argon2.Key([]byte("password"), salt, memory, time, threads, opts)
	fmt.Println(base64.RawStdEncoding.EncodeToString(key))
	// Output:
	// qXMlAYBABLl
	// 512
	// 3
	// 1
	// /OuG+qcZ1ntdTRfhUGFVp2YMcTPJ7aH3e4j7KIEnRho
}

func ExampleCheck() {
	hash := "$argon2id$v=19$m=512,t=3,p=1$qXMlAYBABLl$/OuG+qcZ1ntdTRfhUGFVp2YMcTPJ7aH3e4j7KIEnRho"
	fmt.Println(argon2.Check(hash, "password"))
	fmt.Println(argon2.Check(hash, "test"))
	// Output:
	// <nil>
	// hash and password mismatch
}
