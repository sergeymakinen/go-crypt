package sunmd5_test

import (
	"fmt"

	"github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/sunmd5"
)

func ExampleParams() {
	salt, rounds, _, _ := sunmd5.Params("$md5,rounds=5000$ReCRHeOH$$WOV3YlBRWykkmQDJc.uia/")
	fmt.Println(string(salt))
	fmt.Println(rounds)
	// Output:
	// ReCRHeOH
	// 5000
}

func ExampleKey() {
	salt, rounds, opts, _ := sunmd5.Params("$md5,rounds=5000$ReCRHeOH$$WOV3YlBRWykkmQDJc.uia/")
	fmt.Println(string(salt))
	fmt.Println(rounds)

	key, _ := sunmd5.Key([]byte("password"), salt, rounds, opts)
	fmt.Println(hash.LittleEndianEncoding.EncodeToString(key))
	// Output:
	// ReCRHeOH
	// 5000
	// WOV3YlBRWykkmQDJc.uia/
}

func ExampleCheck() {
	hash := "$md5,rounds=5000$ReCRHeOH$$WOV3YlBRWykkmQDJc.uia/"
	fmt.Println(sunmd5.Check(hash, "password"))
	fmt.Println(sunmd5.Check(hash, "test"))
	// Output:
	// <nil>
	// hash and password mismatch
}
