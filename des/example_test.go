package des_test

import (
	"fmt"

	"github.com/sergeymakinen/go-crypt/des"
	"github.com/sergeymakinen/go-crypt/hash"
)

func ExampleSalt() {
	salt, _ := des.Salt("eNBO0nZMf3rWM")
	fmt.Println(string(salt))
	// Output:
	// eN
}

func ExampleKey() {
	salt, _ := des.Salt("eNBO0nZMf3rWM")
	fmt.Println(string(salt))

	key, _ := des.Key([]byte("password"), salt)
	fmt.Println(hash.BigEndianEncoding.EncodeToString(key))
	// Output:
	// eN
	// BO0nZMf3rWM
}

func ExampleCheck() {
	hash := "eNBO0nZMf3rWM"
	fmt.Println(des.Check(hash, "password"))
	fmt.Println(des.Check(hash, "test"))
	// Output:
	// <nil>
	// hash and password mismatch
}
