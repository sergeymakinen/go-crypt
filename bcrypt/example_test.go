package bcrypt_test

import (
	"fmt"

	"github.com/sergeymakinen/go-crypt/bcrypt"
)

func ExampleParams() {
	salt, cost, _, _ := bcrypt.Params("$2b$10$UVjcf7m8L91VOpIRwEprguF4o9Inqj7aNhqvSzUElX4GWGyIkYLuG")
	fmt.Println(string(salt))
	fmt.Println(cost)
	// Output:
	// UVjcf7m8L91VOpIRwEprgu
	// 10
}

func ExampleKey() {
	salt, cost, opts, _ := bcrypt.Params("$2b$10$UVjcf7m8L91VOpIRwEprguF4o9Inqj7aNhqvSzUElX4GWGyIkYLuG")
	fmt.Println(string(salt))
	fmt.Println(cost)

	key, _ := bcrypt.Key([]byte("password"), salt, cost, opts)
	fmt.Println(bcrypt.Encoding.EncodeToString(key))
	// Output:
	// UVjcf7m8L91VOpIRwEprgu
	// 10
	// F4o9Inqj7aNhqvSzUElX4GWGyIkYLuG
}

func ExampleCheck() {
	hash := "$2b$12$mBhJFLLDJCBCcmMN4DLyrOV.LLSl/mdwGfzwsqvIL0OQN5yXzRihO"
	fmt.Println(bcrypt.Check(hash, "password"))
	fmt.Println(bcrypt.Check(hash, "test"))
	// Output:
	// <nil>
	// hash and password mismatch
}
