package crypt_test

import (
	"fmt"

	"github.com/sergeymakinen/go-crypt"
	_ "github.com/sergeymakinen/go-crypt/argon2"
	_ "github.com/sergeymakinen/go-crypt/bcrypt"
)

var hashes = []string{
	"$argon2id$v=19$m=512,t=3,p=1$qXMlAYBABLl$/OuG+qcZ1ntdTRfhUGFVp2YMcTPJ7aH3e4j7KIEnRho", // Argon2
	"$2b$12$mBhJFLLDJCBCcmMN4DLyrOV.LLSl/mdwGfzwsqvIL0OQN5yXzRihO",                         // bcrypt
	"$unknown$foo", // Not registered
}

var passwords = []string{
	"password",
	"test",
}

func ExampleCheck() {
	for _, hash := range hashes {
		for _, password := range passwords {
			fmt.Printf("%q with %q: %v\n", hash, password, crypt.Check(hash, password))
		}
	}
	// Output:
	// "$argon2id$v=19$m=512,t=3,p=1$qXMlAYBABLl$/OuG+qcZ1ntdTRfhUGFVp2YMcTPJ7aH3e4j7KIEnRho" with "password": <nil>
	// "$argon2id$v=19$m=512,t=3,p=1$qXMlAYBABLl$/OuG+qcZ1ntdTRfhUGFVp2YMcTPJ7aH3e4j7KIEnRho" with "test": hash and password mismatch
	// "$2b$12$mBhJFLLDJCBCcmMN4DLyrOV.LLSl/mdwGfzwsqvIL0OQN5yXzRihO" with "password": <nil>
	// "$2b$12$mBhJFLLDJCBCcmMN4DLyrOV.LLSl/mdwGfzwsqvIL0OQN5yXzRihO" with "test": hash and password mismatch
	// "$unknown$foo" with "password": unknown hash
	// "$unknown$foo" with "test": unknown hash
}
