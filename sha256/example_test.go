package sha256_test

import (
	"fmt"

	"github.com/sergeymakinen/go-crypt/hash"
	"github.com/sergeymakinen/go-crypt/sha256"
)

func ExampleParams() {
	salt, rounds, _ := sha256.Params("$5$rounds=505000$.HnFpd3anFzRwVj5$EdcK/Q9wfmq1XsG5OTKP0Ns.ZlN9DRHslblcgCLtXY5")
	fmt.Println(string(salt))
	fmt.Println(rounds)
	// Output:
	// .HnFpd3anFzRwVj5
	// 505000
}

func ExampleKey() {
	salt, rounds, _ := sha256.Params("$5$rounds=505000$.HnFpd3anFzRwVj5$EdcK/Q9wfmq1XsG5OTKP0Ns.ZlN9DRHslblcgCLtXY5")
	fmt.Println(string(salt))
	fmt.Println(rounds)

	key, _ := sha256.Key([]byte("password"), salt, rounds)
	fmt.Println(hash.LittleEndianEncoding.EncodeToString(key))
	// Output:
	// .HnFpd3anFzRwVj5
	// 505000
	// EdcK/Q9wfmq1XsG5OTKP0Ns.ZlN9DRHslblcgCLtXY5
}

func ExampleCheck() {
	hash := "$5$rounds=505000$.HnFpd3anFzRwVj5$EdcK/Q9wfmq1XsG5OTKP0Ns.ZlN9DRHslblcgCLtXY5"
	fmt.Println(sha256.Check(hash, "password"))
	fmt.Println(sha256.Check(hash, "test"))
	// Output:
	// <nil>
	// hash and password mismatch
}
