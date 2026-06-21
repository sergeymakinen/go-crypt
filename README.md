# crypt

[![tests](https://github.com/sergeymakinen/go-crypt/workflows/tests/badge.svg)](https://github.com/sergeymakinen/go-crypt/actions?query=workflow%3Atests)
[![Go Reference](https://pkg.go.dev/badge/github.com/sergeymakinen/go-crypt.svg)](https://pkg.go.dev/github.com/sergeymakinen/go-crypt)
[![Go Report Card](https://goreportcard.com/badge/github.com/sergeymakinen/go-crypt)](https://goreportcard.com/report/github.com/sergeymakinen/go-crypt)
[![codecov](https://codecov.io/gh/sergeymakinen/go-crypt/branch/main/graph/badge.svg)](https://codecov.io/gh/sergeymakinen/go-crypt)

Package crypt implements a basic interface to validate [crypt(3)](https://en.wikipedia.org/wiki/Crypt_(C)#Key_derivation_functions_supported_by_crypt) hashes.

Validation of any particular hash requires the prior registration of a check function.
Registration is typically automatic as a side effect of initializing that
hash's package so that, to validate an Argon2 has, it suffices to have

```go
import _ "github.com/sergeymakinen/go-crypt/argon2"
```

in a program's main package. The _ means to import a package purely for its
initialization side effects.

## Supported hashing algorithms

<table>
<thead>
<tr>
    <th>Name</th>
    <th>Package</th>
    <th>Supported parameters</th>
    <th>Example hash</th>
</tr>
</thead>
<tbody>
<tr>
    <td>Argon2</td>
    <td>argon2 <a href="https://pkg.go.dev/github.com/sergeymakinen/go-crypt/argon2"><img src="https://pkg.go.dev/badge/github.com/sergeymakinen/go-crypt.svg" alt="Go Reference"></a></td>
    <td>
        <ul>
        <li>Salt</li>
        <li>Memory</li>
        <li>Time</li>
        <li>Threads</li>
        <li>Prefix (<code>$argon2d$</code>, <code>$argon2i$</code>, <code>$argon2id$</code>)</li>
        <li>Version (1.0, 1.3)</li>
        </ul>
    </td>
    <td><code>$argon2id$v=19$m=512,t=3,p=1$qXMlAYBABLl$/OuG+qcZ1ntdTRfhUGFVp2YMcTPJ7aH3e4j7KIEnRho</code></td>
</tr>
<tr>
    <td>bcrypt</td>
    <td>bcrypt <a href="https://pkg.go.dev/github.com/sergeymakinen/go-crypt/bcrypt"><img src="https://pkg.go.dev/badge/github.com/sergeymakinen/go-crypt.svg" alt="Go Reference"></a></td>
    <td>
        <ul>
        <li>Salt</li>
        <li>Cost</li>
        <li>Prefix (<code>$2$</code>, <code>$2a$</code>, <code>$2b$</code>)</li>
        </ul>
    </td>
    <td><code>$2b$10$UVjcf7m8L91VOpIRwEprguF4o9Inqj7aNhqvSzUElX4GWGyIkYLuG</code></td>
</tr>
<tr>
    <td>DES</td>
    <td>des <a href="https://pkg.go.dev/github.com/sergeymakinen/go-crypt/des"><img src="https://pkg.go.dev/badge/github.com/sergeymakinen/go-crypt.svg" alt="Go Reference"></a></td>
    <td>
        <ul>
        <li>Salt</li>
        </ul>
    </td>
    <td><code>eNBO0nZMf3rWM</code></td>
</tr>
<tr>
    <td>DES Extended (BSDi)</td>
    <td>desext <a href="https://pkg.go.dev/github.com/sergeymakinen/go-crypt/desext"><img src="https://pkg.go.dev/badge/github.com/sergeymakinen/go-crypt.svg" alt="Go Reference"></a></td>
    <td>
        <ul>
        <li>Salt</li>
        <li>Rounds</li>
        </ul>
    </td>
    <td><code>_6C/.yaiu.qYIjNR7X.s</code></td>
</tr>
<tr>
    <td>MD5</td>
    <td>md5 <a href="https://pkg.go.dev/github.com/sergeymakinen/go-crypt/md5"><img src="https://pkg.go.dev/badge/github.com/sergeymakinen/go-crypt.svg" alt="Go Reference"></a></td>
    <td>
        <ul>
        <li>Salt</li>
        </ul>
    </td>
    <td><code>$1$ip0xp41O$7DHwMihQRmDjn2tiJ17mw.</code></td>
</tr>
<tr>
    <td>NT Hash</td>
    <td>nthash <a href="https://pkg.go.dev/github.com/sergeymakinen/go-crypt/nthash"><img src="https://pkg.go.dev/badge/github.com/sergeymakinen/go-crypt.svg" alt="Go Reference"></a></td>
    <td></td>
    <td><code>$3$$8846f7eaee8fb117ad06bdd830b7586c</code></td>
</tr>
<tr>
    <td>SHA-1</td>
    <td>sha1 <a href="https://pkg.go.dev/github.com/sergeymakinen/go-crypt/sha1"><img src="https://pkg.go.dev/badge/github.com/sergeymakinen/go-crypt.svg" alt="Go Reference"></a></td>
    <td>
        <ul>
        <li>Salt</li>
        <li>Rounds</li>
        </ul>
    </td>
    <td><code>$sha1$48000$mHh0IIOQ$YS/Lw0PKCThSEBBYqP37zXySQ3cC</code></td>
</tr>
<tr>
    <td>SHA-256</td>
    <td>sha256 <a href="https://pkg.go.dev/github.com/sergeymakinen/go-crypt/sha256"><img src="https://pkg.go.dev/badge/github.com/sergeymakinen/go-crypt.svg" alt="Go Reference"></a></td>
    <td>
        <ul>
        <li>Salt</li>
        <li>Rounds</li>
        </ul>
    </td>
    <td><code>$5$rounds=505000$.HnFpd3anFzRwVj5$EdcK/Q9wfmq1XsG5OTKP0Ns.ZlN9DRHslblcgCLtXY5</code></td>
</tr>
<tr>
    <td>SHA-512</td>
    <td>sha512 <a href="https://pkg.go.dev/github.com/sergeymakinen/go-crypt/sha512"><img src="https://pkg.go.dev/badge/github.com/sergeymakinen/go-crypt.svg" alt="Go Reference"></a></td>
    <td>
        <ul>
        <li>Salt</li>
        <li>Rounds</li>
        </ul>
    </td>
    <td><code>$6$rounds=505000$69oRpYjidkp7hFdm$nbf4615NgTuG8kCnGYSjz/lXw4KrGMVR16cbCa9CSIHXK8UXwCK9bzCqDUw/I8hgb9Wstd1w5Bwgu5YG6Q.dm.</code></td>
</tr>
<tr>
    <td>Sun MD5</td>
    <td>sunmd5 <a href="https://pkg.go.dev/github.com/sergeymakinen/go-crypt/sunmd5"><img src="https://pkg.go.dev/badge/github.com/sergeymakinen/go-crypt.svg" alt="Go Reference"></a></td>
    <td>
        <ul>
        <li>Salt</li>
        <li>Rounds</li>
        <li>Prefix (<code>$md5,</code>, <code>$md5$</code>)</li>
        <li>Whether to add an empty value to a salt</li>
        </ul>
    </td>
    <td><code>$md5,rounds=5000$ReCRHeOH$$WOV3YlBRWykkmQDJc.uia/</code></td>
</tr>
</tbody>
</table>

## Custom hashes

It's also possible to implement a custom hash marshaling/unmarshaling via the <a href="https://pkg.go.dev/github.com/sergeymakinen/go-crypt/hash">hash</a> package.

**Supported schemes**:

- DES: `<value>(<value>)*`
- DES Extended (BSDi): `_<value>(<value>)*`
- MCF/PHC: `$<id>$fragment($<fragment>)*`<br>
  Where:
  - `<fragment>` is `(<group>|<param>=<value>|<value>)`
  - `<group>` is `<param>=<value>,<param>=<value>(,<param>=<value>)*`
    
**Example**:

```go
var scheme = struct {
    HashPrefix string
    Cost       string `hash:"length:2"`
    Salt       []byte   `hash:"length:22,inline"`
    Sum        [31]byte
}
hash.Unmarshal("$2b$10$UVjcf7m8L91VOpIRwEprguF4o9Inqj7aNhqvSzUElX4GWGyIkYLuG", &scheme)
```

## Installation

Use go get:

```bash
go get github.com/sergeymakinen/go-crypt
```

Then import the package into your own code:

```go
import "github.com/sergeymakinen/go-crypt"
```

## Example

```go
package main

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

func main() {
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
```

## License

BSD 3-Clause
