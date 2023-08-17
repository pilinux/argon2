# argon2 Unofficial

Package argon2 is an improved version of the [official Go argon2][01] hashing package.

Features missing from the official Go [argon2][01] package:
-  [NIST 800-63B][02] recommends using a secret value of at least 112 bits.
But as of now (golang.org/x/crypto v0.12.0), `Key` and `IDkey` functions pass `nil`
value when calling `deriveKey` function.
-  Does not provide any straightforward way for password hashing and verification.

This package contains two additional functions `KeyWithSecret` and `IDKeyWithSecret`
to provide an extra layer of security on top of the existing `Key` and `IDKey` functions
by including an additional secret.

One of the standout features of this package is the seamless integration of a user-friendly
wrapper (an improved version of `github.com/alexedwards/argon2id`). The wrapper
encapsulates the complexities of the underlying argon2 package, offering a simplified
and intuitive interface for developers across different projects.

## Usage

```go
package main

import (
	"fmt"

	"github.com/pilinux/argon2"
)

func main() {
	// Argon2i
	// create hash using argon2i and without any secret
	// $argon2i$v=19$m=65536,t=1,p=2$frbISZVHQ/ZgUpNA0SgdNQ$GuGB9vz9rTcJmDIebUFmVk0kyAX9xninyCp696PRdCA
	hash, err := argon2.CreateHash("pa$$word", "", argon2.DefaultParams)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(hash)

	// ComparePasswordAndHash performs a constant-time comparison between a
	// plain-text password and argon2id hash, using the parameters and salt
	// contained in the hash. It returns true if they match, otherwise it returns
	// false.
	match, err := argon2.ComparePasswordAndHash("pa$$word", "", hash)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Match: %v\n", match)

	// create hash using argon2i and with secret
	// $argon2i$v=19$m=65536,t=1,p=2$TfGuJ6SGvluWcQjsDdQWPQ$Seozoi/ZKJngavqpyZ5rs5lX5EKzJ2HSnMWJwVwJmVU
	hash, err = argon2.CreateHash("pa$$word", "12€45", argon2.DefaultParams)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(hash)

	match, err = argon2.ComparePasswordAndHash("pa$$word", "12€45", hash)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Match: %v\n", match)
	// --------------------------------------------------------------

	// Argon2id
	// create hash using argon2id and without any secret
	// $argon2id$v=19$m=65536,t=1,p=2$+Ni27r9ZIaEBs8mZn60Dlg$cxuw8quTcT5fIDqNIU27SinXyKiKQWFo/mfF4sogeKo
	idHash, err := argon2.IDCreateHash("pa$$word", "", argon2.DefaultParams)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(idHash)

	match, err = argon2.ComparePasswordAndHash("pa$$word", "", idHash)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Match: %v\n", match)

	// create hash using argon2id and with secret
	// $argon2id$v=19$m=65536,t=1,p=2$+haa0lKvImdlxrXCs0aJ/A$1h2lpPic8KQ7XckSdg+cE7LJX5kQ83BAZGNCBL6zmZI
	idHash, err = argon2.IDCreateHash("pa$$word", "12€45", argon2.DefaultParams)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(idHash)

	match, err = argon2.ComparePasswordAndHash("pa$$word", "12€45", idHash)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Match: %v\n", match)
}
```

## Parameters

- Memory — The amount of memory used by the Argon2 algorithm (in kibibytes).
- Iterations — The number of iterations (or passes) over the memory.
- Parallelism — The number of threads (or lanes) used by the algorithm.
- Salt length — Length of the random salt. 16 bytes or more is recommended for password hashing.
- Key length — Length of the generated key (or password hash). 16 bytes or more is recommended.

```go
params := &argon2.Params{
		Memory:      128 * 1024,
		Iterations:  4,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}

hash, err := argon2.CreateHash("pa$$word", "", params)
```

For guidance, visit: [rfc9106][04]


[01]: https://pkg.go.dev/golang.org/x/crypto@v0.12.0/argon2
[02]: https://pages.nist.gov/800-63-3/sp800-63b.html
[03]: github.com/alexedwards/argon2id
[04]: https://datatracker.ietf.org/doc/html/rfc9106#name-argon2-algorithm
