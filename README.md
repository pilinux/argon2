# argon2 Unofficial

![CodeQL][11]
![Build][12]
![Linter][13]
[![Codecov][14]][15]
[![Go Reference][16]][17]
[![Go Report Card][18]][19]
[![CodeFactor][20]][21]
[![CodeBeat][22]][23]

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
[11]: https://github.com/pilinux/argon2/actions/workflows/codeql-analysis.yml/badge.svg
[12]: https://github.com/pilinux/argon2/actions/workflows/go.yml/badge.svg
[13]: https://github.com/pilinux/argon2/actions/workflows/golangci-lint.yml/badge.svg
[14]: https://codecov.io/gh/pilinux/argon2/graph/badge.svg?token=B3TY4DDNJP
[15]: https://codecov.io/gh/pilinux/argon2
[16]: https://pkg.go.dev/badge/github.com/pilinux/argon2
[17]: https://pkg.go.dev/github.com/pilinux/argon2
[18]: https://goreportcard.com/badge/github.com/pilinux/argon2
[19]: https://goreportcard.com/report/github.com/pilinux/argon2
[20]: https://www.codefactor.io/repository/github/pilinux/argon2/badge
[21]: https://www.codefactor.io/repository/github/pilinux/argon2
[22]: https://codebeat.co/badges/525303e8-8be8-4c50-8d21-a74df9371cbc
[23]: https://codebeat.co/projects/github-com-pilinux-argon2-main
