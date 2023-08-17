package argon2

// This wrapper is a modified version of https://github.com/alexedwards/argon2id
// Following License is from https://github.com/alexedwards/argon2id
/*
MIT License

Copyright (c) 2018 Alex Edwards

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	// ErrInvalidHash is returned by ComparePasswordAndHash if the provided
	// hash isn't in the expected format.
	ErrInvalidHash = errors.New("argon2: hash is not in the correct format")

	// ErrIncompatibleVariant is returned by ComparePasswordAndHash if the
	// provided hash was created using a unsupported variant of Argon2.
	// Currently only argon2id is supported by this package.
	ErrIncompatibleVariant = errors.New("argon2: incompatible variant of argon2")

	// ErrIncompatibleVersion is returned by ComparePasswordAndHash if the
	// provided hash was created using a different version of Argon2.
	ErrIncompatibleVersion = errors.New("argon2: incompatible version of argon2")
)

// DefaultParams provides some sane default parameters for hashing passwords.
//
// Follows recommendations given by the Argon2 RFC:
// "The Argon2id variant with t=1 and maximum available memory is RECOMMENDED as a
// default setting for all environments. This setting is secure against side-channel
// attacks and maximizes adversarial costs on dedicated brute-force hardware."
//
// The default parameters should generally be used for development/testing purposes
// only. Custom parameters should be set for production applications depending on
// available memory/CPU resources and business requirements.
var DefaultParams = &Params{
	Memory:      64 * 1024,
	Iterations:  1,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

// Params describes the input parameters used by the Argon2id algorithm. The
// Memory and Iterations parameters control the computational cost of hashing
// the password. The higher these figures are, the greater the cost of generating
// the hash and the longer the runtime. It also follows that the greater the cost
// will be for any attacker trying to guess the password. If the code is running
// on a machine with multiple cores, then you can decrease the runtime without
// reducing the cost by increasing the Parallelism parameter. This controls the
// number of threads that the work is spread across. Important note: Changing the
// value of the Parallelism parameter changes the hash output.
//
// For guidance and an outline process for choosing appropriate parameters see
// https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04#section-4
type Params struct {
	// The amount of memory used by the algorithm (in kibibytes).
	Memory uint32

	// The number of iterations over the memory.
	Iterations uint32

	// The number of threads (or lanes) used by the algorithm.
	// Recommended value is between 1 and runtime.NumCPU().
	Parallelism uint8

	// Length of the random salt. 16 bytes is recommended for password hashing.
	SaltLength uint32

	// Length of the generated key. 16 bytes or more is recommended.
	KeyLength uint32
}

// CreateHash generates an Argon2i password hash using the provided password, secret,
// and parameters. It returns the generated hash as a string and any error encountered.
//
// The function takes the user's password, a secret for additional security, and
// a Params struct containing the parameters for key derivation. It generates a
// random salt and derives a key using the Argon2i key derivation function.
//
// Parameters:
//   - password: The user's password.
//   - secret: An additional secret used for key derivation.
//   - params: A Params struct containing key derivation parameters.
//
// Returns:
//   - hash: The generated Argon2i password hash.
//   - err: Any error encountered during hash generation.
//
// The returned hash follows the format used by the Argon2 reference C
// implementation and contains the base64-encoded Argon2i derived key prefixed
// by the salt and parameters. It looks like this:
//
//	$argon2i$v=19$m=65536,t=1,p=2$Ell6DALdx5M3PMaNxPsFyA$VTeuPaGQW621unpzV0zHKT8S4xRir8djGSY63vsYb7U
func CreateHash(password, secret string, params *Params) (hash string, err error) {
	salt, err := generateRandomBytes(params.SaltLength)
	if err != nil {
		return "", err
	}

	var key []byte
	if secret == "" {
		key = Key([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	}
	if secret != "" {
		key = KeyWithSecret([]byte(password), []byte(secret), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	}

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	hash = fmt.Sprintf("$argon2i$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, params.Memory, params.Iterations, params.Parallelism, b64Salt, b64Key)
	return hash, nil
}

// IDCreateHash generates an Argon2id password hash using the provided password, secret,
// and parameters. It returns the generated hash as a string and any error encountered.
//
// The function takes the user's password, a secret for additional security, and
// a Params struct containing the parameters for key derivation. It generates a
// random salt and derives a key using the Argon2id key derivation function.
//
// Parameters:
//   - password: The user's password.
//   - secret: An additional secret used for key derivation.
//   - params: A Params struct containing key derivation parameters.
//
// Returns:
//   - hash: The generated Argon2id password hash.
//   - err: Any error encountered during hash generation.
//
// The returned hash follows the format used by the Argon2 reference C
// implementation and contains the base64-encoded Argon2id derived key prefixed
// by the salt and parameters. It looks like this:
//
//	$argon2id$v=19$m=65536,t=1,p=2$FmIYUI9SfLj+xHJJsM3JXw$DI8bBB2wHgOFwWVXXUSjmwRMeh/1pVVu5PDbsjoFtYE
func IDCreateHash(password, secret string, params *Params) (hash string, err error) {
	salt, err := generateRandomBytes(params.SaltLength)
	if err != nil {
		return
	}

	var key []byte
	if secret == "" {
		key = IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	}
	if secret != "" {
		key = IDKeyWithSecret([]byte(password), []byte(secret), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	}

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	hash = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", Version, params.Memory, params.Iterations, params.Parallelism, b64Salt, b64Key)
	return hash, nil
}

// ComparePasswordAndHash performs a constant-time comparison between a
// plain-text password and Argon2 hash, using the parameters, secret and salt
// contained in the hash. It returns true if they match, otherwise it returns
// false.
func ComparePasswordAndHash(password, secret, hash string) (match bool, err error) {
	match, _, err = CheckHash(password, secret, hash)
	return match, err
}

// CheckHash is like ComparePasswordAndHash, except it also returns the params that the hash was
// created with. This can be useful if you want to update your hash params over time (which you
// should).
func CheckHash(password, secret, hash string) (match bool, params *Params, err error) {
	argon2Variant, params, salt, key, err := DecodeHash(hash)
	if err != nil {
		return false, nil, err
	}

	var otherKey []byte
	if argon2Variant == argon2i {
		if secret == "" {
			otherKey = Key([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
		}
		if secret != "" {
			otherKey = KeyWithSecret([]byte(password), []byte(secret), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
		}
	}
	if argon2Variant == argon2id {
		if secret == "" {
			otherKey = IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
		}
		if secret != "" {
			otherKey = IDKeyWithSecret([]byte(password), []byte(secret), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
		}
	}

	keyLen := int32(len(key))
	otherKeyLen := int32(len(otherKey))

	if subtle.ConstantTimeEq(keyLen, otherKeyLen) == 0 {
		return false, params, nil
	}
	if subtle.ConstantTimeCompare(key, otherKey) == 1 {
		return true, params, nil
	}
	return false, params, nil
}

// DecodeHash expects a hash created from this package, and parses it to return the params used to
// create it, as well as the variant of argon2, salt and key (password hash).
func DecodeHash(hash string) (argon2Variant int, params *Params, salt, key []byte, err error) {
	argon2Variant = -1 // incompatible variant

	vals := strings.Split(hash, "$")
	if len(vals) != 6 {
		return argon2Variant, nil, nil, nil, ErrInvalidHash
	}

	if vals[1] != "argon2i" && vals[1] != "argon2id" {
		return argon2Variant, nil, nil, nil, ErrIncompatibleVariant
	}
	if vals[1] == "argon2i" {
		argon2Variant = argon2i
	}
	if vals[1] == "argon2id" {
		argon2Variant = argon2id
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return argon2Variant, nil, nil, nil, err
	}
	if version != Version {
		return argon2Variant, nil, nil, nil, ErrIncompatibleVersion
	}

	params = &Params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism)
	if err != nil {
		return argon2Variant, nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return argon2Variant, nil, nil, nil, err
	}
	params.SaltLength = uint32(len(salt))

	key, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return argon2Variant, nil, nil, nil, err
	}
	params.KeyLength = uint32(len(key))

	return argon2Variant, params, salt, key, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
