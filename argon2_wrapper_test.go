package argon2

import (
	"regexp"
	"strings"
	"testing"
)

func TestCreateHash(t *testing.T) {
	hashRX, err := regexp.Compile(`^\$argon2i\$v=19\$m=65536,t=1,p=2\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)
	if err != nil {
		t.Fatal(err)
	}

	// without secret
	hash1, err := CreateHash("pa$$word", "", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	if !hashRX.MatchString(hash1) {
		t.Errorf("hash %q not in correct format", hash1)
	}
	hash2, err := CreateHash("pa$$word", "", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Compare(hash1, hash2) == 0 {
		t.Error("hashes must be unique")
	}

	// with secret
	hash1WithSecret, err := CreateHash("pa$$word", "$€cr€t", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	if !hashRX.MatchString(hash1WithSecret) {
		t.Errorf("hash %q not in correct format", hash1WithSecret)
	}
	hash2WithSecret, err := CreateHash("pa$$word", "$€cr€t", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Compare(hash1WithSecret, hash2WithSecret) == 0 {
		t.Error("hashes must be unique")
	}
}

func TestIDCreateHash(t *testing.T) {
	hashRX, err := regexp.Compile(`^\$argon2id\$v=19\$m=65536,t=1,p=2\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)
	if err != nil {
		t.Fatal(err)
	}

	// without secret
	hash1, err := IDCreateHash("pa$$word", "", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	if !hashRX.MatchString(hash1) {
		t.Errorf("hash %q not in correct format", hash1)
	}
	hash2, err := IDCreateHash("pa$$word", "", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Compare(hash1, hash2) == 0 {
		t.Error("hashes must be unique")
	}

	// with secret
	hash1WithSecret, err := IDCreateHash("pa$$word", "$€cr€t", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	if !hashRX.MatchString(hash1WithSecret) {
		t.Errorf("hash %q not in correct format", hash1WithSecret)
	}
	hash2WithSecret, err := IDCreateHash("pa$$word", "$€cr€t", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Compare(hash1WithSecret, hash2WithSecret) == 0 {
		t.Error("hashes must be unique")
	}
}

func TestComparePasswordAndHash(t *testing.T) {
	hash, err := CreateHash("pa$$word", "$€cr€t", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	match, err := ComparePasswordAndHash("pa$$word", "$€cr€t", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Error("expected password and hash to match")
	}
	match, err = ComparePasswordAndHash("otherPa$$word", "$€cr€t", hash)
	if err != nil {
		t.Fatal(err)
	}
	if match {
		t.Error("expected password and hash to not match")
	}

	hash, err = IDCreateHash("pa$$word", "$€cr€t", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	match, err = ComparePasswordAndHash("pa$$word", "$€cr€t", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Error("expected password and hash to match")
	}
	match, err = ComparePasswordAndHash("otherPa$$word", "$€cr€t", hash)
	if err != nil {
		t.Fatal(err)
	}
	if match {
		t.Error("expected password and hash to not match")
	}
}

func TestDecodeHash(t *testing.T) {
	// Argon2i
	hash, err := CreateHash("pa$$word", "$€cr€t", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	argon2Variant, params, _, _, err := DecodeHash(hash)
	if err != nil {
		t.Fatal(err)
	}
	if *params != *DefaultParams {
		t.Fatalf("expected %#v got %#v", *DefaultParams, *params)
	}
	if argon2Variant != argon2i {
		t.Fatalf("argon2 variant: expected %v got %v", argon2i, argon2Variant)
	}

	// Argon2id
	hash, err = IDCreateHash("pa$$word", "$€cr€t", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	argon2Variant, params, _, _, err = DecodeHash(hash)
	if err != nil {
		t.Fatal(err)
	}
	if *params != *DefaultParams {
		t.Fatalf("expected %#v got %#v", *DefaultParams, *params)
	}
	if argon2Variant != argon2id {
		t.Fatalf("argon2 variant: expected %v got %v", argon2id, argon2Variant)
	}
}

func TestCheckHash(t *testing.T) {
	// without secret
	hash, err := CreateHash("pa$$word", "", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	ok, params, err := CheckHash("pa$$word", "", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected password to match")
	}
	if *params != *DefaultParams {
		t.Fatalf("expected %#v got %#v", *DefaultParams, *params)
	}

	// with secret
	hash, err = CreateHash("pa$$word", "$€cr€t", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	ok, params, err = CheckHash("pa$$word", "$€cr€t", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected password to match")
	}
	if *params != *DefaultParams {
		t.Fatalf("expected %#v got %#v", *DefaultParams, *params)
	}
}

func TestStrictDecoding(t *testing.T) {
	// Argon2id without secret
	// password: "bug"
	// secret: ""
	// valid hash: $argon2id$v=19$m=65536,t=1,p=2$UDk0zEuIzbt0x3bwkf8Bgw$ihSfHWUJpTgDvNWiojrgcN4E0pJdUVmqCEdRZesx9tE
	ok, _, err := CheckHash("bug", "", "$argon2id$v=19$m=65536,t=1,p=2$UDk0zEuIzbt0x3bwkf8Bgw$ihSfHWUJpTgDvNWiojrgcN4E0pJdUVmqCEdRZesx9tE")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected password to match")
	}

	// changed one last character of the hash
	ok, _, err = CheckHash("bug", "", "$argon2id$v=19$m=65536,t=1,p=2$UDk0zEuIzbt0x3bwkf8Bgw$ihSfHWUJpTgDvNWiojrgcN4E0pJdUVmqCEdRZesx9tF")
	if err == nil {
		t.Fatal("Hash validation should fail")
	}
	if ok {
		t.Fatal("Hash validation should fail")
	}

	// Argon2id with secret
	// password: "bug"
	// secret: "12€45"
	// valid hash: $argon2id$v=19$m=65536,t=1,p=2$xXH1+P7o0rwI9/lXEcPWkg$HAHY7gZ9CgbAFRQmQLk7v7uDEgomp2CSO/rrEBAvfHg
	ok, _, err = CheckHash("bug", "12€45", "$argon2id$v=19$m=65536,t=1,p=2$xXH1+P7o0rwI9/lXEcPWkg$HAHY7gZ9CgbAFRQmQLk7v7uDEgomp2CSO/rrEBAvfHg")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected password to match")
	}

	// changed one last character of the hash
	ok, _, err = CheckHash("bug", "", "$argon2id$v=19$m=65536,t=1,p=2$xXH1+P7o0rwI9/lXEcPWkg$HAHY7gZ9CgbAFRQmQLk7v7uDEgomp2CSO/rrEBAvfHG")
	if err == nil {
		t.Fatal("Hash validation should fail")
	}
	if ok {
		t.Fatal("Hash validation should fail")
	}
}

func TestVariant(t *testing.T) {
	// Hash contains wrong variant
	_, _, err := CheckHash("pa$$word", "", "$argon2d$v=19$m=16,t=2,p=1$RDZuTU9Mam1TemlBaUVtNA$iDDBu2UH7maUgYcBWCgTVw")
	if err != ErrIncompatibleVariant {
		t.Fatalf("expected error %s", ErrIncompatibleVariant)
	}
}
