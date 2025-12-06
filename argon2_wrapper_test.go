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
	tests := []struct {
		name          string
		hash          string
		wantVariant   int
		wantError     bool
		strictNewLine bool // expect ErrInvalidHash if strict newline check works
	}{
		{
			name:        "valid_argon2i",
			hash:        "$argon2i$v=19$m=65536,t=1,p=2$iU5CxpZvvxDy2X3Q4GLjNw$ltpcxJNlwXbPr2KWxM2uLlOroRSt0xfdvyAAWhjJRA8",
			wantVariant: argon2i,
			wantError:   false,
		},
		{
			name:        "valid_argon2id",
			hash:        "$argon2id$v=19$m=65536,t=1,p=2$RmJMUEPYPYPezp1PY4CYdg$E2RuNE2grivEJV2AuW9J11Goxl8iGGHIiCRs/HU4jd4",
			wantVariant: argon2id,
			wantError:   false,
		},
		{
			name:      "zero_$",
			hash:      "_argon2id_v=19_m=65536,t=1,p=2_RmJMUEPYPYPezp1PY4CYdg_E2RuNE2grivEJV2AuW9J11Goxl8iGGHIiCRs/HU4jd4",
			wantError: true,
		},
		{
			name:      "one_$",
			hash:      "$argon2id_v=19_m=65536,t=1,p=2_RmJMUEPYPYPezp1PY4CYdg_E2RuNE2grivEJV2AuW9J11Goxl8iGGHIiCRs/HU4jd4",
			wantError: true,
		},
		{
			name:      "two_$",
			hash:      "$argon2id$v=19_m=65536,t=1,p=2_RmJMUEPYPYPezp1PY4CYdg_E2RuNE2grivEJV2AuW9J11Goxl8iGGHIiCRs/HU4jd4",
			wantError: true,
		},
		{
			name:      "three_$",
			hash:      "$argon2id$v=19$m=65536,t=1,p=2_RmJMUEPYPYPezp1PY4CYdg_E2RuNE2grivEJV2AuW9J11Goxl8iGGHIiCRs/HU4jd4",
			wantError: true,
		},
		{
			name:      "four_$",
			hash:      "$argon2id$v=19$m=65536,t=1,p=2$RmJMUEPYPYPezp1PY4CYdg_E2RuNE2grivEJV2AuW9J11Goxl8iGGHIiCRs/HU4jd4",
			wantError: true,
		},
		{
			name:      "incompatible_variant",
			hash:      "$argon2d$v=19$m=65536,t=1,p=2$salt$key",
			wantError: true,
		},
		{
			name:      "missing_version_section",
			hash:      "$argon2id$m=65536,t=1,p=2$salt$key",
			wantError: true,
		},
		{
			name:      "malformed_version",
			hash:      "$argon2id$v=XX$m=65536,t=1,p=2$salt$key",
			wantError: true,
		},
		{
			name:      "incompatible_version",
			hash:      "$argon2id$v=99$m=65536,t=1,p=2$salt$key",
			wantError: true,
		},
		{
			name:      "missing_params_section",
			hash:      "$argon2id$v=19$salt$key",
			wantError: true,
		},
		{
			name:      "malformed_params",
			hash:      "$argon2id$v=19$m=fail,t=1,p=2$salt$key",
			wantError: true,
		},
		{
			name:      "missing_salt_section",
			hash:      "$argon2id$v=19$m=65536,t=1,p=2$key",
			wantError: true,
		},
		{
			name:      "newline_in_salt",
			hash:      "$argon2id$v=19$m=65536,t=1,p=2$salt\n$key",
			wantError: true,
		},
		{
			name:      "bad_base64_salt",
			hash:      "$argon2id$v=19$m=65536,t=1,p=2$!@#$key",
			wantError: true,
		},
		{
			name:      "missing_key_section",
			hash:      "$argon2id$v=19$m=65536,t=1,p=2$salt",
			wantError: true,
		},
		{
			name:      "newline_in_key",
			hash:      "$argon2id$v=19$m=65536,t=1,p=2$salt$key\n",
			wantError: true,
		},
		{
			name:      "bad_base64_key",
			hash:      "$argon2id$v=19$m=65536,t=1,p=2$salt$!@#",
			wantError: true,
		},
		{
			name:      "extra_fields_at_the_end",
			hash:      "$argon2id$v=19$m=65536,t=1,p=2$salt$key$extra",
			wantError: true,
		},
	}

	for _, tc := range tests {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			variant, params, _, _, err := DecodeHash(tc.hash)
			if tc.wantError {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else {
					return
				}
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if variant != tc.wantVariant {
				t.Errorf("expected variant %d, got %d", tc.wantVariant, variant)
			}
			if params == nil {
				t.Error("expected params, got nil")
			}
		})
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

	// hash contains newline in salt section (which base64 strict ignores but we should catch)
	ok, _, err = CheckHash("bug", "", "$argon2id$v=19$m=65536,t=1,p=2$xXH1+P7o0rwI9/lXEcPWkg\n$HAHY7gZ9CgbAFRQmQLk7v7uDEgomp2CSO/rrEBAvfHg")
	if err == nil {
		t.Fatal("Hash validation should fail for newline in salt")
	}
	if ok {
		t.Fatal("Hash validation should fail for newline in salt")
	}

	// hash contains newline in key section (which base64 strict ignores but we should catch)
	ok, _, err = CheckHash("bug", "", "$argon2id$v=19$m=65536,t=1,p=2$xXH1+P7o0rwI9/lXEcPWkg$HAHY7gZ9CgbAFRQmQLk7v7uDEgomp2CSO/rrEBAvfHg\n")
	if err == nil {
		t.Fatal("Hash validation should fail for newline in key")
	}
	if ok {
		t.Fatal("Hash validation should fail for newline in key")
	}

}

func TestVariant(t *testing.T) {
	// Hash contains wrong variant
	_, _, err := CheckHash("pa$$word", "", "$argon2d$v=19$m=16,t=2,p=1$RDZuTU9Mam1TemlBaUVtNA$iDDBu2UH7maUgYcBWCgTVw")
	if err != ErrIncompatibleVariant {
		t.Fatalf("expected error %s", ErrIncompatibleVariant)
	}
}
