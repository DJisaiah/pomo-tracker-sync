package validation_test

import (
	"testing"

	"github.com/DJisaiah/pomotracker-sync/internal/validation"
)

func TestUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		want     bool
	}{
		{"too short -> 2 characters", "bo", false},
		{"too short -> 1 character", "b", false},
		{"too short -> 0 characters", "", false},
		{"too long -> 31 characters", "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiii", false},

		{"not fully alphanumeric -> 1 non-alpha", "bobdylan#", false},
		{"not fully alphanumeric -> two non alphas", "b0bdy1an@%", false},
		{"not fully alphanumeric -> non-ASCII characters", "usér", false},
		{"not fully alphanumeric -> includes space", "bob dylan", false},
		{"not fully alphanumeric -> leading non-alpha", "*bobdylan", false},
		{"not fully alphanumeric -> trailing non-alpha", "bobdylan*", false},
		{"not fully alphanumeric -> middle non-alpha", "bob*dylan", false},
		{"not fully alphanumeric -> leading control characters", "\tbobdylan", false},
		{"not fully alphanumeric -> null terminator", "\x00bobdylan", false},

		{"disallowed username 1", "about", false},
		{"disallowed username 1 (case insensitive)", "ABoUt", false},
		{"disallowed username 2", "sixsixsix", false},

		{"valid shorter username 1", "poi", true},
		{"valid shorter username 1 (case insensitive)", "POI", true},
		{"valid shorter username 2", "p0i", true},
		{"valid shorter numeric username", "1234", true},
		{"valid longer numeric username", "123457891011", true},
		{"valid longer username 1", "bobdylan", true},
		{"valid longer username 2", "b0bdy1an", true},

		{"leading disallowed username", "sixsixsixseven", true},
		{"trailing disallowed username", "sevenabout", true},
		{"middle disallowed username", "fivesixsixsixseven", true},

		{"exact min length (3)", "nao", true},
		{"exact max length (30)", "iiiiiiiiiiiiiiiiiiiiiiiiiiiiii", true},
	}
	v, err := validation.NewValidator()
	if err != nil {
		t.Fatalf("Failed to create validator: %s", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.Username(tt.username)
			if got != tt.want {
				t.Errorf("Username(%s) = %t, want %t", tt.username, got, tt.want)
			}
		})
	}
}

func TestPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{"empty", "", false},
		{"too short -> length 1", "1", false},
		{"too short -> length 2", "12", false},
		{"too short -> length 3", "123", false},
		{"too short -> length 14", "iiiiiiiiiiiiii", false},
		{"too long -> length 65", "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii", false},

		{"non-printable ascii -> leading", "\x01iiiiiiiiiiiiiii", false},
		{"non-printable ascii -> trailing", "iiiiiiiiiiiiiii\x01", false},
		{"non-printable ascii -> middle", "iiii\x01iiiiiiii", false},
		{"non-printable ascii -> null terminator", "\x00iiiiiiiiiiiiiii", false},
		{"non-printable ascii -> del", "\x7Fiiiiiiiiiiiiiii", false},

		{"accented characters", "friendofArrianusér", false},

		{"common password", "friendofArriane", false},
		{"common password -> mixed case", "FrIendOfArriane", false},
		{"common password", "11111111111111111111", false},

		{"minimum length", "iiiiiiiiiiiiiii", true},
		{"max length", "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii", true},

		{"valid password 1", "1234567890burgerville", true},
		{"valid password 2", "correct horse battery staple", true},
		{"valid password 3", "huggingBerries%@1bob", true},
	}
	v, err := validation.NewValidator()
	if err != nil {
		t.Fatalf("Failed to create validator: %s", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.Password(tt.password)
			if got != tt.want {
				t.Errorf("Password(%s) = %t, want %t", tt.password, got, tt.want)
			}
		})
	}
}

func TestEmail(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  bool
	}{
		{"too short -> length 1", "@", false},
		{"too short -> length 5", "@b.co", false},
		{"too long -> length of 255", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.comm", false},

		{"no @", "a.b.co", false},
		{"multiple @ 1", "a@b@c.co", false},
		{"multiple @ 2", "a@@d.co", false},

		{"adjacent non-alphanumerics -> consecutive dots in local", "a..b@c.co", false},
		{"adjacent non-alphanumerics -> consecutive dots in domain", "a@b..c.com", false},
		{"adjacent non-alphanumerics -> consecutive symbols in local", "a%+b@c.com", false},

		{"non-alphanumeric start", "!a@b.co", false},
		{"non-alphanumeric end", "a@b.co!", false},

		{"local of length 0", "@baker.com", false},
		{"local of length 64", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@baker.com", true},
		{"local of length 65", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@baker.com", false},
		{"local ends with non-alphanumeric", "a+@baker.com", false},

		{"domain with no dots", "a@bcom", false},
		{"domain label longer than 63 characters", "a@dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.co", false},
		{"domain label cannot start with a hyphen", "a@-b.co", false},
		{"domain label cannot end with a hyphen", "a@b-.co", false},
		{"domain with symbols other than hyphen/dots", "a@b.z%m", false},

		{"tld shorter than 2 chars", "a@b.c", false},
		{"tld shorter than 2 chars with longer local", "aa@b.c", false},
		{"non-alphabetic tld 1", "a@b.co-p", false},
		{"non-alphabetic tld 2", "a@b.co1p", false},

		{"valid email -> length of 6", "a@b.co", true},
		{"valid email -> length of 7", "a@b.com", true},
		{"valid email -> length of 254", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.com", true},
		{"valid email -> domain label with hyphens", "a@b-c.co", true},
		{"valid email -> other symbols in local 1", "a.d@b.co", true},
		{"valid email -> other symbols in local 2", "a_d@b.co", true},
		{"valid email -> other symbols in local 3", "a-d@b.co", true},
		{"valid email -> other symbols in local 4", "a+d@b.co", true},
		{"valid email -> other symbols in local 5", "a%d@b.co", true},
		{"valid email -> consecutive symbols in domain", "a@b--c.com", true},
		{"valid email -> two separated symbols in local", "a.b+c@domain.com", true},
		{"valid email -> subdomain with hyphen", "user@sub-domain.example.com", true},
		{"valid email -> subdomain with number", "user@mail.server2.com", true},
		{"valid email -> subdomain with hyphen", "user@sub.domain-name.com", true},
	}
	v, err := validation.NewValidator()
	if err != nil {
		t.Fatalf("Failed to create validator: %s", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.Email(tt.email)
			if got != tt.want {
				t.Errorf("Email(%s) = %t, want %t", tt.email, got, tt.want)
			}
		})
	}
}
