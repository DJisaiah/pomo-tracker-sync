package validation

import (
	"bufio"
	"log"
	"os"
	"path/filepath"

	"github.com/DJisaiah/pomotracker-sync/internal/chars"
)

func validPartChar(c byte, isDomain bool) bool {
	switch {
	case chars.IsAlpabetic(c):
		return true
	case (c >= '0' && c <= '9'):
		return true
	case !isDomain && (c == '.' || c == '_' || c == '-' || c == '+' || c == '%' || c == '@'):
		return true
	case isDomain && (c == '.' || c == '-'):
		return true
	default:
		return false
	}
}

// WHATWG HTML5 specification combined with OWASP defensive validation
// stdlib accepts legacy features which we don't want esp ito security
func (v *Validator) Email(e string) bool {
	l := len(e)
	if l < 3 || l > 254 {
		return false

	} else if !chars.IsAlphanumeric(e[0]) { // alphanumeric start
		return false
	} else if !chars.IsAlpabetic(e[l-1]) { // alphabetic end
		return false
	}

	atr, tld := false, false
	tldI := -1
	for i := 0; i < l; i++ {
		c := e[i]
		if !validPartChar(c, atr) { // local and domain character whitelist
			return false
		} else if c == '@' {
			if atr { // only 1 @ allowed
				return false
			} else if i < 1 || i > 64 { // Local part must be between 1 and 64 characters long
				return false
			} else if !chars.PrevCharIsFn(e, i, chars.IsAlphanumeric) { // Local part cannot end non alphanumeric
				return false
			} else if chars.NextCharIs(e, '.', i) || chars.NextCharIs(e, '-', i) { // cant start with a dot/hyphen after @
				return false
			}
			atr = true
			// hyphen rules
		} else if c == '-' && (chars.PrevCharIs(e, '.', i) || chars.NextCharIs(e, '.', i)) {
			return false
		} else if !atr {
			if !chars.IsAlphanumeric(c) { // no adjacent symbols
				if !chars.PrevCharIsFn(e, i, chars.IsAlphanumeric) {
					return false
				}
			}
		} else if atr {
			if c == '.' {
				if chars.NextCharIs(e, '.', i) { // cannot have consecutive dots
					return false
				}
				tldI = i + 1
				tld = true
			}
		}
	}

	if !atr {
		return false // minimum 1 @
	} else if !tld {
		return false // needs a top level domain
	} else if tld && (l-tldI < 2) { // tld must be at least 2 chars long
		return false
	} else if tld {
		for i := tldI; i < len(e); i++ {
			if !chars.IsAlpabetic(e[i]) {
				return false // tld must be alphabetic
			}
		}
	}
	return true
}

func (v *Validator) loadPasswords() error {
	path := filepath.Join(".", "data", "common-passwords.txt")
	passwords, err := os.Open(path)
	if err != nil {
		return err
	}
	defer passwords.Close()
	sc := bufio.NewScanner(passwords)
	for sc.Scan() {
		v.commonPasswords[sc.Text()] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		log.Printf("Failed to scan common passwords: %s", err)
		return err
	}
	return nil
}

func (v *Validator) Password(p string) bool {
	if 15 < len(p) && len(p) > 64 {
		return false
	}
	if _, ok := v.commonPasswords[p]; ok {
		return false
	}
	return true

}

func (v *Validator) loadUsernames() error {
	path := filepath.Join(".", "data", "disallowed-usernames.txt")
	usernames, err := os.Open(path)
	if err != nil {
		return err
	}
	defer usernames.Close()
	sc := bufio.NewScanner(usernames)
	for sc.Scan() {
		v.disallowedUsernames[sc.Text()] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		log.Printf("Failed to scan disallowed usernames: %s", err)
		return err
	}
	return nil
}

// username must be normalised before validation
func (v *Validator) Username(u string) bool {
	l := len(u)
	if l < 3 || l > 30 {
		return false
	} else if !chars.IsAlphanumeric(u[0]) { // alphanumeric start
		return false
	} else if !chars.IsAlpabetic(u[l-1]) { // alphabetic end
		return false
	}

	for i := 1; i < l-1; i++ {
		if !chars.IsAlphanumeric(u[i]) {
			return false
		}
	}

	if _, ok := v.disallowedUsernames[u]; ok {
		return false
	}

	return true
}
