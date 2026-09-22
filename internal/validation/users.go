package validation

import (
	"bufio"
	_ "embed"
	"log"
	"strings"

	"github.com/DJisaiah/pomotracker-sync/internal/chars"
)

func domainWhitelist(c byte) bool {
	switch c {
	case '.', '-':
		return true
	default:
		return chars.IsAlphanumeric(c)
	}
}

func localWhitelist(c byte) bool {
	switch c {
	case '.', '_', '-', '+', '%':
		return true
	default:
		return chars.IsAlphanumeric(c)
	}
}

func (v *Validator) Email(e string) bool {
	l := len(e)
	if l < 6 || l > 254 { // needs to be 6 considering TLD must be min 2
		return false
	} else if !chars.IsAlphanumeric(e[0]) { // alphanumeric start
		return false
	} else if !chars.IsAlpabetic(e[l-1]) { // alphabetic end
		return false
	}

	inLocal, inDomain := true, false
	priorNonAlpha := false
	domainLabelLength := 0
	tldIndex := -1
	for i := range l {
		c := e[i]
		switch {
		case c == '@': // only one '@' allowed
			if !inLocal || (i > 64) { // 1 <= local <= 64
				return false
			} else if chars.NextCharIs(e, '-', i) {
				return false // no hyphens at domain label start
			} else if !chars.PrevCharIsFn(e, i, chars.IsAlphanumeric) {
				return false // local cannot end with non-alphanumeric
			}
			inLocal, inDomain = false, true
		case inLocal && localWhitelist(c):
			if !chars.IsAlphanumeric(c) {
				if priorNonAlpha { // no adj symbols
					return false
				}
				priorNonAlpha = true
				continue
			}
			priorNonAlpha = false
		case inDomain && domainWhitelist(c):
			if c == '.' {
				if !chars.PrevCharIsFn(e, i, chars.IsAlphanumeric) {
					return false
				} else if chars.NextCharIs(e, '-', i) {
					return false
				}
				tldIndex = i
				if domainLabelLength < 1 || domainLabelLength > 63 {
					return false
				}
				domainLabelLength = 0
				continue
			}
			domainLabelLength += 1

		default:
			return false
		}
	}

	if tldIndex == -1 ||
		(l-1-tldIndex) < 2 ||
		(l-1-tldIndex) > 63 { // proper tld required
		return false
	}
	for i := tldIndex + 1; i < l; i++ {
		if !chars.IsAlpabetic(e[i]) {
			return false
		}
	}
	return true
}

//go:embed data/common-passwords.txt
var passwords string

func (v *Validator) loadPasswords() error {
	sc := bufio.NewScanner(strings.NewReader(passwords))
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
	l := len(p)
	if l < 15 || l > 64 {
		return false
	}

	for i := range l {
		if !chars.IsPrintableASCII(p[i]) {
			return false
		}
	}

	np := strings.ToLower(p)
	if _, ok := v.commonPasswords[np]; ok {
		return false
	}
	return true

}

//go:embed data/disallowed-usernames.txt
var usernames string

func (v *Validator) loadUsernames() error {
	sc := bufio.NewScanner(strings.NewReader(usernames))
	for sc.Scan() {
		v.disallowedUsernames[sc.Text()] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		log.Printf("Failed to scan disallowed usernames: %s", err)
		return err
	}
	return nil
}

func (v *Validator) Username(u string) bool {
	nu := strings.ToLower(u)
	l := len(nu)
	if l < 3 || l > 30 {
		return false
	}

	for i := range l {
		if !chars.IsAlphanumeric(nu[i]) {
			return false
		}
	}

	if _, ok := v.disallowedUsernames[nu]; ok {
		return false
	}

	return true
}
