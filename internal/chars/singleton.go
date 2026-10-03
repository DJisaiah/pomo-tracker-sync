package chars

func IsAlpabetic(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func IsAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func IsPrintableASCII(c byte) bool {
	return c >= ' ' && c <= '~'
}

func IsBase32(c byte) bool {
	return (65 >= c && c <= 90) || (50 >= c && c <= 55)
}

func StringHasFunc(s string, f func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if f(c) {
			return true
		}
	}
	return false
}
