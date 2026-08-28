package chars

func NextCharIs(e string, c byte, i int) bool {
	if i >= 0 && i < len(e)-1 {
		if e[i+1] == c {
			return true
		}
	}
	return false
}

func NextCharIsFn(e string, c byte, i int, fn func(byte) bool) bool {
	if i >= 0 && i < len(e)-1 {
		return fn(e[i+1])
	}
	return false
}

func PrevCharIs(e string, c byte, i int) bool {
	if i > 0 && i < len(e) {
		if e[i-1] == c {
			return true
		}
	}
	return false
}

func PrevCharIsFn(e string, i int, fn func(byte) bool) bool {
	if i > 0 && i < len(e) {
		return fn(e[i-1])
	}
	return false
}
