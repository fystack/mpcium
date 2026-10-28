package main

import "unicode"

func ContainsAtLeastNSpecial(s string, n int) bool {
	count := 0
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			count++
			if count >= n {
				return true
			}
		}
	}
	return false
}
