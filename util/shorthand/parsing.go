package shorthand

import (
	"log"
	"regexp"
)

func MakeRegex(pattern string) *regexp.Regexp {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		log.Fatal(err)
	}

	return regex
}

func CheckError(e error) {
	if e != nil {
		panic(e)
	}
}

func Max(a int, b int) int {
	if a > b {
		return a
	}

	return b
}

func Min(a int, b int) int {
	if a < b {
		return a
	}

	return b
}
