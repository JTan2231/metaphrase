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
