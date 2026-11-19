// Benchmark sample: calls language.ParseAcceptLanguage of golang.org/x/text
// v0.3.7 (GO-2022-1059, reachable). golang.org/x/text/unicode/norm
// (GO-2026-5970) is not used.
package main

import (
	"fmt"
	"os"

	"golang.org/x/text/language"
)

func parse(header string) {
	tags, _, err := language.ParseAcceptLanguage(header)
	fmt.Println(tags, err)
}

func main() {
	parse(os.Getenv("ACCEPT_LANGUAGE"))
}
