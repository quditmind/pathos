package main

import (
	"fmt"
	"os"

	"golang.org/x/text/language"
)

func main() {
	tags, _, err := language.ParseAcceptLanguage(os.Getenv("ACCEPT_LANGUAGE"))
	fmt.Println(tags, err)
}
