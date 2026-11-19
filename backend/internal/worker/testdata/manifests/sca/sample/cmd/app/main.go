// Sample program for the worker-sca fixtures: it calls language.Parse of
// golang.org/x/text v0.3.7 (GO-2022-1059), so govulncheck reports the
// vulnerability at symbol level.
package main

import (
	"fmt"
	"os"

	"golang.org/x/text/language"
)

func main() {
	tag, err := language.Parse(os.Args[1])
	fmt.Println(tag, err)
}
