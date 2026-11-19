// Benchmark sample: a method of norm.Form (GO-2026-5970 lists Form.String,
// Form.Bytes, ...) is called through reflection, by a name from the
// command line. govulncheck sees the package imported but no call.
package main

import (
	"fmt"
	"os"
	"reflect"

	"golang.org/x/text/unicode/norm"
)

func main() {
	form := reflect.ValueOf(norm.NFC)
	out := form.MethodByName(os.Args[1]).Call([]reflect.Value{reflect.ValueOf(os.Args[2])})
	fmt.Println(out[0].Interface())
}
