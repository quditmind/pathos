// Package parser is the PATHOS worker-fuzz test sample: a length-prefixed
// record parser with a planted bug (it trusts the length byte), found by
// FuzzParse.
package parser

import "errors"

// Parse reads records of the form <len><bytes...>.
func Parse(data []byte) ([][]byte, error) {
	var out [][]byte
	for i := 0; i < len(data); {
		n := int(data[i])
		if n == 0 {
			return nil, errors.New("empty record")
		}
		// Bug: no check that i+1+n <= len(data).
		out = append(out, data[i+1:i+1+n])
		i += 1 + n
	}
	return out, nil
}

// Checksum is correct and never crashes.
func Checksum(data []byte) byte {
	var c byte
	for _, b := range data {
		c ^= b
	}
	return c
}
