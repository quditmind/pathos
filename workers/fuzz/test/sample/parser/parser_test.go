package parser

import "testing"

func FuzzParse(f *testing.F) {
	f.Add([]byte{2, 'h', 'i'})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data)
	})
}

func FuzzChecksum(f *testing.F) {
	f.Add([]byte("abc"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = Checksum(data)
	})
}
