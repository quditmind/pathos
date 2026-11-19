package scanners

import (
	"encoding/json"
	"slices"
	"strings"
)

// labeled returns "label: v", or "" when v is empty (for joinText).
func labeled(label, v string) string {
	if strings.TrimSpace(v) == "" {
		return ""
	}
	return label + ": " + strings.TrimSpace(v)
}

// firstKeys returns the keys of the first element of an array document,
// or of the array in field of an object document (nil when there is none).
func (p *importProbe) firstKeys(field string) map[string]json.RawMessage {
	if p.kind == "array" {
		return p.keys
	}
	return p.firstOf(field)
}

// sortedStrings returns v sorted (for stable descriptions built from maps).
func sortedStrings(v []string) []string {
	slices.Sort(v)
	return v
}
