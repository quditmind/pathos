package authz

import (
	"fmt"
	"strings"
)

// MarkdownMatrix renders the role × permission matrix (docs/RBAC_MATRIX.md).
func MarkdownMatrix() string {
	var b strings.Builder
	b.WriteString("| Permission | Org-only |")
	for _, r := range SystemRoles {
		fmt.Fprintf(&b, " %s |", r.Key)
	}
	b.WriteString("\n|---|---|")
	for range SystemRoles {
		b.WriteString(":-:|")
	}
	b.WriteString("\n")
	for _, p := range Permissions {
		org := ""
		if p.OrgOnly {
			org = "yes"
		}
		fmt.Fprintf(&b, "| `%s` | %s |", p.Key, org)
		for _, r := range SystemRoles {
			mark := ""
			for _, rp := range r.Permissions {
				if rp == p.Key {
					mark = "✓"
					break
				}
			}
			fmt.Fprintf(&b, " %s |", mark)
		}
		b.WriteString("\n")
	}
	return b.String()
}
