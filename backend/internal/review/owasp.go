package review

import (
	"sort"
	"strconv"
	"strings"
)

// OWASP Top 10 (2021) categories by CWE, from the CWE lists OWASP publishes
// for each category. Classifications derived here are labelled as derived
// in the UI; scanners rarely report OWASP categories themselves.
var owaspCategories = []struct {
	ID, Name string
	CWEs     []int
}{
	{"A01:2021", "Broken Access Control", []int{22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540,
		548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275}},
	{"A02:2021", "Cryptographic Failures", []int{261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338,
		340, 347, 523, 720, 757, 759, 760, 780, 818, 916}},
	{"A03:2021", "Injection", []int{20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100, 113, 116, 138, 184, 470,
		471, 564, 610, 643, 644, 652, 917}},
	{"A04:2021", "Insecure Design", []int{73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501,
		522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173}},
	{"A05:2021", "Security Misconfiguration", []int{2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174}},
	{"A06:2021", "Vulnerable and Outdated Components", []int{937, 1035, 1104}},
	{"A07:2021", "Identification and Authentication Failures", []int{255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384,
		521, 613, 620, 640, 798, 940, 1216}},
	{"A08:2021", "Software and Data Integrity Failures", []int{345, 353, 426, 494, 502, 565, 784, 829, 830, 915}},
	{"A09:2021", "Security Logging and Monitoring Failures", []int{117, 223, 532, 778}},
	{"A10:2021", "Server-Side Request Forgery (SSRF)", []int{918}},
}

// OWASPFor derives OWASP Top 10 categories from CWE identifiers ("CWE-89")
// and the finding category (dependency findings map to A06).
func OWASPFor(cwes []string, category string) []string {
	seen := map[string]bool{}
	for _, c := range cwes {
		n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CWE-"))
		if err != nil {
			continue
		}
		for _, cat := range owaspCategories {
			for _, x := range cat.CWEs {
				if x == n {
					seen[cat.ID+" "+cat.Name] = true
				}
			}
		}
	}
	if category == "sca" || category == "container" {
		seen["A06:2021 Vulnerable and Outdated Components"] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
