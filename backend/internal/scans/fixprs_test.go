package scans

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/scm"
)

func TestFixBranchName(t *testing.T) {
	id := uuid.MustParse("01890a5d-ac96-774b-bcce-b302099a8057")
	for _, c := range [][3]string{
		{"npm", "@babel/core", "7.23.2"},
		{"maven", "org.apache.logging.log4j:log4j-core", "2.17.1"},
		{"pypi", "Django", "4.2.11"},
		{"nuget", strings.Repeat("x", 300), "1.0.0"},
		{"pypi", "a..b", "1..2"},
	} {
		b := FixBranchName(id, c[0], c[1], c[2])
		if !scm.ValidFixBranch(b) {
			t.Errorf("FixBranchName(%v) = %q is not a valid fix branch", c, b)
		}
		if !strings.HasSuffix(b, "-099a8057") {
			t.Errorf("branch %q lacks the request suffix", b)
		}
	}
}

func TestFixPRBodyEscapes(t *testing.T) {
	body := fixPRBody("pkg`<x>", "1", "2", "npm", "main", []fixFindingLine{{ID: uuid.New(), Title: "evil\n<script>", CVE: "CVE-1", Severity: "high"}},
		[]string{"package.json"}, nil, "https://pathos.example")
	if strings.Contains(body, "<script>") || strings.Contains(body, "pkg`") {
		t.Errorf("unescaped body: %s", body)
	}
	if !strings.Contains(body, "later scan of `main`") || !strings.Contains(body, "https://pathos.example/findings?finding=") {
		t.Errorf("body: %s", body)
	}
}
