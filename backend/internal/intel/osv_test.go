package intel

import (
	"archive/zip"
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestParseOSV(t *testing.T) {
	raw, err := os.ReadFile("testdata/osv-ghsa.json")
	if err != nil {
		t.Fatal(err)
	}
	vs, err := ParseOSV(raw, "osv-file")
	if err != nil || len(vs) != 1 {
		t.Fatalf("%v %d", err, len(vs))
	}
	v := vs[0]
	if v.ID != "GHSA-xvch-5gv4-984h" || len(v.Aliases) != 1 || v.Aliases[0] != "CVE-2021-44906" || v.Summary != "Prototype Pollution in minimist" {
		t.Errorf("record: %+v", v)
	}
	if len(v.CVSS) != 1 || !strings.HasPrefix(v.CVSS[0], "CVSS:3.1/") || len(v.CWEs) != 1 || v.CWEs[0] != "CWE-1321" {
		t.Errorf("cvss/cwe: %v %v", v.CVSS, v.CWEs)
	}
	if v.ExploitRefs != 0 || len(v.References) == 0 || v.Published == nil {
		t.Errorf("references: %d %d", v.ExploitRefs, len(v.References))
	}
	if len(v.Affected) == 0 || v.Affected[0].Package != "minimist" || len(v.Affected[0].Fixed) == 0 {
		t.Errorf("affected: %+v", v.Affected)
	}

	// An array with an exploit reference; invalid ids and unsafe URLs are dropped.
	arr := []byte(`[{"id":"CVE-2099-0001","references":[{"type":"EVIDENCE","url":"https://exploit.example/poc"},
	  {"type":"WEB","url":"javascript:alert(1)"}]},{"id":"bad id with spaces"}]`)
	vs, err = ParseOSV(arr, "osv-file")
	if err != nil || len(vs) != 1 || vs[0].ExploitRefs != 1 || len(vs[0].References) != 1 {
		t.Fatalf("array: %v %+v", err, vs)
	}

	// A zip export (OSV all.zip layout: one record per file).
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"GHSA-xvch-5gv4-984h.json", "README.md"} {
		w, _ := zw.Create(name)
		_, _ = w.Write(raw)
	}
	_ = zw.Close()
	if vs, err := ParseOSV(buf.Bytes(), "osv-file"); err != nil || len(vs) != 1 {
		t.Fatalf("zip: %v %d", err, len(vs))
	}
	if _, err := ParseOSV([]byte(`{"nope": 1}`), "osv-file"); err == nil {
		t.Error("a document without records must fail")
	}
}

func TestPickVector(t *testing.T) {
	id := uuid.New()
	f, ok := pickVector(id, []string{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
	if !ok || f.ver != "3.1" || f.score == nil || *f.score != 9.8 {
		t.Errorf("3.1 preferred with its base score: %+v", f)
	}
	if f, ok := pickVector(id, []string{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}); !ok || f.score != nil || f.ver != "4.0" {
		t.Errorf("4.0 has no computed score: %+v", f)
	}
	if _, ok := pickVector(id, []string{"garbage"}); ok {
		t.Error("invalid vectors are ignored")
	}
}

func TestPURLs(t *testing.T) {
	for purl, want := range map[string][3]string{
		"pkg:npm/%40babel/core@7.0.0":            {"npm", "@babel/core", "pkg:npm/%40babel/core"},
		"pkg:npm/@babel/core@7.0.0":              {"npm", "@babel/core", "pkg:npm/@babel/core"},
		"pkg:npm/lodash@4.17.20?package-id=abc":  {"npm", "lodash", "pkg:npm/lodash"},
		"pkg:pypi/PyYAML@6.0":                    {"pypi", "pyyaml", "pkg:pypi/PyYAML"},
		"pkg:golang/github.com/gin-gonic/gin@v1": {"go", "github.com/gin-gonic/gin", "pkg:golang/github.com/gin-gonic/gin"},
		"pkg:maven/org.apache.commons/commons-text@1.9": {"maven", "org.apache.commons:commons-text", "pkg:maven/org.apache.commons/commons-text"},
	} {
		sys, name, ok := PURLPackage(purl)
		if !ok || sys != want[0] || name != want[1] || PURLBase(purl) != want[2] {
			t.Errorf("%s: %s %s %v %s", purl, sys, name, ok, PURLBase(purl))
		}
	}
	if _, _, ok := PURLPackage("pkg:deb/debian/openssl@3"); ok {
		t.Error("unsupported ecosystems are skipped")
	}
}
