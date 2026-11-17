package intel

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

const epssCSV = `#model_version:v2025.03.14,score_date:2026-11-16T12:55:00Z
cve,epss,percentile
CVE-2021-44228,0.94358,0.99962
CVE-2024-0001,0.00043,0.11
not-a-cve,0.5,0.5
CVE-2024-0002,abc,0.1
`

func TestParseEPSS(t *testing.T) {
	var got []EPSSRow
	asOf, n, err := ParseEPSS(strings.NewReader(epssCSV), func(r EPSSRow) error { got = append(got, r); return nil })
	if err != nil || n != 2 || asOf != "2026-11-16T12:55:00Z" {
		t.Fatalf("asOf=%q n=%d err=%v", asOf, n, err)
	}
	if got[0].CVE != "CVE-2021-44228" || got[0].Percentile != 0.99962 {
		t.Errorf("row: %+v", got[0])
	}
	// gzip is detected.
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write([]byte(epssCSV))
	_ = zw.Close()
	if _, n, err := ParseEPSS(&b, func(EPSSRow) error { return nil }); err != nil || n != 2 {
		t.Errorf("gzip: %d %v", n, err)
	}
	if _, _, err := ParseEPSS(strings.NewReader("a,b\n1,2\n"), func(EPSSRow) error { return nil }); err == nil {
		t.Error("wrong columns must fail")
	}
	if _, _, err := ParseEPSS(strings.NewReader("cve,epss,percentile\n"), func(EPSSRow) error { return nil }); err == nil {
		t.Error("an empty file must fail")
	}
}

func TestParseKEV(t *testing.T) {
	c, err := ParseKEV(strings.NewReader(`{"catalogVersion":"2026.11.16","vulnerabilities":[
		{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2","dueDate":"2021-12-24","knownRansomwareCampaignUse":"Known"},
		{"cveID":"bogus"}]}`))
	if err != nil || len(c.Vulnerabilities) != 1 || c.Version != "2026.11.16" || c.Vulnerabilities[0].Product != "Log4j2" {
		t.Fatalf("%+v %v", c, err)
	}
	if date(c.Vulnerabilities[0].DueDate) == nil {
		t.Error("due date")
	}
	if _, err := ParseKEV(strings.NewReader(`{"vulnerabilities":[]}`)); err == nil {
		t.Error("empty catalog must fail")
	}
	if _, err := ParseKEV(strings.NewReader(`<html>`)); err == nil {
		t.Error("non-JSON must fail")
	}
}
