package eol

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func catalog(t *testing.T) *Catalog {
	t.Helper()
	raw, err := os.ReadFile("testdata/products-full.json")
	if err != nil {
		t.Fatal(err)
	}
	ps, asOf, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if asOf == "" || len(ps) != 16 {
		t.Fatalf("as of %q, %d products", asOf, len(ps))
	}
	return NewCatalog(ps)
}

var day = time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)

func TestParseRejectsOtherDocuments(t *testing.T) {
	for _, in := range []string{`[]`, `{"schema_version":"2.0.0","result":[]}`, `{"schema_version":"1.2.1","result":[]}`, `not json`} {
		if _, _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", in)
		}
	}
	// A single product document is accepted.
	one := `{"schema_version":"1.2.1","generated_at":"2026-11-18T09:37:30+00:00","result":{"name":"nodejs","label":"Node.js",
		"identifiers":[{"type":"purl","id":"pkg:docker/library/node"}],"releases":[{"name":"18","isEol":true,"eolFrom":"2025-04-30"}]}}`
	ps, asOf, err := Parse([]byte(one))
	if err != nil || len(ps) != 1 || asOf != "2026-11-18" || ps[0].Cycles[0].EOL == nil || !ps[0].Cycles[0].IsEOL {
		t.Fatalf("%v %q %+v", err, asOf, ps)
	}
}

func TestNormalizePURL(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:npm/%40angular/core@15.2.0":                     "pkg:npm/@angular/core",
		"pkg:npm/@angular/core":                              "pkg:npm/@angular/core",
		"pkg:pypi/Django@3.2.1?arch=x":                       "pkg:pypi/django",
		"pkg:maven/org.springframework.boot/spring-boot@2.7": "pkg:maven/org.springframework.boot/spring-boot",
		"pkg:docker/library/node":                            "pkg:docker/library/node",
		"https://example.com":                                "",
	} {
		if got := NormalizePURL(in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

func TestCycleForAndStatus(t *testing.T) {
	c := catalog(t)
	py := c.Product("python")
	for v, want := range map[string]string{"3.10.4": "3.10", "3.8": "3.8", "v3.12.1": "3.12", "3.1": "", "4.0": ""} {
		got := ""
		if cy := py.CycleFor(v); cy != nil {
			got = cy.Name
		}
		if got != want {
			t.Errorf("python %s: cycle %q, want %q", v, got, want)
		}
	}
	if s := py.CycleFor("3.8.10").Status(day); s != "eol" {
		t.Errorf("python 3.8: %s", s)
	}
	if s := py.CycleFor("3.13").Status(day); s != "supported" {
		t.Errorf("python 3.13: %s", s)
	}
	// Approaching: support ends within six months.
	cy := &Cycle{Name: "x", EOL: ptr(day.Add(90 * 24 * time.Hour))}
	if s := cy.Status(day); s != "approaching" {
		t.Errorf("approaching: %s", s)
	}
	// No date, but the feed says end-of-life.
	if s := (&Cycle{IsEOL: true}).Status(day); s != "eol" {
		t.Errorf("flag: %s", s)
	}
	// Codenames.
	if cy := c.Product("debian").CycleFor("bookworm"); cy == nil || cy.Name != "12" {
		t.Errorf("bookworm: %+v", cy)
	}
	if c.Product("node") == nil || c.Product("node").Name != "nodejs" {
		t.Error("alias node")
	}
}

func ptr(t time.Time) *time.Time { return &t }

func TestMatchImage(t *testing.T) {
	c := catalog(t)
	type m struct{ product, cycle string }
	for ref, want := range map[string][]m{
		"node:18-alpine":                  {{"nodejs", "18"}},
		"docker.io/library/node:16.20.2":  {{"nodejs", "16"}},
		"python:3.8-slim-bullseye":        {{"python", "3.8"}, {"debian", "11"}},
		"python:3.12-alpine3.18":          {{"python", "3.12"}, {"alpine-linux", "3.18"}},
		"debian:bookworm-slim":            {{"debian", "12"}},
		"ubuntu:22.04":                    {{"ubuntu", "22.04"}},
		"alpine:3.18.4":                   {{"alpine-linux", "3.18"}},
		"ghcr.io/acme/app:1.0":            nil,
		"nginx:latest":                    nil,
		"postgres:13@sha256:" + zeros(64): {{"postgresql", "13"}},
	} {
		got := c.MatchImage(ref)
		if len(got) != len(want) {
			t.Errorf("%s: %d matches, want %d", ref, len(got), len(want))
			continue
		}
		for i, w := range want {
			if got[i].Product.Name != w.product || got[i].Cycle.Name != w.cycle {
				t.Errorf("%s: %s %s, want %s %s", ref, got[i].Product.Name, got[i].Cycle.Name, w.product, w.cycle)
			}
		}
	}
}

func zeros(n int) string { return strings.Repeat("0", n) }

func TestComputeAndFindings(t *testing.T) {
	c := catalog(t)
	target := uuid.New()
	in := Inputs{
		Components: []Component{
			{Name: "django", Version: "3.2.18", PURL: "pkg:pypi/django@3.2.18"},
			{Name: "spring-boot", Version: "2.7.18", PURL: "pkg:maven/org.springframework.boot/spring-boot@2.7.18"},
			{Name: "spring-boot-starter-web", Version: "2.7.18", PURL: "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.7.18"},
			{Name: "react", Version: "19.1.0", PURL: "pkg:npm/react@19.1.0"},
			{Name: "left-pad", Version: "1.3.0", PURL: "pkg:npm/left-pad@1.3.0"},
		},
		Runtimes: []Runtime{
			{Kind: "runtime", Name: "node", Version: "16.20.0", Path: ".nvmrc"},
			{Kind: "runtime", Name: "python", Version: "3.13", Path: ".python-version"},
			{Kind: "image", Name: "node:16-bullseye", Path: "Dockerfile"},
		},
		Images: []Image{{TargetID: target, Reference: "registry.example.com/team/api:1.2"}, {TargetID: target, Reference: "python:3.8"}},
	}
	ms := c.Compute(in, day)
	got := map[string]string{}
	for _, m := range ms {
		got[m.Source+" "+m.Product.Name+" "+m.Cycle.Name] = m.Status
	}
	for k, want := range map[string]string{
		"sbom django 3.2": "eol", "sbom spring-boot 2.7": "eol", "sbom react 19": "supported",
		"runtime nodejs 16": "eol", "runtime python 3.13": "supported", "runtime debian 11": "eol",
		"image python 3.8": "eol",
	} {
		if got[k] != want {
			t.Errorf("%s: %q, want %q (all: %v)", k, got[k], want, got)
		}
	}
	if ms[0].Status != "eol" {
		t.Error("end-of-life first")
	}
	fs := Findings(ms, day)
	byRule := map[string]FindingFor{}
	for _, f := range fs {
		byRule[f.Product+"/"+f.Cycle] = f
	}
	// One finding per product cycle: both Spring Boot packages together.
	sb, ok := byRule["spring-boot/2.7"]
	if !ok || !strings.Contains(sb.Description, "spring-boot 2.7.18") || !strings.Contains(sb.Description, "spring-boot-starter-web 2.7.18") {
		t.Fatalf("spring boot: %+v", sb)
	}
	if len(fs) != 5 { // django, spring-boot, nodejs 16, debian 11, python 3.8 (image)
		t.Errorf("%d findings: %v", len(fs), byRule)
	}
	if n := byRule["nodejs/16"]; n.Severity != "high" || n.Path != ".nvmrc" || !strings.Contains(n.Title, "end-of-life") ||
		!strings.Contains(n.Description, "Upgrade to a supported release") {
		t.Errorf("node: %+v", n)
	}
	if py := byRule["python/3.8"]; py.TargetID == nil || *py.TargetID != target || py.Fingerprint == byRule["django/3.2"].Fingerprint {
		t.Errorf("image finding: %+v", py)
	}
	// Fingerprints are stable across runs.
	if again := Findings(c.Compute(in, day), day); again[0].Fingerprint != fs[0].Fingerprint {
		t.Error("unstable fingerprint")
	}
}
