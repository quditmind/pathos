package eol

import (
	"regexp"
	"strings"
	"time"
)

// ApproachingWindow: a cycle whose support ends within this window is
// "approaching" end of life.
const ApproachingWindow = 180 * 24 * time.Hour

// Catalog indexes products for matching.
type Catalog struct {
	Products []Product
	byPURL   map[string]int
	byName   map[string]int
}

// NewCatalog builds the indexes.
func NewCatalog(ps []Product) *Catalog {
	c := &Catalog{Products: ps, byPURL: map[string]int{}, byName: map[string]int{}}
	for i, p := range ps {
		for _, id := range p.Identifiers {
			if _, dup := c.byPURL[id]; !dup {
				c.byPURL[id] = i
			}
		}
		c.byName[p.Name] = i
	}
	for i, p := range ps {
		for _, a := range p.Aliases {
			if _, dup := c.byName[a]; !dup {
				c.byName[a] = i
			}
		}
	}
	return c
}

// Product returns a product by name or alias.
func (c *Catalog) Product(name string) *Product {
	if c == nil {
		return nil
	}
	if i, ok := c.byName[strings.ToLower(name)]; ok {
		return &c.Products[i]
	}
	return nil
}

// ByPURL returns the product a package URL belongs to.
func (c *Catalog) ByPURL(purl string) *Product {
	if c == nil {
		return nil
	}
	if i, ok := c.byPURL[NormalizePURL(purl)]; ok {
		return &c.Products[i]
	}
	return nil
}

var leadingVersionRe = regexp.MustCompile(`^[vV]?(\d+(?:\.\d+){0,3})`)

// CycleFor returns the release cycle a version belongs to: the longest
// cycle name that equals the version or prefixes it at a dot boundary
// ("3.11" for 3.11.4, "18" for 18.17.0). Cycles that are not numeric are
// matched exactly or by codename.
func (p *Product) CycleFor(version string) *Cycle {
	if p == nil {
		return nil
	}
	v := strings.TrimSpace(version)
	if m := leadingVersionRe.FindStringSubmatch(v); m != nil {
		v = m[1]
	}
	var best *Cycle
	for i := range p.Cycles {
		c := &p.Cycles[i]
		n := c.Name
		if v == n || strings.HasPrefix(v, n+".") {
			if best == nil || len(n) > len(best.Name) {
				best = c
			}
		}
	}
	if best == nil && v == strings.TrimSpace(version) {
		// A codename ("bookworm", "jammy").
		lv := strings.ToLower(v)
		for i := range p.Cycles {
			c := &p.Cycles[i]
			if f := strings.Fields(strings.ToLower(c.Codename)); len(f) > 0 && f[0] == lv {
				return c
			}
		}
	}
	return best
}

// Status is eol, approaching or supported on a date.
func (c *Cycle) Status(now time.Time) string {
	if c.EOL != nil {
		switch {
		case !now.Before(*c.EOL):
			return "eol"
		case c.EOL.Sub(now) <= ApproachingWindow:
			return "approaching"
		}
		return "supported"
	}
	if c.IsEOL {
		return "eol"
	}
	return "supported"
}

// runtimeProducts maps runtime names declared in repositories to products.
// Java versions use the Eclipse Temurin (OpenJDK) support dates.
var runtimeProducts = map[string]string{"node": "nodejs", "python": "python", "ruby": "ruby", "go": "go", "java": "eclipse-temurin",
	"dotnet": "dotnet", "php": "php"}

// RuntimeProduct is the product of a declared runtime.
func (c *Catalog) RuntimeProduct(name string) *Product {
	if n, ok := runtimeProducts[strings.ToLower(name)]; ok {
		return c.Product(n)
	}
	return nil
}

// imageProducts maps official image names that endoflife.date lists
// without a docker package URL.
var imageProducts = map[string]string{"debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine-linux", "nginx": "nginx", "php": "php",
	"httpd": "apache-http-server", "tomcat": "tomcat", "eclipse-temurin": "eclipse-temurin", "mongo": "mongodb", "rabbitmq": "rabbitmq",
	"elasticsearch": "elasticsearch", "centos": "centos", "fedora": "fedora", "rockylinux": "rocky-linux", "almalinux": "almalinux",
	"haproxy": "haproxy", "kibana": "kibana", "logstash": "logstash", "solr": "solr", "jenkins": "jenkins", "sonarqube": "sonar",
	"amazoncorretto": "amazon-corretto", "erlang": "erlang", "perl": "perl", "django": "django", "busybox": "busybox"}

// ImageMatch is a product found in a container image reference.
type ImageMatch struct {
	Product *Product
	Cycle   *Cycle
	Version string
	// Base: the operating system named in the tag (node:18-bullseye).
	Base bool
}

// ParseImageRef splits a reference into repository path (without the
// registry) and tag.
func ParseImageRef(ref string) (repo, tag string) {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.Index(ref, "/"); i > 0 {
		first := ref[:i]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			ref = ref[i+1:]
		}
	}
	if i := strings.LastIndex(ref, ":"); i > 0 && !strings.Contains(ref[i:], "/") {
		ref, tag = ref[:i], ref[i+1:]
	}
	repo = strings.ToLower(strings.TrimPrefix(ref, "library/"))
	return repo, tag
}

var alpineTagRe = regexp.MustCompile(`^alpine(\d+\.\d+)$`)

// MatchImage finds the products (and cycles) of an image reference: the
// image itself (node:18 → Node.js 18) and its base operating system when
// the tag names one (node:18-bullseye → Debian 11, python:3.12-alpine3.20 →
// Alpine 3.20).
func (c *Catalog) MatchImage(ref string) []ImageMatch {
	if c == nil {
		return nil
	}
	repo, tag := ParseImageRef(ref)
	if repo == "" {
		return nil
	}
	name := repo
	if i := strings.LastIndex(repo, "/"); i >= 0 {
		name = repo[i+1:]
	}
	var p *Product
	if !strings.Contains(repo, "/") {
		p = c.ByPURL("pkg:docker/library/" + repo)
	} else {
		p = c.ByPURL("pkg:docker/" + repo)
	}
	if p == nil && !strings.Contains(repo, "/") {
		if n, ok := imageProducts[name]; ok {
			p = c.Product(n)
		}
	}
	var out []ImageMatch
	parts := strings.Split(tag, "-")
	if p != nil && tag != "" {
		if cy := p.CycleFor(parts[0]); cy != nil {
			out = append(out, ImageMatch{Product: p, Cycle: cy, Version: parts[0]})
		}
	}
	// Base operating system in the tag.
	for _, t := range parts[1:] {
		t = strings.ToLower(t)
		if m := alpineTagRe.FindStringSubmatch(t); m != nil {
			if ap := c.Product("alpine-linux"); ap != nil && ap != p {
				if cy := ap.CycleFor(m[1]); cy != nil {
					out = append(out, ImageMatch{Product: ap, Cycle: cy, Version: m[1], Base: true})
				}
			}
			continue
		}
		for _, os := range []string{"debian", "ubuntu"} {
			if op := c.Product(os); op != nil && op != p {
				if cy := op.CycleFor(t); cy != nil && cy.Codename != "" {
					out = append(out, ImageMatch{Product: op, Cycle: cy, Version: t, Base: true})
				}
			}
		}
	}
	return out
}
