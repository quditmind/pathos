package worker

import (
	"net/url"
	"os"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// maxAPIURLs bounds the URL list of a non-intrusive API scan.
const maxAPIURLs = 500

// apiOperationURLs returns the URLs Nuclei checks for an API target without
// intrusive testing: the base URL, every server and every operation path.
//
// Nuclei reads OpenAPI documents (-im openapi) only for its DAST (fuzzing)
// templates; with the ordinary http and ssl templates it loads no template
// at all and exits with "no templates provided for scan". So the
// non-intrusive scan gets a plain URL list instead. Path parameters are
// filled with "1" (an example value would be equally arbitrary).
func apiOperationURLs(base string, spec []byte) []string {
	var doc struct {
		Swagger  string   `yaml:"swagger"`
		Host     string   `yaml:"host"`
		BasePath string   `yaml:"basePath"`
		Schemes  []string `yaml:"schemes"`
		Servers  []struct {
			URL string `yaml:"url"`
		} `yaml:"servers"`
		Paths map[string]any `yaml:"paths"`
	}
	_ = yaml.Unmarshal(spec, &doc) // the API validated the document; a bad one still scans the base URL
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if len(out) >= maxAPIURLs {
			return
		}
		p, err := url.Parse(u)
		if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	add(base)
	var servers []string
	for _, s := range doc.Servers {
		servers = append(servers, strings.TrimRight(s.URL, "/"))
	}
	if strings.HasPrefix(doc.Swagger, "2.") && doc.Host != "" {
		scheme := "https"
		if len(doc.Schemes) > 0 {
			scheme = doc.Schemes[0]
		}
		servers = append(servers, scheme+"://"+doc.Host+strings.TrimRight(doc.BasePath, "/"))
	}
	if len(servers) == 0 {
		servers = []string{strings.TrimRight(base, "/")}
	}
	paths := make([]string, 0, len(doc.Paths))
	for p := range doc.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, s := range servers {
		add(s)
		for _, p := range paths {
			if !strings.HasPrefix(p, "/") {
				continue
			}
			add(s + fillPathParams(p))
		}
	}
	return out
}

// fillPathParams replaces OpenAPI path parameters ({id}) with "1".
func fillPathParams(p string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(p, '{')
		j := strings.IndexByte(p, '}')
		if i < 0 || j < i {
			b.WriteString(p)
			return b.String()
		}
		b.WriteString(p[:i])
		b.WriteString("1")
		p = p[j+1:]
	}
}

// writeAPIURLList writes the URL list of a non-intrusive API scan.
func writeAPIURLList(base, specFile, out string) error {
	// #nosec G304 -- the worker wrote specFile into its own job directory
	spec, err := os.ReadFile(specFile)
	if err != nil {
		return err
	}
	return os.WriteFile(out, []byte(strings.Join(apiOperationURLs(base, spec), "\n")+"\n"), 0o600)
}
