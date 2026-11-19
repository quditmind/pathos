package inventory

import (
	"net/url"
	"slices"
	"sort"
	"strings"
)

// frameworkRule maps a package (purl type and the start of its
// namespace/name path) to a framework name.
type frameworkRule struct {
	typ, prefix, name string
}

// frameworkRules are well-known application frameworks. Detection is
// evidence based: a framework is reported only when the SBOM of a linked
// repository contains its package.
var frameworkRules = []frameworkRule{
	{"npm", "react", "React"}, {"npm", "next", "Next.js"}, {"npm", "@angular/core", "Angular"}, {"npm", "vue", "Vue.js"},
	{"npm", "svelte", "Svelte"}, {"npm", "express", "Express"}, {"npm", "@nestjs/core", "NestJS"}, {"npm", "fastify", "Fastify"},
	{"npm", "koa", "Koa"},
	{"pypi", "django", "Django"}, {"pypi", "flask", "Flask"}, {"pypi", "fastapi", "FastAPI"}, {"pypi", "tornado", "Tornado"},
	{"maven", "org.springframework.boot/", "Spring Boot"}, {"maven", "org.springframework/spring-webmvc", "Spring MVC"},
	{"maven", "io.quarkus/", "Quarkus"}, {"maven", "io.micronaut/", "Micronaut"},
	{"golang", "github.com/go-chi/chi", "chi"}, {"golang", "github.com/gin-gonic/gin", "Gin"},
	{"golang", "github.com/labstack/echo", "Echo"}, {"golang", "github.com/gofiber/fiber", "Fiber"},
	{"golang", "github.com/gorilla/mux", "Gorilla mux"},
	{"gem", "rails", "Ruby on Rails"}, {"gem", "sinatra", "Sinatra"},
	{"composer", "laravel/framework", "Laravel"}, {"composer", "symfony/http-kernel", "Symfony"},
	{"nuget", "microsoft.aspnetcore", "ASP.NET Core"},
	{"cargo", "actix-web", "Actix Web"}, {"cargo", "axum", "Axum"}, {"cargo", "rocket", "Rocket"},
}

// runtimeByType maps package ecosystems to the runtime they need.
var runtimeByType = map[string]string{
	"npm": "Node.js", "pypi": "Python", "maven": "JVM", "gradle": "JVM", "golang": "Go", "gem": "Ruby",
	"composer": "PHP", "nuget": ".NET", "cargo": "Rust (native)", "hex": "Erlang/OTP", "pub": "Dart",
	"swift": "Swift", "cocoapods": "Swift",
}

// runtimeByLanguage is the fallback when no SBOM exists yet.
var runtimeByLanguage = map[string]string{
	"javascript": "Node.js", "typescript": "Node.js", "python": "Python", "java": "JVM", "kotlin": "JVM",
	"scala": "JVM", "go": "Go", "ruby": "Ruby", "php": "PHP", "c#": ".NET", "f#": ".NET", "rust": "Rust (native)",
	"elixir": "Erlang/OTP", "dart": "Dart", "swift": "Swift",
}

// purlParts returns the type and the decoded, lower-case namespace/name
// path of a package URL ("", "" when it is not one).
func purlParts(purl string) (string, string) {
	p, ok := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !ok {
		return "", ""
	}
	if i := strings.IndexAny(p, "@?#"); i >= 0 {
		p = p[:i]
	}
	typ, rest, ok := strings.Cut(p, "/")
	if !ok {
		return "", ""
	}
	if dec, err := url.PathUnescape(rest); err == nil {
		rest = dec
	}
	return strings.ToLower(typ), strings.ToLower(rest)
}

// DetectFromPackages derives frameworks and runtimes from SBOM package
// URLs. Results are sorted and unique.
func DetectFromPackages(purls []string) (frameworks, runtimes []string) {
	fw, rt := map[string]bool{}, map[string]bool{}
	for _, purl := range purls {
		typ, path := purlParts(purl)
		if typ == "" {
			continue
		}
		if r, ok := runtimeByType[typ]; ok {
			rt[r] = true
		}
		for _, rule := range frameworkRules {
			if rule.typ != typ {
				continue
			}
			if path == rule.prefix || strings.HasPrefix(path, strings.TrimSuffix(rule.prefix, "/")+"/") ||
				(strings.HasSuffix(rule.prefix, "/") && strings.HasPrefix(path, rule.prefix)) ||
				(typ == "nuget" && strings.HasPrefix(path, rule.prefix)) {
				fw[rule.name] = true
			}
		}
	}
	return keys(fw), keys(rt)
}

// RuntimesFromLanguages maps languages to runtimes (fallback without SBOM).
func RuntimesFromLanguages(langs []string) []string {
	rt := map[string]bool{}
	for _, l := range langs {
		if r, ok := runtimeByLanguage[strings.ToLower(l)]; ok {
			rt[r] = true
		}
	}
	return keys(rt)
}

// TopLanguages returns languages by size (bytes), largest first, ignoring
// those under 2% of the total (vendored snippets, configuration).
func TopLanguages(sizes map[string]int64) []string {
	var total int64
	for _, v := range sizes {
		total += v
	}
	type kv struct {
		k string
		v int64
	}
	var all []kv
	for k, v := range sizes {
		if total == 0 || v*50 >= total {
			all = append(all, kv{k, v})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	out := make([]string, 0, len(all))
	for _, x := range all {
		out = append(out, x.k)
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// mergeUnique appends b to a without duplicates (case-insensitive), keeping order.
func mergeUnique(a, b []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, v := range list {
			v = strings.TrimSpace(v)
			if v == "" || seen[strings.ToLower(v)] {
				continue
			}
			seen[strings.ToLower(v)] = true
			out = append(out, v)
		}
	}
	return out
}
