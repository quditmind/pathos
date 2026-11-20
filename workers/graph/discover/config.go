package main

import (
	"path"
	"regexp"
	"strings"
)

// Secret references and configuration: environment variables with
// credential-like names read in code, credential-like names assigned a
// literal (the value is never copied), and connection URLs in
// configuration files. Only names, hosts and locations are recorded.

var credNameRe = regexp.MustCompile(`(?i)(passw(or)?d|passwd|secret|token|api_?key|private_?key|access_?key|credential|_key$|^database_url$|_dsn$|^dsn$|_auth$|client_secret)`)

func credentialName(n string) bool {
	n = strings.TrimSpace(n)
	if n == "" || len(n) > 120 {
		return false
	}
	// Names of files or settings that only point at a secret are still
	// references; exclude obvious non-secrets.
	lower := strings.ToLower(n)
	for _, x := range []string{"_file", "_path", "_url_file", "token_url", "_ttl", "_expiry", "_length", "_header", "_name", "_id"} {
		if strings.HasSuffix(lower, x) {
			return false
		}
	}
	return credNameRe.MatchString(n)
}

// envReadRe captures the variable name read from the environment.
var envReadRe = map[string]*regexp.Regexp{
	"go":   regexp.MustCompile(`os\.(?:Getenv|LookupEnv)\(\s*"([A-Za-z_][A-Za-z0-9_]*)"`),
	"js":   regexp.MustCompile(`process\.env(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\])`),
	"py":   regexp.MustCompile(`os\.(?:environ(?:\.get)?\s*[\[(]|getenv\()\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]`),
	"java": regexp.MustCompile(`(?:System\.getenv\(\s*"([A-Za-z_][A-Za-z0-9_]*)"|@Value\(\s*"\$\{([A-Za-z_][A-Za-z0-9_.]*))`),
	"cs":   regexp.MustCompile(`(?:Environment\.GetEnvironmentVariable\(\s*"([A-Za-z_][A-Za-z0-9_]*)"|Configuration\[\s*"([A-Za-z_][A-Za-z0-9_:]*)"\s*\])`),
	"php":  regexp.MustCompile(`(?:getenv|env)\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]|\$_(?:ENV|SERVER)\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]`),
	"rb":   regexp.MustCompile(`ENV(?:\.fetch\(\s*|\[\s*)['"]([A-Za-z_][A-Za-z0-9_]*)['"]`),
}

// literalCredRe: a credential-looking name assigned a string literal.
var literalCredRe = regexp.MustCompile(`(?i)\b([A-Za-z_][A-Za-z0-9_]*(?:password|passwd|secret|api_?key|token|private_?key)[A-Za-z0-9_]*)\s*(?::=|=|:)\s*["']([^"'\s]{12,})["']`)

// credentialLike: a literal that looks like a credential (long, mixed
// character classes), not an identifier such as "api_token".
func credentialLike(v string) bool {
	if strings.Contains(v, "${") || strings.HasPrefix(v, "{{") || strings.Contains(v, "://") || strings.Contains(v, "/") {
		return false
	}
	var lower, upper, digit, other bool
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			n++
		}
	}
	return n >= 3 || (n == 2 && digit && len(v) >= 20)
}

func envRegexFor(lang string) *regexp.Regexp {
	switch lang {
	case "ts", "tsx":
		lang = "js"
	}
	return envReadRe[lang]
}

func (p *project) extractSecretRefs() {
	for _, f := range p.files {
		re := envRegexFor(f.lang)
		lines := strings.Split(string(f.data), "\n")
		test := isTestPath(f.rel)
		for i, ln := range lines {
			if len(ln) > 2000 {
				continue
			}
			if re != nil {
				for _, m := range re.FindAllStringSubmatch(ln, -1) {
					name := ""
					for _, g := range m[1:] {
						if g != "" {
							name = g
							break
						}
					}
					if !credentialName(name) {
						continue
					}
					sk := "secret:env:" + name
					p.g.AddNode(sk, "secret_ref", name, "", map[string]any{"source": "environment variable"})
					p.g.AddEdge(p.enclosing(f.rel, i+1), "reads", sk, fileLine(f.rel, i+1, "reads environment variable "+name))
				}
			}
			if test {
				continue // test fixtures assign fake credentials on purpose
			}
			for _, m := range literalCredRe.FindAllStringSubmatch(ln, -1) {
				name := m[1]
				if !credentialName(name) || !credentialLike(m[2]) {
					continue
				}
				sk := "secret:literal:" + f.rel + "#" + name
				p.g.AddNode(sk, "secret_ref", name, "", map[string]any{"source": "literal in code", "file": f.rel, "line": i + 1})
				p.g.AddEdge(p.enclosing(f.rel, i+1), "reads", sk, fileLine(f.rel, i+1, name+": literal value present (not stored)"))
			}
		}
	}
}

func isTestPath(rel string) bool {
	l := strings.ToLower(rel)
	return strings.Contains(l, "/test/") || strings.Contains(l, "/tests/") || strings.Contains(l, "testdata/") ||
		strings.Contains(l, "/fixtures/") || strings.HasSuffix(l, "_test.go") || strings.Contains(l, ".test.") ||
		strings.Contains(l, ".spec.") || strings.HasPrefix(l, "test/") || strings.HasPrefix(l, "tests/") ||
		strings.Contains(l, "__tests__/") || strings.HasPrefix(path.Base(l), "test_")
}

// isConfigFile: files whose connection URLs declare services.
func isConfigFile(rel string) bool {
	b := strings.ToLower(path.Base(rel))
	switch {
	case strings.HasPrefix(b, ".env"), strings.HasSuffix(b, ".env.example"), strings.HasSuffix(b, ".env.sample"):
		return true
	case strings.HasSuffix(b, ".properties"):
		return true
	case strings.HasPrefix(b, "application") && (strings.HasSuffix(b, ".yml") || strings.HasSuffix(b, ".yaml")):
		return true
	case strings.HasPrefix(b, "appsettings") && strings.HasSuffix(b, ".json"):
		return true
	case b == "settings.py" || b == "database.yml" || b == "config.yml" || b == "config.yaml" || b == "config.toml":
		return true
	case strings.HasPrefix(rel, "config/") && (strings.HasSuffix(b, ".yml") || strings.HasSuffix(b, ".yaml") || strings.HasSuffix(b, ".php")):
		return true
	}
	return false
}

var (
	connURLRe = regexp.MustCompile(`(?i)\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|kafka|nats|sqlserver|jdbc:[a-z]+)://`)
	cfgURLRe  = regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]*(?:url|endpoint|base_?uri|host))["']?\s*[:=]\s*["']?(https://[^\s"'<>]+)`)
)

func connTech(scheme string) (kind, tech string) {
	s := strings.ToLower(strings.TrimPrefix(strings.ToLower(scheme), "jdbc:"))
	switch {
	case strings.HasPrefix(s, "postgres"):
		return "datastore", "postgresql"
	case s == "mysql" || s == "mariadb":
		return "datastore", "mysql"
	case strings.HasPrefix(s, "mongodb"):
		return "datastore", "mongodb"
	case strings.HasPrefix(s, "redis"):
		return "datastore", "redis"
	case s == "sqlserver":
		return "datastore", "sqlserver"
	case strings.HasPrefix(s, "amqp"):
		return "queue", "rabbitmq"
	case s == "kafka":
		return "queue", "kafka"
	case s == "nats":
		return "queue", "nats"
	}
	return "", ""
}

// configURL links a configuration owner (file or container) to the
// datastore, queue or external service a connection URL names.
func (p *project) configURL(rel, owner, value string, line int) {
	if m := connURLRe.FindStringSubmatch(value); m != nil {
		if kind, tech := connTech(m[1]); kind != "" {
			p.g.AddEdge(owner, "depends_on", p.serviceNode(kind, tech), fileLine(rel, line, tech+" connection URL (value not stored)"))
		}
		return
	}
	if host := urlHost(value); host != "" && !isLocalHost(host) && strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "https://") {
		key := "ext:" + host
		p.g.AddNode(key, "external_service", host, "", map[string]any{"host": host, "technology": "https"})
		p.g.AddEdge(owner, "depends_on", key, fileLine(rel, line, "configured endpoint "+host))
	}
}

func (p *project) extractConfig() {
	for _, rel := range p.paths {
		if !isConfigFile(rel) || isTestPath(rel) {
			continue
		}
		data, err := p.read(rel)
		if err != nil {
			continue
		}
		owner := ""
		for i, ln := range strings.Split(string(data), "\n") {
			if len(ln) > 2000 {
				continue
			}
			hit := connURLRe.MatchString(ln)
			var ext []string
			if !hit {
				if m := cfgURLRe.FindStringSubmatch(ln); m != nil {
					ext = m
				}
			}
			if !hit && ext == nil {
				continue
			}
			if owner == "" {
				owner = p.fileNode(rel, "")
			}
			if hit {
				p.configURL(rel, owner, ln[connURLRe.FindStringIndex(ln)[0]:], i+1)
			} else {
				p.configURL(rel, owner, ext[2], i+1)
			}
		}
	}
}
