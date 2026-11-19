package bench

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
)

// The secrets corpus is self-made: PATHOS generates it at run time from a
// seed (the same seed gives the same files), so no secret-shaped string is
// stored in the repository. Every file holds exactly one labelled item:
//
//   - positives: values in the published formats of common credentials
//     (cloud keys, source-hosting and package-registry tokens, chat and
//     payment API keys, private keys, connection strings with a password,
//     a JWT, a generic high-entropy password), random characters in the
//     right alphabet and length, each in several file types;
//   - negatives: things that look like secrets but are not: environment
//     variable references, placeholders, the AWS documentation example
//     key, hashes, commit IDs, UUIDs, lockfile integrity values, public
//     keys, data URIs and UI strings.
//
// The values are random, so none is a working credential, and no tool can
// verify them; the corpus measures detection, not validation. Because the
// author chose the formats knowing which tools look for them, recall on
// this corpus is an upper bound for real repositories (docs/BENCHMARKS.md).

const (
	alnum   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	upper32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b64     = alnum + "+/"
	b64url  = alnum + "-_"
	hexchar = "0123456789abcdef"
)

type secretGen struct{ r *rand.Rand }

func (g secretGen) s(alphabet string, n int) string {
	var b strings.Builder
	for range n {
		b.WriteByte(alphabet[g.r.IntN(len(alphabet))])
	}
	return b.String()
}

func (g secretGen) bytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(g.r.UintN(256)) // #nosec G115 -- UintN(256) is below 256
	}
	return b
}

func (g secretGen) digits(n int) string { return g.s("0123456789", n) }

func (g secretGen) pem(kind string) string {
	body := base64.StdEncoding.EncodeToString(g.bytes(1190))
	var b strings.Builder
	b.WriteString("-----BEGIN " + kind + "-----\n")
	for len(body) > 64 {
		b.WriteString(body[:64] + "\n")
		body = body[64:]
	}
	b.WriteString(body + "\n-----END " + kind + "-----\n")
	return b.String()
}

func (g secretGen) uuid() string {
	h := hex.EncodeToString(g.bytes(16))
	return h[:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32]
}

// item is one labelled value and the files it is written into.
type item struct {
	category string
	positive bool
	// value returns the value; files the contexts it is written in
	// (file extension -> content with %s for the value).
	value func(g secretGen) string
	ctx   []string
}

// Contexts: assignment in Python, JavaScript, .env, YAML and JSON.
const (
	ctxPy   = "py|import os\n\nSERVICE = \"billing\"\nAPI_TOKEN = \"%s\"\n"
	ctxJS   = "js|const service = 'billing';\nconst apiToken = '%s';\nmodule.exports = { service, apiToken };\n"
	ctxEnv  = "env|APP_ENV=production\nAPI_TOKEN=%s\n"
	ctxYAML = "yaml|service: billing\ncredentials:\n  token: \"%s\"\n"
	ctxJSON = "json|{\n  \"service\": \"billing\",\n  \"token\": \"%s\"\n}\n"
)

var secretItems = []item{
	// Positives.
	{"aws-access-key", true, func(g secretGen) string {
		return "AKIA" + g.s(upper32, 16) + "\naws_secret_access_key = " + g.s(b64, 40)
	}, []string{"ini|[default]\naws_access_key_id = %s\n", "py|import boto3\n\naws_access_key_id = \"\"\nKEYS = '''aws_access_key_id = %s'''\n",
		"env|AWS_DEFAULT_REGION=eu-west-1\naws_access_key_id = %s\n", "cfg|# deploy credentials\naws_access_key_id = %s\n"}},
	{"github-token", true, func(g secretGen) string { return "ghp_" + g.s(alnum, 36) }, []string{ctxPy, ctxJS, ctxEnv, ctxYAML}},
	{"github-fine-grained-token", true, func(g secretGen) string {
		return "github_pat_" + g.s(alnum, 22) + "_" + g.s(alnum, 59)
	}, []string{ctxPy, ctxJS, ctxEnv, ctxJSON}},
	{"gitlab-token", true, func(g secretGen) string { return "glpat-" + g.s(alnum, 20) }, []string{ctxPy, ctxJS, ctxEnv, ctxYAML}},
	{"slack-bot-token", true, func(g secretGen) string {
		return "xoxb-" + g.digits(11) + "-" + g.digits(13) + "-" + g.s(alnum, 24)
	}, []string{ctxPy, ctxJS, ctxEnv, ctxJSON}},
	{"stripe-secret-key", true, func(g secretGen) string { return "sk_live_" + g.s(alnum, 24) }, []string{ctxPy, ctxJS, ctxEnv, ctxYAML}},
	{"google-api-key", true, func(g secretGen) string { return "AIza" + g.s(b64url, 35) }, []string{ctxPy, ctxJS, ctxEnv, ctxJSON}},
	{"sendgrid-api-key", true, func(g secretGen) string { return "SG." + g.s(b64url, 22) + "." + g.s(b64url, 43) }, []string{ctxPy, ctxJS, ctxEnv, ctxYAML}},
	{"npm-token", true, func(g secretGen) string { return "npm_" + g.s(alnum, 36) }, []string{ctxEnv, "npmrc|registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=%s\n", ctxJS, ctxYAML}},
	{"twilio-api-key", true, func(g secretGen) string { return "SK" + g.s(hexchar, 32) }, []string{ctxPy, ctxJS, ctxEnv, ctxJSON}},
	{"private-key-rsa", true, func(g secretGen) string { return g.pem("RSA PRIVATE KEY") }, []string{"pem|%s", "py|KEY = \"\"\"%s\"\"\"\n", "key|%s", "yaml|tls:\n  key: |\n    %s\n"}},
	{"private-key-pkcs8", true, func(g secretGen) string { return g.pem("PRIVATE KEY") }, []string{"pem|%s", "js|const key = `%s`;\n", "key|%s", "txt|%s"}},
	{"postgres-url-password", true, func(g secretGen) string {
		return "postgresql://app_admin:" + g.s(alnum, 18) + "@db.internal.example:5432/orders"
	}, []string{"py|DATABASE_URL = \"%s\"\n", "env|DATABASE_URL=%s\n", "yaml|database:\n  url: %s\n", "js|const url = '%s';\n"}},
	{"jwt", true, func(g secretGen) string {
		h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
		p := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"%s","name":"svc","iat":1700000000}`, g.digits(10))))
		return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(g.bytes(32))
	}, []string{ctxPy, ctxJS, ctxEnv, ctxJSON}},
	{"azure-storage-key", true, func(g secretGen) string {
		return "DefaultEndpointsProtocol=https;AccountName=orders" + g.digits(4) + ";AccountKey=" +
			base64.StdEncoding.EncodeToString(g.bytes(64)) + ";EndpointSuffix=core.windows.net"
	}, []string{ctxPy, ctxJS, ctxEnv, ctxYAML}},
	{"generic-password", true, func(g secretGen) string { return g.s(alnum, 6) + "!" + g.s(alnum, 6) + "#" + g.s(alnum, 6) },
		[]string{"py|DB_PASSWORD = \"%s\"\n", "yaml|database:\n  password: \"%s\"\n", "properties|spring.datasource.password=%s\n", "js|const password = '%s';\n"}},

	// Negatives.
	{"env-reference", false, func(secretGen) string { return "" }, []string{
		"py|import os\n\nAPI_TOKEN = os.environ[\"GITHUB_TOKEN\"]%s\n", "js|const token = process.env.STRIPE_SECRET_KEY%s;\n",
		"yaml|credentials:\n  token: ${SLACK_BOT_TOKEN}%s\n", "env|AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}%s\n"}},
	{"placeholder", false, func(secretGen) string { return "" }, []string{
		"py|API_TOKEN = \"<YOUR_API_TOKEN>\"%s\n", "yaml|database:\n  password: \"********\"%s\n",
		"env|API_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx%s\n", "json|{\n  \"token\": \"REPLACE_ME\"%s\n}\n"}},
	{"aws-documentation-example", false, func(secretGen) string { return "AKIAIOSFODNN7EXAMPLE" }, []string{
		"ini|[default]\naws_access_key_id = %s\n", "py|# example from the AWS documentation\nEXAMPLE_KEY_ID = \"%s\"\n"}},
	{"sha256-hash", false, func(g secretGen) string { return hex.EncodeToString(g.bytes(32)) }, []string{
		"txt|%s  release.tar.gz\n", "py|EXPECTED_SHA256 = \"%s\"\n", "json|{\n  \"checksum\": \"%s\"\n}\n", "yaml|artifact:\n  sha256: %s\n"}},
	{"git-commit-id", false, func(g secretGen) string { return hex.EncodeToString(g.bytes(20)) }, []string{
		"yaml|steps:\n  - uses: actions/checkout@%s\n", "txt|revision: %s\n", "json|{\n  \"commit\": \"%s\"\n}\n"}},
	{"uuid", false, func(g secretGen) string { return g.uuid() }, []string{
		"py|REQUEST_ID = \"%s\"\n", "json|{\n  \"id\": \"%s\"\n}\n", "yaml|tenant_id: %s\n", "js|const correlationId = '%s';\n"}},
	{"lockfile-integrity", false, func(g secretGen) string { return "sha512-" + base64.StdEncoding.EncodeToString(g.bytes(64)) }, []string{
		"json|{\n  \"node_modules/left-pad\": {\n    \"version\": \"1.3.0\",\n    \"integrity\": \"%s\"\n  }\n}\n",
		"yaml|left-pad@1.3.0:\n  resolution: {integrity: %s}\n", "txt|integrity %s\n"}},
	{"public-key", false, func(g secretGen) string {
		return "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ" + base64.StdEncoding.EncodeToString(g.bytes(256)) + " deploy@example.org"
	}, []string{"pub|%s\n", "txt|%s\n", "yaml|authorized_keys:\n  - %s\n"}},
	{"public-key-pem", false, func(g secretGen) string { return g.pem("PUBLIC KEY") }, []string{"pem|%s", "py|PUBLIC_KEY = \"\"\"%s\"\"\"\n", "txt|%s"}},
	{"data-uri", false, func(g secretGen) string {
		return "data:image/png;base64," + base64.StdEncoding.EncodeToString(g.bytes(96))
	}, []string{
		"css|.logo { background-image: url(%s); }\n", "html|<img alt=\"logo\" src=\"%s\">\n", "js|const logo = '%s';\n"}},
	{"ui-text", false, func(secretGen) string { return "" }, []string{
		"json|{\n  \"password_label\": \"Enter your password\",\n  \"token_help\": \"Paste the token from your account settings\"%s\n}\n",
		"py|PASSWORD_PROMPT = \"Password: \"%s\n", "yaml|messages:\n  secret_hint: \"The secret is shown only once\"%s\n"}},
	{"function-call", false, func(secretGen) string { return "" }, []string{
		"py|password = get_password_from_vault(\"orders-db\")%s\n", "js|const apiKey = await secrets.read('stripe/secret');%s\n",
		"py|token = keyring.get_password(\"svc\", \"token\")%s\n"}},
}

// GenerateSecrets writes the corpus to dir/src and returns its labels.
// Files are named by number only, so no path gives the answer away.
func GenerateSecrets(dir string, seed uint64) (Labels, error) {
	l := Labels{Suite: "secrets-selfmade", Source: fmt.Sprintf("generated by pathos-bench gen-secrets, seed %d", seed),
		License: "Apache-2.0 (PATHOS; generated, self-made)", Match: MatchFile, Categories: []string{"secrets"}}
	// #nosec G404 -- deterministic test data, not a security value
	g := secretGen{r: rand.New(rand.NewPCG(seed, seed^0x5eed))}
	type entry struct {
		it  item
		ctx string
	}
	var all []entry
	for _, it := range secretItems {
		for _, c := range it.ctx {
			all = append(all, entry{it, c})
		}
	}
	// Shuffle so positives and negatives are interleaved.
	g.r.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
	src := filepath.Join(dir, "src")
	for i, e := range all {
		ext, tmpl, _ := strings.Cut(e.ctx, "|")
		rel := fmt.Sprintf("module%03d/settings.%s", i+1, ext)
		if ext == "env" {
			rel = fmt.Sprintf("module%03d/.env", i+1)
		}
		p := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { // #nosec G301 -- generated test data, read by scanner containers (another UID)
			return l, err
		}
		v := e.it.value(g)
		if ext == "yaml" && strings.Contains(v, "\n") {
			v = strings.ReplaceAll(strings.TrimRight(v, "\n"), "\n", "\n    ")
		}
		if err := os.WriteFile(p, []byte(fmt.Sprintf(tmpl, v)), 0o644); err != nil { // #nosec G306 -- generated test data, read by scanner containers
			return l, err
		}
		l.Cases = append(l.Cases, Case{ID: rel, Category: e.it.category, Vulnerable: e.it.positive, File: rel})
	}
	return l, nil
}
