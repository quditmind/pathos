package material

import (
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Categories of material change.
const (
	CatAuth       = "auth"
	CatEndpoint   = "api_endpoint"
	CatDependency = "dependency"
	CatCrypto     = "crypto"
	CatIaC        = "iac_exposure"
	CatSecrets    = "secrets_handling"
	CatCICD       = "cicd"
	CatData       = "sensitive_data"
)

// Categories lists every category in display order.
var Categories = []string{CatAuth, CatEndpoint, CatDependency, CatCrypto, CatIaC, CatSecrets, CatCICD, CatData}

// CategoryLabels names categories for people.
var CategoryLabels = map[string]string{
	CatAuth:       "Authentication / authorization",
	CatEndpoint:   "New API endpoint",
	CatDependency: "New dependency",
	CatCrypto:     "Cryptography",
	CatIaC:        "Infrastructure exposure",
	CatSecrets:    "Secrets handling",
	CatCICD:       "CI/CD pipeline",
	CatData:       "Sensitive data model",
}

// Rule is one explainable detection rule.
type Rule struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Explanation string `json:"explanation"`
	// Level orders the importance of a change: high | medium | low.
	Level string `json:"level"`
	// Frameworks/languages the rule targets (documentation only).
	Applies string `json:"applies"`

	exts    []string       // file extensions (lower case, with dot); nil = any
	files   *regexp.Regexp // path pattern (matched on the slash path); nil = any
	pattern *regexp.Regexp // line pattern; nil = the file change itself matches
	removed bool           // also match removed lines ("changed or removed")
	fileFn  func(string) bool
}

var (
	javaLike = []string{".java", ".kt", ".kts", ".groovy", ".scala"}
	pyExt    = []string{".py"}
	jsExt    = []string{".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
	goExt    = []string{".go"}
	csExt    = []string{".cs", ".cshtml"}
	code     = []string{".java", ".kt", ".kts", ".groovy", ".scala", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go",
		".cs", ".rb", ".php", ".rs", ".swift", ".c", ".cc", ".cpp", ".h", ".hpp", ".m", ".ex", ".exs"}
	iacExt = []string{".tf", ".tfvars", ".json", ".yaml", ".yml", ".bicep", ".template"}
)

func re(s string) *regexp.Regexp { return regexp.MustCompile(s) }

// Rules is the catalog. Patterns are deliberately specific: a material
// change is a prompt for a closer look, not a finding.
var Rules = []Rule{
	// --- authentication / authorization -----------------------------------
	{ID: "auth.spring-security", Category: CatAuth, Level: "high", Applies: "Java/Kotlin, Spring Security",
		Title:       "Spring Security configuration changed",
		Explanation: "Lines that configure Spring Security (filter chains, method security, request authorization rules) were added, changed or removed. Such changes can open or close access to endpoints.",
		exts:        javaLike, removed: true,
		pattern: re(`@EnableWebSecurity|@EnableMethodSecurity|@EnableGlobalMethodSecurity|SecurityFilterChain|WebSecurityConfigurerAdapter|\.authorizeHttpRequests|\.authorizeRequests|\.requestMatchers\(|\.antMatchers\(|\.mvcMatchers\(|\.permitAll\(\)|\.anonymous\(\)|\.hasRole\(|\.hasAuthority\(|\.csrf\(|@PreAuthorize|@PostAuthorize|@Secured\(|@RolesAllowed|@PermitAll`)},
	{ID: "auth.django", Category: CatAuth, Level: "high", Applies: "Python, Django / Django REST framework",
		Title:       "Django authentication or permission code changed",
		Explanation: "Django authentication decorators, permission classes, authentication backends or middleware settings were added, changed or removed.",
		exts:        pyExt, removed: true,
		pattern: re(`@login_required|@permission_required|@user_passes_test|@staff_member_required|LoginRequiredMixin|PermissionRequiredMixin|permission_classes|authentication_classes|AUTHENTICATION_BACKENDS|DEFAULT_PERMISSION_CLASSES|DEFAULT_AUTHENTICATION_CLASSES|IsAuthenticated|AllowAny|IsAdminUser|has_permission\(|has_object_permission\(|AuthenticationMiddleware|@csrf_exempt`)},
	{ID: "auth.python-web", Category: CatAuth, Level: "high", Applies: "Python, Flask / FastAPI",
		Title:       "Flask or FastAPI authentication code changed",
		Explanation: "Flask-Login / JWT decorators or FastAPI security dependencies were added, changed or removed.",
		exts:        pyExt, removed: true,
		pattern: re(`@login_required|@jwt_required|@roles_required|@auth\.login_required|Depends\(\s*(get_current_user|oauth2_scheme|verify_token|get_current_active_user)|OAuth2PasswordBearer|HTTPBearer\(|HTTPBasic\(|Security\(`)},
	{ID: "auth.express", Category: CatAuth, Level: "high", Applies: "JavaScript/TypeScript, Express / Passport / NestJS",
		Title:       "Express/Passport/NestJS authentication middleware changed",
		Explanation: "Passport strategies, authentication middleware, JWT verification, sessions or NestJS guards were added, changed or removed.",
		exts:        jsExt, removed: true,
		pattern: re(`passport\.(use|authenticate|initialize|session)|new\s+\w*Strategy\(|express-jwt|expressjwt\(|jwt\.verify\(|express-session|requireAuth|isAuthenticated\b|ensureAuthenticated|@UseGuards\(|AuthGuard\(|canActivate\(|next-auth|getServerSession\(`)},
	{ID: "auth.go-middleware", Category: CatAuth, Level: "high", Applies: "Go, net/http / gin / echo / chi",
		Title:       "Go authentication middleware changed",
		Explanation: "Authentication or authorization middleware (JWT, basic auth, sessions, role checks) was added, changed or removed in Go code.",
		exts:        goExt, removed: true,
		pattern: re(`(?i)func\s+(\([^)]*\)\s*)?\w*(authenticat|authoriz|requirelogin|requirerole|requireauth|authmiddleware|withauth|basicauth)\w*\s*\(|middleware\.(BasicAuth|JWT|KeyAuth)|gin\.BasicAuth|echojwt|jwtauth\.|jwt\.Parse|\.Use\(\s*\w*(Auth|auth|JWT|jwt)\w*|SetBasicAuth|BasicAuth\(\)`)},
	{ID: "auth.aspnet", Category: CatAuth, Level: "high", Applies: "C#, ASP.NET Core",
		Title:       "ASP.NET authorization changed",
		Explanation: "[Authorize]/[AllowAnonymous] attributes, authorization policies or the authentication pipeline were added, changed or removed.",
		exts:        csExt, removed: true,
		pattern: re(`\[Authorize|\[AllowAnonymous|AddAuthentication\(|AddAuthorization\(|UseAuthentication\(|UseAuthorization\(|RequireAuthorization\(|AllowAnonymous\(\)|AddJwtBearer\(|AddPolicy\(`)},
	{ID: "auth.generic", Category: CatAuth, Level: "medium", Applies: "Any language",
		Title:       "Authentication module changed",
		Explanation: "A file whose path indicates authentication, authorization, login, session or permission handling was added, changed or removed.",
		exts:        code, fileFn: authPath},

	// --- HTTP endpoints ---------------------------------------------------
	{ID: "endpoint.express", Category: CatEndpoint, Level: "medium", Applies: "JavaScript/TypeScript, Express / Fastify / Koa / NestJS",
		Title:       "New HTTP route (Node.js)",
		Explanation: "A new route was registered: it extends the application's attack surface and needs the same authentication, authorization and input validation as existing routes.",
		exts:        jsExt,
		pattern:     re(`\b(app|router|server|fastify|routes?)\.(get|post|put|patch|delete|all|route)\s*\(\s*['"\x60/]|\bfastify\.route\s*\(|@(Get|Post|Put|Patch|Delete|All)\s*\(`)},
	{ID: "endpoint.python", Category: CatEndpoint, Level: "medium", Applies: "Python, Flask / FastAPI / Django",
		Title:       "New HTTP route (Python)",
		Explanation: "A new Flask/FastAPI route or Django URL pattern was added: it extends the attack surface and needs authentication, authorization and input validation.",
		exts:        pyExt,
		pattern:     re(`@(app|bp|blueprint|router|api|\w+_bp)\.(route|get|post|put|patch|delete|api_route)\s*\(|\b(re_)?path\s*\(\s*r?['"]|\burl\s*\(\s*r['"]\^|add_url_rule\s*\(|@action\s*\(`)},
	{ID: "endpoint.spring", Category: CatEndpoint, Level: "medium", Applies: "Java/Kotlin, Spring MVC / JAX-RS",
		Title:       "New HTTP endpoint (Spring / JAX-RS)",
		Explanation: "A new request mapping was added: it extends the attack surface and needs authorization and input validation.",
		exts:        javaLike,
		pattern:     re(`@(RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping)\b|@Path\s*\(|@(GET|POST|PUT|DELETE|PATCH)\b`)},
	{ID: "endpoint.go", Category: CatEndpoint, Level: "medium", Applies: "Go, net/http / gin / echo / chi / gorilla",
		Title:       "New HTTP route (Go)",
		Explanation: "A new HTTP handler or route was registered in Go code: it extends the attack surface and needs authentication, authorization and input validation.",
		exts:        goExt,
		pattern:     re(`\.(HandleFunc|Handle)\s*\(\s*"|\.(GET|POST|PUT|PATCH|DELETE|Any|Get|Post|Put|Patch|Delete|Group|Route|Mount)\s*\(\s*"/`)},
	{ID: "endpoint.aspnet", Category: CatEndpoint, Level: "medium", Applies: "C#, ASP.NET Core",
		Title:       "New HTTP endpoint (ASP.NET)",
		Explanation: "A new controller, action route or minimal API endpoint was added: it extends the attack surface and needs authorization and input validation.",
		exts:        csExt,
		pattern:     re(`\[(HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|Route)\b|\[ApiController\]|:\s*(Controller|ControllerBase)\b|\.Map(Get|Post|Put|Patch|Delete|Methods)\s*\(`)},

	// --- cryptography -----------------------------------------------------
	{ID: "crypto.usage", Category: CatCrypto, Level: "medium", Applies: "Any language",
		Title:       "Cryptography usage changed",
		Explanation: "Code that encrypts, hashes, signs, generates keys or random values, or configures TLS was added, changed or removed. Check algorithms, modes, key sizes and randomness.",
		exts:        code, removed: true,
		pattern: re(`(?i)\b(Cipher\.getInstance|MessageDigest\.getInstance|KeyGenerator|KeyPairGenerator|SecretKeySpec|SecureRandom|createCipheriv|createDecipheriv|createHash|createHmac|crypto\.subtle|randomBytes|pbkdf2|bcrypt|scrypt|argon2|hashlib\.|hmac\.new|Crypto\.Cipher|cryptography\.hazmat|Fernet\(|aes\.NewCipher|cipher\.NewGCM|rsa\.GenerateKey|md5\.|sha1\.|crypto/(md5|sha1|des|rc4)|tls\.Config|InsecureSkipVerify|verify\s*=\s*False|rejectUnauthorized|ssl\.(create_default_context|_create_unverified_context)|AesManaged|RSACryptoServiceProvider|SHA1Managed|MD5\.Create|TripleDES)`)},

	// --- infrastructure as code -------------------------------------------
	{ID: "iac.open-ingress", Category: CatIaC, Level: "high", Applies: "Terraform, CloudFormation, Kubernetes, Bicep",
		Title:       "Network rule open to the internet",
		Explanation: "An infrastructure definition now allows traffic from any address (0.0.0.0/0 or ::/0). Confirm the resource is meant to be internet-facing.",
		exts:        iacExt,
		pattern:     re(`0\.0\.0\.0/0|::/0|sourceAddressPrefix"?\s*[:=]\s*"(\*|Internet|Any)"`)},
	{ID: "iac.public-storage", Category: CatIaC, Level: "high", Applies: "Terraform, CloudFormation, Bicep",
		Title:       "Storage or resource made public",
		Explanation: "An infrastructure definition grants public access to a storage bucket, container or resource (public ACL, disabled public access block, public network access). Confirm the data is meant to be public.",
		exts:        iacExt,
		pattern:     re(`(?i)acl\s*[:=]\s*"?(public-read|public-read-write)|PublicRead|block_public_(acls|policy)\s*=\s*false|restrict_public_buckets\s*=\s*false|ignore_public_acls\s*=\s*false|BlockPublic(Acls|Policy)"?\s*:\s*false|allow_blob_public_access\s*=\s*true|allowBlobPublicAccess"?\s*:\s*true|public_network_access_enabled\s*=\s*true|publicly_accessible\s*=\s*true|PubliclyAccessible"?\s*:\s*true|"Principal"\s*:\s*"\*"|principal\s*=\s*"\*"|type:\s*LoadBalancer|hostNetwork:\s*true|privileged:\s*true`)},

	// --- secrets handling -------------------------------------------------
	{ID: "secrets.handling", Category: CatSecrets, Level: "medium", Applies: "Any language",
		Title:       "Secrets-handling code added",
		Explanation: "Code that reads, stores or passes credentials, API keys, tokens or private keys was added (environment variables, vaults, key stores). Check that secrets are not logged, hard-coded or exposed.",
		exts:        code,
		pattern:     re(`(?i)(getenv|environ(\.get)?|process\.env|System\.getenv|Environment\.GetEnvironmentVariable|os\.LookupEnv)\s*[\[(.]\s*['"]?\w*(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL|ACCESS_?KEY)\w*|SecretsManager|secretsmanager|KeyVault|SecretClient|hvac\.Client|vault\.(NewClient|Client)|ssm\.get_parameter|GetParameter\(|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|KeyStore\.getInstance|\.pem['"]`)},

	// --- CI/CD ------------------------------------------------------------
	{ID: "cicd.pipeline", Category: CatCICD, Level: "medium", Applies: "GitHub Actions, GitLab CI, Jenkins, Azure Pipelines, CircleCI, Bitbucket, Buildkite, Tekton, Drone",
		Title:       "CI/CD pipeline changed",
		Explanation: "A build or deployment pipeline definition was added, changed or removed. Pipelines run with credentials and can publish artifacts: review triggers, permissions, third-party actions and secret usage.",
		files:       re(`(?i)(^|/)\.github/workflows/[^/]+\.ya?ml$|(^|/)\.github/actions/.+/action\.ya?ml$|(^|/)\.gitlab-ci\.ya?ml$|(^|/)\.gitlab/ci/.+\.ya?ml$|(^|/)Jenkinsfile[^/]*$|(^|/)azure-pipelines[^/]*\.ya?ml$|(^|/)\.circleci/config\.ya?ml$|(^|/)bitbucket-pipelines\.ya?ml$|(^|/)\.buildkite/.+\.ya?ml$|(^|/)\.tekton/.+\.ya?ml$|(^|/)\.drone\.ya?ml$|(^|/)\.travis\.ya?ml$|(^|/)cloudbuild\.ya?ml$`)},
	{ID: "cicd.dangerous-trigger", Category: CatCICD, Level: "high", Applies: "GitHub Actions",
		Title:       "Privileged workflow trigger or permissions",
		Explanation: "A workflow uses pull_request_target/workflow_run triggers or write-all permissions; these run untrusted pull request code with repository secrets if misused.",
		files:       re(`(?i)(^|/)\.github/workflows/[^/]+\.ya?ml$`),
		pattern:     re(`pull_request_target|workflow_run|permissions:\s*write-all|contents:\s*write|id-token:\s*write|secrets:\s*inherit`)},

	// --- sensitive data models --------------------------------------------
	// --- dependencies (evaluated by the API from the two scans' SBOMs) -----
	{ID: DependencyRuleID, Category: CatDependency, Level: "medium", Applies: "Every ecosystem Syft catalogs",
		Title:       "New dependency",
		Explanation: "The scan's SBOM contains a package that the previous scan's SBOM did not. New dependencies add code you did not write: check its licence, maintenance and known vulnerabilities."},

	{ID: "data.pii-field", Category: CatData, Level: "medium", Applies: "Any language, SQL, schemas",
		Title:       "Personal or sensitive data field added",
		Explanation: "A model, schema or table now has a field whose name indicates personal or sensitive data (government IDs, payment data, health data, dates of birth, credentials). Check classification, encryption at rest, logging and retention.",
		exts:        append(append([]string{}, code...), ".sql", ".prisma", ".graphql", ".gql", ".proto", ".avsc"),
		pattern:     re(`(?i)\b(ssn|social_?security(_?number)?|national_?id|passport(_?(no|number))?|tax_?id|tin_?number|driver'?s?_?licen[cs]e|date_?of_?birth|dob|birth_?date|credit_?card(_?number)?|card_?number|cc_?number|cvv|cvc|pan_?number|iban|bank_?account(_?number)?|routing_?number|medical_?record|diagnosis|health_?condition|biometric|fingerprint_?data|ethnicity|religion|sexual_?orientation|salary)\b\s*[:=(]|\b(ssn|social_?security_?number|passport_?number|date_?of_?birth|credit_?card_?number|card_?number|iban|bank_?account_?number|medical_?record_?number)\b\s+(varchar|text|char|string|int|bigint|numeric|String|str)\b|(Column|Field|Property|@Column|models\.\w+Field)\b.*\b(ssn|passport|date_?of_?birth|credit_?card|card_?number|iban|medical)`)},
}

// DependencyRuleID is the SBOM comparison rule; it is not applied to diffs.
const DependencyRuleID = "dependency.new"

// RuleByID returns a rule.
func RuleByID(id string) (Rule, bool) {
	i := slices.IndexFunc(Rules, func(r Rule) bool { return r.ID == id })
	if i < 0 {
		return Rule{}, false
	}
	return Rules[i], true
}

// Change is one detected material change.
type Change struct {
	Category    string `json:"category"`
	RuleID      string `json:"rule_id"`
	FilePath    string `json:"file_path"`
	ChangeType  string `json:"change_type"` // added | modified | deleted | renamed
	Side        string `json:"side"`        // added | removed | file
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	MatchCount  int    `json:"match_count"`
	Snippet     string `json:"snippet"`
	Explanation string `json:"explanation"`
	// Detail names the dependency for dependency changes.
	Detail string `json:"detail,omitempty"`
}

const (
	// MaxChanges bounds one scan's material changes.
	MaxChanges     = 1000
	maxSnippet     = 300
	mergeLineGap   = 3
	maxPerFileRule = 20
)

func (r Rule) appliesTo(p string) bool {
	if r.files != nil && !r.files.MatchString(p) {
		return false
	}
	if r.fileFn != nil && !r.fileFn(p) {
		return false
	}
	if r.exts != nil && !slices.Contains(r.exts, strings.ToLower(path.Ext(p))) {
		return false
	}
	return true
}

// authWords are path words that indicate authentication or authorization
// code ("AuthController.java", "auth/", "login_view.py"; not "author.go").
var authWords = map[string]bool{"auth": true, "authn": true, "authz": true, "authentication": true, "authorization": true,
	"authenticator": true, "authorizer": true, "login": true, "logon": true, "signin": true, "session": true, "sessions": true,
	"permission": true, "permissions": true, "rbac": true, "acl": true, "oauth": true, "oauth2": true, "oidc": true,
	"saml": true, "jwt": true, "sso": true, "guard": true, "guards": true, "security": true}

// camelWords splits "JWTUtilAuth" into JWT, Util, Auth.
func camelWords(s string) []string {
	var out []string
	r := []rune(s)
	start := 0
	isUp := func(c rune) bool { return c >= 'A' && c <= 'Z' }
	isLow := func(c rune) bool { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') }
	for i := 1; i < len(r); i++ {
		if (isLow(r[i-1]) && isUp(r[i])) || (i+1 < len(r) && isUp(r[i-1]) && isUp(r[i]) && isLow(r[i+1])) {
			out = append(out, string(r[start:i]))
			start = i
		}
	}
	if start < len(r) {
		out = append(out, string(r[start:]))
	}
	return out
}

func authPath(p string) bool {
	dir, file := path.Split(p)
	file = strings.TrimSuffix(file, path.Ext(file))
	for _, part := range append(strings.Split(strings.Trim(dir, "/"), "/"), file) {
		for _, w := range strings.FieldsFunc(part, func(r rune) bool { return r == '_' || r == '-' || r == '.' || r == ' ' }) {
			for _, x := range camelWords(w) {
				if authWords[strings.ToLower(x)] {
					return true
				}
			}
		}
	}
	return false
}

// vendored paths are not the repository's own code.
var vendored = regexp.MustCompile(`(?i)(^|/)(node_modules|vendor|third_party|bower_components|dist|build|\.venv|venv|site-packages|testdata|__snapshots__)/|\.min\.js$|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|go\.sum)$`)

// testPath marks test code (reported at most once per rule and file at low
// weight would be noise: tests are skipped except for CI/CD files).
var testPath = regexp.MustCompile(`(?i)(^|/)(tests?|__tests__|spec|specs)/|(_test\.go|\.test\.[jt]sx?|\.spec\.[jt]sx?|_test\.py|Test\.java|Tests\.cs)$|(^|/)test_[^/]+\.py$`)

// Analyze applies the rules to file diffs. Results are ordered by file,
// then category and line; at most MaxChanges are returned and truncated
// reports whether more were found.
func Analyze(files []FileDiff) (out []Change, truncated bool) {
	for _, f := range files {
		p := f.DisplayPath()
		if p == "" || f.Binary || vendored.MatchString(p) {
			continue
		}
		isTest := testPath.MatchString(p)
		for _, r := range Rules {
			if r.Category == CatDependency || !r.appliesTo(p) || (isTest && r.Category != CatCICD) {
				continue
			}
			if r.pattern == nil {
				c := Change{Category: r.Category, RuleID: r.ID, FilePath: p, ChangeType: f.Status, Side: "file", MatchCount: 1,
					Explanation: r.Explanation}
				if len(f.Added) > 0 {
					c.StartLine, c.EndLine = f.Added[0].No, f.Added[len(f.Added)-1].No
				}
				out = append(out, c)
				continue
			}
			out = append(out, matchLines(r, f, p, f.Added, "added")...)
			if r.removed {
				out = append(out, matchLines(r, f, p, f.Removed, "removed")...)
			}
		}
	}
	out = dedupeGeneric(out)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].FilePath != out[j].FilePath {
			return out[i].FilePath < out[j].FilePath
		}
		if out[i].Category != out[j].Category {
			return slices.Index(Categories, out[i].Category) < slices.Index(Categories, out[j].Category)
		}
		return out[i].StartLine < out[j].StartLine
	})
	if len(out) > MaxChanges {
		return out[:MaxChanges], true
	}
	return out, false
}

// matchLines groups matching lines of one side into ranges.
func matchLines(r Rule, f FileDiff, p string, lines []Line, side string) []Change {
	var out []Change
	var cur *Change
	for _, l := range lines {
		if !r.pattern.MatchString(l.Text) || looksLikeComment(l.Text) {
			continue
		}
		if cur != nil && l.No-cur.EndLine <= mergeLineGap {
			cur.EndLine = l.No
			cur.MatchCount++
			continue
		}
		if len(out) >= maxPerFileRule {
			break
		}
		out = append(out, Change{Category: r.Category, RuleID: r.ID, FilePath: p, ChangeType: f.Status, Side: side,
			StartLine: l.No, EndLine: l.No, MatchCount: 1, Snippet: snippet(l.Text), Explanation: r.Explanation})
		cur = &out[len(out)-1]
	}
	return out
}

// looksLikeComment skips whole-line comments (a commented-out decorator is
// not a change of behaviour).
func looksLikeComment(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "#[") || strings.HasPrefix(t, "/*") ||
		strings.HasPrefix(t, "* ") || strings.HasPrefix(t, "--")
}

func snippet(s string) string {
	s = strings.TrimSpace(strings.ToValidUTF8(s, "?"))
	if len(s) > maxSnippet {
		s = strings.ToValidUTF8(s[:maxSnippet], "") + "…"
	}
	return s
}

// dedupeGeneric drops the path-based auth rule for files where a specific
// auth rule already matched.
func dedupeGeneric(in []Change) []Change {
	specific := map[string]bool{}
	for _, c := range in {
		if c.Category == CatAuth && c.RuleID != "auth.generic" {
			specific[c.FilePath] = true
		}
	}
	return slices.DeleteFunc(in, func(c Change) bool { return c.RuleID == "auth.generic" && specific[c.FilePath] })
}
