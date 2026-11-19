package material

import (
	"strings"
	"testing"
)

const sampleDiff = `diff --git a/src/main/java/com/acme/SecurityConfig.java b/src/main/java/com/acme/SecurityConfig.java
index 1111111..2222222 100644
--- a/src/main/java/com/acme/SecurityConfig.java
+++ b/src/main/java/com/acme/SecurityConfig.java
@@ -20,1 +20,2 @@ public class SecurityConfig {
-        http.authorizeHttpRequests(a -> a.requestMatchers("/admin/**").hasRole("ADMIN"));
+        http.authorizeHttpRequests(a -> a.requestMatchers("/admin/**").permitAll());
+        // .csrf(c -> c.disable()) commented out
diff --git a/app/routes.js b/app/routes.js
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/app/routes.js
@@ -0,0 +1,3 @@
+const router = require('express').Router();
+router.post('/api/payments', pay);
+module.exports = router;
diff --git a/.github/workflows/release.yml b/.github/workflows/release.yml
index 1..2 100644
--- a/.github/workflows/release.yml
+++ b/.github/workflows/release.yml
@@ -1 +1 @@
-on: push
+on: pull_request_target
diff --git a/infra/sg.tf b/infra/sg.tf
--- a/infra/sg.tf
+++ b/infra/sg.tf
@@ -5,0 +6,1 @@
+    cidr_blocks = ["0.0.0.0/0"]
diff --git a/models/user.py b/models/user.py
--- a/models/user.py
+++ b/models/user.py
@@ -10,0 +11,2 @@ class User(models.Model):
+    date_of_birth = models.DateField()
+    nickname = models.CharField(max_length=40)
diff --git a/node_modules/x/index.js b/node_modules/x/index.js
--- a/node_modules/x/index.js
+++ b/node_modules/x/index.js
@@ -1 +1 @@
+app.get('/x', h)
diff --git a/old/auth.go b/old/auth.go
deleted file mode 100644
--- a/old/auth.go
+++ /dev/null
@@ -1,2 +0,0 @@
-package old
-func RequireAuth(next http.Handler) http.Handler { return next }
diff --git a/logo.png b/logo.png
Binary files a/logo.png and b/logo.png differ
`

func TestParseUnified(t *testing.T) {
	files := ParseUnified([]byte(sampleDiff))
	if len(files) != 8 {
		t.Fatalf("files = %d", len(files))
	}
	if f := files[1]; f.Status != "added" || f.Path != "app/routes.js" || len(f.Added) != 3 || f.Added[1].No != 2 {
		t.Fatalf("routes.js = %+v", f)
	}
	if f := files[0]; f.Status != "modified" || len(f.Removed) != 1 || f.Removed[0].No != 20 || f.Added[1].No != 21 {
		t.Fatalf("SecurityConfig = %+v", f)
	}
	if f := files[6]; f.Status != "deleted" || f.DisplayPath() != "old/auth.go" || len(f.Removed) != 2 {
		t.Fatalf("auth.go = %+v", f)
	}
	if !files[7].Binary || files[7].Path != "logo.png" {
		t.Fatalf("binary = %+v", files[7])
	}
}

func TestAnalyze(t *testing.T) {
	changes, truncated := Analyze(ParseUnified([]byte(sampleDiff)))
	if truncated {
		t.Fatal("truncated")
	}
	got := map[string]Change{}
	for _, c := range changes {
		got[c.RuleID+" "+c.FilePath+" "+c.Side] = c
		if strings.HasPrefix(c.FilePath, "node_modules/") {
			t.Fatalf("vendored code reported: %+v", c)
		}
	}
	for _, want := range []string{
		"auth.spring-security src/main/java/com/acme/SecurityConfig.java added",
		"auth.spring-security src/main/java/com/acme/SecurityConfig.java removed",
		"endpoint.express app/routes.js added",
		"cicd.pipeline .github/workflows/release.yml file",
		"cicd.dangerous-trigger .github/workflows/release.yml added",
		"iac.open-ingress infra/sg.tf added",
		"data.pii-field models/user.py added",
		"auth.go-middleware old/auth.go removed",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %q; got %v", want, keys(got))
		}
	}
	if c := got["auth.spring-security src/main/java/com/acme/SecurityConfig.java added"]; c.StartLine != 20 || c.EndLine != 20 || c.MatchCount != 1 {
		t.Errorf("commented line counted or wrong range: %+v", c)
	}
	if _, ok := got["auth.generic old/auth.go file"]; ok {
		t.Error("generic auth rule not deduplicated")
	}
	if c := got["data.pii-field models/user.py added"]; c.StartLine != 11 || !strings.Contains(c.Snippet, "date_of_birth") {
		t.Errorf("pii = %+v", c)
	}
}

func keys(m map[string]Change) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestAuthPath(t *testing.T) {
	for p, want := range map[string]bool{
		"src/AuthController.java": true, "internal/auth/x.go": true, "app/login_view.py": true, "pkg/author.go": false,
		"lib/oauth2/client.ts": true, "web/Sessions.cs": true, "src/authorship.ts": false, "src/JWTUtil.java": true,
	} {
		if got := authPath(p); got != want {
			t.Errorf("authPath(%q) = %v", p, got)
		}
	}
}

func TestRulesAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules {
		if seen[r.ID] || r.Title == "" || r.Explanation == "" || CategoryLabels[r.Category] == "" {
			t.Errorf("bad rule %+v", r.ID)
		}
		if r.Level != "high" && r.Level != "medium" && r.Level != "low" {
			t.Errorf("rule %s level %q", r.ID, r.Level)
		}
		seen[r.ID] = true
	}
}

func TestFrameworkPatterns(t *testing.T) {
	cases := []struct {
		path, line, rule string
	}{
		{"api/views.py", "    permission_classes = [AllowAny]", "auth.django"},
		{"api/urls.py", "    path('orders/<int:pk>/', views.order),", "endpoint.python"},
		{"app/main.py", "@app.get('/items/{id}')", "endpoint.python"},
		{"app/main.py", "def read(user=Depends(get_current_user)):", "auth.python-web"},
		{"src/server.ts", "passport.use(new LocalStrategy(verify));", "auth.express"},
		{"src/orders.controller.ts", "  @Post('refund')", "endpoint.express"},
		{"cmd/api/main.go", `	r.POST("/v1/users", createUser)`, "endpoint.go"},
		{"cmd/api/main.go", `	mux.HandleFunc("/admin", admin)`, "endpoint.go"},
		{"Controllers/Orders.cs", "    [AllowAnonymous]", "auth.aspnet"},
		{"Controllers/Orders.cs", `    [HttpPost("refund")]`, "endpoint.aspnet"},
		{"src/main/java/A.java", `    @GetMapping("/orders")`, "endpoint.spring"},
		{"src/crypto.py", "h = hashlib.md5(data)", "crypto.usage"},
		{"src/client.go", "tls := &tls.Config{InsecureSkipVerify: true}", "crypto.usage"},
		{"infra/s3.tf", `  acl = "public-read"`, "iac.public-storage"},
		{"src/config.js", "const key = process.env.STRIPE_API_KEY;", "secrets.handling"},
		{"db/schema.sql", "  ssn varchar(11) NOT NULL,", "data.pii-field"},
	}
	for _, c := range cases {
		changes, _ := Analyze([]FileDiff{{Path: c.path, Status: "modified", Added: []Line{{No: 7, Text: c.line}}}})
		found := false
		for _, ch := range changes {
			found = found || ch.RuleID == c.rule
		}
		if !found {
			t.Errorf("%s: %q did not match %s (got %+v)", c.path, c.line, c.rule, changes)
		}
	}
	// Negative cases.
	for _, c := range []struct{ path, line string }{
		{"src/x.go", `resp, err := http.Get("https://example.com")`},
		{"src/author.go", "func authorName() string { return a }"},
		{"README.md", "permission_classes = [AllowAny]"},
	} {
		if changes, _ := Analyze([]FileDiff{{Path: c.path, Status: "modified", Added: []Line{{No: 1, Text: c.line}}}}); len(changes) > 0 {
			t.Errorf("%s: %q matched %+v", c.path, c.line, changes)
		}
	}
}
