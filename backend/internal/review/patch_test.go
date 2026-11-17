package review

import "testing"

func TestValidatePatch(t *testing.T) {
	good := "Fix the query:\n--- a/routes/users.js\n+++ b/routes/users.js\n@@ -10,3 +10,3 @@\n const id = req.query.id;\n-db.query('SELECT * FROM users WHERE id = ' + id);\n+db.query('SELECT * FROM users WHERE id = ?', [id]);\n \n"
	if err := ValidatePatch(good, "routes/users.js"); err != nil {
		t.Fatalf("valid patch rejected: %v", err)
	}
	for name, p := range map[string]string{
		"other file":      "--- a/etc/passwd\n+++ b/etc/passwd\n@@ -1 +1 @@\n-root\n+x\n",
		"two files":       good + "--- a/x.js\n+++ b/x.js\n@@ -1 +1 @@\n-a\n+b\n",
		"no hunk":         "--- a/routes/users.js\n+++ b/routes/users.js\n",
		"bad hunk":        "--- a/routes/users.js\n+++ b/routes/users.js\n@@ nonsense @@\n-a\n",
		"garbage line":    "--- a/routes/users.js\n+++ b/routes/users.js\n@@ -1 +1 @@\n-a\nrm -rf /\n",
		"no plus":         "--- a/routes/users.js\n@@ -1 +1 @@\n-a\n+b\n",
		"not a diff":      "just prose",
		"whitespace only": "--- a/routes/users.js\n+++ b/routes/users.js\n@@ -1,2 +1,2 @@\n-  a  b\n+a b\n",
		"path traverse":   "--- a/../../routes/users.js\n+++ b/../../routes/users.js\n@@ -1 +1 @@\n-a\n+b\n",
	} {
		if ValidatePatch(p, "routes/users.js") == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}
