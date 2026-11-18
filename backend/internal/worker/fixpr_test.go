package worker

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyFix(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "requirements.txt"), []byte("requests==2.28.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const commit = "0123456789abcdef0123456789abcdef01234567"
	res := applyFix(src, commit, FixJob{Ecosystem: "pypi", PackageName: "requests", CurrentVersion: "2.28.0", TargetVersion: "2.31.0"})
	if res.Status != "ok" || res.BaseCommit != commit || len(res.Files) != 1 {
		t.Fatalf("result: %+v", res)
	}
	b, _ := base64.StdEncoding.DecodeString(res.Files[0].ContentBase64)
	if string(b) != "requests==2.31.0\n" || res.Files[0].Path != "requirements.txt" {
		t.Errorf("file %s: %q", res.Files[0].Path, b)
	}
	if res := applyFix(src, commit, FixJob{Ecosystem: "golang", PackageName: "x", CurrentVersion: "1", TargetVersion: "2"}); res.Status != "not_supported" {
		t.Errorf("go: %+v", res)
	}
	if res := applyFix(src, commit, FixJob{Ecosystem: "pypi", PackageName: "requests", CurrentVersion: "2.28.0", TargetVersion: "2.31;rm"}); res.Status != "failed" {
		t.Errorf("invalid target: %+v", res)
	}
}

func TestRedactToken(t *testing.T) {
	if got := redactToken("fatal: could not read from https://x-access-token:s3cr3t@github.com/a/b", "s3cr3t"); strings.Contains(got, "s3cr3t") {
		t.Errorf("token leaked: %s", got)
	}
	if got := redactToken("http.extraHeader=Authorization: Basic abc", ""); got != "[message withheld]" {
		t.Errorf("header line not withheld: %s", got)
	}
}
