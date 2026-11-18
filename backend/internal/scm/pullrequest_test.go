package scm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const (
	prBase   = "0123456789abcdef0123456789abcdef01234567"
	prTree   = "1111111111111111111111111111111111111111"
	prCommit = "2222222222222222222222222222222222222222"
)

func TestValidFixBranch(t *testing.T) {
	for b, want := range map[string]bool{
		"pathos/fix/npm-lodash-4.17.21": true,
		"pathos/fix/":                   false,
		"main":                          false,
		"pathos/fixes/x":                false,
		"pathos/fix/a..b":               false,
		"pathos/fix/a b":                false,
		"pathos/fix/x.lock":             false,
		"pathos/fix/.hidden":            false,
		"pathos/fix/a~1":                false,
		"pathos/fix/a:b":                false,
	} {
		if got := ValidFixBranch(b); got != want {
			t.Errorf("ValidFixBranch(%q) = %v, want %v", b, got, want)
		}
	}
}

// prRecorder records request bodies by "METHOD path".
type prRecorder struct {
	mu     sync.Mutex
	bodies map[string][]byte
	ctypes map[string]string
}

func (p *prRecorder) put(r *http.Request) []byte {
	b, _ := io.ReadAll(r.Body)
	p.mu.Lock()
	defer p.mu.Unlock()
	k := r.Method + " " + r.URL.Path
	p.bodies[k] = b
	p.ctypes[k] = r.Header.Get("Content-Type")
	return b
}

func (p *prRecorder) json(t *testing.T, key string) map[string]any {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	b, ok := p.bodies[key]
	if !ok {
		keys := make([]string, 0, len(p.bodies))
		for k := range p.bodies {
			keys = append(keys, k)
		}
		t.Fatalf("no request %s (got %v)", key, keys)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return m
}

func TestPullRequestWriters(t *testing.T) {
	rec := &prRecorder{bodies: map[string][]byte{}, ctypes: map[string]string{}}
	srv := newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		body := rec.put(r)
		p := r.URL.Path
		switch {
		// GitHub
		case r.Method == "POST" && p == "/repos/acme/api/git/refs":
			w.WriteHeader(201)
			jsonResp(w, map[string]any{"ref": "refs/heads/x"})
		case r.Method == "GET" && p == "/repos/acme/api/git/commits/"+prBase:
			jsonResp(w, map[string]any{"sha": prBase, "tree": map[string]string{"sha": prTree}})
		case r.Method == "POST" && p == "/repos/acme/api/git/blobs":
			jsonResp(w, map[string]string{"sha": "3333333333333333333333333333333333333333"})
		case r.Method == "POST" && p == "/repos/acme/api/git/trees":
			jsonResp(w, map[string]string{"sha": "4444444444444444444444444444444444444444"})
		case r.Method == "POST" && p == "/repos/acme/api/git/commits":
			jsonResp(w, map[string]string{"sha": prCommit})
		case r.Method == "PATCH" && strings.HasPrefix(p, "/repos/acme/api/git/refs/heads/pathos/fix/"):
			jsonResp(w, map[string]any{})
		case r.Method == "POST" && p == "/repos/acme/api/pulls":
			jsonResp(w, map[string]any{"number": 12, "html_url": "https://github.example/acme/api/pull/12", "state": "open"})
		case r.Method == "GET" && p == "/repos/acme/api/pulls/12":
			jsonResp(w, map[string]any{"number": 12, "html_url": "https://github.example/acme/api/pull/12", "state": "closed", "merged": true})
		// GitLab
		case r.Method == "POST" && p == "/api/v4/projects/7/repository/branches":
			if r.URL.Query().Get("ref") != prBase || !strings.HasPrefix(r.URL.Query().Get("branch"), FixBranchPrefix) {
				status(w, 400)
				return
			}
			jsonResp(w, map[string]any{"name": r.URL.Query().Get("branch")})
		case r.Method == "POST" && p == "/api/v4/projects/7/repository/commits":
			jsonResp(w, map[string]string{"id": prCommit})
		case r.Method == "POST" && p == "/api/v4/projects/7/merge_requests":
			jsonResp(w, map[string]any{"iid": 5, "web_url": "https://gitlab.example/acme/api/-/merge_requests/5", "state": "opened"})
		case r.Method == "GET" && p == "/api/v4/projects/7/merge_requests/5":
			jsonResp(w, map[string]any{"iid": 5, "web_url": "https://gitlab.example/acme/api/-/merge_requests/5", "state": "closed"})
		// Bitbucket
		case r.Method == "POST" && p == "/repositories/acme/api/refs/branches":
			w.WriteHeader(201)
			jsonResp(w, map[string]any{"name": "x"})
		case r.Method == "POST" && p == "/repositories/acme/api/src":
			_ = body
			w.Header().Set("Location", "https://api.bitbucket.org/2.0/repositories/acme/api/commit/"+prCommit)
			w.WriteHeader(201)
		case r.Method == "POST" && p == "/repositories/acme/api/pullrequests":
			jsonResp(w, map[string]any{"id": 3, "state": "OPEN", "links": map[string]any{"html": map[string]string{"href": "https://bitbucket.org/acme/api/pull-requests/3"}}})
		case r.Method == "GET" && p == "/repositories/acme/api/pullrequests/3":
			jsonResp(w, map[string]any{"id": 3, "state": "DECLINED"})
		// Azure DevOps
		case r.Method == "POST" && strings.HasSuffix(p, "/_apis/git/repositories/7/refs"):
			jsonResp(w, map[string]any{"value": []map[string]any{{"success": true, "updateStatus": "succeeded"}}})
		case r.Method == "POST" && strings.HasSuffix(p, "/_apis/git/repositories/7/pushes"):
			jsonResp(w, map[string]any{"commits": []map[string]string{{"commitId": prCommit}}})
		case r.Method == "POST" && strings.HasSuffix(p, "/_apis/git/repositories/7/pullrequests"):
			jsonResp(w, map[string]any{"pullRequestId": 9, "status": "active", "repository": map[string]string{"webUrl": "https://dev.azure.example/org/acme/_git/api"}})
		case r.Method == "GET" && strings.HasSuffix(p, "/_apis/git/repositories/7/pullrequests/9"):
			jsonResp(w, map[string]any{"pullRequestId": 9, "status": "completed"})
		default:
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	ref := RepoRef{ExternalID: "7", FullName: "acme/api", Project: "acme"}
	files := []FileChange{{Path: "requirements.txt", Content: []byte("django==4.2.11\n")}, {Path: "sub/pom.xml", Content: []byte("<project/>")}}
	spec := PullRequestSpec{Branch: "pathos/fix/pypi-django-4.2.11", BaseBranch: "main", Title: "Bump django to 4.2.11", Body: "Fixes CVE-2024-0001"}
	cases := []struct {
		cfg       Config
		wantURL   string
		wantID    string
		wantState string
	}{
		{Config{Provider: GitHub, BaseURL: srv.URL, AuthType: AuthPAT, Secret: []byte("t")}, "https://github.example/acme/api/pull/12", "12", PRMerged},
		{Config{Provider: GitLab, BaseURL: srv.URL, AuthType: AuthPAT, Secret: []byte("t")}, "https://gitlab.example/acme/api/-/merge_requests/5", "5", PRClosed},
		{Config{Provider: Bitbucket, BaseURL: srv.URL, AuthType: AuthAPIToken, Secret: []byte(`{"username":"a@b.c","token":"t"}`)}, "https://bitbucket.org/acme/api/pull-requests/3", "3", PRClosed},
		{Config{Provider: AzureDevOps, BaseURL: srv.URL + "/org", AuthType: AuthPAT, Secret: []byte("t")}, "https://dev.azure.example/org/acme/_git/api/pullrequest/9", "9", PRMerged},
	}
	for _, c := range cases {
		c.cfg.HTTP = srv.Client()
		w, ok := mustNew(t, c.cfg).(PullRequestWriter)
		if !ok {
			t.Fatalf("%s: not a PullRequestWriter", c.cfg.Provider)
		}
		r := ref
		if c.cfg.Provider == GitHub {
			r.ExternalID = ""
		}
		if err := w.CreateBranch(ctx, r, spec.Branch, prBase); err != nil {
			t.Fatalf("%s CreateBranch: %v", c.cfg.Provider, err)
		}
		sha, err := w.CommitFiles(ctx, r, spec.Branch, prBase, "Bump django", files)
		if err != nil {
			t.Fatalf("%s CommitFiles: %v", c.cfg.Provider, err)
		}
		if sha != prCommit {
			t.Errorf("%s commit = %q", c.cfg.Provider, sha)
		}
		pr, err := w.CreatePullRequest(ctx, r, spec)
		if err != nil {
			t.Fatalf("%s CreatePullRequest: %v", c.cfg.Provider, err)
		}
		if pr.URL != c.wantURL || pr.ID != c.wantID || pr.State != PROpen {
			t.Errorf("%s PR = %+v", c.cfg.Provider, pr)
		}
		got, err := w.GetPullRequest(ctx, r, pr.ID)
		if err != nil {
			t.Fatalf("%s GetPullRequest: %v", c.cfg.Provider, err)
		}
		if got.State != c.wantState {
			t.Errorf("%s state = %q, want %q", c.cfg.Provider, got.State, c.wantState)
		}
		// Never the default branch, never an arbitrary branch.
		if err := w.CreateBranch(ctx, r, "main", prBase); err == nil {
			t.Errorf("%s: CreateBranch on main accepted", c.cfg.Provider)
		}
		if _, err := w.CommitFiles(ctx, r, "main", prBase, "x", files); err == nil {
			t.Errorf("%s: CommitFiles on main accepted", c.cfg.Provider)
		}
		if _, err := w.CommitFiles(ctx, r, spec.Branch, prBase, "x", []FileChange{{Path: "../etc/passwd", Content: []byte("x")}}); err == nil {
			t.Errorf("%s: path traversal accepted", c.cfg.Provider)
		}
		bad := spec
		bad.Branch = "develop"
		if _, err := w.CreatePullRequest(ctx, r, bad); err == nil {
			t.Errorf("%s: PR from a non-PATHOS branch accepted", c.cfg.Provider)
		}
		if _, err := w.GetPullRequest(ctx, r, "1;drop"); err == nil {
			t.Errorf("%s: invalid PR id accepted", c.cfg.Provider)
		}
	}

	// Request shapes.
	gh := rec.json(t, "POST /repos/acme/api/git/commits")
	if gh["tree"] != "4444444444444444444444444444444444444444" || gh["parents"].([]any)[0] != prBase {
		t.Errorf("GitHub commit body: %v", gh)
	}
	if ref := rec.json(t, "POST /repos/acme/api/git/refs"); ref["ref"] != "refs/heads/"+spec.Branch || ref["sha"] != prBase {
		t.Errorf("GitHub ref body: %v", ref)
	}
	if patch := rec.json(t, "PATCH /repos/acme/api/git/refs/heads/"+spec.Branch); patch["force"] != false {
		t.Errorf("GitHub ref update must not force: %v", patch)
	}
	if pull := rec.json(t, "POST /repos/acme/api/pulls"); pull["head"] != spec.Branch || pull["base"] != "main" {
		t.Errorf("GitHub pull body: %v", pull)
	}
	gl := rec.json(t, "POST /api/v4/projects/7/repository/commits")
	acts := gl["actions"].([]any)
	if gl["branch"] != spec.Branch || len(acts) != 2 {
		t.Fatalf("GitLab commit body: %v", gl)
	}
	a0 := acts[0].(map[string]any)
	if dec, _ := base64.StdEncoding.DecodeString(a0["content"].(string)); string(dec) != "django==4.2.11\n" || a0["action"] != "update" {
		t.Errorf("GitLab action: %v", a0)
	}
	if mr := rec.json(t, "POST /api/v4/projects/7/merge_requests"); mr["source_branch"] != spec.Branch || mr["target_branch"] != "main" {
		t.Errorf("GitLab MR body: %v", mr)
	}
	rec.mu.Lock()
	ct := rec.ctypes["POST /repositories/acme/api/src"]
	bb := string(rec.bodies["POST /repositories/acme/api/src"])
	rec.mu.Unlock()
	if !strings.HasPrefix(ct, "multipart/form-data") || !strings.Contains(bb, "django==4.2.11") || !strings.Contains(bb, prBase) || !strings.Contains(bb, spec.Branch) {
		t.Errorf("Bitbucket src request: %s", ct)
	}
	if pr := rec.json(t, "POST /repositories/acme/api/pullrequests"); pr["close_source_branch"] != true {
		t.Errorf("Bitbucket PR body: %v", pr)
	}
	var azPush map[string]any
	rec.mu.Lock()
	for k, v := range rec.bodies {
		if strings.HasSuffix(k, "/pushes") {
			_ = json.Unmarshal(v, &azPush)
		}
	}
	rec.mu.Unlock()
	ru := azPush["refUpdates"].([]any)[0].(map[string]any)
	if ru["name"] != "refs/heads/"+spec.Branch || ru["oldObjectId"] != prBase {
		t.Errorf("Azure push refUpdates: %v", ru)
	}
}

func TestPullRequestWriterErrors(t *testing.T) {
	srv := newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/git/refs"):
			status(w, http.StatusForbidden)
		case strings.HasSuffix(r.URL.Path, "/pulls"):
			status(w, http.StatusUnprocessableEntity)
		default:
			http.NotFound(w, r)
		}
	})
	c := mustNew(t, Config{Provider: GitHub, BaseURL: srv.URL, AuthType: AuthPAT, Secret: []byte("tok-secret"), HTTP: srv.Client()}).(PullRequestWriter)
	ctx := context.Background()
	ref := RepoRef{FullName: "acme/api"}
	err := c.CreateBranch(ctx, ref, "pathos/fix/x", prBase)
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("want ErrForbidden, got %v", err)
	}
	assertNoLeak(t, err, "tok-secret")
	_, err = c.CreatePullRequest(ctx, ref, PullRequestSpec{Branch: "pathos/fix/x", BaseBranch: "main", Title: "t"})
	if !errors.Is(err, ErrConflict) {
		t.Errorf("want ErrConflict, got %v", err)
	}
	assertNoLeak(t, err, "tok-secret")
}
