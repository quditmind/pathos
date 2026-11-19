package scm

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// bbdcFake mimics Bitbucket Data Center REST 1.0 (shapes from the
// published OpenAPI description, v1000).
func bbdcFake(t *testing.T, version string, forbid bool) *fake {
	return newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer bbdc-token" && !strings.HasPrefix(auth, "Basic ") {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		repo := func(id, slug string) string {
			return `{"id":` + id + `,"slug":"` + slug + `","name":"` + slug + `","public":false,"archived":false,
				"project":{"key":"SEC","name":"Security"},
				"links":{"clone":[{"href":"ssh://git@bb.example.com:7999/sec/` + slug + `.git","name":"ssh"},
				{"href":"` + f.URL + `/scm/sec/` + slug + `.git","name":"http"}],"self":[{"href":"` + f.URL + `/projects/SEC/repos/` + slug + `/browse"}]}}`
		}
		switch r.URL.Path {
		case "/ctx/rest/api/1.0/application-properties":
			_, _ = w.Write([]byte(`{"version":"` + version + `","buildNumber":"1","displayName":"Bitbucket"}`))
		case "/ctx/rest/api/1.0/repos", "/ctx/rest/api/1.0/projects/SEC/repos":
			if forbid {
				w.WriteHeader(403)
				return
			}
			if r.URL.Query().Get("start") == "1" {
				_, _ = w.Write([]byte(`{"values":[` + repo("2", "web") + `],"isLastPage":true,"start":1,"limit":1,"size":1}`))
				return
			}
			_, _ = w.Write([]byte(`{"values":[` + repo("1", "api") + `],"isLastPage":false,"nextPageStart":1,"start":0,"limit":1,"size":1}`))
		case "/ctx/rest/api/1.0/projects":
			_, _ = w.Write([]byte(`{"values":[{"key":"SEC","name":"Security"}],"isLastPage":true}`))
		case "/ctx/rest/api/1.0/projects/SEC/repos/api":
			_, _ = w.Write([]byte(repo("1", "api")))
		case "/ctx/rest/api/1.0/projects/SEC/repos/api/branches/default":
			_, _ = w.Write([]byte(`{"id":"refs/heads/main","displayId":"main"}`))
		case "/ctx/rest/api/1.0/projects/SEC/repos/api/branches":
			_, _ = w.Write([]byte(`{"values":[{"id":"refs/heads/main","displayId":"main","latestCommit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","default":true},
				{"id":"refs/heads/dev","displayId":"dev","latestCommit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","default":false}],"isLastPage":true}`))
		case "/ctx/rest/api/1.0/projects/SEC/repos/api/commits":
			if r.URL.Query().Get("until") != "main" || r.URL.Query().Get("limit") != "1" {
				w.WriteHeader(400)
				return
			}
			_, _ = w.Write([]byte(`{"values":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","message":"Fix it\nbody","author":{"name":"Ana"},"committerTimestamp":1700000000000}],"isLastPage":true}`))
		default:
			w.WriteHeader(404)
		}
	})
}

func TestBitbucketDataCenter(t *testing.T) {
	srv := bbdcFake(t, "9.4.3", false)
	ctx := context.Background()
	c, err := New(Config{Provider: BitbucketDataCenter, BaseURL: srv.URL + "/ctx/rest/api/1.0", AuthType: AuthPAT, Secret: []byte("bbdc-token"), HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := c.Check(ctx)
	if err != nil || !strings.Contains(msg, "9.4.3") {
		t.Fatalf("check: %q %v", msg, err)
	}
	p1, err := c.ListRepositoriesPage(ctx, RepoQuery{PageSize: 1})
	if err != nil || len(p1.Items) != 1 || p1.NextPageToken == "" || p1.Items[0].FullName != "SEC/api" {
		t.Fatalf("page 1: %+v %v", p1, err)
	}
	if !strings.HasSuffix(p1.Items[0].CloneURL, "/scm/sec/api.git") || p1.Items[0].ExternalID != "1" {
		t.Fatalf("clone URL must be the http link: %+v", p1.Items[0])
	}
	p2, err := c.ListRepositoriesPage(ctx, RepoQuery{PageSize: 1, PageToken: p1.NextPageToken})
	if err != nil || len(p2.Items) != 1 || p2.NextPageToken != "" || p2.Items[0].Name != "web" {
		t.Fatalf("page 2: %+v %v", p2, err)
	}
	if _, err := c.ListRepositoriesPage(ctx, RepoQuery{PageSize: 1, PageToken: p1.NextPageToken, Search: "x"}); !errors.Is(err, ErrInvalidPageToken) {
		t.Fatalf("a token replayed with another query must be refused: %v", err)
	}
	projects, err := c.ListProjects(ctx, "")
	if err != nil || len(projects) != 1 || projects[0].Name != "SEC" {
		t.Fatalf("projects %+v %v", projects, err)
	}
	rr, err := c.GetRepository(ctx, RepoRef{FullName: "SEC/api"})
	if err != nil || rr.DefaultBranch != "main" {
		t.Fatalf("get: %+v %v", rr, err)
	}
	heads, err := c.ListBranchHeads(ctx, rr.Ref())
	if err != nil || len(heads) != 2 || !heads[0].Default {
		t.Fatalf("branches %+v %v", heads, err)
	}
	cm, err := c.LatestCommit(ctx, rr.Ref(), "main")
	if err != nil || cm.Message != "Fix it" || cm.CommittedAt == nil || cm.CommittedAt.Year() != 2023 {
		t.Fatalf("commit %+v %v", cm, err)
	}
	cred, err := c.CloneCredential(ctx)
	if err != nil || cred.Scheme != "bearer" || cred.Token != "bbdc-token" {
		t.Fatalf("project/repository tokens clone with Bearer: %+v", cred)
	}

	// A user token: Basic with the user name.
	u, _ := New(Config{Provider: BitbucketDataCenter, BaseURL: srv.URL + "/ctx", AuthType: AuthAPIToken,
		Secret: []byte(`{"username":"svc-pathos","token":"t"}`), HTTP: srv.Client()})
	if cred, _ := u.CloneCredential(ctx); cred.Username != "svc-pathos" || cred.Scheme != "" {
		t.Fatalf("user token clone credential %+v", cred)
	}

	// Rejected token: PTH-CONN-1007.
	bad, _ := New(Config{Provider: BitbucketDataCenter, BaseURL: srv.URL + "/ctx", AuthType: AuthPAT, Secret: []byte("nope"), HTTP: srv.Client()})
	if _, err := bad.Check(ctx); DiagCode(err) != "PTH-CONN-1007" {
		t.Fatalf("bad token: %s %v", DiagCode(err), err)
	}
}

func TestBitbucketDataCenterPermissionAndVersion(t *testing.T) {
	ctx := context.Background()
	srv := bbdcFake(t, "9.4.3", true)
	c, _ := New(Config{Provider: BitbucketDataCenter, BaseURL: srv.URL + "/ctx", AuthType: AuthPAT, Secret: []byte("bbdc-token"), HTTP: srv.Client()})
	if _, err := c.Check(ctx); DiagCode(err) != "PTH-CONN-1124" || !errors.Is(err, ErrForbidden) {
		t.Fatalf("403 with an access token: %s %v", DiagCode(err), err)
	}
	old := bbdcFake(t, "8.9.0", false)
	c, _ = New(Config{Provider: BitbucketDataCenter, BaseURL: old.URL + "/ctx", AuthType: AuthPAT, Secret: []byte("bbdc-token"), HTTP: old.Client()})
	msg, err := c.Check(ctx)
	if DiagCode(err) != "PTH-CONN-1123" || msg == "" {
		t.Fatalf("old version must warn but still connect: %q %s %v", msg, DiagCode(err), err)
	}
}

func TestBitbucketDataCenterWebhook(t *testing.T) {
	body := []byte(`{"eventKey":"repo:refs_changed","repository":{"id":42,"slug":"api","project":{"key":"SEC"}},
		"changes":[{"ref":{"id":"refs/heads/main","displayId":"main","type":"BRANCH"},"fromHash":"1111111111111111111111111111111111111111","toHash":"2222222222222222222222222222222222222222","type":"UPDATE"}]}`)
	ev, ext, err := ParseBitbucketDataCenterEvent("repo:refs_changed", body)
	if err != nil || ev.Kind != "push" || ext != "42" || ev.Ref != "main" || ev.CommitSHA != "2222222222222222222222222222222222222222" || ev.Before != "1111111111111111111111111111111111111111" {
		t.Fatalf("push: %+v %s %v", ev, ext, err)
	}
	del := []byte(`{"repository":{"id":42},"changes":[{"ref":{"displayId":"old","type":"BRANCH"},"toHash":"0000000000000000000000000000000000000000","type":"DELETE"}]}`)
	if ev, _, _ := ParseBitbucketDataCenterEvent("repo:refs_changed", del); ev.Kind != "ignored" {
		t.Fatalf("branch deletion must be ignored: %+v", ev)
	}
	pr := []byte(`{"pullRequest":{"id":7,"state":"OPEN","fromRef":{"displayId":"feat","latestCommit":"3333333333333333333333333333333333333333","repository":{"id":42}},
		"toRef":{"displayId":"main","latestCommit":"2222222222222222222222222222222222222222","repository":{"id":42}},"properties":{"mergeCommit":{"id":"4444444444444444444444444444444444444444"}}}}`)
	if ev, ext, _ := ParseBitbucketDataCenterEvent("pr:opened", pr); ev.Kind != "pull_request" || ev.PullRequest != 7 || ev.Ref != "feat" || ext != "42" {
		t.Fatalf("pr opened: %+v %s", ev, ext)
	}
	if ev, _, _ := ParseBitbucketDataCenterEvent("pr:from_ref_updated", pr); ev.Kind != "pull_request" || ev.CommitSHA != "3333333333333333333333333333333333333333" {
		t.Fatalf("pr updated: %+v", ev)
	}
	if ev, _, _ := ParseBitbucketDataCenterEvent("pr:merged", pr); ev.Kind != "merge" || ev.Ref != "main" || ev.CommitSHA != "4444444444444444444444444444444444444444" {
		t.Fatalf("pr merged: %+v", ev)
	}
	if ev, _, _ := ParseBitbucketDataCenterEvent("diagnostics:ping", []byte(`{}`)); ev.Kind != "ping" {
		t.Fatalf("ping: %+v", ev)
	}
	// Same X-Hub-Signature verifier as Bitbucket Cloud and GitHub.
	if err := VerifyBitbucketSignature([]byte("s"), body, "sha256=00"); !errors.Is(err, ErrSignature) {
		t.Fatal("bad signature accepted")
	}
}
