package scm

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// ErrSignature means a webhook failed authentication.
var ErrSignature = errors.New("scm: invalid webhook signature")

// VerifyGitHubSignature checks X-Hub-Signature-256 (HMAC-SHA256 of the raw body).
func VerifyGitHubSignature(secret, body []byte, header string) error {
	sig, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return ErrSignature
	}
	got, err := hex.DecodeString(sig)
	if err != nil {
		return ErrSignature
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return ErrSignature
	}
	return nil
}

// VerifyAzureBasicAuth checks the Basic credentials Azure DevOps service
// hooks send. The configured webhook secret is the password; any username
// is accepted.
func VerifyAzureBasicAuth(secret []byte, authorization string) error {
	enc, ok := strings.CutPrefix(authorization, "Basic ")
	if !ok {
		return ErrSignature
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return ErrSignature
	}
	_, pass, ok := strings.Cut(string(raw), ":")
	if !ok || subtle.ConstantTimeCompare([]byte(pass), secret) != 1 {
		return ErrSignature
	}
	return nil
}

// WebhookEvent is the normalized form of a push / PR / merge event.
type WebhookEvent struct {
	Kind        string // push | pull_request | merge | ping | ignored
	ExternalID  string // repository external ID
	Ref         string
	CommitSHA   string
	PullRequest int
	// Before is the branch head before a push (GitHub, GitLab); all zeros
	// for a new branch, empty when the provider does not send it.
	Before string
}

// ParseGitHubEvent normalizes a GitHub webhook payload.
func ParseGitHubEvent(event string, body []byte) (WebhookEvent, error) {
	var p struct {
		Ref        string `json:"ref"`
		Before     string `json:"before"`
		After      string `json:"after"`
		Deleted    bool   `json:"deleted"`
		Action     string `json:"action"`
		Number     int    `json:"number"`
		Repository struct {
			ID int64 `json:"id"`
		} `json:"repository"`
		PullRequest struct {
			Merged         bool   `json:"merged"`
			MergeCommitSHA string `json:"merge_commit_sha"`
			Head           struct {
				Ref string `json:"ref"`
				SHA string `json:"sha"`
			} `json:"head"`
			Base struct {
				Ref string `json:"ref"`
			} `json:"base"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return WebhookEvent{}, errors.New("scm: invalid JSON payload")
	}
	ev := WebhookEvent{Kind: "ignored"}
	if p.Repository.ID != 0 {
		ev.ExternalID = strconv.FormatInt(p.Repository.ID, 10)
	}
	switch event {
	case "ping":
		ev.Kind = "ping"
	case "push":
		if !p.Deleted && strings.HasPrefix(p.Ref, "refs/heads/") {
			ev.Kind, ev.Ref, ev.CommitSHA = "push", strings.TrimPrefix(p.Ref, "refs/heads/"), p.After
			ev.Before = p.Before
		}
	case "pull_request":
		ev.PullRequest = p.Number
		switch {
		case p.Action == "closed" && p.PullRequest.Merged:
			ev.Kind, ev.Ref, ev.CommitSHA = "merge", p.PullRequest.Base.Ref, p.PullRequest.MergeCommitSHA
		case p.Action == "opened" || p.Action == "synchronize" || p.Action == "reopened":
			ev.Kind, ev.Ref, ev.CommitSHA = "pull_request", p.PullRequest.Head.Ref, p.PullRequest.Head.SHA
		}
	}
	return ev, nil
}

// ParseAzureEvent normalizes an Azure DevOps service hook payload
// (git.push, git.pullrequest.created/updated/merged).
func ParseAzureEvent(body []byte) (WebhookEvent, string, error) {
	var p struct {
		ID        string `json:"id"`
		EventType string `json:"eventType"`
		Resource  struct {
			Repository struct {
				ID string `json:"id"`
			} `json:"repository"`
			RefUpdates []struct {
				Name        string `json:"name"`
				NewObjectID string `json:"newObjectId"`
			} `json:"refUpdates"`
			PullRequestID         int    `json:"pullRequestId"`
			Status                string `json:"status"`
			SourceRefName         string `json:"sourceRefName"`
			TargetRefName         string `json:"targetRefName"`
			LastMergeSourceCommit struct {
				CommitID string `json:"commitId"`
			} `json:"lastMergeSourceCommit"`
			LastMergeCommit struct {
				CommitID string `json:"commitId"`
			} `json:"lastMergeCommit"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return WebhookEvent{}, "", errors.New("scm: invalid JSON payload")
	}
	r := p.Resource
	ev := WebhookEvent{Kind: "ignored", ExternalID: r.Repository.ID}
	switch p.EventType {
	case "git.push":
		for _, u := range r.RefUpdates {
			if strings.HasPrefix(u.Name, "refs/heads/") && strings.Trim(u.NewObjectID, "0") != "" {
				ev.Kind, ev.Ref, ev.CommitSHA = "push", strings.TrimPrefix(u.Name, "refs/heads/"), u.NewObjectID
				break
			}
		}
	case "git.pullrequest.merged":
		ev.Kind, ev.Ref, ev.CommitSHA, ev.PullRequest = "merge", strings.TrimPrefix(r.TargetRefName, "refs/heads/"), r.LastMergeCommit.CommitID, r.PullRequestID
	case "git.pullrequest.created", "git.pullrequest.updated":
		if r.Status == "completed" {
			ev.Kind, ev.Ref, ev.CommitSHA = "merge", strings.TrimPrefix(r.TargetRefName, "refs/heads/"), r.LastMergeCommit.CommitID
		} else if r.Status == "active" {
			ev.Kind, ev.Ref, ev.CommitSHA = "pull_request", strings.TrimPrefix(r.SourceRefName, "refs/heads/"), r.LastMergeSourceCommit.CommitID
		}
		ev.PullRequest = r.PullRequestID
	}
	return ev, p.ID, nil
}

// VerifyGitLabToken checks the X-Gitlab-Token header (GitLab sends the
// configured secret token verbatim) in constant time.
func VerifyGitLabToken(secret []byte, header string) error {
	if len(secret) == 0 || subtle.ConstantTimeCompare([]byte(header), secret) != 1 {
		return ErrSignature
	}
	return nil
}

// GitLabSignatureTolerance is how far a signed GitLab delivery's
// webhook-timestamp may be from the receiver's clock.
const GitLabSignatureTolerance = 5 * time.Minute

// ParseGitLabSigningToken decodes a GitLab webhook signing token
// ("whsec_" + base64 key, Standard Webhooks) into the HMAC key.
func ParseGitLabSigningToken(token string) ([]byte, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(token), "whsec_")
	if !ok {
		return nil, errors.New("scm: a GitLab signing token starts with whsec_")
	}
	key, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		if key, err = base64.RawStdEncoding.DecodeString(rest); err != nil {
			return nil, errors.New("scm: the GitLab signing token is not valid base64 after whsec_")
		}
	}
	if len(key) < 16 {
		return nil, errors.New("scm: the GitLab signing token is too short")
	}
	return key, nil
}

// VerifyGitLabSignature checks a delivery signed with a GitLab webhook
// signing token (GitLab 19.0+, generally available in 19.1): the
// webhook-signature header holds space-separated "v1,<base64>" entries,
// each an HMAC-SHA256 over "<webhook-id>.<webhook-timestamp>.<raw body>"
// with the decoded token as key. Deliveries whose timestamp is more than
// GitLabSignatureTolerance from now are refused (replay protection).
func VerifyGitLabSignature(signingToken []byte, msgID, timestamp, signature string, body []byte, now time.Time) error {
	key, err := ParseGitLabSigningToken(string(signingToken))
	if err != nil || msgID == "" || timestamp == "" || signature == "" {
		return ErrSignature
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return ErrSignature
	}
	if d := now.Sub(time.Unix(ts, 0)); d > GitLabSignatureTolerance || d < -GitLabSignatureTolerance {
		return ErrSignature
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msgID + "." + timestamp + "."))
	m.Write(body)
	want := m.Sum(nil)
	for _, part := range strings.Fields(signature) {
		v, sig, ok := strings.Cut(part, ",")
		if !ok || v != "v1" {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(sig)
		if err == nil && hmac.Equal(got, want) {
			return nil
		}
	}
	return ErrSignature
}

// ParseGitLabEvent normalizes a GitLab webhook (X-Gitlab-Event: Push Hook,
// Merge Request Hook). It returns the project ID, which is also the event's
// ExternalID.
func ParseGitLabEvent(eventHeader string, body []byte) (WebhookEvent, string, error) {
	var p struct {
		Ref       string `json:"ref"`
		Before    string `json:"before"`
		After     string `json:"after"`
		ProjectID int64  `json:"project_id"`
		Project   struct {
			ID int64 `json:"id"`
		} `json:"project"`
		ObjectAttributes struct {
			IID            int    `json:"iid"`
			Action         string `json:"action"`
			State          string `json:"state"`
			SourceBranch   string `json:"source_branch"`
			TargetBranch   string `json:"target_branch"`
			MergeCommitSHA string `json:"merge_commit_sha"`
			LastCommit     struct {
				ID string `json:"id"`
			} `json:"last_commit"`
		} `json:"object_attributes"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return WebhookEvent{}, "", errors.New("scm: invalid JSON payload")
	}
	id := p.Project.ID
	if id == 0 {
		id = p.ProjectID
	}
	ev := WebhookEvent{Kind: "ignored"}
	if id != 0 {
		ev.ExternalID = strconv.FormatInt(id, 10)
	}
	switch eventHeader {
	case "Push Hook":
		if strings.HasPrefix(p.Ref, "refs/heads/") && strings.Trim(p.After, "0") != "" {
			ev.Kind, ev.Ref, ev.CommitSHA = "push", strings.TrimPrefix(p.Ref, "refs/heads/"), p.After
			ev.Before = p.Before
		}
	case "Merge Request Hook":
		a := p.ObjectAttributes
		ev.PullRequest = a.IID
		switch {
		case a.Action == "merge" || (a.Action == "" && a.State == "merged"):
			ev.Kind, ev.Ref, ev.CommitSHA = "merge", a.TargetBranch, a.MergeCommitSHA
		case a.Action == "open" || a.Action == "reopen" || a.Action == "update":
			ev.Kind, ev.Ref, ev.CommitSHA = "pull_request", a.SourceBranch, a.LastCommit.ID
		}
	}
	return ev, ev.ExternalID, nil
}

// VerifyBitbucketSignature checks X-Hub-Signature (sha256=<hex HMAC of the
// raw body>) sent by Bitbucket Cloud webhooks configured with a secret.
func VerifyBitbucketSignature(secret, body []byte, header string) error {
	if len(secret) == 0 {
		return ErrSignature
	}
	return VerifyGitHubSignature(secret, body, header)
}

// ParseBitbucketEvent normalizes a Bitbucket Cloud webhook (X-Event-Key:
// repo:push, pullrequest:created/updated/fulfilled). It returns the
// repository UUID, which is also the event's ExternalID.
func ParseBitbucketEvent(eventKey string, body []byte) (WebhookEvent, string, error) {
	type branchRef struct {
		Branch struct {
			Name string `json:"name"`
		} `json:"branch"`
		Commit struct {
			Hash string `json:"hash"`
		} `json:"commit"`
	}
	var p struct {
		Repository struct {
			UUID string `json:"uuid"`
		} `json:"repository"`
		Push struct {
			Changes []struct {
				New *struct {
					Type   string `json:"type"`
					Name   string `json:"name"`
					Target struct {
						Hash string `json:"hash"`
					} `json:"target"`
				} `json:"new"`
			} `json:"changes"`
		} `json:"push"`
		PullRequest struct {
			ID          int       `json:"id"`
			State       string    `json:"state"`
			Source      branchRef `json:"source"`
			Destination branchRef `json:"destination"`
			MergeCommit *struct {
				Hash string `json:"hash"`
			} `json:"merge_commit"`
		} `json:"pullrequest"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return WebhookEvent{}, "", errors.New("scm: invalid JSON payload")
	}
	ev := WebhookEvent{Kind: "ignored", ExternalID: p.Repository.UUID}
	pr := p.PullRequest
	switch eventKey {
	case "diagnostics:ping":
		ev.Kind = "ping"
	case "repo:push":
		for _, c := range p.Push.Changes {
			if c.New != nil && c.New.Type == "branch" && c.New.Target.Hash != "" {
				ev.Kind, ev.Ref, ev.CommitSHA = "push", c.New.Name, c.New.Target.Hash
				break
			}
		}
	case "pullrequest:fulfilled":
		ev.Kind, ev.Ref, ev.PullRequest = "merge", pr.Destination.Branch.Name, pr.ID
		if pr.MergeCommit != nil {
			ev.CommitSHA = pr.MergeCommit.Hash
		}
	case "pullrequest:created", "pullrequest:updated":
		ev.PullRequest = pr.ID
		if pr.State == "" || pr.State == "OPEN" {
			ev.Kind, ev.Ref, ev.CommitSHA = "pull_request", pr.Source.Branch.Name, pr.Source.Commit.Hash
		}
	}
	return ev, p.Repository.UUID, nil
}

// ParseBitbucketDataCenterEvent normalizes a Bitbucket Data Center webhook
// (X-Event-Key repo:refs_changed, pr:opened, pr:from_ref_updated,
// pr:merged, diagnostics:ping; payloads per
// https://confluence.atlassian.com/bitbucketserver/event-payload-938025882.html,
// checked 2026-11-20). Deliveries are signed like Bitbucket Cloud
// (X-Hub-Signature: sha256=<hex HMAC>, VerifyBitbucketSignature). It
// returns the numeric repository ID, which is also the ExternalID.
func ParseBitbucketDataCenterEvent(eventKey string, body []byte) (WebhookEvent, string, error) {
	type ref struct {
		DisplayID    string `json:"displayId"`
		LatestCommit string `json:"latestCommit"`
		Repository   struct {
			ID int `json:"id"`
		} `json:"repository"`
	}
	var p struct {
		Repository *struct {
			ID int `json:"id"`
		} `json:"repository"`
		Changes []struct {
			Ref struct {
				DisplayID string `json:"displayId"`
				Type      string `json:"type"`
			} `json:"ref"`
			FromHash string `json:"fromHash"`
			ToHash   string `json:"toHash"`
			Type     string `json:"type"`
		} `json:"changes"`
		PullRequest struct {
			ID         int    `json:"id"`
			State      string `json:"state"`
			FromRef    ref    `json:"fromRef"`
			ToRef      ref    `json:"toRef"`
			Properties struct {
				MergeCommit *struct {
					ID string `json:"id"`
				} `json:"mergeCommit"`
			} `json:"properties"`
		} `json:"pullRequest"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return WebhookEvent{}, "", errors.New("scm: invalid JSON payload")
	}
	ext := ""
	switch {
	case p.Repository != nil && p.Repository.ID > 0:
		ext = strconv.Itoa(p.Repository.ID)
	case p.PullRequest.ToRef.Repository.ID > 0:
		ext = strconv.Itoa(p.PullRequest.ToRef.Repository.ID)
	}
	ev := WebhookEvent{Kind: "ignored", ExternalID: ext}
	pr := p.PullRequest
	switch eventKey {
	case "diagnostics:ping":
		ev.Kind = "ping"
	case "repo:refs_changed":
		for _, c := range p.Changes {
			if c.Ref.Type == "BRANCH" && c.Type != "DELETE" && c.ToHash != "" {
				ev.Kind, ev.Ref, ev.CommitSHA, ev.Before = "push", c.Ref.DisplayID, c.ToHash, c.FromHash
				break
			}
		}
	case "pr:merged":
		ev.Kind, ev.Ref, ev.PullRequest = "merge", pr.ToRef.DisplayID, pr.ID
		if pr.Properties.MergeCommit != nil {
			ev.CommitSHA = pr.Properties.MergeCommit.ID
		}
	case "pr:opened", "pr:from_ref_updated":
		ev.PullRequest = pr.ID
		if pr.State == "" || pr.State == "OPEN" {
			ev.Kind, ev.Ref, ev.CommitSHA = "pull_request", pr.FromRef.DisplayID, pr.FromRef.LatestCommit
		}
	}
	return ev, ext, nil
}
