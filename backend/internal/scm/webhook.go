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
}

// ParseGitHubEvent normalizes a GitHub webhook payload.
func ParseGitHubEvent(event string, body []byte) (WebhookEvent, error) {
	var p struct {
		Ref        string `json:"ref"`
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

// ParseGitLabEvent normalizes a GitLab webhook (X-Gitlab-Event: Push Hook,
// Merge Request Hook). It returns the project ID, which is also the event's
// ExternalID.
func ParseGitLabEvent(eventHeader string, body []byte) (WebhookEvent, string, error) {
	var p struct {
		Ref       string `json:"ref"`
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
