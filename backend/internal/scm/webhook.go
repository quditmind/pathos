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
