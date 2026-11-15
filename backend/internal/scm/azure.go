package scm

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// azureDevOps implements Client for Azure DevOps Services
// (https://dev.azure.com/<org>) and Server (https://host/<collection>).
type azureDevOps struct {
	cfg Config
}

const adoAPIVersion = "7.1"

func (a *azureDevOps) get(ctx context.Context, path string, out any) (*http.Response, error) {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	req, err := http.NewRequest(http.MethodGet, a.cfg.BaseURL+path+sep+"api-version="+adoAPIVersion, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(append([]byte(":"), a.cfg.Secret...)))
	return doJSON(ctx, a.cfg.HTTP, req, out)
}

func (a *azureDevOps) Check(ctx context.Context) (string, error) {
	var out struct {
		Count int `json:"count"`
	}
	if _, err := a.get(ctx, "/_apis/projects?$top=1", &out); err != nil {
		return "", err
	}
	return "connected to " + a.cfg.BaseURL, nil
}

type adoRepo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	RemoteURL     string `json:"remoteUrl"`
	WebURL        string `json:"webUrl"`
	DefaultBranch string `json:"defaultBranch"`
	IsDisabled    bool   `json:"isDisabled"`
	Project       struct {
		Name       string `json:"name"`
		Visibility string `json:"visibility"`
	} `json:"project"`
}

func (a *azureDevOps) ListRepositories(ctx context.Context) ([]RemoteRepo, error) {
	path := "/_apis/git/repositories"
	if a.cfg.Owner != "" {
		path = "/" + url.PathEscape(a.cfg.Owner) + "/_apis/git/repositories"
	}
	var out struct {
		Value []adoRepo `json:"value"`
	}
	if _, err := a.get(ctx, path, &out); err != nil {
		return nil, err
	}
	repos := make([]RemoteRepo, 0, len(out.Value))
	for _, r := range out.Value {
		vis := "private"
		if strings.EqualFold(r.Project.Visibility, "public") {
			vis = "public"
		}
		repos = append(repos, RemoteRepo{
			ExternalID: r.ID, FullName: r.Project.Name + "/" + r.Name, Name: r.Name, URL: r.WebURL,
			CloneURL: r.RemoteURL, DefaultBranch: strings.TrimPrefix(r.DefaultBranch, "refs/heads/"),
			Visibility: vis, Archived: r.IsDisabled,
		})
		if len(repos) >= MaxRepositories {
			break
		}
	}
	return repos, nil
}

func (a *azureDevOps) ListBranches(ctx context.Context, repo RemoteRepo) ([]string, error) {
	project, _, ok := strings.Cut(repo.FullName, "/")
	if !ok {
		return nil, fmt.Errorf("scm: invalid repository name")
	}
	var out struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	path := fmt.Sprintf("/%s/_apis/git/repositories/%s/refs?filter=heads/&$top=1000", url.PathEscape(project), url.PathEscape(repo.ExternalID))
	if _, err := a.get(ctx, path, &out); err != nil {
		return nil, err
	}
	branches := make([]string, 0, len(out.Value))
	for _, r := range out.Value {
		branches = append(branches, strings.TrimPrefix(r.Name, "refs/heads/"))
	}
	return branches, nil
}

// CloneCredential implements Client (Azure DevOps accepts any username with a PAT).
func (a *azureDevOps) CloneCredential(context.Context) (Credential, error) {
	return Credential{Username: "pathos", Token: string(a.cfg.Secret)}, nil
}
