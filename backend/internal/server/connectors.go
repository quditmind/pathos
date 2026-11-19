package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"pathos/internal/ai"
	"pathos/internal/connectors"
	"pathos/internal/notify"
	"pathos/internal/platform/objstore"
	"pathos/internal/repos"
	"pathos/internal/runtimectx"
	"pathos/internal/scm"
	"pathos/internal/tickets"
	"pathos/internal/vault"
)

// Adapters from the existing services to the connector health checks.
// Each check reuses the service's own client and credential handling.

type scmChecker struct{ s *repos.Service }

func (a scmChecker) CheckConnection(ctx context.Context, orgID, id uuid.UUID) (connectors.SCMCheck, error) {
	c, err := a.s.CheckConnection(ctx, orgID, id)
	return connectors.SCMCheck{Account: c.Account, TokenExpiresAt: c.TokenExpiresAt, GitLabWebhookAuth: c.GitLabWebhookAuth}, err
}

type notifyChecker struct{ s *notify.Service }

func (a notifyChecker) ProbeSMTP(ctx context.Context, orgID uuid.UUID) (connectors.SMTPProbe, error) {
	h, err := a.s.ProbeSMTP(ctx, orgID)
	out := connectors.SMTPProbe{Configured: h.Configured, Enabled: h.Enabled, TLS: h.TLSMode, Auth: h.Auth}
	var se *notify.SMTPError
	if errors.As(err, &se) {
		switch se.Stage {
		case "starttls":
			if errors.Is(err, notify.ErrNoSTARTTLS) {
				err = errors.Join(connectors.ErrSMTPNoSTARTTLS, err)
			}
		case "auth":
			err = errors.Join(connectors.ErrSMTPAuth, err)
		}
	}
	return out, err
}

func (a notifyChecker) CheckWebhook(ctx context.Context, orgID, id uuid.UUID) (connectors.WebhookCheck, error) {
	h, err := a.s.CheckWebhook(ctx, orgID, id)
	return connectors.WebhookCheck{Format: h.Format, Host: h.Host, LastStatus: h.LastStatus, LastAt: h.LastAt, LastResponse: h.LastResponse,
		Failed24h: h.Failed24h, TriggerAuth: h.TriggerAuth, TriggerAuthError: h.TriggerAuthErr}, err
}

type runtimeChecker struct{ s *runtimectx.Service }

func (a runtimeChecker) CheckCluster(ctx context.Context, orgID, id uuid.UUID) (connectors.ClusterCheck, error) {
	h, err := a.s.CheckCluster(ctx, orgID, id)
	return connectors.ClusterCheck{ServerVersion: h.ServerVersion, Readable: h.Readable, Denied: h.Denied, LongLived: h.LongLived}, err
}

func (a runtimeChecker) CheckRegistry(ctx context.Context, orgID, id uuid.UUID) (connectors.RegistryCheck, error) {
	h, err := a.s.CheckRegistry(ctx, orgID, id)
	return connectors.RegistryCheck{Repository: h.Repository, Tags: h.Tags, RateLimit: h.RateLimitRemaining}, err
}

type objectStore struct {
	p interface{ Ping(context.Context) error }
}

func (o objectStore) Ping(ctx context.Context) error {
	err := o.p.Ping(ctx)
	var ae *objstore.AccessError
	switch {
	case errors.As(err, &ae):
		return errors.Join(connectors.ErrObjectStoreDenied, err)
	case errors.Is(err, objstore.ErrBucketNotFound):
		return errors.Join(connectors.ErrBucketNotFound, err)
	}
	return err
}

// ConnectorEnv builds the environment of the connector health checks from
// the existing services (shared by the API and jobs roles).
func ConnectorEnv(d Deps, role string, repoSvc *repos.Service, aiSvc *ai.Service, rt *runtimectx.Service) *connectors.Env {
	env := &connectors.Env{DB: d.DB, Secrets: d.Secrets, Log: d.Log, Role: role, Offline: d.Offline,
		SCM:         scmChecker{repoSvc},
		Tickets:     &tickets.Service{DB: d.DB, Secrets: d.Secrets, Log: d.Log},
		Notify:      notifyChecker{&notify.Service{DB: d.DB, Secrets: d.Secrets, Log: d.Log}},
		EgressProxy: d.EgressProxyURL, Interval: d.ConnectorCheckInterval,
		HTTP: func(allowPrivate bool) *http.Client {
			return scm.NetPolicy{AllowPrivate: allowPrivate, AllowHTTP: d.SCMNet.AllowHTTP}.Client()
		},
	}
	if repoSvc != nil {
		env.SCMCreator = repoSvc
	}
	if d.DB != nil && d.Secrets != nil {
		// "vault:" secret references resolve through the organization's
		// Vault/OpenBao connector of the registry.
		vault.Default.Source = connectors.VaultSource(d.DB, d.Secrets)
	}
	if aiSvc != nil {
		env.AI = aiSvc
	}
	if rt != nil {
		env.Runtime = runtimeChecker{rt}
	}
	if p, ok := d.Artifacts.(interface{ Ping(context.Context) error }); ok && d.Artifacts != nil {
		env.ObjectStore = objectStore{p}
		env.ObjectStoreMeta = d.ObjectStoreMeta
	}
	return env
}
