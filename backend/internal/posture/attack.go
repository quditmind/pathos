package posture

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"pathos/internal/authz"
	"pathos/internal/platform/httpx"
	"pathos/internal/runtimectx"
)

// Attack paths: how an attacker on the internet could reach a weakness.
//
//	internet → tested web application or API (DAST target) → finding
//	internet → internet-exposed repository → code finding (SAST, secrets, IaC)
//	internet → internet-exposed repository → reachable vulnerable dependency
//	internet → internet-exposed repository → its container image → finding
//	internet → Ingress/LoadBalancer → running workload → image → finding
//	  (observed in a connected Kubernetes cluster; see internal/runtimectx)
//
// Dependency findings count only when the code uses the package (reachable);
// unreachable or unknown dependencies are not attack paths. Paths are ranked
// by the finding's contextual risk.

// Step is one hop of an attack path.
type Step struct {
	Type  string `json:"type"` // internet, target, repository, application, component, image, workload, finding
	Label string `json:"label"`
	Sub   string `json:"sub,omitempty"`
	Link  string `json:"link,omitempty"`
}

// AttackPath is a path from the internet to a finding.
type AttackPath struct {
	FindingID uuid.UUID `json:"finding_id"`
	Risk      float64   `json:"risk"`
	Severity  string    `json:"severity"`
	KEV       bool      `json:"kev"`
	Exploit   bool      `json:"exploit_available"`
	Entry     string    `json:"entry"` // dast_target | exposed_repository | runtime_exposure
	Steps     []Step    `json:"steps"`
	Reasons   []string  `json:"reasons"`
}

func (s *Service) attackPaths(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	minRisk, err := intParam(r, "min_risk", 50, 0, 100)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	limit, err := intParam(r, "limit", 100, 1, 500)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cond, args, err := scope(p, authz.PermFindingsRead, 4)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	args = append([]any{p.OrganizationID, minRisk, limit}, args...)
	// #nosec G202 -- cond is built from placeholders
	rows, err := s.DB.Query(ctx, `
	SELECT f.id, f.title, f.severity, f.category, f.risk_score::float8, f.kev, f.exploit_available, f.reachability, f.reachability_basis,
	       f.package_name, f.package_version, f.file_path, f.start_line, st.kind, st.name, st.reference,
	       r.id, COALESCE(NULLIF(r.display_name, ''), r.full_name), r.repository_key, r.public_exposure,
	       COALESCE((SELECT string_agg(e.value, ', ' ORDER BY e.position) FROM repository_public_endpoints e WHERE e.repository_id = r.id), ''),
	       COALESCE(NULLIF(r.production_url, ''), ''), a.id, a.name, f.runtime_exposed, f.runtime_context
	FROM findings f
	JOIN repositories r ON r.id = f.repository_id
	LEFT JOIN applications a ON a.id = r.application_id
	LEFT JOIN scan_targets st ON st.id = f.scan_target_id
	WHERE f.organization_id = $1 AND f.status IN `+openStatuses+` AND f.risk_score >= $2 AND r.archived_at IS NULL AND `+cond+`
	  AND (st.kind IN ('url', 'api') OR f.runtime_exposed
	       OR (r.public_exposure = 'yes' AND st.id IS NULL AND (f.category <> 'sca' OR f.reachability = 'reachable'))
	       OR (r.public_exposure = 'yes' AND st.kind = 'image'))
	ORDER BY f.risk_score DESC, f.kev DESC, f.id LIMIT $3`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	out := []AttackPath{}
	entries := map[string]int{}
	for rows.Next() {
		var a AttackPath
		var title, category, reach, basis, pkg, ver, file, repoName, repoKey, exposure, endpoints, prodURL string
		var line *int
		var tKind, tName, tRef, appName *string
		var repoID uuid.UUID
		var appID *uuid.UUID
		var risk *float64
		var rtExposed bool
		var rtCtx []byte
		if err := rows.Scan(&a.FindingID, &title, &a.Severity, &category, &risk, &a.KEV, &a.Exploit, &reach, &basis, &pkg, &ver, &file, &line,
			&tKind, &tName, &tRef, &repoID, &repoName, &repoKey, &exposure, &endpoints, &prodURL, &appID, &appName, &rtExposed, &rtCtx); err != nil {
			s.fail(w, r, err)
			return
		}
		if risk != nil {
			a.Risk = *risk
		}
		repoStep := Step{Type: "repository", Label: repoName, Sub: repoKey, Link: "/repositories?repo=" + repoID.String()}
		var appStep *Step
		if appID != nil {
			appStep = &Step{Type: "application", Label: *appName, Link: "/posture/graph?node=application:" + appID.String()}
		}
		finding := Step{Type: "finding", Label: title, Sub: a.Severity + " · " + strings.ToUpper(category), Link: "/findings?finding=" + a.FindingID.String()}
		where := firstNonEmpty(endpoints, prodURL)
		var observed *runtimectx.DeploymentEvidence
		if rtExposed {
			var rc runtimectx.RuntimeContext
			if json.Unmarshal(rtCtx, &rc) == nil {
				for i := range rc.Deployments {
					if rc.Deployments[i].Exposed {
						observed = &rc.Deployments[i]
						break
					}
				}
			}
		}
		switch {
		case tKind != nil && (*tKind == "url" || *tKind == "api"):
			a.Entry = "dast_target"
			a.Steps = append(a.Steps, Step{Type: "internet", Label: "Internet", Sub: *tRef},
				Step{Type: "target", Label: *tName, Sub: map[string]string{"url": "web application", "api": "API"}[*tKind], Link: "/scans/targets"})
			a.Reasons = append(a.Reasons, "found by testing the running application from outside")
		case observed != nil:
			// Observed in a cluster: the entry point is the Ingress host or
			// the load balancer address that routes to the workload.
			a.Entry = "runtime_exposure"
			entry, detail := "", ""
			for _, x := range observed.Exposure {
				if x.Internet {
					entry, detail = firstNonEmpty(x.Host, x.Address, x.Service), x.Detail
					break
				}
			}
			a.Steps = append(a.Steps, Step{Type: "internet", Label: "Internet", Sub: entry},
				Step{Type: "workload", Label: observed.Kind + " " + observed.Workload, Sub: observed.Cluster + " / " + observed.Namespace, Link: "/runtime"},
				Step{Type: "image", Label: observed.Image, Sub: observed.BasisDetail})
			a.Reasons = append(a.Reasons, "observed in cluster "+observed.Cluster+": "+detail)
			if observed.Privileged || observed.HostNetwork || observed.HostPID {
				a.Reasons = append(a.Reasons, "the workload is privileged or shares the host's namespaces")
			}
		case tKind != nil && *tKind == "image":
			a.Entry = "exposed_repository"
			a.Steps = append(a.Steps, Step{Type: "internet", Label: "Internet", Sub: where}, repoStep,
				Step{Type: "image", Label: *tName, Sub: *tRef, Link: "/scans/targets"})
			a.Reasons = append(a.Reasons, "the asset is exposed to the internet and runs this image")
		default:
			a.Entry = "exposed_repository"
			a.Steps = append(a.Steps, Step{Type: "internet", Label: "Internet", Sub: where}, repoStep)
			if category == "sca" {
				a.Steps = append(a.Steps, Step{Type: "component", Label: pkg + "@" + ver, Sub: basis})
				a.Reasons = append(a.Reasons, "the asset is exposed to the internet and its code uses the vulnerable package")
			} else {
				loc := file
				if line != nil {
					loc += ":" + strconv.Itoa(*line)
				}
				finding.Sub += " · " + loc
				a.Reasons = append(a.Reasons, "the asset is exposed to the internet")
			}
		}
		if appStep != nil {
			// The application sits between the entry point and the code.
			a.Steps = append(a.Steps[:1], append([]Step{*appStep}, a.Steps[1:]...)...)
		}
		a.Steps = append(a.Steps, finding)
		if a.KEV {
			a.Reasons = append(a.Reasons, "actively exploited (CISA KEV)")
		} else if a.Exploit {
			a.Reasons = append(a.Reasons, "a public exploit or proof of concept exists")
		}
		entries[a.Entry]++
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"min_risk": minRisk, "items": out, "counts": entries, "truncated": len(out) >= limit})
}
