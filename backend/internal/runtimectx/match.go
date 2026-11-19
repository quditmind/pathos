package runtimectx

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Pure matching rules of the linker (unit-tested in match_test.go).

// MatchTarget decides whether a running image is the image an image scan
// target scanned:
//
//   - digest: the running digest equals the digest pinned in the target's
//     reference or a digest the target's scans resolved to (Trivy
//     repoDigests). Content-addressed, so exact.
//   - tag: same registry, repository and tag, and either the running
//     digest is unknown (no running pod) or no scan has recorded the
//     target's digest yet. Weaker: the tag may have moved.
//
// A running digest that differs from every recorded digest of the target
// is not linked: the findings belong to another build.
func MatchTarget(running, target ImageRef, scanned []string) (basis, detail string, ok bool) {
	known := slices.Clone(scanned)
	if target.Digest != "" {
		known = append(known, target.Digest)
	}
	if running.Digest != "" && slices.Contains(known, running.Digest) {
		return "digest", "running digest " + short(running.Digest) + " is the scanned image", true
	}
	if !SameRepository(running, target) || target.Tag == "" || running.Tag != target.Tag {
		return "", "", false
	}
	switch {
	case running.Digest == "":
		return "tag", "same tag " + target.Tag + "; the running digest is not known (no running pod)", true
	case len(known) == 0:
		return "tag", "same tag " + target.Tag + "; the scanned digest is not recorded yet (scan the target again for an exact match)", true
	}
	return "", "", false
}

func short(d string) string {
	if i := strings.Index(d, ":"); i >= 0 && len(d) > i+13 {
		return d[:i+13]
	}
	return d
}

// AlertLocation splits the location of an imported runtime alert
// ("namespace/pod" or "namespace/pod (container)") into namespace and pod.
func AlertLocation(loc string) (ns, pod string, ok bool) {
	loc = strings.TrimSpace(loc)
	if i := strings.Index(loc, " ("); i >= 0 {
		loc = loc[:i]
	}
	ns, pod, ok = strings.Cut(loc, "/")
	if !ok || ns == "" || pod == "" || strings.ContainsAny(pod, "/ ") || strings.HasPrefix(loc, "host ") {
		return "", "", false
	}
	return ns, pod, true
}

var (
	rsHashRe  = `[a-z0-9]{5,10}`
	podSufRe  = `[a-z0-9]{5}`
	patternFn = map[string]func(string) string{
		"Deployment":  func(n string) string { return "^" + regexp.QuoteMeta(n) + "-" + rsHashRe + "-" + podSufRe + "$" },
		"StatefulSet": func(n string) string { return "^" + regexp.QuoteMeta(n) + `-\d+$` },
		"DaemonSet":   func(n string) string { return "^" + regexp.QuoteMeta(n) + "-" + podSufRe + "$" },
		"Job":         func(n string) string { return "^" + regexp.QuoteMeta(n) + "-" + podSufRe + "$" },
		"CronJob":     func(n string) string { return "^" + regexp.QuoteMeta(n) + `-\d{6,12}-` + podSufRe + "$" },
	}
)

// MatchAlertPod decides whether a pod named in a runtime alert belongs to a
// workload: pod_name when the pod was seen at the last sync, else
// pod_name_pattern when the name has the shape the workload's controller
// gives its pods (pods are replaced, alerts outlive them).
func MatchAlertPod(ns, pod string, w Workload) (string, bool) {
	if ns != w.Namespace {
		return "", false
	}
	if slices.Contains(w.PodNames, pod) || (w.Kind == "Pod" && pod == w.Name) {
		return "pod_name", true
	}
	if f, ok := patternFn[w.Kind]; ok {
		if re, err := regexp.Compile(f(w.Name)); err == nil && re.MatchString(pod) {
			return "pod_name_pattern", true
		}
	}
	return "", false
}

// Mapping assigns workloads to an application.
type Mapping struct {
	ID            string
	ClusterID     string // "" = every cluster
	Namespace     string // "" = every namespace
	LabelKey      string
	LabelValue    string // "" with a key: the key exists
	ApplicationID string
}

// specificity orders mappings: cluster, label and namespace conditions
// each make a mapping more specific.
func (m Mapping) specificity() int {
	n := 0
	if m.ClusterID != "" {
		n += 4
	}
	if m.LabelKey != "" {
		n += 2
	}
	if m.Namespace != "" {
		n++
	}
	return n
}

// Describe explains a mapping for the evidence.
func (m Mapping) Describe() string {
	var parts []string
	if m.Namespace != "" {
		parts = append(parts, "namespace "+m.Namespace)
	}
	if m.LabelKey != "" {
		if m.LabelValue != "" {
			parts = append(parts, "label "+m.LabelKey+"="+m.LabelValue)
		} else {
			parts = append(parts, "label "+m.LabelKey)
		}
	}
	return strings.Join(parts, " and ")
}

// MapApplication returns the most specific mapping that matches a workload.
func MapApplication(clusterID string, w Workload, ms []Mapping) (Mapping, bool) {
	sorted := slices.Clone(ms)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].specificity() > sorted[j].specificity() })
	for _, m := range sorted {
		if m.ClusterID != "" && m.ClusterID != clusterID {
			continue
		}
		if m.Namespace != "" && m.Namespace != w.Namespace {
			continue
		}
		if m.LabelKey != "" {
			v, ok := w.Labels[m.LabelKey]
			if !ok || (m.LabelValue != "" && v != m.LabelValue) {
				continue
			}
		}
		return m, true
	}
	return Mapping{}, false
}

// --- finding summary ---------------------------------------------------------

// DeploymentEvidence is one place a finding runs (stored in the finding's
// runtime_context and shown in the finding drawer).
type DeploymentEvidence struct {
	ClusterID   string     `json:"cluster_id"`
	Cluster     string     `json:"cluster"`
	WorkloadID  string     `json:"workload_id"`
	Namespace   string     `json:"namespace"`
	Kind        string     `json:"kind"`
	Workload    string     `json:"workload"`
	Container   string     `json:"container"`
	Image       string     `json:"image"`
	Digest      string     `json:"digest,omitempty"`
	Basis       string     `json:"basis"`
	BasisDetail string     `json:"basis_detail"`
	Exposed     bool       `json:"internet_exposed"`
	Exposure    []Exposure `json:"exposure,omitempty"`
	Privileged  bool       `json:"privileged"`
	HostNetwork bool       `json:"host_network"`
	HostPID     bool       `json:"host_pid"`
	RunAsRoot   string     `json:"run_as_root"`
	Alerts      []Alert    `json:"alerts,omitempty"`
}

// Alert is an open runtime alert matched to a workload.
type Alert struct {
	FindingID string `json:"finding_id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Location  string `json:"location"`
	Basis     string `json:"basis"`
}

// FindingRuntime is what the linker stores on a finding.
type FindingRuntime struct {
	Status     string // "", deployed, not_deployed
	Exposed    bool
	Privileged bool
	Alert      bool
	Context    *RuntimeContext
}

// RuntimeContext is the stored evidence.
type RuntimeContext struct {
	Status      string               `json:"status"`
	Deployments []DeploymentEvidence `json:"deployments"`
	Total       int                  `json:"total_deployments"`
	// NotDeployed explains a not_deployed status.
	NotDeployed string   `json:"not_deployed_reason,omitempty"`
	Images      []string `json:"images,omitempty"` // images PATHOS knows for the finding
	Clusters    []string `json:"clusters"`         // connected clusters with a recent inventory
}

// maxEvidence bounds the deployments kept per finding.
const maxEvidence = 25

// Summarize computes a finding's runtime facts from its deployments.
// eligible: PATHOS knows which image(s) the finding ships in (an image
// scan target, or a repository whose images are known), so the absence of
// a deployment means "not deployed". clusters are the connected clusters
// with a recent successful inventory (none: the status stays unknown).
func Summarize(deps []DeploymentEvidence, eligible bool, images, clusters []string) FindingRuntime {
	var out FindingRuntime
	if len(clusters) == 0 {
		return out
	}
	sort.SliceStable(deps, func(i, j int) bool {
		a, b := deps[i], deps[j]
		if a.Exposed != b.Exposed {
			return a.Exposed
		}
		if (len(a.Alerts) > 0) != (len(b.Alerts) > 0) {
			return len(a.Alerts) > 0
		}
		if a.Privileged != b.Privileged {
			return a.Privileged
		}
		return a.Cluster+"/"+a.Namespace+"/"+a.Workload+"/"+a.Container < b.Cluster+"/"+b.Namespace+"/"+b.Workload+"/"+b.Container
	})
	ctx := &RuntimeContext{Total: len(deps), Clusters: clusters, Images: images}
	if len(images) > 20 {
		ctx.Images = images[:20]
	}
	switch {
	case len(deps) > 0:
		out.Status = "deployed"
		for _, d := range deps {
			out.Exposed = out.Exposed || d.Exposed
			out.Privileged = out.Privileged || d.Privileged || d.HostNetwork || d.HostPID
			out.Alert = out.Alert || len(d.Alerts) > 0
		}
		if len(deps) > maxEvidence {
			deps = deps[:maxEvidence]
		}
		ctx.Deployments = deps
	case eligible:
		out.Status = "not_deployed"
		ctx.Deployments = []DeploymentEvidence{}
		ctx.NotDeployed = fmt.Sprintf("no workload in the %d connected cluster(s) (%s) runs %s", len(clusters), strings.Join(clusters, ", "),
			strings.Join(ctx.Images, ", "))
	default:
		return out
	}
	ctx.Status = out.Status
	out.Context = ctx
	return out
}

// FactorEvidence turns a stored runtime context into the evidence lines of
// the risk factors (cluster, namespace, workload, ingress host, alert).
func FactorEvidence(ctx *RuntimeContext) (deployed, exposed, privileged, alerts []string) {
	if ctx == nil {
		return
	}
	if ctx.Status == "not_deployed" {
		return []string{ctx.NotDeployed}, nil, nil, nil
	}
	for _, d := range ctx.Deployments {
		where := fmt.Sprintf("cluster %s, namespace %s, %s %s (container %s, image %s; %s)", d.Cluster, d.Namespace, d.Kind, d.Workload,
			d.Container, d.Image, d.BasisDetail)
		if len(deployed) < 5 {
			deployed = append(deployed, where)
		}
		for _, x := range d.Exposure {
			if x.Internet && len(exposed) < 5 {
				exposed = append(exposed, fmt.Sprintf("cluster %s, namespace %s, %s %s: %s", d.Cluster, d.Namespace, d.Kind, d.Workload, x.Detail))
			}
		}
		if (d.Privileged || d.HostNetwork || d.HostPID) && len(privileged) < 5 {
			var what []string
			if d.Privileged {
				what = append(what, "privileged container")
			}
			if d.HostNetwork {
				what = append(what, "hostNetwork")
			}
			if d.HostPID {
				what = append(what, "hostPID")
			}
			privileged = append(privileged, fmt.Sprintf("cluster %s, namespace %s, %s %s: %s", d.Cluster, d.Namespace, d.Kind, d.Workload, strings.Join(what, ", ")))
		}
		for _, a := range d.Alerts {
			if len(alerts) < 5 {
				alerts = append(alerts, fmt.Sprintf("%s (%s) at %s, matched to %s %s in cluster %s by %s", a.Title, a.Severity, a.Location, d.Kind, d.Workload,
					d.Cluster, strings.ReplaceAll(a.Basis, "_", " ")))
			}
		}
	}
	if ctx.Total > len(ctx.Deployments) && len(deployed) > 0 {
		deployed = append(deployed, fmt.Sprintf("and %d more", ctx.Total-len(ctx.Deployments)))
	}
	return
}
