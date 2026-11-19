package runtimectx

import (
	"os"
	"strings"
	"testing"
)

func ref(t *testing.T, s string) ImageRef {
	t.Helper()
	r, ok := ParseImageRef(s)
	if !ok {
		t.Fatalf("parse %q", s)
	}
	return r
}

func TestParseImageRef(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"nginx", "docker.io/library/nginx:latest"},
		{"nginx:1.25", "docker.io/library/nginx:1.25"},
		{"acme/app:2", "docker.io/acme/app:2"},
		{"index.docker.io/acme/app", "docker.io/acme/app:latest"},
		{"ghcr.io/Acme/App:1.0", "ghcr.io/acme/app:1.0"},
		{"localhost/app", "localhost/app:latest"},
		{"registry.internal:5000/pay/api:v1@" + digAPI, "registry.internal:5000/pay/api:v1@" + digAPI},
		{"registry.internal:5000/pay/api@" + digAPI, "registry.internal:5000/pay/api@" + digAPI},
		{"docker-pullable://ghcr.io/acme/shop@" + digWeb, "ghcr.io/acme/shop@" + digWeb},
	} {
		if got := ref(t, c.in).String(); got != c.want {
			t.Errorf("%s: got %s want %s", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"", "a b", "ghcr.io/acme/app@sha256:short", "@" + digWeb} {
		if _, ok := ParseImageRef(bad); ok {
			t.Errorf("%q should not parse", bad)
		}
	}
}

func TestNormalizeSourceURL(t *testing.T) {
	want := "github.com/acme/shop"
	for _, s := range []string{"https://github.com/acme/shop", "https://github.com/Acme/Shop.git", "git@github.com:acme/shop.git",
		"https://user@github.com/acme/shop/", "https://github.com:443/acme/shop", "ssh://git@github.com/acme/shop"} {
		if got := NormalizeSourceURL(s); got != want {
			t.Errorf("%s: %s", s, got)
		}
	}
	if NormalizeSourceURL("https://github.com") != "" || NormalizeSourceURL("") != "" {
		t.Error("no path, no match")
	}
}

func TestMatchTarget(t *testing.T) {
	running := ref(t, "ghcr.io/acme/shop:1.0@"+digWeb)
	cases := []struct {
		name    string
		target  string
		scanned []string
		run     ImageRef
		basis   string
	}{
		{"scanned digest", "ghcr.io/acme/shop:1.0", []string{digWeb}, running, "digest"},
		{"pinned target digest", "ghcr.io/acme/shop@" + digWeb, nil, running, "digest"},
		{"digest across a mirror name", "mirror.example.com/acme/shop:1.0", []string{digWeb}, running, "digest"},
		{"tag, digest not recorded yet", "ghcr.io/acme/shop:1.0", nil, running, "tag"},
		{"tag moved: another build", "ghcr.io/acme/shop:1.0", []string{digWebOld}, running, ""},
		{"other tag", "ghcr.io/acme/shop:2.0", nil, running, ""},
		{"other repository", "ghcr.io/acme/other:1.0", nil, running, ""},
		{"no running digest (scaled to zero)", "ghcr.io/acme/shop:1.0", []string{digWebOld}, ref(t, "ghcr.io/acme/shop:1.0"), "tag"},
		{"docker hub library", "nginx:1.25", nil, ref(t, "docker.io/library/nginx:1.25@"+digDB), "tag"},
	}
	for _, c := range cases {
		basis, detail, ok := MatchTarget(c.run, ref(t, c.target), c.scanned)
		if basis != c.basis || ok != (c.basis != "") || (ok && detail == "") {
			t.Errorf("%s: got %q %v (%s)", c.name, basis, ok, detail)
		}
	}
}

// TestLinkingKnownAnswers measures the linking rules on a labelled sample:
// pairs of (running image, scan target) where the truth is known because
// the digests are content addresses. Precision and recall are printed;
// both must be 1.0 for the digest rule, and the tag rule must never link
// a pair whose recorded digest differs.
func TestLinkingKnownAnswers(t *testing.T) {
	type pair struct {
		run, target string
		scanned     []string
		same        bool // ground truth: the running image is the scanned image
	}
	pairs := []pair{
		{"ghcr.io/acme/shop:1.0@" + digWeb, "ghcr.io/acme/shop:1.0", []string{digWeb}, true},
		{"ghcr.io/acme/shop:1.0@" + digWebOld, "ghcr.io/acme/shop:1.0", []string{digWeb}, false},
		{"ghcr.io/acme/shop:1.1@" + digWeb, "ghcr.io/acme/shop:1.0", []string{digWeb}, true}, // retagged, same content
		{"registry.internal:5000/pay/api@" + digAPI, "registry.internal:5000/pay/api@" + digAPI, nil, true},
		{"registry.internal:5000/pay/api@" + digAPI, "registry.internal:5000/pay/api@" + digDB, nil, false},
		{"docker.io/library/postgres:16@" + digDB, "postgres:16", []string{digDB}, true},
		{"docker.io/library/postgres:16@" + digDB, "postgres:15", []string{digAgent}, false},
		{"quay.io/acme/agent:v1@" + digAgent, "quay.io/acme/agent:v2", []string{digReport}, false},
		{"ghcr.io/acme/report:2@" + digReport, "ghcr.io/acme/report:2", []string{digReport, digWeb}, true},
		{"ghcr.io/acme/report:2@" + digReport, "ghcr.io/acme/reports:2", nil, false},
	}
	tp, fp, fn := 0, 0, 0
	for _, p := range pairs {
		basis, _, ok := MatchTarget(ref(t, p.run), ref(t, p.target), p.scanned)
		switch {
		case ok && p.same:
			tp++
		case ok && !p.same:
			fp++
			t.Errorf("false link (%s): %s ↔ %s", basis, p.run, p.target)
		case !ok && p.same:
			fn++
			t.Errorf("missed link: %s ↔ %s", p.run, p.target)
		}
	}
	precision := float64(tp) / float64(max(tp+fp, 1))
	recall := float64(tp) / float64(max(tp+fn, 1))
	t.Logf("digest/tag linking on %d labelled pairs: precision %.2f, recall %.2f", len(pairs), precision, recall)
}

func TestAlertMatching(t *testing.T) {
	ns, pod, ok := AlertLocation("shop/web-7d9f8c6b5-zzzzz (web)")
	if !ok || ns != "shop" || pod != "web-7d9f8c6b5-zzzzz" {
		t.Fatalf("location: %s %s %v", ns, pod, ok)
	}
	for _, bad := range []string{"host node-1", "container abc", "shop", "/pod"} {
		if _, _, ok := AlertLocation(bad); ok {
			t.Errorf("%q is not a pod location", bad)
		}
	}
	web := Workload{Namespace: "shop", Kind: "Deployment", Name: "web", PodNames: []string{"web-7d9f8c6b5-abcde"}}
	webAPI := Workload{Namespace: "shop", Kind: "Deployment", Name: "web-api"}
	db := Workload{Namespace: "payments", Kind: "StatefulSet", Name: "db"}
	agent := Workload{Namespace: "kube-system", Kind: "DaemonSet", Name: "agent"}
	report := Workload{Namespace: "shop", Kind: "CronJob", Name: "report"}
	debug := Workload{Namespace: "shop", Kind: "Pod", Name: "debug"}
	cases := []struct {
		ns, pod string
		w       Workload
		basis   string
	}{
		{"shop", "web-7d9f8c6b5-abcde", web, "pod_name"},
		{"shop", "web-7d9f8c6b5-zzzzz", web, "pod_name_pattern"}, // replaced pod
		{"shop", "web-api-6f7b8c9d4-abcde", web, ""},             // another deployment's pod
		{"shop", "web-api-6f7b8c9d4-abcde", webAPI, "pod_name_pattern"},
		{"other", "web-7d9f8c6b5-abcde", web, ""}, // other namespace
		{"payments", "db-0", db, "pod_name_pattern"},
		{"payments", "db-backup", db, ""},
		{"kube-system", "agent-x7k2p", agent, "pod_name_pattern"},
		{"shop", "report-28000000-q9w8e", report, "pod_name_pattern"},
		{"shop", "debug", debug, "pod_name"},
		{"shop", "debug-2", debug, ""},
	}
	for _, c := range cases {
		basis, ok := MatchAlertPod(c.ns, c.pod, c.w)
		if basis != c.basis || ok != (c.basis != "") {
			t.Errorf("%s/%s vs %s: got %q", c.ns, c.pod, c.w.Key(), basis)
		}
	}
}

func TestMapApplication(t *testing.T) {
	ms := []Mapping{
		{ID: "1", Namespace: "shop", ApplicationID: "app-shop"},
		{ID: "2", Namespace: "shop", LabelKey: "app", LabelValue: "report", ApplicationID: "app-reporting"},
		{ID: "3", LabelKey: "app.kubernetes.io/part-of", LabelValue: "payments", ApplicationID: "app-pay"},
		{ID: "4", ClusterID: "c2", Namespace: "shop", ApplicationID: "app-shop-eu"},
	}
	cases := []struct {
		cluster string
		w       Workload
		app     string
	}{
		{"c1", Workload{Namespace: "shop", Labels: map[string]string{"app": "web"}}, "app-shop"},
		{"c1", Workload{Namespace: "shop", Labels: map[string]string{"app": "report"}}, "app-reporting"},
		{"c2", Workload{Namespace: "shop", Labels: map[string]string{"app": "report"}}, "app-shop-eu"},
		{"c1", Workload{Namespace: "billing", Labels: map[string]string{"app.kubernetes.io/part-of": "payments"}}, "app-pay"},
		{"c1", Workload{Namespace: "billing"}, ""},
	}
	for _, c := range cases {
		m, ok := MapApplication(c.cluster, c.w, ms)
		if m.ApplicationID != c.app || ok != (c.app != "") {
			t.Errorf("%s %v: got %q", c.cluster, c.w, m.ApplicationID)
		}
	}
	if d := ms[1].Describe(); d != "namespace shop and label app=report" {
		t.Errorf("describe: %s", d)
	}
}

func TestSummarizeAndEvidence(t *testing.T) {
	clusters := []string{"prod-eu"}
	exposed := DeploymentEvidence{Cluster: "prod-eu", Namespace: "shop", Kind: "Deployment", Workload: "web", Container: "web",
		Image: "ghcr.io/acme/shop:1.0", Digest: digWeb, Basis: "digest", BasisDetail: "running digest is the scanned image", Exposed: true,
		Exposure: []Exposure{{Via: "ingress", Host: "shop.example.com", Internet: true, Detail: "Ingress shop routes https://shop.example.com/"}}}
	priv := DeploymentEvidence{Cluster: "prod-eu", Namespace: "payments", Kind: "Deployment", Workload: "api", Container: "api", Image: "pay/api",
		Basis: "tag", BasisDetail: "same tag", Privileged: true,
		Alerts: []Alert{{Title: "Terminal shell in container", Severity: "medium", Location: "payments/api-5c8d7b9f4-k2l3m", Basis: "pod_name"}}}

	if r := Summarize([]DeploymentEvidence{exposed}, true, []string{"ghcr.io/acme/shop:1.0"}, nil); r.Status != "" || r.Context != nil {
		t.Errorf("no connected cluster: unknown, got %+v", r)
	}
	r := Summarize([]DeploymentEvidence{priv, exposed}, true, nil, clusters)
	if r.Status != "deployed" || !r.Exposed || !r.Privileged || !r.Alert || r.Context.Deployments[0].Workload != "web" {
		t.Fatalf("deployed: %+v", r)
	}
	dep, exp, pr, al := FactorEvidence(r.Context)
	if len(dep) != 2 || !strings.Contains(dep[0], "cluster prod-eu, namespace shop, Deployment web") {
		t.Errorf("deployed evidence: %v", dep)
	}
	if len(exp) != 1 || !strings.Contains(exp[0], "shop.example.com") {
		t.Errorf("exposure evidence names the ingress host: %v", exp)
	}
	if len(pr) != 1 || !strings.Contains(pr[0], "privileged container") || len(al) != 1 || !strings.Contains(al[0], "Terminal shell") {
		t.Errorf("privileged/alert evidence: %v %v", pr, al)
	}
	nd := Summarize(nil, true, []string{"ghcr.io/acme/shop:1.0"}, clusters)
	if nd.Status != "not_deployed" || !strings.Contains(nd.Context.NotDeployed, "prod-eu") || !strings.Contains(nd.Context.NotDeployed, "ghcr.io/acme/shop:1.0") {
		t.Errorf("not deployed: %+v", nd.Context)
	}
	if u := Summarize(nil, false, nil, clusters); u.Status != "" {
		t.Errorf("no known image: unknown, got %q", u.Status)
	}
	many := make([]DeploymentEvidence, 40)
	for i := range many {
		many[i] = exposed
	}
	if m := Summarize(many, true, nil, clusters); len(m.Context.Deployments) != maxEvidence || m.Context.Total != 40 {
		t.Errorf("evidence is bounded: %d of %d", len(m.Context.Deployments), m.Context.Total)
	}
}

func TestTrivyRepoDigests(t *testing.T) {
	// testdata/trivy-image.sarif was produced by running Trivy 0.76.2 (the
	// worker-core image) against an image pushed to a local registry:2
	// container: trivy image --image-src remote --format sarif c4-registry:5000/acme/shop:1.0
	raw, err := os.ReadFile("testdata/trivy-image.sarif")
	if err != nil {
		t.Fatal(err)
	}
	got := TrivyRepoDigests(raw)
	if len(got) != 1 || got[0].Digest != "sha256:f16d318b7cdfd30d392ab3ff5723ce85005fb0ba948220b0ab76751ea9d50e87" ||
		!strings.HasPrefix(got[0].Reference, "c4-registry:5000/acme/shop@") {
		t.Fatalf("repoDigests: %+v", got)
	}
	if TrivyRepoDigests([]byte(`{"runs":[{}]}`)) != nil || TrivyRepoDigests([]byte("not json")) != nil {
		t.Error("no digests")
	}
}
