package runtimectx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
)

// A fake Kubernetes API server (httptest, TLS) serving list responses in
// the shape of the real API (v1 lists with metadata.continue). No real
// cluster is ever contacted.

const (
	digWeb    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digWebOld = "sha256:1010101010101010101010101010101010101010101010101010101010101010"
	digAPI    = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	digDB     = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	digAgent  = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	digReport = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
)

var fakeCluster = map[string][]string{
	"/api/v1/namespaces": {
		`{"metadata":{"name":"shop","labels":{"team":"web"}}}`, `{"metadata":{"name":"payments"}}`, `{"metadata":{"name":"kube-system"}}`},
	"/apis/apps/v1/deployments": {
		`{"metadata":{"name":"web","namespace":"shop"},"spec":{"replicas":2,"template":{"metadata":{"labels":{"app":"web","app.kubernetes.io/part-of":"shop"}},
		  "spec":{"securityContext":{"runAsNonRoot":true},"containers":[{"name":"web","image":"ghcr.io/acme/shop:1.0"}]}}},"status":{"readyReplicas":2}}`,
		`{"metadata":{"name":"api","namespace":"payments"},"spec":{"replicas":1,"template":{"metadata":{"labels":{"app":"api"}},
		  "spec":{"containers":[{"name":"api","image":"registry.internal:5000/pay/api@` + digAPI + `","securityContext":{"privileged":true}}]}}},"status":{"readyReplicas":1}}`,
		`{"metadata":{"name":"idle","namespace":"shop"},"spec":{"replicas":0,"template":{"metadata":{"labels":{"app":"idle"}},
		  "spec":{"containers":[{"name":"idle","image":"ghcr.io/acme/idle:3"}]}}},"status":{}}`},
	"/apis/apps/v1/replicasets": {
		`{"metadata":{"name":"web-7d9f8c6b5","namespace":"shop","ownerReferences":[{"kind":"Deployment","name":"web","controller":true}]}}`,
		`{"metadata":{"name":"api-5c8d7b9f4","namespace":"payments","ownerReferences":[{"kind":"Deployment","name":"api","controller":true}]}}`},
	"/apis/apps/v1/statefulsets": {
		`{"metadata":{"name":"db","namespace":"payments"},"spec":{"replicas":1,"template":{"metadata":{"labels":{"app":"db"}},
		  "spec":{"securityContext":{"runAsUser":0},"containers":[{"name":"postgres","image":"postgres:16"}]}}},"status":{"readyReplicas":1}}`},
	"/apis/apps/v1/daemonsets": {
		`{"metadata":{"name":"agent","namespace":"kube-system"},"spec":{"template":{"metadata":{"labels":{"app":"agent"}},
		  "spec":{"hostNetwork":true,"hostPID":true,"containers":[{"name":"agent","image":"quay.io/acme/agent:v1"}]}}},
		  "status":{"desiredNumberScheduled":3,"numberReady":3}}`},
	"/apis/batch/v1/cronjobs": {
		`{"metadata":{"name":"report","namespace":"shop"},"spec":{"jobTemplate":{"spec":{"template":{"metadata":{"labels":{"app":"report"}},
		  "spec":{"containers":[{"name":"report","image":"ghcr.io/acme/report:2"}]}}}}},"status":{"active":[{"name":"report-28000000"}]}}`},
	"/apis/batch/v1/jobs": {
		`{"metadata":{"name":"report-28000000","namespace":"shop","ownerReferences":[{"kind":"CronJob","name":"report","controller":true}]},
		  "spec":{"template":{"spec":{"containers":[{"name":"report","image":"ghcr.io/acme/report:2"}]}}}}`},
	"/api/v1/pods": {
		`{"metadata":{"name":"web-7d9f8c6b5-abcde","namespace":"shop","labels":{"app":"web"},"ownerReferences":[{"kind":"ReplicaSet","name":"web-7d9f8c6b5","controller":true}]},
		  "spec":{"containers":[{"name":"web","image":"ghcr.io/acme/shop:1.0"}]},
		  "status":{"phase":"Running","containerStatuses":[{"name":"web","image":"ghcr.io/acme/shop:1.0","imageID":"ghcr.io/acme/shop@` + digWeb + `"}]}}`,
		`{"metadata":{"name":"web-7d9f8c6b5-fghij","namespace":"shop","labels":{"app":"web"},"ownerReferences":[{"kind":"ReplicaSet","name":"web-7d9f8c6b5","controller":true}]},
		  "spec":{"containers":[{"name":"web","image":"ghcr.io/acme/shop:1.0"}]},
		  "status":{"phase":"Running","containerStatuses":[{"name":"web","image":"ghcr.io/acme/shop:1.0","imageID":"docker-pullable://ghcr.io/acme/shop@` + digWebOld + `"}]}}`,
		`{"metadata":{"name":"api-5c8d7b9f4-k2l3m","namespace":"payments","labels":{"app":"api"},"ownerReferences":[{"kind":"ReplicaSet","name":"api-5c8d7b9f4","controller":true}]},
		  "spec":{"containers":[{"name":"api","image":"registry.internal:5000/pay/api@` + digAPI + `"}]},
		  "status":{"phase":"Running","containerStatuses":[{"name":"api","image":"registry.internal:5000/pay/api@` + digAPI + `","imageID":"registry.internal:5000/pay/api@` + digAPI + `"}]}}`,
		`{"metadata":{"name":"db-0","namespace":"payments","labels":{"app":"db"},"ownerReferences":[{"kind":"StatefulSet","name":"db","controller":true}]},
		  "spec":{"containers":[{"name":"postgres","image":"postgres:16"}]},
		  "status":{"phase":"Running","containerStatuses":[{"name":"postgres","image":"docker.io/library/postgres:16","imageID":"docker.io/library/postgres@` + digDB + `"}]}}`,
		`{"metadata":{"name":"agent-x7k2p","namespace":"kube-system","ownerReferences":[{"kind":"DaemonSet","name":"agent","controller":true}]},
		  "spec":{"containers":[{"name":"agent","image":"quay.io/acme/agent:v1"}]},
		  "status":{"phase":"Running","containerStatuses":[{"name":"agent","image":"quay.io/acme/agent:v1","imageID":"quay.io/acme/agent@` + digAgent + `"}]}}`,
		`{"metadata":{"name":"report-28000000-q9w8e","namespace":"shop","ownerReferences":[{"kind":"Job","name":"report-28000000","controller":true}]},
		  "spec":{"containers":[{"name":"report","image":"ghcr.io/acme/report:2"}]},
		  "status":{"phase":"Running","containerStatuses":[{"name":"report","image":"ghcr.io/acme/report:2","imageID":"ghcr.io/acme/report@` + digReport + `"}]}}`,
		`{"metadata":{"name":"debug","namespace":"shop","labels":{"run":"debug"}},
		  "spec":{"containers":[{"name":"debug","image":"busybox"}]},"status":{"phase":"Pending"}}`},
	"/api/v1/services": {
		`{"metadata":{"name":"web","namespace":"shop"},"spec":{"type":"ClusterIP","selector":{"app":"web"},"ports":[{"port":80}]}}`,
		`{"metadata":{"name":"web-public","namespace":"shop"},"spec":{"type":"LoadBalancer","selector":{"app":"web"},"ports":[{"port":443,"nodePort":31443}]},
		  "status":{"loadBalancer":{"ingress":[{"hostname":"a1b2.elb.example.com"}]}}}`,
		`{"metadata":{"name":"api","namespace":"payments","annotations":{"service.beta.kubernetes.io/aws-load-balancer-internal":"true"}},
		  "spec":{"type":"LoadBalancer","selector":{"app":"api"},"ports":[{"port":443,"nodePort":30443}]},"status":{"loadBalancer":{"ingress":[{"ip":"10.1.2.3"}]}}}`,
		`{"metadata":{"name":"db","namespace":"payments"},"spec":{"type":"NodePort","selector":{"app":"db"},"ports":[{"port":5432,"nodePort":30432}]}}`,
		`{"metadata":{"name":"external","namespace":"shop"},"spec":{"type":"ExternalName"}}`},
	"/apis/networking.k8s.io/v1/ingresses": {
		`{"metadata":{"name":"shop","namespace":"shop"},"spec":{"ingressClassName":"nginx","tls":[{"hosts":["shop.example.com"]}],
		  "rules":[{"host":"shop.example.com","http":{"paths":[{"path":"/","backend":{"service":{"name":"web","port":{"number":80}}}}]}},
		           {"host":"report.example.com","http":{"paths":[{"path":"/","backend":{"service":{"name":"missing","port":{"number":80}}}}]}}]},
		  "status":{"loadBalancer":{"ingress":[{"ip":"203.0.113.10"}]}}}`,
		`{"metadata":{"name":"admin","namespace":"payments"},"spec":{"ingressClassName":"nginx-internal",
		  "rules":[{"host":"pay-admin.corp","http":{"paths":[{"path":"/","backend":{"service":{"name":"api","port":{"number":443}}}}]}}]}}`},
	"/apis/networking.k8s.io/v1/networkpolicies": {
		`{"metadata":{"name":"default-deny","namespace":"shop"},"spec":{"podSelector":{},"policyTypes":["Ingress"]}}`,
		`{"metadata":{"name":"db-only-api","namespace":"payments"},"spec":{"podSelector":{"matchLabels":{"app":"db"}},"ingress":[{}]}}`},
}

type fakeAPI struct {
	mu        sync.Mutex
	token     string
	forbidden map[string]bool
	paths     []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"kind":"Status","message":"Unauthorized"}`))
		return
	}
	if f.forbidden[r.URL.Path] {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"kind":"Status","message":"cannot list resource"}`))
		return
	}
	items, ok := fakeCluster[r.URL.Path]
	if !ok {
		// Namespaced paths: filter the cluster-wide list.
		parts := strings.Split(r.URL.Path, "/namespaces/")
		if len(parts) == 2 {
			ns, plural, _ := strings.Cut(parts[1], "/")
			for _, it := range fakeCluster[parts[0]+"/"+plural] {
				if strings.Contains(it, `"namespace":"`+ns+`"`) {
					items = append(items, it)
				}
			}
			ok = true
		}
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	// Page with limit/continue like the API server.
	limit := 2
	start := 0
	if c := r.URL.Query().Get("continue"); c != "" {
		start = len(c)
	}
	end := min(start+limit, len(items))
	cont := ""
	if end < len(items) {
		cont = strings.Repeat("x", end)
	}
	_, _ = w.Write([]byte(`{"kind":"List","metadata":{"continue":"` + cont + `"},"items":[` + strings.Join(items[start:end], ",") + `]}`))
}

func fakeClient(t *testing.T, api *fakeAPI) *KubeClient {
	srv := httptest.NewTLSServer(api)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return &KubeClient{Base: u, HTTP: srv.Client(), Token: api.token, PageSize: 2}
}

func workload(inv Inventory, key string) *Workload {
	for i := range inv.Workloads {
		if inv.Workloads[i].Key() == key {
			return &inv.Workloads[i]
		}
	}
	return nil
}

func TestCollectAndBuildInventory(t *testing.T) {
	api := &fakeAPI{token: "test-token"}
	kc := fakeClient(t, api)
	raw, warnings, err := kc.Collect(context.Background(), nil)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("collect: %v %v", err, warnings)
	}
	if len(raw["Pod"]) != 7 {
		t.Fatalf("pagination: %d pods", len(raw["Pod"]))
	}
	for _, p := range api.paths {
		if !strings.HasPrefix(p, "GET ") || strings.Contains(p, "secrets") || strings.Contains(p, "configmaps") {
			t.Errorf("only GET list requests, never secrets or configmaps: %s", p)
		}
	}
	inv := Build(raw)
	if inv.Skipped != 0 || len(inv.Namespaces) != 3 {
		t.Fatalf("skipped %d, namespaces %v", inv.Skipped, inv.Namespaces)
	}
	var keys []string
	for _, w := range inv.Workloads {
		keys = append(keys, w.Key())
	}
	slices.Sort(keys)
	want := []string{"kube-system/DaemonSet/agent", "payments/Deployment/api", "payments/StatefulSet/db", "shop/CronJob/report",
		"shop/Deployment/idle", "shop/Deployment/web", "shop/Pod/debug"}
	if !slices.Equal(keys, want) {
		t.Fatalf("workloads:\n got %v\nwant %v", keys, want)
	}

	web := workload(inv, "shop/Deployment/web")
	if len(web.Images) != 2 || web.Images[0].Ref.Digest != digWeb || web.Images[1].Ref.Digest != digWebOld || web.Images[0].Ref.Name() != "ghcr.io/acme/shop" {
		t.Errorf("web images (one entry per running digest): %+v", web.Images)
	}
	if !slices.Equal(web.PodNames, []string{"web-7d9f8c6b5-abcde", "web-7d9f8c6b5-fghij"}) || *web.Replicas != 2 || *web.Ready != 2 {
		t.Errorf("web pods: %v", web.PodNames)
	}
	if !web.InternetExposed || web.RunAsRoot != "no" || web.Privileged {
		t.Errorf("web: exposed %v root %s priv %v", web.InternetExposed, web.RunAsRoot, web.Privileged)
	}
	var hosts, vias []string
	for _, x := range web.Exposure {
		vias = append(vias, x.Via)
		if x.Host != "" {
			hosts = append(hosts, x.Host)
		}
	}
	if !slices.Equal(hosts, []string{"shop.example.com"}) || !slices.Contains(vias, "loadbalancer") || !slices.Contains(vias, "ingress") {
		t.Errorf("web exposure: %+v", web.Exposure)
	}
	if !slices.Equal(web.NetworkPolicies, []string{"default-deny"}) {
		t.Errorf("web network policies: %v", web.NetworkPolicies)
	}

	api2 := workload(inv, "payments/Deployment/api")
	if api2.InternetExposed || !api2.Privileged || len(api2.Images) != 1 || api2.Images[0].Ref.Registry != "registry.internal:5000" {
		t.Errorf("api: internal LB and internal ingress class only, privileged: %+v", api2)
	}
	for _, x := range api2.Exposure {
		if x.Internet || !strings.Contains(x.Detail, "internal") {
			t.Errorf("api exposure must be internal: %+v", x)
		}
	}
	db := workload(inv, "payments/StatefulSet/db")
	if db.InternetExposed || db.RunAsRoot != "yes" || len(db.Exposure) != 1 || db.Exposure[0].Via != "nodeport" ||
		db.Images[0].Ref.String() != "docker.io/library/postgres:16@"+digDB || !slices.Equal(db.NetworkPolicies, []string{"db-only-api"}) {
		t.Errorf("db: %+v", db)
	}
	agent := workload(inv, "kube-system/DaemonSet/agent")
	if !agent.HostNetwork || !agent.HostPID || *agent.Replicas != 3 || agent.RunAsRoot != "unknown" {
		t.Errorf("agent: %+v", agent)
	}
	report := workload(inv, "shop/CronJob/report")
	if len(report.Images) != 1 || report.Images[0].Ref.Digest != digReport || !slices.Equal(report.PodNames, []string{"report-28000000-q9w8e"}) {
		t.Errorf("cronjob pods roll up through their job: %+v", report)
	}
	idle := workload(inv, "shop/Deployment/idle")
	if len(idle.Images) != 1 || idle.Images[0].Ref.Digest != "" || idle.Images[0].Ref.Tag != "3" || len(idle.PodNames) != 0 {
		t.Errorf("idle (scaled to zero): template image without digest: %+v", idle.Images)
	}
	debug := workload(inv, "shop/Pod/debug")
	if debug.Images[0].Ref.String() != "docker.io/library/busybox:latest" {
		t.Errorf("bare pod: %+v", debug.Images)
	}
	var kinds []string
	for _, n := range inv.Network {
		kinds = append(kinds, n.Kind)
	}
	if len(kinds) != 9 {
		t.Errorf("network objects: %v", kinds)
	}
	raw2, _ := json.Marshal(inv.Workloads)
	if strings.Contains(string(raw2), "secret") {
		t.Errorf("inventory must not contain secret data")
	}
}

func TestCollectErrors(t *testing.T) {
	// Wrong credentials abort.
	api := &fakeAPI{token: "right"}
	kc := fakeClient(t, api)
	kc.Token = "wrong"
	if _, _, err := kc.Collect(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("401: %v", err)
	}
	// A resource the ClusterRole does not grant is a warning (partial).
	api = &fakeAPI{token: "t", forbidden: map[string]bool{"/apis/batch/v1/cronjobs": true, "/apis/networking.k8s.io/v1/networkpolicies": true}}
	kc = fakeClient(t, api)
	raw, warnings, err := kc.Collect(context.Background(), nil)
	if err != nil || len(warnings) != 2 || !strings.Contains(warnings[0], "403") {
		t.Fatalf("403 → warnings: %v %v", err, warnings)
	}
	inv := Build(raw)
	// Without the CronJob, its job's pods are a Job workload.
	if workload(inv, "shop/Job/report-28000000") != nil || workload(inv, "shop/Pod/report-28000000-q9w8e") == nil {
		var keys []string
		for _, w := range inv.Workloads {
			keys = append(keys, w.Key())
		}
		t.Errorf("partial inventory: %v", keys)
	}
	// Namespace-scoped collection lists per namespace.
	api = &fakeAPI{token: "t"}
	kc = fakeClient(t, api)
	raw, _, err = kc.Collect(context.Background(), []string{"payments"})
	if err != nil {
		t.Fatal(err)
	}
	inv = Build(raw)
	if len(inv.Workloads) != 2 || len(inv.Namespaces) != 1 {
		t.Errorf("payments only: %d workloads", len(inv.Workloads))
	}
	for _, p := range api.paths {
		if strings.Contains(p, "/pods") && !strings.Contains(p, "/namespaces/payments/") {
			t.Errorf("namespace-scoped request expected: %s", p)
		}
	}
	// Object limit.
	api = &fakeAPI{token: "t"}
	kc = fakeClient(t, api)
	kc.MaxObjects = 3
	if items, err := kc.List(context.Background(), Resources[1], ""); err != ErrTruncated || len(items) != 3 {
		t.Errorf("max objects: %d %v", len(items), err)
	}
}
