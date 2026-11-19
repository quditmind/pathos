//go:build integration

package integration

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/posture"
	"pathos/internal/risk"
	"pathos/internal/runtimectx"
	"pathos/internal/scans"
	"pathos/internal/secrets"
)

// The Kubernetes API is a fake (httptest TLS server answering list
// requests); the registry is a real registry:2 container when
// PATHOS_TEST_REGISTRY_URL is set (see docs/OPERATIONS.md), otherwise its
// inventory row is inserted directly. No real cluster is contacted.

const (
	rtDigShop  = "sha256:c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4"
	rtDigBuild = "sha256:f16d318b7cdfd30d392ab3ff5723ce85005fb0ba948220b0ab76751ea9d50e87" // pushed to the test registry
)

type rtFakeAPI struct {
	mu    sync.Mutex
	calls int
	lists map[string]string
}

func (f *rtFakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer c4-sa-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	items, ok := f.lists[r.URL.Path]
	if !ok {
		items = ""
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"kind":"List","metadata":{},"items":[` + items + `]}`))
}

func TestRuntimeContext(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	store := &secrets.Store{Keys: kr}
	tag := uuid.NewString()[:6]
	shopImage := "ghcr.io/acme-c4-" + tag + "/shop"
	buildImage := "c4-registry:5000/acme/shop"

	webDeploy := `{"metadata":{"name":"web","namespace":"shop"},"spec":{"replicas":1,"template":{"metadata":{"labels":{"app":"web"}},
		"spec":{"containers":[{"name":"web","image":"` + shopImage + `:1.0"}]}}},"status":{"readyReplicas":1}}`
	builderDeploy := `{"metadata":{"name":"builder","namespace":"shop"},"spec":{"replicas":1,"template":{"metadata":{"labels":{"app":"builder"}},
		"spec":{"containers":[{"name":"b","image":"` + buildImage + `:1.0","securityContext":{"privileged":true}}]}}},"status":{"readyReplicas":1}}`
	webPod := `{"metadata":{"name":"web-6b7c8d9f5-abcde","namespace":"shop","ownerReferences":[{"kind":"ReplicaSet","name":"web-6b7c8d9f5","controller":true}]},
		"spec":{"containers":[{"name":"web","image":"` + shopImage + `:1.0"}]},
		"status":{"phase":"Running","containerStatuses":[{"name":"web","imageID":"` + shopImage + `@` + rtDigShop + `"}]}}`
	builderPod := `{"metadata":{"name":"builder-5d6f7b8c9-fghij","namespace":"shop","ownerReferences":[{"kind":"ReplicaSet","name":"builder-5d6f7b8c9","controller":true}]},
		"spec":{"containers":[{"name":"b","image":"` + buildImage + `:1.0"}]},
		"status":{"phase":"Running","containerStatuses":[{"name":"b","imageID":"` + buildImage + `@` + rtDigBuild + `"}]}}`
	fake := &rtFakeAPI{lists: map[string]string{
		"/api/v1/namespaces":        `{"metadata":{"name":"shop"}}`,
		"/apis/apps/v1/deployments": webDeploy + "," + builderDeploy,
		"/apis/apps/v1/replicasets": `{"metadata":{"name":"web-6b7c8d9f5","namespace":"shop","ownerReferences":[{"kind":"Deployment","name":"web","controller":true}]}},
			{"metadata":{"name":"builder-5d6f7b8c9","namespace":"shop","ownerReferences":[{"kind":"Deployment","name":"builder","controller":true}]}}`,
		"/api/v1/pods":     webPod + "," + builderPod,
		"/api/v1/services": `{"metadata":{"name":"web","namespace":"shop"},"spec":{"type":"ClusterIP","selector":{"app":"web"},"ports":[{"port":80}]}}`,
		"/apis/networking.k8s.io/v1/ingresses": `{"metadata":{"name":"shop","namespace":"shop"},"spec":{"rules":[{"host":"shop-` + tag + `.example.com",
			"http":{"paths":[{"path":"/","backend":{"service":{"name":"web","port":{"number":80}}}}]}}]}}`,
	}}
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))

	registryURL := os.Getenv("PATHOS_TEST_REGISTRY_URL")
	svc := &runtimectx.Service{DB: appPool, Authz: az, Secrets: store, Log: log, Principal: auth.PrincipalFrom, AllowHTTP: true,
		// Tests reach loopback servers; the TLS configuration (the
		// cluster's CA) is the one PATHOS built.
		NewHTTP: func(_ bool, tlsCfg *tls.Config) *http.Client {
			return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
		}}
	scanSvc := &scans.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}
	postureSvc := &posture.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}
	mux := newMux(func(m *http.ServeMux) { svc.Register(m); scanSvc.Register(m); postureSvc.Register(m) })
	call := func(p *authz.Principal, method, path string, body any) (int, map[string]any) {
		var rd *bytes.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rd = bytes.NewReader(raw)
		} else {
			rd = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rd).WithContext(auth.WithPrincipal(ctx, p))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	viewer := scoped("viewer", authz.Scope{Type: authz.ScopeOrganization, ID: orgID})

	// Empty state.
	if code, out := call(admin, "GET", "/api/v1/runtime/clusters", nil); code != 200 || out["can_manage"] != true {
		t.Fatalf("list: %d %v", code, out)
	}

	// --- connection management (no outbound call from the API) ---------------
	if code, _ := call(viewer, "POST", "/api/v1/runtime/clusters", map[string]any{}); code != 403 {
		t.Errorf("viewer cannot add clusters: %d", code)
	}
	for name, body := range map[string]map[string]any{
		"loopback":    {"name": "x", "auth_type": "token", "api_server": "https://127.0.0.1:6443", "token": "t"},
		"metadata":    {"name": "x", "auth_type": "token", "api_server": "https://169.254.169.254", "token": "t", "allow_private": true},
		"http":        {"name": "x", "auth_type": "token", "api_server": "http://k8s.example.test", "token": "t"},
		"no token":    {"name": "x", "auth_type": "token", "api_server": "https://k8s.example.test"},
		"bad ca":      {"name": "x", "auth_type": "token", "api_server": "https://k8s.example.test", "token": "t", "ca_cert": "nope"},
		"exec plugin": {"name": "x", "auth_type": "kubeconfig", "kubeconfig": "apiVersion: v1\ncurrent-context: a\ncontexts: [{name: a, context: {cluster: c, user: u}}]\nclusters: [{name: c, cluster: {server: 'https://k8s.example.test'}}]\nusers: [{name: u, user: {exec: {command: aws}}}]\n"},
		"namespace":   {"name": "x", "auth_type": "token", "api_server": "https://k8s.example.test", "token": "t", "namespaces": []string{"Bad_NS"}},
	} {
		if code, out := call(admin, "POST", "/api/v1/runtime/clusters", body); code != 400 {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	code, cl := call(admin, "POST", "/api/v1/runtime/clusters", map[string]any{"name": "prod-" + tag, "auth_type": "token",
		"api_server": "https://k8s.example.test", "token": "c4-sa-token", "ca_cert": caPEM})
	if code != 201 || cl["has_ca_cert"] != true || cl["token"] != nil {
		t.Fatalf("create cluster: %d %v", code, cl)
	}
	clusterID := uuid.MustParse(cl["id"].(string))
	t.Cleanup(func() {
		// Leave no cluster behind: later tests see no runtime facts.
		_, _ = appPool.Exec(ctx, `DELETE FROM runtime_clusters WHERE id = $1`, clusterID)
		_, _ = appPool.Exec(ctx, `DELETE FROM registry_connections WHERE name = $1`, "reg-"+tag)
		_ = runtimectx.Link(ctx, appPool, orgID)
	})
	var stored []byte
	_ = appPool.QueryRow(ctx, `SELECT s.ciphertext FROM secrets s JOIN runtime_clusters c ON c.secret_id = s.id WHERE c.id = $1`, clusterID).Scan(&stored)
	if bytes.Contains(stored, []byte("c4-sa-token")) {
		t.Error("the token is stored encrypted")
	}
	_, _ = appPool.Exec(ctx, `UPDATE runtime_clusters SET api_server = $2 WHERE id = $1`, clusterID, srv.URL)
	if code, out := call(admin, "POST", "/api/v1/runtime/clusters/"+clusterID.String()+"/sync", nil); code != 202 || out["sync_requested_at"] == nil {
		t.Fatalf("sync request: %d %v", code, out)
	}
	if fake.calls != 0 {
		t.Fatalf("the API server must not call the cluster (%d calls)", fake.calls)
	}

	// --- assets and findings --------------------------------------------------
	appID := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO applications (id, organization_id, name, criticality) VALUES ($1, $2, $3, 'high')`,
		appID, orgID, "Shop "+tag); err != nil {
		t.Fatal(err)
	}
	shopRepo := createRepo(t, "rt-shop-"+tag)
	buildRepo := createRepo(t, "rt-build-"+tag)
	idleRepo := createRepo(t, "rt-idle-"+tag)
	_, _ = appPool.Exec(ctx, `UPDATE repositories SET url = 'https://github.com/acme-test/shop', clone_url = 'https://github.com/acme-test/shop.git' WHERE id = $1`, buildRepo)
	target := func(repo uuid.UUID, ref string) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		if _, err := appPool.Exec(ctx, `INSERT INTO scan_targets (id, organization_id, repository_id, kind, name, reference) VALUES ($1, $2, $3, 'image', $4, $4)`,
			id, orgID, repo, ref); err != nil {
			t.Fatal(err)
		}
		return id
	}
	shopTarget := target(shopRepo, shopImage+":1.0")
	idleTarget := target(idleRepo, "ghcr.io/acme-c4-"+tag+"/idle:2")
	// The digest the image scan resolved to (Trivy repoDigests).
	if _, err := appPool.Exec(ctx, `INSERT INTO image_scan_digests (organization_id, scan_target_id, digest, reference) VALUES ($1, $2, $3, $4)`,
		orgID, shopTarget, rtDigShop, shopImage+"@"+rtDigShop); err != nil {
		t.Fatal(err)
	}
	finding := func(repo uuid.UUID, tgt *uuid.UUID, category, title, sev, path string) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		if _, err := appPool.Exec(ctx, `INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id, title, severity,
			file_path, scan_target_id) VALUES ($1, $2, $3, $4, $5, '{test}', 'R1', $6, $7, $8, $9)`, id, orgID, repo, uuid.NewString(), category, title, sev, path, tgt); err != nil {
			t.Fatal(err)
		}
		return id
	}
	imgFinding := finding(shopRepo, &shopTarget, "container", "CVE in openssl", "high", "")
	codeFinding := finding(shopRepo, nil, "sast", "SQL injection", "high", "app/db.go")
	iacFinding := finding(shopRepo, nil, "iac", "Bucket is public", "high", "infra/main.tf")
	idleFinding := finding(idleRepo, &idleTarget, "container", "CVE in zlib", "high", "")
	buildFinding := finding(buildRepo, nil, "sca", "Vulnerable dependency", "high", "go.mod")
	alertFinding := finding(shopRepo, nil, "runtime", "Terminal shell in container", "medium", "shop/web-6b7c8d9f5-zzzzz (web)")

	// Workload → application by namespace.
	if code, out := call(admin, "POST", "/api/v1/runtime/mappings", map[string]any{"namespace": "shop", "cluster_id": clusterID, "application_id": appID}); code != 201 {
		t.Fatalf("mapping: %d %v", code, out)
	}

	// Registry inventory: the real registry:2 container, or its row.
	if registryURL != "" {
		code, reg := call(admin, "POST", "/api/v1/runtime/registries", map[string]any{"name": "reg-" + tag, "base_url": registryURL,
			"repositories": []string{"acme/shop"}, "allow_private": true})
		if code != 201 {
			t.Fatalf("registry: %d %v", code, reg)
		}
		// The registry is reached as c4-registry:5000 by the cluster.
		status, err := svc.SyncRegistry(ctx, uuid.MustParse(reg["id"].(string)))
		if err != nil || status != "succeeded" {
			t.Fatalf("registry sync: %s %v", status, err)
		}
		_, _ = appPool.Exec(ctx, `UPDATE registry_images SET registry = 'c4-registry:5000' WHERE registry_id = $1`, reg["id"])
		var src, dig string
		_ = appPool.QueryRow(ctx, `SELECT source_url, digest FROM registry_images WHERE registry_id = $1 AND tag = '1.0'`, reg["id"]).Scan(&src, &dig)
		if src != "https://github.com/acme-test/shop" || dig != rtDigBuild {
			t.Fatalf("registry image labels: %s %s", src, dig)
		}
	} else {
		t.Log("PATHOS_TEST_REGISTRY_URL not set: registry inventory row inserted directly")
		regID := uuid.Must(uuid.NewV7())
		if _, err := appPool.Exec(ctx, `INSERT INTO registry_connections (id, organization_id, name, base_url, repositories) VALUES ($1, $2, $3, 'https://c4-registry.example', '{acme/shop}')`,
			regID, orgID, "reg-"+tag); err != nil {
			t.Fatal(err)
		}
		_, _ = appPool.Exec(ctx, `INSERT INTO registry_images (organization_id, registry_id, registry, repository, tag, digest, source_url, revision)
			VALUES ($1, $2, 'c4-registry:5000', 'acme/shop', '1.0', $3, 'https://github.com/acme-test/shop', '0123456789abcdef0123456789abcdef01234567')`, orgID, regID, rtDigBuild)
	}

	// --- synchronisation (what the jobs service runs) --------------------------
	status, err := svc.SyncCluster(ctx, clusterID)
	if err != nil || status != "succeeded" {
		t.Fatalf("cluster sync: %s %v", status, err)
	}
	if fake.calls == 0 {
		t.Fatal("the sync lists the fake cluster")
	}
	code, wl := call(admin, "GET", "/api/v1/runtime/workloads?cluster_id="+clusterID.String(), nil)
	if code != 200 || len(wl["items"].([]any)) != 2 {
		t.Fatalf("workloads: %d %v", code, wl)
	}
	var web map[string]any
	for _, it := range wl["items"].([]any) {
		if it.(map[string]any)["name"] == "web" {
			web = it.(map[string]any)
		}
	}
	if web["internet_exposed"] != true || web["application_name"] != "Shop "+tag || web["runtime_alerts"].(float64) != 1 {
		t.Errorf("web workload: %v", web)
	}
	if fc := web["findings"].(map[string]any); fc["total"].(float64) != 2 || fc["high"].(float64) != 2 {
		t.Errorf("web findings (image CVE + code finding; not IaC): %v", fc)
	}
	img := web["images"].([]any)[0].(map[string]any)
	if img["digest"] != rtDigShop || img["links"].([]any)[0].(map[string]any)["basis"] != "digest" {
		t.Errorf("web image link: %v", img)
	}

	type facts struct {
		status               string
		exposed, priv, alert bool
		ctx                  string
	}
	get := func(id uuid.UUID) facts {
		var f facts
		var raw []byte
		if err := appPool.QueryRow(ctx, `SELECT runtime_status, runtime_exposed, runtime_privileged, runtime_alert, runtime_context FROM findings WHERE id = $1`, id).
			Scan(&f.status, &f.exposed, &f.priv, &f.alert, &raw); err != nil {
			t.Fatal(err)
		}
		f.ctx = string(raw)
		return f
	}
	if f := get(imgFinding); f.status != "deployed" || !f.exposed || f.priv || !f.alert || !strings.Contains(f.ctx, "shop-"+tag+".example.com") {
		t.Errorf("image finding: %+v", f)
	}
	if f := get(codeFinding); f.status != "deployed" || !f.exposed {
		t.Errorf("code finding of the image's repository: %+v", f)
	}
	if f := get(iacFinding); f.status != "" {
		t.Errorf("IaC is not in the image: %+v", f)
	}
	if f := get(idleFinding); f.status != "not_deployed" || !strings.Contains(f.ctx, "prod-"+tag) {
		t.Errorf("image not running anywhere: %+v", f)
	}
	if f := get(buildFinding); f.status != "deployed" || !f.priv || f.exposed || !strings.Contains(f.ctx, "oci_source") || !strings.Contains(f.ctx, "acme-test/shop") {
		t.Errorf("OCI source label links the repository: %+v", f)
	}
	var matched int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM runtime_alert_matches WHERE finding_id = $1`, alertFinding).Scan(&matched)
	if matched != 1 {
		t.Errorf("runtime alert matched to the web workload: %d", matched)
	}

	// --- risk factors with evidence -------------------------------------------
	for {
		n, err := risk.Recompute(ctx, appPool, orgID, 2000)
		if err != nil {
			t.Fatal(err)
		}
		if n < 2000 {
			break
		}
	}
	explain := func(id uuid.UUID) (float64, map[string]risk.Factor) {
		var score float64
		var raw []byte
		if err := appPool.QueryRow(ctx, `SELECT risk_score::float8, risk_factors FROM findings WHERE id = $1`, id).Scan(&score, &raw); err != nil {
			t.Fatal(err)
		}
		var res risk.Result
		_ = json.Unmarshal(raw, &res)
		m := map[string]risk.Factor{}
		for _, f := range res.Factors {
			m[f.Key] = f
		}
		return score, m
	}
	imgScore, fs := explain(imgFinding)
	if f, ok := fs["deployed"]; !ok || len(f.Evidence) == 0 || !strings.Contains(f.Evidence[0], "cluster prod-"+tag+", namespace shop, Deployment web") {
		t.Errorf("deployed factor evidence: %+v", f)
	}
	if f, ok := fs["runtime_exposure"]; !ok || !strings.Contains(strings.Join(f.Evidence, " "), "shop-"+tag+".example.com") {
		t.Errorf("exposure factor names the ingress host: %+v", f)
	}
	if f, ok := fs["runtime_alert"]; !ok || !strings.Contains(strings.Join(f.Evidence, " "), "Terminal shell") {
		t.Errorf("runtime alert factor: %+v", f)
	}
	idleScore, fs := explain(idleFinding)
	if f, ok := fs["deployed"]; !ok || f.Weight >= 1 || idleScore >= imgScore {
		t.Errorf("not deployed lowers priority: %v vs %v %+v", idleScore, imgScore, f)
	}
	if _, fs := explain(buildFinding); fs["privileged"].Weight <= 1 || len(fs["privileged"].Evidence) == 0 {
		t.Errorf("privileged workload factor: %+v", fs["privileged"])
	}

	// --- findings filters and the drawer endpoint -----------------------------
	ids := func(q string) map[string]bool {
		code, out := call(admin, "GET", "/api/v1/findings?limit=200&"+q, nil)
		if code != 200 {
			t.Fatalf("%s: %d %v", q, code, out)
		}
		m := map[string]bool{}
		for _, it := range out["items"].([]any) {
			m[it.(map[string]any)["id"].(string)] = true
		}
		return m
	}
	dep := ids("deployed=true&repository_id=" + shopRepo.String())
	if !dep[imgFinding.String()] || !dep[codeFinding.String()] || dep[iacFinding.String()] {
		t.Errorf("deployed filter: %v", dep)
	}
	if nd := ids("deployed=false&repository_id=" + idleRepo.String()); !nd[idleFinding.String()] {
		t.Errorf("not deployed filter: %v", nd)
	}
	if ex := ids("internet_exposed=true&repository_id=" + buildRepo.String()); len(ex) != 0 {
		t.Errorf("internet exposed filter: %v", ex)
	}
	if code, _ := call(admin, "GET", "/api/v1/findings?deployed=maybe", nil); code != 400 {
		t.Errorf("invalid filter value: %d", code)
	}
	code, rt := call(admin, "GET", "/api/v1/findings/"+imgFinding.String()+"/runtime", nil)
	if code != 200 || rt["status"] != "deployed" || rt["context"].(map[string]any)["deployments"].([]any)[0].(map[string]any)["namespace"] != "shop" {
		t.Errorf("finding runtime: %d %v", code, rt)
	}
	other := scoped("viewer", authz.Scope{Type: authz.ScopeRepository, ID: idleRepo})
	if code, _ := call(other, "GET", "/api/v1/findings/"+imgFinding.String()+"/runtime", nil); code != 404 {
		t.Errorf("runtime evidence follows the finding's permission: %d", code)
	}
	if code, _ := call(other, "GET", "/api/v1/runtime/workloads", nil); code != 403 {
		t.Errorf("inventory needs organization-wide read: %d", code)
	}
	code, sum := call(admin, "GET", "/api/v1/runtime/summary", nil)
	if code != 200 || sum["deployed_findings"].(float64) < 3 || sum["internet_exposed_workloads"].(float64) < 1 {
		t.Errorf("summary: %d %v", code, sum)
	}

	// Attack paths: internet → ingress host → workload → image → finding.
	code, ap := call(admin, "GET", "/api/v1/posture/attack-paths?min_risk=0&limit=500", nil)
	found := false
	for _, it := range ap["items"].([]any) {
		m := it.(map[string]any)
		if m["finding_id"] != imgFinding.String() {
			continue
		}
		found = true
		steps := m["steps"].([]any)
		if m["entry"] != "runtime_exposure" || steps[0].(map[string]any)["sub"] != "shop-"+tag+".example.com" ||
			steps[1].(map[string]any)["type"] != "workload" {
			t.Errorf("runtime attack path: %v", m)
		}
	}
	if code != 200 || !found {
		t.Errorf("attack path for the exposed image finding: %d %v", code, found)
	}

	// A workload that disappears from the cluster is removed and the
	// findings' facts follow.
	fake.mu.Lock()
	fake.lists["/apis/apps/v1/deployments"] = webDeploy
	fake.lists["/api/v1/pods"] = webPod
	fake.mu.Unlock()
	_, _ = appPool.Exec(ctx, `UPDATE runtime_clusters SET sync_requested_at = now() WHERE id = $1`, clusterID)
	if status, err := svc.SyncCluster(ctx, clusterID); err != nil || status != "succeeded" {
		t.Fatalf("resync: %s %v", status, err)
	}
	if f := get(buildFinding); f.status != "not_deployed" {
		t.Errorf("builder removed: %+v", f)
	}
	var runs int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM runtime_sync_runs WHERE cluster_id = $1 AND status = 'succeeded'`, clusterID).Scan(&runs)
	if runs != 2 {
		t.Errorf("sync history: %d", runs)
	}

	// A disabled cluster's inventory is ignored (and is not synchronised).
	_, _ = appPool.Exec(ctx, `UPDATE runtime_clusters SET enabled = false WHERE id = $1`, clusterID)
	if err := runtimectx.Link(ctx, appPool, orgID); err != nil {
		t.Fatal(err)
	}
	if f := get(imgFinding); f.status != "" {
		t.Errorf("disabled cluster: %+v", f)
	}
	if code, _ := call(admin, "POST", "/api/v1/runtime/clusters/"+clusterID.String()+"/sync", nil); code != 409 {
		t.Errorf("sync of a disabled cluster: %d", code)
	}
	_, _ = appPool.Exec(ctx, `UPDATE runtime_clusters SET enabled = true WHERE id = $1`, clusterID)

	// Deleting the cluster removes its inventory and the runtime facts.
	if code, _ := call(admin, "DELETE", "/api/v1/runtime/clusters/"+clusterID.String(), nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if f := get(imgFinding); f.status != "" || f.exposed || f.ctx != "" {
		t.Errorf("facts cleared with the last cluster: %+v", f)
	}
	var audits int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE target_id = $1 AND action LIKE 'runtime_cluster.%'`, clusterID.String()).Scan(&audits)
	if audits != 3 {
		t.Errorf("create, sync request and delete audited: %d", audits)
	}
}
