//go:build integration

package integration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/rea"
	"pathos/internal/scans"
)

// reaHarness is the scan service (worker API), CodeGraph and reverse
// engineering wired as in the server.
type reaHarness struct {
	*graphHarness
	rea *rea.Service
}

func newREAHarness(t *testing.T) *reaHarness {
	g := newGraphHarness(t)
	r := &rea.Service{DB: appPool, Authz: g.svc.Authz, Log: log, Principal: auth.PrincipalFrom, Graph: g.graph}
	g.svc.OnREAResult = r.OnREAResult
	r.Register(g.api)
	return &reaHarness{graphHarness: g, rea: r}
}

// uploadArtifact uploads a build artifact target with optional signature
// and provenance material.
func (h *reaHarness) uploadArtifact(p *authz.Principal, repo uuid.UUID, name string, data []byte, provenance string) map[string]any {
	t := h.t
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("repository_id", repo.String())
	if provenance != "" {
		_ = mw.WriteField("provenance", provenance)
	}
	fw, _ := mw.CreateFormFile("file", name)
	_, _ = fw.Write(data)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/v1/scan-targets/artifact", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	h.api.ServeHTTP(rec, req.WithContext(auth.WithPrincipal(req.Context(), p)))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 201 {
		t.Fatalf("upload artifact: %d %v", rec.Code, out)
	}
	return out
}

// reaSourceGraph is a CodeGraph discovery document of a small Go service
// (test data): main imports net/http/pprof at cmd/server/main.go:7.
func reaSourceGraph() []byte {
	fl := func(ref, d string) []map[string]any {
		return []map[string]any{{"kind": "file_line", "ref": ref, "detail": d}}
	}
	doc := map[string]any{"schema": "pathos.codegraph/v1", "generator": map[string]string{"name": "test"}, "engines": map[string]string{},
		"stats": map[string]any{},
		"nodes": []map[string]any{
			{"key": "repository", "type": "repository", "label": "svc"},
			{"key": "mod:cmd/server", "type": "module", "label": "cmd/server", "parent": "repository", "attrs": map[string]any{"path": "cmd/server", "qualified_name": "example.com/svc/cmd/server"}},
			{"key": "mod:internal/api", "type": "module", "label": "internal/api", "parent": "repository", "attrs": map[string]any{"path": "internal/api", "qualified_name": "example.com/svc/internal/api"}},
			{"key": "file:cmd/server/main.go", "type": "file", "label": "main.go", "parent": "mod:cmd/server", "attrs": map[string]any{"file": "cmd/server/main.go", "language": "Go", "sensitive_imports": "net/http/pprof:7"}},
			{"key": "file:internal/api/api.go", "type": "file", "label": "api.go", "parent": "mod:internal/api", "attrs": map[string]any{"file": "internal/api/api.go", "language": "Go"}},
			{"key": "fn:go:cmd/server.main", "type": "function", "label": "main", "parent": "file:cmd/server/main.go", "attrs": map[string]any{"file": "cmd/server/main.go", "line": 10, "qualified_name": "cmd/server.main", "language": "Go"}},
			{"key": "fn:go:internal/api.Orders", "type": "function", "label": "Orders", "parent": "file:internal/api/api.go", "attrs": map[string]any{"file": "internal/api/api.go", "line": 20, "qualified_name": "internal/api.Orders", "language": "Go"}},
			{"key": "route:GET /api/orders", "type": "route", "label": "GET /api/orders", "parent": "file:internal/api/api.go", "attrs": map[string]any{"file": "internal/api/api.go", "line": 15, "path": "/api/orders", "method": "GET"}},
		},
		"edges": []map[string]any{
			{"source": "file:cmd/server/main.go", "target": "fn:go:cmd/server.main", "type": "defines", "evidence": "verified", "evidence_refs": fl("cmd/server/main.go:10", "func main")},
			{"source": "file:internal/api/api.go", "target": "fn:go:internal/api.Orders", "type": "defines", "evidence": "verified", "evidence_refs": fl("internal/api/api.go:20", "func Orders")},
			{"source": "fn:go:cmd/server.main", "target": "fn:go:internal/api.Orders", "type": "calls", "evidence": "verified", "evidence_refs": fl("cmd/server/main.go:12", "api.Orders()")},
			{"source": "route:GET /api/orders", "target": "fn:go:internal/api.Orders", "type": "calls", "evidence": "verified", "evidence_refs": fl("internal/api/api.go:15", "route handler")},
		},
	}
	b, _ := json.Marshal(doc)
	return b
}

// reaDocument is pathos-rea output for the artifact (test data, shaped
// like the real analyser's): a Go server with a planted net/http/pprof.
func reaDocument(sha string) []byte {
	fn := func(id, name, pkg string, off int, lib bool) map[string]any {
		return map[string]any{"id": id, "name": name, "addr": strings.TrimPrefix(id, "fn:"), "offset": off, "size": 64, "section": ".text",
			"tool": "radare2", "library": lib, "package": pkg}
	}
	doc := map[string]any{"schema": rea.Schema, "generator": map[string]string{"name": "pathos-rea", "version": "test"},
		"artifact": map[string]any{"file_name": "server", "sha256": sha, "size": 64, "format": "elf", "arch": "x86", "bits": 64, "os": "linux", "language": "go"},
		"tools":    map[string]any{"radare2": map[string]any{"version": "6.2.6", "status": "succeeded"}, "binwalk": map[string]any{"version": "3.1.0", "status": "succeeded"}},
		"sections": []map[string]any{{"name": ".text", "offset": 4096, "vaddr": 4198400, "size": 8192, "perm": "r-x", "tool": "radare2"}},
		"functions": []map[string]any{fn("fn:0x401000", "main.main", "main", 4096, false), fn("fn:0x401100", "example.com/svc/internal/api.Orders", "example.com/svc/internal/api", 4352, false),
			fn("fn:0x402000", "net/http/pprof.Index", "net/http/pprof", 8192, true), fn("fn:0x402100", "net/http/pprof.init.0", "net/http/pprof", 8448, true)},
		"imports": []map[string]any{{"id": "imp:go:net/http/pprof", "name": "net/http/pprof", "kind": "package", "tool": "go"},
			{"id": "imp:go:example.com/svc/internal/api", "name": "example.com/svc/internal/api", "kind": "package", "tool": "go"}},
		"strings": []map[string]any{{"id": "str:0x3010", "value": "/debug/pprof/", "offset": 12304, "kind": "route", "tool": "radare2"},
			{"id": "str:0x3020", "value": "/api/orders", "offset": 12320, "kind": "route", "tool": "radare2"},
			{"id": "str:0x3030", "value": "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "offset": 12336, "kind": "text", "tool": "radare2"}},
		"calls":       []map[string]any{{"from": "fn:0x401000", "to": "fn:0x401100", "offset": 4100, "tool": "radare2"}},
		"string_refs": []map[string]any{{"from": "fn:0x402100", "to": "str:0x3010", "offset": 8460, "tool": "radare2"}},
		"go": map[string]any{"go_version": "go1.27.4", "path": "example.com/svc/cmd/server", "main_module": map[string]string{"path": "example.com/svc"},
			"settings": map[string]string{"vcs.revision": strings.Repeat("e", 40)}},
		"code":  []map[string]any{{"function": "fn:0x402100", "tool": "radare2", "kind": "disassembly", "text": "lea rax, [str./debug/pprof/]"}},
		"stats": map[string]any{"truncated": false},
	}
	b, _ := json.Marshal(doc)
	return b
}

func provenanceBundle(sha, commit string) string {
	st := `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"server","digest":{"sha256":"` + sha + `"}}],` +
		`"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"resolvedDependencies":[{"uri":"git+https://git.example.test/acme/svc",` +
		`"digest":{"gitCommit":"` + commit + `"}}]},"runDetails":{"builder":{"id":"https://ci.example.test/builder"}}}}`
	b, _ := json.Marshal(map[string]any{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"dsseEnvelope": map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString([]byte(st))}})
	return string(b)
}

func TestReverseEngineering(t *testing.T) {
	quietNotifications(t)
	h := newREAHarness(t)
	ctx := t.Context()
	admin := tmUser(t, authz.RoleSuperAdmin)
	analyst := tmUser(t, "security_analyst") // rea.run, not rea.authorize
	viewer := tmUser(t, "viewer")
	repo := createRepo(t, "rea-"+uuid.NewString()[:6])
	appID := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO applications (id, organization_id, name, criticality) VALUES ($1, $2, $3, 'high')`,
		appID, orgID, "REA app "+uuid.NewString()[:6]); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `UPDATE repositories SET application_id = $2 WHERE id = $1`, repo, appID); err != nil {
		t.Fatal(err)
	}

	// Behind the flag.
	setFlag(t, rea.Flag, false)
	if code, b := h.user(admin, "GET", "/api/v1/rea/artifacts", nil); code != 404 || !strings.Contains(fmt.Sprint(b), "PTH-PLAT-1007") {
		t.Fatalf("flag off: %d %v", code, b)
	}
	setFlag(t, rea.Flag, true)
	setFlag(t, "codegraph", true)
	t.Cleanup(func() { setFlag(t, rea.Flag, false); setFlag(t, "codegraph", false) })

	// --- an unknown, unsigned artifact is refused by default -------------------
	unknown := h.uploadArtifact(admin, repo, "vendor-tool.bin", []byte("\x7fELF third-party build "+uuid.NewString()), "")
	unknownID := unknown["id"].(string)
	code, list := h.user(admin, "GET", "/api/v1/rea/artifacts?repository_id="+repo.String(), nil)
	if code != 200 {
		t.Fatalf("artifacts: %d %v", code, list)
	}
	trustOf := func(id string) map[string]any {
		_, l := h.user(admin, "GET", "/api/v1/rea/artifacts?repository_id="+repo.String(), nil)
		for _, a := range l["artifacts"].([]any) {
			if a.(map[string]any)["target_id"] == id {
				return a.(map[string]any)["trust"].(map[string]any)
			}
		}
		t.Fatalf("artifact %s not listed", id)
		return nil
	}
	if tr := trustOf(unknownID); tr["status"] != "untrusted" {
		t.Fatalf("an unsigned artifact must be untrusted: %v", tr)
	}
	code, out := h.user(admin, "POST", "/api/v1/rea/analyses", map[string]any{"target_id": unknownID})
	if code != 403 || !strings.Contains(fmt.Sprint(out), "PTH-REA-1001") {
		t.Fatalf("an unsigned artifact must be refused by default: %d %v", code, out)
	}
	var queued int
	if err := appPool.QueryRow(ctx, `SELECT count(*) FROM scan_jobs WHERE target_id = $1 AND trigger = 'rea'`, unknownID).Scan(&queued); err != nil || queued != 0 {
		t.Fatalf("a refused artifact was queued: %d %v", queued, err)
	}
	var refusedAudit int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'rea.analysis.refused' AND target_id = $1`, unknownID).Scan(&refusedAudit)
	if refusedAudit != 1 {
		t.Errorf("the refusal is audited: %d", refusedAudit)
	}
	// Authorising needs rea.authorize and a reason; the strict policy
	// forbids it.
	if code, _ := h.user(analyst, "POST", "/api/v1/rea/artifacts/"+unknownID+"/authorizations", map[string]any{"reason": "vendor tool we must review"}); code != 403 {
		t.Errorf("authorise without rea.authorize: %d", code)
	}
	if code, _ := h.user(admin, "POST", "/api/v1/rea/artifacts/"+unknownID+"/authorizations", map[string]any{"reason": "short"}); code != 422 {
		t.Errorf("authorise without a real reason: %d", code)
	}
	st := map[string]any{"enabled_tools": []string{"radare2", "binwalk"}, "memory_mb": 2048, "timeout_minutes": 20,
		"input_policy": "own_builds_only", "decompiled_code_ai": "none"}
	if code, out := h.user(analyst, "PUT", "/api/v1/rea/settings", st); code != 403 {
		t.Errorf("settings need scanners.manage: %d %v", code, out)
	}
	if code, out := h.user(admin, "PUT", "/api/v1/rea/settings", st); code != 200 || out["input_policy"] != "own_builds_only" {
		t.Fatalf("settings: %d %v", code, out)
	}
	if code, out := h.user(admin, "POST", "/api/v1/rea/artifacts/"+unknownID+"/authorizations", map[string]any{"reason": "vendor tool we must review"}); code != 409 ||
		!strings.Contains(fmt.Sprint(out), "PTH-REA-1007") {
		t.Errorf("own builds only refuses authorisations: %d %v", code, out)
	}
	st["decompiled_code_ai"] = "cloud"
	if code, out := h.user(admin, "PUT", "/api/v1/rea/settings", st); code != 422 || !strings.Contains(fmt.Sprint(out), "PTH-REA-1010") {
		t.Errorf("cloud without the AI send-code setting: %d %v", code, out)
	}
	st["input_policy"], st["decompiled_code_ai"] = "own_builds_or_authorized", "none"
	if code, _ := h.user(admin, "PUT", "/api/v1/rea/settings", st); code != 200 {
		t.Fatal("settings reset")
	}
	code, auth1 := h.user(admin, "POST", "/api/v1/rea/artifacts/"+unknownID+"/authorizations", map[string]any{"reason": "vendor tool we must review"})
	if code != 201 {
		t.Fatalf("authorise: %d %v", code, auth1)
	}
	if tr := trustOf(unknownID); tr["status"] != "authorized" || tr["basis"] != "authorization" {
		t.Fatalf("authorised artifact: %v", tr)
	}
	// Revoking makes it untrusted again.
	if code, _ := h.user(admin, "DELETE", "/api/v1/rea/artifacts/"+unknownID+"/authorizations/"+auth1["id"].(string), nil); code != 204 {
		t.Errorf("revoke: %d", code)
	}
	if tr := trustOf(unknownID); tr["status"] != "untrusted" {
		t.Errorf("revoked: %v", tr)
	}

	// --- our own build: provenance verified by the existing cosign check ------
	commit := strings.Repeat("c", 40)
	data := []byte("\x7fELF own build of example.com/svc " + uuid.NewString())
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	own := h.uploadArtifact(admin, repo, "server", data, provenanceBundle(sha, commit))
	ownID := own["id"].(string)
	if own["has_provenance"] != true {
		t.Errorf("provenance attached: %v", own)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if code, out := h.user(admin, "PUT", "/api/v1/scan-targets/"+ownID, map[string]any{"config": map[string]any{
		"signature": map[string]any{"mode": "key", "public_key": pub, "attestation": "slsaprovenance1"}}}); code != 200 {
		t.Fatalf("signature policy with provenance: %d %v", code, out)
	}
	if tr := trustOf(ownID); tr["status"] != "untrusted" {
		t.Fatalf("not yet verified: %v", tr)
	}
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "core-" + uuid.NewString()[:6], "family": "core",
		"scanners": map[string]string{"cosign": "test", "trivy-fs": "test", "binary-hardening": "test"}})
	coreToken := reg["token"].(string)
	code, sc := h.user(admin, "POST", "/api/v1/scan-targets/"+ownID+"/scan", nil)
	if code != 202 {
		t.Fatalf("target scan: %d %v", code, sc)
	}
	job := leaseJob(t, h.scanHarness, coreToken, sc["job_id"].(string))
	lt := job["target"].(map[string]any)
	if lt["provenance_material"] == nil || lt["provenance_material"] == "" {
		t.Fatalf("the provenance bundle is leased for cosign: %v", lt)
	}
	report, _ := json.Marshal(map[string]any{"version": 1, "subject": "server", "mode": "key", "status": "unsigned", "required": false,
		"detail": "no signature", "attestation": map[string]any{"type": "slsaprovenance1", "status": "verified"}})
	jid := job["job_id"].(string)
	if code, r := h.worker(coreToken, "POST", "/internal/worker/v1/jobs/"+jid+"/results", map[string]any{"scanner": "cosign", "version": "test",
		"status": "succeeded", "duration_ms": 10, "output_gzip": gzB64(report)}); code != 200 {
		t.Fatalf("cosign result: %d %v", code, r)
	}
	if code, r := h.worker(coreToken, "POST", "/internal/worker/v1/jobs/"+jid+"/complete", map[string]any{"status": "succeeded"}); code != 200 {
		t.Fatalf("complete: %d %v", code, r)
	}
	tr := trustOf(ownID)
	if tr["status"] != "trusted" || tr["basis"] != "provenance" || tr["provenance"].(map[string]any)["commit"] != commit {
		t.Fatalf("own build with verified provenance: %v", tr)
	}

	// The CodeGraph source snapshot of the commit (the graph worker).
	_, greg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "graph-" + uuid.NewString()[:6], "family": "graph",
		"scanners": map[string]string{"pathos-graph": "test"}})
	srcSnap := h.runGraphBuild(admin, appID, repo, greg["token"].(string), commit, reaSourceGraph())

	// --- no reverse-engineering worker: refused, nothing queued -------------
	if _, err := appPool.Exec(ctx, `UPDATE workers SET last_seen_at = now() - interval '1 hour' WHERE scanners ? 'pathos-rea'`); err != nil {
		t.Fatal(err)
	}
	if code, out := h.user(admin, "POST", "/api/v1/rea/analyses", map[string]any{"target_id": ownID}); code != 409 || !strings.Contains(fmt.Sprint(out), "PTH-REA-1002") {
		t.Fatalf("no worker: %d %v", code, out)
	}
	_, rreg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "rea-" + uuid.NewString()[:6], "family": "rea",
		"scanners": map[string]string{"pathos-rea": "pathos-rea test; radare2 6.2.6; binwalk 3.1.0; ghidra -; jadx -; ilspy -"}})
	reaToken := rreg["token"].(string)
	code, tools := h.user(viewer, "GET", "/api/v1/rea/tools", nil)
	if code != 200 || tools["worker_online"] != true {
		t.Fatalf("tools: %d %v", code, tools)
	}
	if code, _ := h.user(viewer, "POST", "/api/v1/rea/analyses", map[string]any{"target_id": ownID}); code != 403 {
		t.Errorf("a viewer cannot start an analysis: %d", code)
	}

	// A normal scan of the same repository is queued too: the lanes are
	// separate.
	normal, err := scans.EnqueueWith(ctx, appPool, orgID, repo, "manual", "main", "", nil, scans.EnqueueOpts{})
	if err != nil {
		t.Fatal(err)
	}
	code, started := h.user(analyst, "POST", "/api/v1/rea/analyses", map[string]any{"target_id": ownID})
	if code != 202 {
		t.Fatalf("start: %d %v", code, started)
	}
	an := started["analysis"].(map[string]any)
	if an["trust_basis"] != "provenance" || an["commit_sha"] != commit || an["commit_source"] != "provenance" {
		t.Fatalf("analysis: %v", an)
	}
	anID := an["id"].(string)
	reaJob := an["scan_job_id"].(string)
	// The core worker never leases it (no fallback outside the lane).
	for range 20 {
		code, j := h.worker(coreToken, "POST", "/internal/worker/v1/lease", map[string]any{})
		if code == 204 {
			break
		}
		if j["job_id"] == reaJob || j["kind"] == "rea" {
			t.Fatal("a core worker leased a reverse-engineering execution")
		}
		if j["job_id"] == normal.JobID.String() {
			// Put the normal scan back for the lane check below.
			if _, err := appPool.Exec(ctx, `UPDATE scan_jobs SET status = 'queued', leased_by = NULL, lease_expires_at = NULL WHERE id = $1`, normal.JobID); err != nil {
				t.Fatal(err)
			}
			break
		}
		h.worker(coreToken, "POST", "/internal/worker/v1/jobs/"+j["job_id"].(string)+"/complete", map[string]any{"status": "failed", "error": "drained by test"})
	}
	code, rj := h.worker(reaToken, "POST", "/internal/worker/v1/lease", map[string]any{})
	if code != 200 || rj["job_id"] != reaJob || rj["kind"] != "rea" {
		t.Fatalf("the rea worker leases the analysis: %d %v", code, rj)
	}
	scs := rj["scanners"].([]any)
	if len(scs) != 1 || scs[0].(map[string]any)["key"] != "pathos-rea" {
		t.Fatalf("only pathos-rea runs: %v", scs)
	}
	cfg := scs[0].(map[string]any)["config"].(map[string]any)
	if cfg["memory_mb"].(float64) != 2048 || fmt.Sprint(cfg["tools"]) != "[radare2 binwalk]" {
		t.Errorf("analysis configuration: %v", cfg)
	}
	tg := rj["target"].(map[string]any)
	if tg["sha256"] != sha || tg["signature_material"] != nil || tg["provenance_material"] != nil {
		t.Errorf("leased target: %v", tg)
	}
	// While it runs, the repository's normal scan still runs (own lane),
	// and the rea worker takes nothing else.
	if code, _ := h.worker(reaToken, "POST", "/internal/worker/v1/lease", map[string]any{}); code != 204 {
		t.Errorf("the rea worker leased a normal scan: %d", code)
	}
	if code, j := h.worker(coreToken, "POST", "/internal/worker/v1/lease", map[string]any{}); code != 200 || j["job_id"] != normal.JobID.String() {
		t.Errorf("the repository's scan is blocked by the analysis: %d %v", code, j["job_id"])
	} else {
		h.worker(coreToken, "POST", "/internal/worker/v1/jobs/"+normal.JobID.String()+"/complete", map[string]any{"status": "failed", "error": "test"})
	}
	if code, r := h.worker(reaToken, "POST", "/internal/worker/v1/jobs/"+reaJob+"/results", map[string]any{"scanner": "pathos-rea",
		"version": "test", "status": "succeeded", "duration_ms": 1000, "output_gzip": gzB64(reaDocument(sha))}); code != 200 {
		t.Fatalf("upload: %d %v", code, r)
	}
	if code, r := h.worker(reaToken, "POST", "/internal/worker/v1/jobs/"+reaJob+"/complete", map[string]any{"status": "succeeded"}); code != 200 {
		t.Fatalf("complete: %d %v", code, r)
	}
	var findings int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE last_scan_job_id = $1`, reaJob).Scan(&findings)
	if findings != 0 {
		t.Errorf("an analysis creates no findings by itself: %d", findings)
	}

	base := "/api/v1/rea/analyses/" + anID
	code, got := h.user(viewer, "GET", base, nil)
	if code != 200 {
		t.Fatalf("analysis: %d %v", code, got)
	}
	a := got["analysis"].(map[string]any)
	if a["status"] != "ready" || a["diff_status"] != "ready" || a["source_snapshot_id"] != srcSnap || a["snapshot_id"] == nil {
		t.Fatalf("analysis not ready: %v", a)
	}
	if c := got["counts"].(map[string]any); c["functions"].(float64) != 4 || c["strings"].(float64) != 3 || c["calls"].(float64) != 1 {
		t.Errorf("counts: %v", c)
	}
	// The binary graph is in the CodeGraph store, verified binary evidence
	// on every edge, and never visible as a source snapshot.
	var bad, edges int
	if err := appPool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM codegraph_evidence v WHERE v.edge_id = e.id
		AND v.kind = 'binary' AND v.evidence = 'verified' AND v.ref ~ '^0x' AND v.detail LIKE '%:%')), count(*)
		FROM codegraph_edges e WHERE e.snapshot_id = $1`, a["snapshot_id"]).Scan(&bad, &edges); err != nil || bad != 0 || edges == 0 {
		t.Fatalf("binary evidence: %d of %d edges without it (%v)", bad, edges, err)
	}
	_, snaps := h.user(admin, "GET", "/api/v1/codegraph/applications/"+appID.String()+"/snapshots", nil)
	for _, s := range snaps["snapshots"].([]any) {
		if s.(map[string]any)["id"] == a["snapshot_id"] {
			t.Error("a binary snapshot is listed with the application's source snapshots")
		}
	}
	code, fns := h.user(viewer, "GET", base+"/functions?match=binary_only", nil)
	if code != 200 {
		t.Fatalf("functions: %d %v", code, fns)
	}
	code, fns = h.user(viewer, "GET", base+"/functions?q=main.main", nil)
	if code != 200 || fns["total"].(float64) != 1 || fns["items"].([]any)[0].(map[string]any)["match"] != "matched" {
		t.Errorf("main.main matched: %d %v", code, fns)
	}
	code, strs := h.user(viewer, "GET", base+"/strings?limit=10", nil)
	if code != 200 || strings.Contains(fmt.Sprint(strs), "wJalrXUtnFEMI") {
		t.Errorf("strings (secret must stay redacted): %d %v", code, strs)
	}
	if code, g := h.user(viewer, "GET", base+"/graph?view=binary_call_graph", nil); code != 200 || len(g["nodes"].([]any)) == 0 {
		t.Errorf("graph: %d %v", code, g)
	}
	if code, _ := h.user(viewer, "GET", base+"/graph?view=architecture", nil); code != 400 {
		t.Errorf("source views do not apply to binary graphs: %d", code)
	}
	code, d := h.user(viewer, "GET", base+"/diff?side=binary_only", nil)
	if code != 200 || d["status"] != "ready" || d["commit_source"] != "provenance" {
		t.Fatalf("diff: %d %v", code, d)
	}
	var pprofRoute map[string]any
	for _, it := range d["items"].([]any) {
		if m := it.(map[string]any); m["kind"] == "route" && m["name"] == "/debug/pprof/" {
			pprofRoute = m
		}
	}
	if pprofRoute == nil || pprofRoute["sensitive"] != true || !strings.Contains(fmt.Sprint(pprofRoute["evidence"]), "cmd/server/main.go:7") {
		t.Fatalf("pprof route only in the binary, explained by the import line: %v", d["items"])
	}
	code, dr := h.user(viewer, "GET", base+"/drafts", nil)
	drafts := dr["drafts"].([]any)
	if code != 200 || len(drafts) != 1 {
		t.Fatalf("drafts: %d %v", code, dr)
	}
	draft := drafts[0].(map[string]any)
	if draft["status"] != "proposed" || draft["label"] != "proposal" || draft["finding_id"] != nil {
		t.Fatalf("a draft is a proposal: %v", draft)
	}
	if code, _ := h.user(viewer, "POST", "/api/v1/rea/drafts/"+draft["id"].(string)+"/create-finding", nil); code != 403 {
		t.Errorf("a viewer cannot create a finding: %d", code)
	}
	code, cf := h.user(analyst, "POST", "/api/v1/rea/drafts/"+draft["id"].(string)+"/create-finding", nil)
	if code != 201 || cf["status"] != "needs_review" {
		t.Fatalf("create finding: %d %v", code, cf)
	}
	var fstatus, fcat string
	if err := appPool.QueryRow(ctx, `SELECT status, category FROM findings WHERE id = $1`, cf["finding_id"]).Scan(&fstatus, &fcat); err != nil ||
		fstatus != "needs_review" || fcat != "binary" {
		t.Errorf("finding: %s %s %v", fstatus, fcat, err)
	}
	if code, _ := h.user(analyst, "POST", "/api/v1/rea/drafts/"+draft["id"].(string)+"/create-finding", nil); code != 409 {
		t.Errorf("a decided draft cannot be created twice: %d", code)
	}
	if code, _ := h.user(admin, "POST", base+"/diff", map[string]any{"source_snapshot_id": srcSnap}); code != 409 {
		t.Errorf("recompute after a decision: %d", code)
	}
	code, hist := h.user(viewer, "GET", "/api/v1/rea/analyses?target_id="+ownID, nil)
	if code != 200 || len(hist["analyses"].([]any)) != 1 {
		t.Errorf("history: %d %v", code, hist)
	}

	// An invalid document fails the analysis with PTH-REA-1005.
	code, again := h.user(admin, "POST", "/api/v1/rea/analyses", map[string]any{"target_id": ownID})
	if code != 202 {
		t.Fatalf("second analysis: %d %v", code, again)
	}
	j2 := again["analysis"].(map[string]any)["scan_job_id"].(string)
	if code, j := h.worker(reaToken, "POST", "/internal/worker/v1/lease", map[string]any{}); code != 200 || j["job_id"] != j2 {
		t.Fatalf("lease 2: %d %v", code, j)
	}
	h.worker(reaToken, "POST", "/internal/worker/v1/jobs/"+j2+"/results", map[string]any{"scanner": "pathos-rea", "version": "test",
		"status": "succeeded", "duration_ms": 1, "output_gzip": gzB64(reaDocument(strings.Repeat("0", 64)))})
	h.worker(reaToken, "POST", "/internal/worker/v1/jobs/"+j2+"/complete", map[string]any{"status": "succeeded"})
	_, a2 := h.user(admin, "GET", "/api/v1/rea/analyses/"+again["analysis"].(map[string]any)["id"].(string), nil)
	if an2 := a2["analysis"].(map[string]any); an2["status"] != "failed" || an2["error_code"] != "PTH-REA-1005" {
		t.Errorf("a document for another artifact: %v", an2)
	}
	if code, out := h.user(admin, "GET", "/api/v1/rea/analyses/"+again["analysis"].(map[string]any)["id"].(string)+"/functions", nil); code != 409 ||
		!strings.Contains(fmt.Sprint(out), "PTH-REA-1011") {
		t.Errorf("facts of a failed analysis: %d %v", code, out)
	}
	// The authorised third-party artifact keeps an authorisation row for
	// the isolation suite (B's data); re-authorise it.
	if code, _ := h.user(admin, "POST", "/api/v1/rea/artifacts/"+unknownID+"/authorizations", map[string]any{"reason": "vendor tool we must review"}); code != 201 {
		t.Error("re-authorise")
	}
}
