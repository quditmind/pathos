//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"testing"

	"github.com/google/uuid"
)

var repoKeyRe = regexp.MustCompile(`^QD-REPO-\d{6,}$`)

// TestRepositoryIdentityAndExposure: permanent Repository IDs, application
// URLs and public exposure are stored, validated, searchable and audited.
func TestRepositoryIdentityAndExposure(t *testing.T) {
	o := newOnboarding(t)
	ctx := t.Context()
	// platform_admin, not super_admin: other tests expect no super admin before bootstrap.
	admin := dbUser(t, "platform_admin")
	owner := dbUser(t, "viewer")
	bu := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO business_units (id, organization_id, name) VALUES ($1, $2, $3)`, bu, orgID, "Ident "+uuid.NewString()[:6]); err != nil {
		t.Fatal(err)
	}
	base := func() map[string]any {
		return map[string]any{"business_owner_id": owner.UserID, "technical_owner_id": owner.UserID, "business_unit_id": bu,
			"business_region_id": firstRegion(t), "criticality": "high", "data_classification": "internal", "environment": "production"}
	}
	validate := func(md map[string]any) map[string]any {
		t.Helper()
		_, val := o.do(admin, "POST", "/api/v1/repository-imports/validate", map[string]any{"source": "upload", "idempotency_key": "x-" + uuid.NewString(),
			"metadata": md, "items": []any{map[string]any{"upload_id": uuid.NewString()}}})
		f, _ := val["fields"].(map[string]any)
		return f
	}

	// Validation of URLs, exposure answers and endpoints.
	md := base()
	if f := validate(md); f["public_exposure"] != "required" {
		t.Errorf("public exposure must be answered: %v", f)
	}
	md["public_exposure"] = "yes"
	if f := validate(md); f["public_urls"] == nil {
		t.Errorf("yes needs at least one endpoint: %v", f)
	}
	md["public_urls"] = []string{"ftp://x.example"}
	md["public_ips"] = []string{"10.1.2.3"}
	md["production_url"] = "not a url"
	md["public_domains"] = []string{"exa mple.com"}
	f := validate(md)
	for _, k := range []string{"public_urls", "public_ips", "production_url", "public_domains"} {
		if f[k] == nil {
			t.Errorf("%s should be rejected: %v", k, f)
		}
	}
	md = base()
	md["public_exposure"], md["public_urls"] = "no", []string{"https://a.example.com"}
	if f := validate(md); f["public_urls"] == nil {
		t.Errorf("no with endpoints must be rejected: %v", f)
	}

	// Register three repositories through the shared upload workflow.
	keys := map[string]string{}
	for i, exp := range []string{"yes", "no", "unknown"} {
		md := base()
		md["public_exposure"] = exp
		if exp == "yes" {
			md["public_urls"] = []string{"HTTPS://Shop.Example.COM:443/", "https://shop.example.com"}
			md["public_domains"] = []string{"Shop.Example.com", "*.cdn.example.com"}
			md["public_ips"] = []string{"203.0.113.10"}
			md["exposure_notes"] = "Behind the CDN"
			md["production_url"] = "https://shop.example.com/"
			md["staging_url"] = "https://staging.shop.example.com"
		}
		uid := o.upload(t, admin, fmt.Sprintf("ident-%d-%s.zip", i, uuid.NewString()[:4]), zipOf(t, map[string]string{"f.txt": exp + uuid.NewString()}))
		code, job := o.do(admin, "POST", "/api/v1/repository-imports", map[string]any{"source": "upload", "idempotency_key": "x-" + uuid.NewString(),
			"metadata": md, "items": []any{map[string]any{"upload_id": uid}}})
		if code != 202 {
			t.Fatalf("import %s: %d %v", exp, code, job)
		}
		o.drain(t)
		it := items(o.job(t, admin, id(job, "id")))[0]
		if it["status"] != "completed" {
			t.Fatalf("import %s: %v", exp, it)
		}
		_, repo := o.do(admin, "GET", "/api/v1/repositories/"+it["repository_id"].(string), nil)
		key, _ := repo["repository_key"].(string)
		if !repoKeyRe.MatchString(key) {
			t.Fatalf("repository_key %q", key)
		}
		keys[exp] = it["repository_id"].(string)
		if exp == "yes" {
			want := map[string]any{"production_url": "https://shop.example.com", "staging_url": "https://staging.shop.example.com",
				"public_exposure": "yes", "exposure_notes": "Behind the CDN"}
			for k, v := range want {
				if repo[k] != v {
					t.Errorf("%s = %v, want %v", k, repo[k], v)
				}
			}
			if u := repo["public_urls"].([]any); len(u) != 1 || u[0] != "https://shop.example.com" {
				t.Errorf("URLs not normalized / de-duplicated: %v", u)
			}
			if d := repo["public_domains"].([]any); len(d) != 2 || d[0] != "shop.example.com" {
				t.Errorf("domains: %v", d)
			}
			if repo["registered_by"].(map[string]any)["id"] != admin.UserID.String() {
				t.Errorf("registration owner: %v", repo["registered_by"])
			}
			// Searchable by Repository ID (any case) and by URL.
			for _, q := range []string{"repository_key=" + key, "q=" + key[len(key)-6:], "production_url=shop.example", "q=cdn.example.com"} {
				_, list := o.do(admin, "GET", "/api/v1/repositories?"+q, nil)
				if n := len(list["items"].([]any)); n != 1 {
					t.Errorf("search %s: %d results", q, n)
				}
			}
			// Audit entries carry the Repository ID.
			var n int
			_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE target_id = $1 AND metadata->>'repository_key' = $2`, it["repository_id"], key).Scan(&n)
			if n < 1 {
				t.Error("repository_key missing from the audit log")
			}
		}
	}

	// Permanent: not editable through the API or SQL, kept on other changes.
	yesID := keys["yes"]
	_, before := o.do(admin, "GET", "/api/v1/repositories/"+yesID, nil)
	if code, _ := o.do(admin, "PATCH", "/api/v1/repositories/"+yesID, map[string]any{"repository_key": "QD-REPO-999999"}); code != 400 {
		t.Errorf("repository_key must not be accepted in PATCH: %d", code)
	}
	if _, err := appPool.Exec(ctx, `UPDATE repositories SET repository_key = 'QD-REPO-000000' WHERE id = $1`, yesID); err == nil {
		t.Error("the database allowed changing a repository key")
	}
	code, after := o.do(admin, "PATCH", "/api/v1/repositories/"+yesID, map[string]any{"display_name": "Renamed shop", "public_exposure": "unknown",
		"public_urls": []string{}, "public_domains": []string{}, "public_ips": []string{}})
	if code != 200 || after["repository_key"] != before["repository_key"] || after["public_exposure"] != "unknown" {
		t.Errorf("key changed or exposure update failed: %d %v", code, after)
	}
	var diff json.RawMessage
	_ = appPool.QueryRow(ctx, `SELECT metadata FROM audit_logs WHERE action = 'repository.update' AND target_id = $1 ORDER BY created_at DESC LIMIT 1`, yesID).Scan(&diff)
	var d map[string]any
	_ = json.Unmarshal(diff, &d)
	if ch, _ := d["changed"].(map[string]any); ch["public_exposure"] == nil || ch["public_urls"] == nil {
		t.Errorf("exposure change not audited: %s", diff)
	}

	// Never reused: deleting a repository does not free its number.
	delKey := before["repository_key"].(string)
	o.do(admin, "POST", "/api/v1/repositories/"+keys["no"]+"/archive", nil)
	if code, _ := o.do(admin, "DELETE", "/api/v1/repositories/"+keys["no"], nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	var max string
	_ = appPool.QueryRow(ctx, `SELECT max(repository_key) FROM repositories`).Scan(&max)
	newKey := ""
	if _, err := appPool.Exec(ctx, `INSERT INTO repositories (id, organization_id, source_type, external_id, full_name, name, url, clone_url, repository_key)
		VALUES ($1, $2, 'upload', $3, 'k', 'k', '', '', 'QD-REPO-000001')`, uuid.Must(uuid.NewV7()), orgID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	_ = appPool.QueryRow(ctx, `SELECT repository_key FROM repositories WHERE full_name = 'k' ORDER BY created_at DESC LIMIT 1`).Scan(&newKey)
	if newKey <= max || newKey == "QD-REPO-000001" || newKey == delKey {
		t.Errorf("key reused or client-supplied: new=%s max=%s", newKey, max)
	}

	// Concurrent registrations get distinct keys.
	var wg sync.WaitGroup
	got := make(chan string, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var k string
			id := uuid.Must(uuid.NewV7())
			if err := appPool.QueryRow(ctx, `INSERT INTO repositories (id, organization_id, source_type, external_id, full_name, name, url, clone_url)
				VALUES ($1, $2, 'upload', $3, 'c', 'c', '', '') RETURNING repository_key`, id, orgID, id.String()).Scan(&k); err == nil {
				got <- k
			}
		}()
	}
	wg.Wait()
	close(got)
	seen := map[string]bool{}
	for k := range got {
		if seen[k] || !repoKeyRe.MatchString(k) {
			t.Errorf("duplicate or malformed concurrent key %s", k)
		}
		seen[k] = true
	}
	if len(seen) != 20 {
		t.Errorf("concurrent inserts: %d keys", len(seen))
	}
	_, _ = appPool.Exec(ctx, `DELETE FROM repositories WHERE full_name IN ('c', 'k')`)

	// Dashboard figures come from the records.
	_, ins := o.do(admin, "GET", "/api/v1/repositories/insights?business_unit_id="+bu.String(), nil)
	tot := ins["totals"].(map[string]any)
	if tot["exposure_unknown"].(float64) != 2 || tot["publicly_exposed"].(float64) != 0 || tot["missing_production_url"].(float64) != 1 {
		t.Errorf("insights: %v", tot)
	}
	_, list := o.do(admin, "GET", "/api/v1/repositories?public_exposure=unknown&missing_production_url=true&business_unit_id="+bu.String(), nil)
	if n := len(list["items"].([]any)); n != 1 {
		t.Errorf("exposure filters: %d", n)
	}
}
