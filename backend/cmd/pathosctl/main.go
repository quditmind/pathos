// Command pathosctl performs administrative operations.
//
//	pathosctl migrate             apply migrations, sync RBAC catalog, ensure organization
//	pathosctl migrate-status      print current and latest migration versions
//	pathosctl gen-key             print a new random master key (base64)
//	pathosctl rotate-master-key   re-wrap all secret DEKs with the current master key
//	pathosctl multi-tenancy enable|disable|status
//	pathosctl installation-admin grant|revoke <email> | list
//	pathosctl organizations       list organizations
//	pathosctl version             print the version and build metadata
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/ai"
	"pathos/internal/authz"
	"pathos/internal/notify"
	"pathos/internal/org"
	"pathos/internal/platform/buildinfo"
	"pathos/internal/platform/config"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/db"
	"pathos/internal/platform/logging"
	"pathos/internal/platform/objstore"
	"pathos/internal/review"
	"pathos/internal/scanners"
	"pathos/internal/scans"
	"pathos/internal/secrets"
	"pathos/internal/tenancy"
	"pathos/internal/vuln"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage: pathosctl <command>

commands:
  migrate             apply migrations, sync the RBAC catalog, ensure the organization exists
  migrate-status      print current and latest migration versions
  migrate-down <ver>  roll back migrations above version <ver> (release rollback; may delete data)
  migrate-artifacts   move scan artifacts stored in PostgreSQL to the configured S3 bucket
  gen-key             print a new random 32-byte master key (base64)
  rbac-matrix         print the role/permission matrix as Markdown
  rotate-master-key   re-wrap every secret's data key with the current master key
  multi-tenancy enable|disable|status
                      turn multi-tenancy (row-level security on every tenant table) on or off
  installation-admin grant <email> | revoke <email> | list
                      manage installation administrators (the person must have signed in once)
  organizations       list organizations with their status
  version             print the version and build metadata`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	if cmd == "version" || cmd == "--version" || cmd == "-v" {
		fmt.Println(buildinfo.Banner())
		return
	}
	if cmd == "rbac-matrix" {
		fmt.Print(authz.MarkdownMatrix())
		return
	}
	if cmd == "gen-key" {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			panic(err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(k))
		return
	}

	// Admin commands need only the database and master key, which is the
	// scheduler role's configuration (no web settings, no public URL).
	if os.Getenv("PATHOS_ROLE") == "" {
		_ = os.Setenv("PATHOS_ROLE", "scheduler")
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error:\n%v\n", err)
		os.Exit(2)
	}
	log := logging.New(os.Stdout, cfg.LogLevel).With("service", "pathosctl", "command", cmd)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.Connect(ctx, cfg.DatabaseURL, log)
	if err != nil {
		log.Error("connect", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	switch cmd {
	case "migrate":
		err = migrate(ctx, pool, cfg, log)
	case "migrate-down":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		var v int64
		if v, err = strconv.ParseInt(os.Args[2], 10, 64); err != nil || v < 0 {
			fmt.Fprintln(os.Stderr, "migrate-down: version must be a non-negative integer")
			os.Exit(2)
		}
		err = db.MigrateDownTo(ctx, pool, v, log)
	case "migrate-status":
		var cur, latest int64
		cur, latest, err = db.MigrationStatus(ctx, pool)
		if err == nil {
			fmt.Printf("current=%d latest=%d pending=%t\n", cur, latest, cur < latest)
		}
	case "rotate-master-key":
		err = rotate(ctx, pool, cfg, log)
	case "multi-tenancy":
		err = multiTenancy(ctx, pool, os.Args[2:], log)
	case "installation-admin":
		err = installationAdmin(ctx, pool, os.Args[2:], log)
	case "organizations":
		err = listOrganizations(ctx, pool)
	case "migrate-artifacts":
		if cfg.S3Bucket == "" {
			err = fmt.Errorf("PATHOS_S3_BUCKET is not set; configure object storage first")
			break
		}
		var st *objstore.S3
		if st, err = objstore.NewS3(objstore.Config{Endpoint: cfg.S3Endpoint, Region: cfg.S3Region, Bucket: cfg.S3Bucket,
			AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey, PathStyle: cfg.S3PathStyle}); err != nil {
			break
		}
		if err = st.EnsureBucket(ctx); err != nil {
			break
		}
		var n int
		n, err = scans.MigrateArtifacts(ctx, pool, st, 200)
		log.Info("artifacts moved to object storage", "count", n, "bucket", cfg.S3Bucket)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Error("failed", "err", err)
		os.Exit(1)
	}
}

func migrate(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, log *slog.Logger) error {
	if err := db.Migrate(ctx, pool, log); err != nil {
		return err
	}
	if err := org.SyncCatalog(ctx, pool); err != nil {
		return fmt.Errorf("sync rbac catalog: %w", err)
	}
	if err := scanners.Sync(ctx, pool); err != nil {
		return fmt.Errorf("sync scanner catalog: %w", err)
	}
	id, created, err := org.EnsureOrganization(ctx, pool, cfg.OrgName, cfg.OrgSlug)
	if err != nil {
		return fmt.Errorf("ensure organization: %w", err)
	}
	if err := vuln.EnsureDefaults(ctx, pool, id); err != nil {
		return fmt.Errorf("seed SLA and license policies: %w", err)
	}
	kr, err := crypto.NewKeyring(cfg.MasterKeys)
	if err != nil {
		return err
	}
	if err := notify.EnsureDefaults(ctx, pool, &secrets.Store{Keys: kr}, id); err != nil {
		return fmt.Errorf("seed notification rules: %w", err)
	}
	if err := scans.EnsureDefaultProfile(ctx, pool, id); err != nil {
		return fmt.Errorf("ensure default scan profile: %w", err)
	}
	// The Quick, Standard and Comprehensive profiles of every organization
	// (idempotent; seeded once per organization and template).
	orgRows, err := pool.Query(ctx, `SELECT id FROM organizations ORDER BY id`)
	if err != nil {
		return err
	}
	orgIDs, err := pgx.CollectRows(orgRows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	for _, oid := range orgIDs {
		if err := scans.EnsureTierProfiles(ctx, pool, oid); err != nil {
			return fmt.Errorf("seed scan profile tiers: %w", err)
		}
	}
	if err := review.EnsureSettings(ctx, pool, id); err != nil {
		return fmt.Errorf("ensure Human Eye settings: %w", err)
	}
	if err := org.EnsureAuditPartitions(ctx, pool); err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, `SELECT pathos_apply_app_grants()`); err != nil {
		return fmt.Errorf("apply grants: %w", err)
	}
	log.Info("migrate complete", "organization_id", id, "organization_created", created)
	return nil
}

func rotate(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, log *slog.Logger) error {
	kr, err := crypto.NewKeyring(cfg.MasterKeys)
	if err != nil {
		return err
	}
	store := &secrets.Store{Keys: kr}
	var n int
	err = db.InTx(ctx, pool, func(tx pgx.Tx) error {
		if n, err = store.RewrapAll(ctx, tx); err != nil {
			return err
		}
		// AI evidence payloads (PATHOS 3.0 M7) use the same master key.
		var m int
		m, err = ai.RewrapPayloads(ctx, tx, kr)
		n += m
		return err
	})
	if err == nil {
		log.Info("rotation complete", "rewrapped", n, "key_version", kr.CurrentVersion())
		// Stored source archives and Human Eye evidence files seal their
		// data keys with the master key too and are not rewrapped: they
		// stay readable only while their key version is configured.
		log.Warn("keep the previous master keys in PATHOS_MASTER_KEYS_PREVIOUS: stored source archives and evidence files are not rewrapped and need them until they are deleted by retention")
	}
	return err
}

// multiTenancy turns multi-tenancy on or off (pathos_set_multi_tenant).
// Restart the api, jobs and scheduler services afterwards: they read the
// mode at startup.
func multiTenancy(ctx context.Context, pool *pgxpool.Pool, args []string, log *slog.Logger) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: pathosctl multi-tenancy enable|disable|status")
	}
	switch args[0] {
	case "enable", "disable":
		if _, err := pool.Exec(ctx, `SELECT pathos_set_multi_tenant($1)`, args[0] == "enable"); err != nil {
			return err
		}
		log.Info("multi-tenancy changed; restart the api, jobs and scheduler services", "enabled", args[0] == "enable")
		fallthrough
	case "status":
		on, err := tenancy.MultiTenant(ctx, pool)
		if err != nil {
			return err
		}
		gaps, err := tenancy.RLSGaps(ctx, pool)
		if err != nil {
			return err
		}
		fmt.Printf("multi_tenant=%t rls_gaps=%d\n", on, len(gaps))
		for _, g := range gaps {
			fmt.Println("  not isolated:", g)
		}
		return nil
	}
	return fmt.Errorf("usage: pathosctl multi-tenancy enable|disable|status")
}

// installationAdmin grants, revokes or lists installation administrators. A person
// is identified by the identity-provider subject of any of their users
// rows, so they must have signed in once.
func installationAdmin(ctx context.Context, pool *pgxpool.Pool, args []string, log *slog.Logger) error {
	if len(args) == 1 && args[0] == "list" {
		admins, err := tenancy.ListInstallationAdmins(ctx, pool)
		if err != nil {
			return err
		}
		for _, a := range admins {
			fmt.Printf("%s\t%s\t%s\n", a.Email, a.Subject, a.CreatedAt.Format(time.RFC3339))
		}
		return nil
	}
	if len(args) != 2 || (args[0] != "grant" && args[0] != "revoke") {
		return fmt.Errorf("usage: pathosctl installation-admin grant|revoke <email> | list")
	}
	email := strings.ToLower(strings.TrimSpace(args[1]))
	rows, err := pool.Query(ctx, `SELECT DISTINCT keycloak_subject FROM users WHERE email = $1 AND keycloak_subject IS NOT NULL`, email)
	if err != nil {
		return err
	}
	subs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	if len(subs) != 1 {
		return fmt.Errorf("found %d identities for %s; the person must have signed in once (and the email must be unambiguous)", len(subs), email)
	}
	var changed bool
	if args[0] == "grant" {
		changed, err = tenancy.GrantInstallationAdmin(ctx, pool, subs[0], email, "pathosctl")
	} else {
		changed, err = tenancy.RevokeInstallationAdmin(ctx, pool, subs[0])
	}
	if err != nil {
		return err
	}
	_ = tenancy.WriteInstallationAudit(ctx, pool, tenancy.InstallationAuditEntry{ActorSubject: "pathosctl", Action: "installation_admin." + args[0],
		Metadata: map[string]any{"email": email, "changed": changed}})
	log.Info("installation administrator updated", "action", args[0], "email", email, "changed", changed)
	return nil
}

func listOrganizations(ctx context.Context, pool *pgxpool.Pool) error {
	orgs, err := tenancy.ListOrganizations(ctx, pool)
	if err != nil {
		return err
	}
	for _, o := range orgs {
		fmt.Printf("%s\t%s\t%s\tusers=%d\trepositories=%d\t%s\n", o.Slug, o.Status, o.ID, o.Users, o.Repositories, o.Name)
	}
	return nil
}
