// Command pathosctl performs administrative operations.
//
//	pathosctl migrate             apply migrations, sync RBAC catalog, ensure organization
//	pathosctl migrate-status      print current and latest migration versions
//	pathosctl gen-key             print a new random master key (base64)
//	pathosctl rotate-master-key   re-wrap all secret DEKs with the current master key
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
	"syscall"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/notify"
	"pathos/internal/org"
	"pathos/internal/platform/config"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/db"
	"pathos/internal/platform/logging"
	"pathos/internal/platform/objstore"
	"pathos/internal/scanners"
	"pathos/internal/scans"
	"pathos/internal/secrets"
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
  rotate-master-key   re-wrap every secret's data key with the current master key`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
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
		n, err = store.RewrapAll(ctx, tx)
		return err
	})
	if err == nil {
		log.Info("rotation complete", "rewrapped", n, "key_version", kr.CurrentVersion())
	}
	return err
}
