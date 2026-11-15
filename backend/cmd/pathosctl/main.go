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
	"syscall"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/config"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/db"
	"pathos/internal/platform/logging"
	"pathos/internal/secrets"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage: pathosctl <command>

commands:
  migrate             apply migrations, sync the RBAC catalog, ensure the organization exists
  migrate-status      print current and latest migration versions
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

	// Admin commands reuse the jobs-role configuration (no web settings).
	if os.Getenv("PATHOS_ROLE") == "" {
		os.Setenv("PATHOS_ROLE", "jobs")
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
	case "migrate-status":
		var cur, latest int64
		cur, latest, err = db.MigrationStatus(ctx, pool)
		if err == nil {
			fmt.Printf("current=%d latest=%d pending=%t\n", cur, latest, cur < latest)
		}
	case "rotate-master-key":
		err = rotate(ctx, pool, cfg, log)
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
	id, created, err := org.EnsureOrganization(ctx, pool, cfg.OrgName, cfg.OrgSlug)
	if err != nil {
		return fmt.Errorf("ensure organization: %w", err)
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
