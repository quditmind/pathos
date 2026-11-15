package schedule

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// RegisterMetrics publishes platform gauges (queue depth, workers,
// notification backlog, open findings). Only the leader reports, so
// dashboards do not double-count across scheduler replicas.
func RegisterMetrics(pool *pgxpool.Pool, isLeader func() bool) error {
	m := otel.Meter("pathos")
	jobs, err := m.Int64ObservableGauge("pathos.scan.jobs", metric.WithDescription("Scan jobs by status (queued, running)"))
	if err != nil {
		return err
	}
	workers, err := m.Int64ObservableGauge("pathos.workers.online", metric.WithDescription("Scan workers that polled recently"))
	if err != nil {
		return err
	}
	pending, err := m.Int64ObservableGauge("pathos.notifications.pending", metric.WithDescription("Emails waiting for delivery"))
	if err != nil {
		return err
	}
	backlog, err := m.Int64ObservableGauge("pathos.notification_events.backlog", metric.WithDescription("Notification events not yet dispatched"))
	if err != nil {
		return err
	}
	open, err := m.Int64ObservableGauge("pathos.findings.open", metric.WithDescription("Open findings by severity"))
	if err != nil {
		return err
	}
	leader, err := m.Int64ObservableGauge("pathos.scheduler.leader", metric.WithDescription("1 on the replica holding scheduler leadership"))
	if err != nil {
		return err
	}
	_, err = m.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		if !isLeader() {
			o.ObserveInt64(leader, 0)
			return nil
		}
		o.ObserveInt64(leader, 1)
		var queued, running, online, mail, events int64
		if err := pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM scan_jobs WHERE status = 'queued'),
			(SELECT count(*) FROM scan_jobs WHERE status = 'running'),
			(SELECT count(*) FROM workers WHERE revoked_at IS NULL AND last_seen_at > now() - interval '2 minutes'),
			(SELECT count(*) FROM notifications WHERE status = 'pending' AND channel = 'email'),
			(SELECT count(*) FROM notification_events WHERE processed_at IS NULL)`).
			Scan(&queued, &running, &online, &mail, &events); err != nil {
			return err
		}
		o.ObserveInt64(jobs, queued, metric.WithAttributes(attribute.String("status", "queued")))
		o.ObserveInt64(jobs, running, metric.WithAttributes(attribute.String("status", "running")))
		o.ObserveInt64(workers, online)
		o.ObserveInt64(pending, mail)
		o.ObserveInt64(backlog, events)
		rows, err := pool.Query(ctx, `SELECT severity, count(*) FROM findings WHERE status IN ('open', 'in_progress', 'needs_review') GROUP BY severity`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sev string
			var n int64
			if err := rows.Scan(&sev, &n); err != nil {
				return err
			}
			o.ObserveInt64(open, n, metric.WithAttributes(attribute.String("severity", sev)))
		}
		return rows.Err()
	}, jobs, workers, pending, backlog, open, leader)
	return err
}
