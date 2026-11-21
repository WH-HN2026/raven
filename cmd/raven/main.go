// Command raven is the single RAVEN binary: HTTP API + embedded SPA, scheduler
// and scan workers (D2).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/config"
	"github.com/WH-HN2026/raven/internal/cve"
	"github.com/WH-HN2026/raven/internal/db"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dojo"
	"github.com/WH-HN2026/raven/internal/httpapi"
	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner/httpx"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
	"github.com/WH-HN2026/raven/internal/scanner/nuclei"
	"github.com/WH-HN2026/raven/internal/scheduler"
	"github.com/WH-HN2026/raven/internal/signatures"
)

func main() {
	level := slog.LevelInfo
	if os.Getenv("RAVEN_DEBUG") == "1" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL, cfg.EncryptionKey)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	q := gen.New(pool)
	signatures.LoadBuiltins(ctx, pool) // seed/update the built-in signature pack (C2)

	authSvc := auth.NewService(q, cfg.SessionTTL)
	if err := authSvc.EnsureBootstrapAdmin(ctx, cfg.AdminUsername, cfg.AdminPassword); err != nil {
		return err
	}
	go every(ctx, time.Hour, func() {
		if err := authSvc.CleanupSessions(ctx); err != nil {
			slog.Warn("session cleanup", "err", err)
		}
	})

	// Dojo bootstrap must never block the HTTP server (Dojo's first boot takes minutes).
	// Push jobs (D2) are enqueued from the start and wait until it's done.
	var hook pipeline.BatchHook
	var dojoPush *dojo.PushService
	cveMatcher, err := cve.Default() // offline CVE data (C3), embedded
	if err != nil {
		return err
	}
	dojoWrite := &dojo.Lazy{} // write-through edits (D6); set once bootstrap is done
	if cfg.DojoURL != "" {
		push, err := dojo.NewPushService(pool, map[string]dojo.ParseFunc{
			"nmap": nmap.Parse, "httpx": httpx.Parse, "nuclei": nuclei.Parse,
		})
		if err != nil {
			return err
		}
		if err := push.Start(ctx); err != nil {
			return err
		}
		defer shutdown("dojo push", push.Shutdown)
		hook = push // enqueues one push job per finished batch
		dojoPush = push
		go func() {
			res, err := dojo.Bootstrap(ctx, dojo.BootstrapConfig{
				URL: cfg.DojoURL, Token: cfg.DojoToken,
				AdminUser: cfg.DojoAdminUser, AdminPass: cfg.DojoAdminPass,
				Organization: cfg.DojoOrganization,
			})
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					slog.Error("dojo bootstrap", "err", err)
				}
				return
			}
			push.SetPusher(&dojo.Pusher{Client: res.Client, OrganizationID: res.Organization.ID,
				Parallel: res.Client.Concurrency()})
			dojoWrite.Set(res.Client)
			// Planned engagements poller (D5): once now, then every 5 min.
			go (&dojo.PlanningPoller{Client: res.Client, Pool: pool, PlanningAssetID: res.Planning.ID}).Run(ctx, 5*time.Minute)
			// Offline CVE matching + push (C3): now, then every 5 min.
			go (&dojo.CVESync{Pool: pool, Matcher: cveMatcher,
				Pusher: &dojo.CVEPusher{Client: res.Client, OrganizationID: res.Organization.ID}}).Run(ctx, 5*time.Minute)
			// Read-model pull (D3): once now, then every 5 min.
			(&dojo.Syncer{Client: res.Client, Pool: pool, OrganizationID: res.Organization.ID}).Run(ctx, 5*time.Minute)
		}()
	} else {
		slog.Warn("RAVEN_DOJO_URL is empty: DefectDojo integration disabled")
		go (&dojo.CVESync{Pool: pool, Matcher: cveMatcher}).Run(ctx, 5*time.Minute) // match only (C3)
	}

	// Scan pipeline: River workers running nmap/httpx/nuclei per batch (S3, S5).
	pipe, err := pipeline.New(pool, pipeline.Config{
		Scanner: nmap.New(nmap.Config{}), Resolver: net.DefaultResolver, Hook: hook, Workers: cfg.MaxWorkers,
	})
	if err != nil {
		return err
	}
	if err := pipe.Start(ctx); err != nil {
		return err
	}
	defer shutdown("pipeline", pipe.Shutdown)
	go (scheduler.Scheduler{Queries: q, Runs: pipe}).Run(ctx, 30*time.Second)

	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: httpapi.NewRouter(httpapi.Deps{
			Pool: pool, Queries: q, Auth: authSvc, CookieSecure: cfg.CookieSecure,
			DojoPublicURL: cfg.DojoPublicURL,
			Pipeline:      pipe,
			Dojo:          dojoWrite,
			DojoPush:      dojoPush,
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		slog.Info("http server listening", "addr", cfg.HTTPAddr)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	slog.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutCtx)
}

func shutdown(name string, f func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f(ctx); err != nil {
		slog.Warn(name+" shutdown", "err", err)
	}
}

func every(ctx context.Context, d time.Duration, f func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f()
		}
	}
}
