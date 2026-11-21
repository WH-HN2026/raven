// Command asi is the single ASI binary: HTTP API + embedded SPA, scheduler
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

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/config"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/db"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/dojo"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/httpapi"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/pipeline"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner/nmap"
)

func main() {
	level := slog.LevelInfo
	if os.Getenv("ASI_DEBUG") == "1" {
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
	if cfg.DojoURL != "" {
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
			// Read-model pull (D3): once now, then every 5 min.
			(&dojo.Syncer{Client: res.Client, Pool: pool, OrganizationID: res.Organization.ID}).Run(ctx, 5*time.Minute)
		}()
	} else {
		slog.Warn("ASI_DOJO_URL is empty: DefectDojo integration disabled")
	}

	// Scan pipeline: River workers running nmap per batch (S3).
	pipe, err := pipeline.New(pool, pipeline.Config{Scanner: nmap.New(nmap.Config{}), Resolver: net.DefaultResolver})
	if err != nil {
		return err
	}
	if err := pipe.Start(ctx); err != nil {
		return err
	}
	defer shutdownPipeline(pipe)

	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: httpapi.NewRouter(httpapi.Deps{
			Pool: pool, Queries: q, Auth: authSvc, CookieSecure: cfg.CookieSecure,
			DojoPublicURL: cfg.DojoPublicURL,
			Pipeline: pipe,
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

func shutdownPipeline(p *pipeline.Service) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Shutdown(ctx); err != nil {
		slog.Warn("pipeline shutdown", "err", err)
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
