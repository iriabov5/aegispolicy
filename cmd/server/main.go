package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	apidocs "github.com/iriabov5/aegispolicy/docs"
	"github.com/iriabov5/aegispolicy/internal/authn"
	"github.com/iriabov5/aegispolicy/internal/authorization"
	"github.com/iriabov5/aegispolicy/internal/config"
	"github.com/iriabov5/aegispolicy/internal/httpapi"
	"github.com/iriabov5/aegispolicy/internal/policy"
	"github.com/iriabov5/aegispolicy/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// main настраивает structured logger и завершает process с ненулевым кодом при fatal error.
func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

// run создаёт dependencies, проверяет readiness, запускает HTTP server и выполняет graceful shutdown.
func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	poolConfig, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	poolConfig.MaxConns = cfg.MaxDBConnections
	startupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(startupCtx, poolConfig)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := pool.Ping(startupCtx); err != nil {
		return err
	}

	storeAdapter := store.NewPostgres(pool)
	opaClient := &http.Client{Timeout: cfg.OPATimeout}
	opaAdapter := policy.NewOPA(cfg.OPAURL, opaClient)
	if err := opaAdapter.Ready(startupCtx); err != nil {
		return err
	}
	service := authorization.NewService(storeAdapter, opaAdapter, storeAdapter)
	jwksClient := &http.Client{Timeout: cfg.JWKSTimeout}
	jwksCache := authn.NewJWKSCache(cfg.JWKSURL, jwksClient, cfg.JWKSCacheTTL)
	verifier := authn.NewJWTVerifier(cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTClockSkew, jwksCache)
	readiness := func(ctx context.Context) error {
		if err := pool.Ping(ctx); err != nil {
			return err
		}
		return opaAdapter.Ready(ctx)
	}
	server := &http.Server{
		Addr: cfg.HTTPAddress, Handler: httpapi.New(service, verifier, readiness, apidocs.OpenAPI, log),
		ReadTimeout: cfg.ReadTimeout, WriteTimeout: cfg.WriteTimeout, IdleTimeout: cfg.IdleTimeout,
		ReadHeaderTimeout: 2 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Info("server started", "address", cfg.HTTPAddress)
		serverErr <- server.ListenAndServe()
	}()

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-signalCtx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer shutdownCancel()
		return server.Shutdown(shutdownCtx)
	}
}
