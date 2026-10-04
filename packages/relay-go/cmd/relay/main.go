// main.go
// Entrypoint for the CPace-Relay Go server.
package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	relay "github.com/laeeq14/cpace-relay"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port

	rs, err := relay.StartRelay(addr, logger)
	if err != nil {
		logger.Error("failed to start relay", "err", err)
		os.Exit(1)
	}

	logger.Info("CPace-Relay listening", "addr", rs.Addr())
	logger.Info("This is the local dev relay — do not use with real PHI in production without HIPAA review.")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down…")
	if err := rs.Close(); err != nil {
		logger.Error("shutdown error", "err", err)
	}
	logger.Info("relay stopped cleanly")
}
