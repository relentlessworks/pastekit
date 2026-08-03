package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/relentlessworks/pastekit/internal/api"
	"github.com/relentlessworks/pastekit/internal/auth"
	"github.com/relentlessworks/pastekit/internal/config"
	"github.com/relentlessworks/pastekit/internal/store"
)

func main() {
	cfg := config.Load()

	s, err := store.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to initialize store: %v", err)
	}

	a := auth.New(cfg, s)
	h := api.New(cfg, s, a)

	// Start expired paste cleanup goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			count := s.CleanupExpired()
			if count > 0 {
				log.Printf("Cleaned up %d expired pastes", count)
			}
		}
	}()

	srv := &http.Server{
		Addr:         cfg.Addr,
		Handler:      h.Routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		log.Printf("pastekit listening on %s", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Forced shutdown: %v", err)
	}
	log.Println("Server stopped")
}
