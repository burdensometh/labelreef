package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"labelreef/reload"
	"labelreef/serve"
	"labelreef/zone"
)

func configCommand(ctx context.Context, command string, args []string, out, stderr io.Writer) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := flags.String("config", "", "v1 daemon configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *config == "" || flags.NArg() != 0 {
		return fmt.Errorf("%w: -config FILE is required", errUsage)
	}
	if command == "check" {
		manager, err := reload.Open(*config, reload.Boundary{})
		if err != nil {
			return err
		}
		return zone.EncodeJSON(out, manager.Status())
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	return runDaemon(ctx, *config, logger)
}

func runDaemon(ctx context.Context, path string, logger *slog.Logger) error {
	runtime, err := reload.Check(path)
	if err != nil {
		return err
	}
	release, err := lockState(runtime.StateDir)
	if err != nil {
		return err
	}
	defer release()
	manager, err := reload.Open(path, reload.Boundary{})
	if err != nil {
		return err
	}
	if runtime != manager.Runtime() {
		return fmt.Errorf("configuration runtime settings changed during startup")
	}
	ctlListener, err := serve.ControlListener(runtime.Control)
	if err != nil {
		return fmt.Errorf("open control listener: %w", err)
	}
	defer ctlListener.Close()
	dns, err := serve.Listen(manager, serve.Options{
		Address: runtime.DNS, MaxUDP: runtime.MaxUDP, FrameRecords: runtime.FrameRecords, IOTimeout: runtime.IOTimeout,
	})
	if err != nil {
		return fmt.Errorf("open DNS listener: %w", err)
	}
	defer dns.Close()

	handler := serve.Control{Manager: manager, DNS: dns, Client: serve.Client{IOTimeout: runtime.IOTimeout}}
	httpServer := handler.HTTPServer()
	defer httpServer.Close()
	controlStopped := make(chan error, 1)
	go func() { controlStopped <- httpServer.Serve(ctlListener) }()
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	logger.Info("ready", "dns", dns.Address(), "control", runtime.Control, "epoch", manager.Status().Epoch)
	for {
		select {
		case <-ctx.Done():
			return shutdown(httpServer)
		case err := <-dns.Errors():
			return err
		case err := <-controlStopped:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case item := <-signals:
			if item != syscall.SIGHUP {
				return shutdown(httpServer)
			}
			status, err := manager.Reload()
			if err != nil {
				logger.Error("configuration reload failed", "error", err)
			} else {
				logger.Info("configuration reloaded", "epoch", status.Epoch)
			}
		}
	}
}

func shutdown(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return server.Shutdown(ctx)
}
