package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/go-chi/chi/v5"
	flags "github.com/jessevdk/go-flags"
	"go.uber.org/zap"

	"github.com/btschwartz12/honeypot/api"
	"github.com/btschwartz12/honeypot/cron"
	"github.com/btschwartz12/honeypot/repo"
	"github.com/btschwartz12/honeypot/report"
)

type arguments struct {
	DevLogging   bool   `short:"d" long:"dev-logging" env:"DEV_LOGGING" description:"Enable development logging"`
	Port         int    `short:"p" long:"port" env:"PORT" default:"8080" description:"Port to listen on"`
	CowrieDbPath string `short:"c" long:"cowrie-db-path" env:"COWRIE_DB_PATH" default:"./var/cowrie.db" description:"Path to cowrie db"`
	SlackWebhook string `short:"s" long:"slack-webhook" env:"SLACK_WEBHOOK" description:"Slack webhook"`
	AuthToken    string `short:"t" long:"auth-token" env:"AUTH_TOKEN" description:"API token"`
}

const (
	apiPrefix = "/api"
	varDir = "./var"
)

var opts arguments

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	_, err := flags.Parse(&opts)
	if err != nil {
		panic(fmt.Errorf("failed to parse flags: %w", err))
	}
	var l *zap.Logger
	if opts.DevLogging {
		l, err = zap.NewDevelopment()
	} else {
		l, err = zap.NewProduction()
	}
	if err != nil {
		panic(fmt.Errorf("failed to create logger: %w", err))
	}
	logger := l.Sugar()

	reportTmpDir, err := filepath.Abs(filepath.Join(varDir, "report"))
	if err != nil {
		logger.Fatalw("failed to get absolute path for report directory", "error", err)
	}
	rb := &report.ReportBuilder{}
	err = rb.Init(fmt.Sprintf("http://localhost:%d", opts.Port), opts.AuthToken, reportTmpDir)
	if err != nil {
		logger.Fatalw("failed to init report builder", "error", err)
	}
	defer rb.Cleanup()
	go cron.GenerateReport(logger, rb)

	rpo, err := repo.NewRepo(opts.CowrieDbPath, varDir)
	if err != nil {
		logger.Fatalw("failed to create repo", "error", err)
	}
	go cron.SyncSessions(logger, rpo)

	if opts.SlackWebhook != "" {
		go cron.SyncSlack(opts.SlackWebhook, logger, rpo)
	}

	r := chi.NewRouter()
	apiServer := &api.ApiServer{}
	err = apiServer.Init(logger, rpo, rb, opts.AuthToken, apiPrefix)
	if err != nil {
		logger.Fatalw("failed to init api server", "error", err)
	}
	r.Mount(apiPrefix, apiServer.GetRouter())

	errChan := make(chan error)
	go func() {
		logger.Infow("starting http server", "port", opts.Port)
		errChan <- http.ListenAndServe(fmt.Sprintf(":%d", opts.Port), r)
	}()
	select {
	case <-ctx.Done():
		logger.Info("shutting down gracefully")
	case err = <-errChan:
		logger.Fatalw("http server failed", "error", err)
	}
}
