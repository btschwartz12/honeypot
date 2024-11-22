package cron

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/btschwartz12/honeypot/report"
)

const (
	jobTimeout  = 5 * time.Minute
	jobInterval = 10 * time.Minute
)

func GenerateReport(logger *zap.SugaredLogger, rb *report.ReportBuilder) {
	ticker := time.NewTicker(jobInterval)
	for {
		select {
		case <-ticker.C:
			go generateReport(logger, rb)
		}
	}
}

func generateReport(logger *zap.SugaredLogger, rb *report.ReportBuilder) {
	logger.Infow("generating report...")

	ctx, cancel := context.WithTimeout(context.Background(), jobTimeout)
	defer cancel()

	done := make(chan struct{})
	var stdout, stderr string
	var err error

	go func() {
		stdout, stderr, err = rb.Generate()
		close(done)
	}()

	select {
	case <-ctx.Done():
		logger.Errorw("report generation timed out", "error", ctx.Err())
		return
	case <-done:
		if err != nil {
			logger.Errorw("failed to generate report", "error", err, "stdout", stdout, "stderr", stderr)
			return
		}
		logger.Infow("generated report", "output", rb.GetReportPath())
	}
}
