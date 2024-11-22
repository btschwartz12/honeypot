package cron

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/btschwartz12/honeypot/repo"
)

func SyncSessions(logger *zap.SugaredLogger, rpo *repo.Repo) {
	ticker := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-ticker.C:
			go func() {
				ctx := context.Background()
				numSynced, err := rpo.SyncSessions(ctx)
				if err != nil {
					logger.Errorw("failed to sync sessions", "error", err)
				}
				if numSynced > 0 {
					logger.Infow("synced sessions", "numSynced", numSynced)
				}
			}()
		}
	}
}
