package repo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	maindb "github.com/btschwartz12/honeypot/repo/db"
)

func (r *Repo) UpdateLastSlackUpdate(ctx context.Context, lastUpdate time.Time) (string, error) {
	timeStr := lastUpdate.UTC().Format("2006-01-02T15:04:05.000000Z")
	q := maindb.New(r.mainDb)
	time, err := q.UpdateLastSlackUpdate(ctx, timeStr)
	if err != nil {
		return "", fmt.Errorf("failed to update last slack update: %w", err)
	}
	return time, nil
}

func (r *Repo) GetLastSlackUpdate(ctx context.Context) (time.Time, error) {
	q := maindb.New(r.mainDb)
	timeStr, err := q.GetLastSlackUpdate(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get last slack update: %w", err)
	}
	t, err := time.Parse("2006-01-02T15:04:05.000000Z", timeStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse time: %w", err)
	}
	return t, nil
}

func (r *Repo) AlreadySyncedInSlack(ctx context.Context, sessionID string) (bool, error) {
	q := maindb.New(r.mainDb)
	_, err := q.AlreadySynced(ctx, sessionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = q.InsertSyncedMessage(ctx, sessionID)
			if err != nil {
				return false, fmt.Errorf("failed to insert synced message: %w", err)
			}
			return false, nil
		}
		return false, fmt.Errorf("failed to check if already synced: %w", err)
	}
	return true, nil
}
