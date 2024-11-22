package repo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	maindb "github.com/btschwartz12/honeypot/repo/db"
	cowriedb "github.com/btschwartz12/honeypot/repo/db/cowrie"
)

func (r *Repo) SyncSessions(ctx context.Context) (int, error) {
	// get all the sessions from the cowrie db
	qC := cowriedb.New(r.cowrieDb)
	sessions, err := qC.GetAllSessions(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get sessions: %w", err)
	}

	numSynced := 0

	// insert all the sessions into the main db
	qM := maindb.New(r.mainDb)
	for _, session := range sessions {
		_, err := qM.SessionExists(ctx, session.ID)
		if err == nil {
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return 0, fmt.Errorf("failed to check if session exists: %w", err)
		}
		_, err = qM.InsertSession(ctx, maindb.InsertSessionParams{
			ID:        session.ID,
			Starttime: session.Starttime.UTC().Format("2006-01-02T15:04:05.000000Z"),
			Ip:        session.Ip,
		})
		if err != nil {
			return 0, fmt.Errorf("failed to insert session %s: %w", session.ID, err)
		}
		numSynced++
	}

	return numSynced, nil
}
