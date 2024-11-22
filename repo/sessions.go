package repo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	maindb "github.com/btschwartz12/honeypot/repo/db"
	cowriedb "github.com/btschwartz12/honeypot/repo/db/cowrie"
)

func (r *Repo) GetSessions(ctx context.Context, filter *GetSessionsFilter) ([]Session, error) {
	q := maindb.New(r.mainDb)
	sessionIDs, err := q.GetSessionIds(ctx, filter.ToDb())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get all sessions: %w", err)
	}
	res := make([]Session, 0, len(sessionIDs))
	for _, id := range sessionIDs {
		s, err := r.GetSession(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("failed to get session %s: %w", id, err)
		}
		if filter.SuccessfulLogin.IsPresent() && filter.SuccessfulLogin.MustGet() && !s.SuccessfulLogin() {
			continue
		}
		res = append(res, *s)
	}
	return res, nil
}

func (r *Repo) GetSessionIds(ctx context.Context, filter *GetSessionsFilter) ([]string, error) {
	q := maindb.New(r.mainDb)
	sessionIDs, err := q.GetSessionIds(ctx, filter.ToDb())
	if err != nil {
		return nil, fmt.Errorf("failed to get all sessions: %w", err)
	}
	return sessionIDs, nil
}

func (r *Repo) GetSession(ctx context.Context, id string) (*Session, error) {
	q := cowriedb.New(r.cowrieDb)

	sessionRow, err := q.GetSession(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	authRows, err := q.GetAuthsForSession(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get auths for session: %w", err)
	}
	inputRows, err := q.GetInputsForSession(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get inputs for session: %w", err)
	}
	ttylogRows, err := q.GetTtylogsForSession(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get ttylogs for session: %w", err)
	}
	downloadRows, err := q.GetDownloadsForSession(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get downloads for session: %w", err)
	}
	keyFingerprintRows, err := q.GetKeyfingerprintsForSession(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get keyfingerprints for session: %w", err)
	}
	ipforwardsRows, err := q.GetIpforwardsForSession(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get ipforwards for session: %w", err)
	}
	ipforwardsdataRows, err := q.GetIpforwardsdataForSession(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get ipforwardsdata for session: %w", err)
	}
	paramsRows, err := q.GetParamsForSession(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get params for session: %w", err)
	}

	s := Session{}
	s.FromDb(
		sessionRow,
		authRows,
		downloadRows,
		inputRows,
		ipforwardsRows,
		ipforwardsdataRows,
		keyFingerprintRows,
		paramsRows,
		ttylogRows,
	)
	return &s, nil
}
