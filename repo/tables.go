package repo

import (
	"context"
	"fmt"

	cowriedb "github.com/btschwartz12/honeypot/repo/db/cowrie"
)

type FullAuth struct {
	ID        int64   `json:"id"`
	Session   string  `json:"session"`
	Success   bool    `json:"success"`
	Username  string  `json:"username"`
	Password  string  `json:"password"`
	Timestamp EstTime `json:"timestamp"`
	Sensor    string  `json:"sensor"`
	Ip        string  `json:"ip"`
}

func (a *FullAuth) fromDb(row cowriedb.GetAuthsRow) {
	a.ID = row.ID
	a.Session = row.Session
	if row.Success == 0 {
		a.Success = false
	} else {
		a.Success = true
	}
	a.Username = row.Username
	a.Password = row.Password
	a.Timestamp = EstTime{row.Timestamp}
	a.Sensor = row.SensorIp.String
	a.Ip = row.SessionIp.String
}

func (r *Repo) GetAllAuths(ctx context.Context) ([]FullAuth, error) {
	q := cowriedb.New(r.cowrieDb)
	rows, err := q.GetAuths(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get all auth: %w", err)
	}
	auths := make([]FullAuth, 0, len(rows))
	for _, row := range rows {
		a := FullAuth{}
		a.fromDb(row)
		auths = append(auths, a)
	}
	return auths, nil
}
