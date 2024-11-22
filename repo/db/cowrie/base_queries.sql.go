// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: base_queries.sql

package db

import (
	"context"
	"database/sql"
	"time"
)

const deleteAllAuth = `-- name: DeleteAllAuth :exec
DELETE FROM auth
`

func (q *Queries) DeleteAllAuth(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllAuth)
	return err
}

const deleteAllClients = `-- name: DeleteAllClients :exec
DELETE FROM clients
`

func (q *Queries) DeleteAllClients(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllClients)
	return err
}

const deleteAllDownloads = `-- name: DeleteAllDownloads :exec
DELETE FROM downloads
`

func (q *Queries) DeleteAllDownloads(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllDownloads)
	return err
}

const deleteAllInputs = `-- name: DeleteAllInputs :exec
DELETE FROM input
`

func (q *Queries) DeleteAllInputs(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllInputs)
	return err
}

const deleteAllIpforwards = `-- name: DeleteAllIpforwards :exec
DELETE FROM ipforwards
`

func (q *Queries) DeleteAllIpforwards(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllIpforwards)
	return err
}

const deleteAllIpforwardsdata = `-- name: DeleteAllIpforwardsdata :exec
DELETE FROM ipforwardsdata
`

func (q *Queries) DeleteAllIpforwardsdata(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllIpforwardsdata)
	return err
}

const deleteAllKeyfingerprints = `-- name: DeleteAllKeyfingerprints :exec
DELETE FROM keyfingerprints
`

func (q *Queries) DeleteAllKeyfingerprints(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllKeyfingerprints)
	return err
}

const deleteAllParams = `-- name: DeleteAllParams :exec
DELETE FROM params
`

func (q *Queries) DeleteAllParams(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllParams)
	return err
}

const deleteAllSensors = `-- name: DeleteAllSensors :exec
DELETE FROM sensors
`

func (q *Queries) DeleteAllSensors(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllSensors)
	return err
}

const deleteAllSessions = `-- name: DeleteAllSessions :exec
DELETE FROM sessions
`

func (q *Queries) DeleteAllSessions(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllSessions)
	return err
}

const deleteAllTtylogs = `-- name: DeleteAllTtylogs :exec
DELETE FROM ttylog
`

func (q *Queries) DeleteAllTtylogs(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllTtylogs)
	return err
}

const getAllSessions = `-- name: GetAllSessions :many
SELECT 
    id,
    starttime,
    ip
FROM sessions
ORDER BY starttime ASC
`

type GetAllSessionsRow struct {
	ID        string
	Starttime time.Time
	Ip        string
}

func (q *Queries) GetAllSessions(ctx context.Context) ([]GetAllSessionsRow, error) {
	rows, err := q.db.QueryContext(ctx, getAllSessions)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetAllSessionsRow
	for rows.Next() {
		var i GetAllSessionsRow
		if err := rows.Scan(&i.ID, &i.Starttime, &i.Ip); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getAuths = `-- name: GetAuths :many
SELECT 
    auth.id, auth.session, auth.success, auth.username, auth.password, auth.timestamp,
    sessions.starttime,
    sessions.endtime,
    sessions.ip AS session_ip,
    sensors.ip AS sensor_ip
FROM auth
LEFT JOIN sessions ON auth.session = sessions.id
LEFT JOIN sensors ON sessions.sensor = sensors.id
`

type GetAuthsRow struct {
	ID        int64
	Session   string
	Success   int64
	Username  string
	Password  string
	Timestamp time.Time
	Starttime sql.NullTime
	Endtime   sql.NullTime
	SessionIp sql.NullString
	SensorIp  sql.NullString
}

func (q *Queries) GetAuths(ctx context.Context) ([]GetAuthsRow, error) {
	rows, err := q.db.QueryContext(ctx, getAuths)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetAuthsRow
	for rows.Next() {
		var i GetAuthsRow
		if err := rows.Scan(
			&i.ID,
			&i.Session,
			&i.Success,
			&i.Username,
			&i.Password,
			&i.Timestamp,
			&i.Starttime,
			&i.Endtime,
			&i.SessionIp,
			&i.SensorIp,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getAuthsForSession = `-- name: GetAuthsForSession :many
SELECT id, session, success, username, password, timestamp FROM auth WHERE session = ?
`

func (q *Queries) GetAuthsForSession(ctx context.Context, session string) ([]Auth, error) {
	rows, err := q.db.QueryContext(ctx, getAuthsForSession, session)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Auth
	for rows.Next() {
		var i Auth
		if err := rows.Scan(
			&i.ID,
			&i.Session,
			&i.Success,
			&i.Username,
			&i.Password,
			&i.Timestamp,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getDownloadsForSession = `-- name: GetDownloadsForSession :many
SELECT id, session, timestamp, url, outfile, shasum FROM downloads WHERE session = ?
`

func (q *Queries) GetDownloadsForSession(ctx context.Context, session string) ([]Download, error) {
	rows, err := q.db.QueryContext(ctx, getDownloadsForSession, session)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Download
	for rows.Next() {
		var i Download
		if err := rows.Scan(
			&i.ID,
			&i.Session,
			&i.Timestamp,
			&i.Url,
			&i.Outfile,
			&i.Shasum,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getInputsForSession = `-- name: GetInputsForSession :many
SELECT id, session, timestamp, realm, success, input FROM input WHERE session = ?
`

func (q *Queries) GetInputsForSession(ctx context.Context, session string) ([]Input, error) {
	rows, err := q.db.QueryContext(ctx, getInputsForSession, session)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Input
	for rows.Next() {
		var i Input
		if err := rows.Scan(
			&i.ID,
			&i.Session,
			&i.Timestamp,
			&i.Realm,
			&i.Success,
			&i.Input,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getIpforwardsForSession = `-- name: GetIpforwardsForSession :many
SELECT id, session, timestamp, dst_ip, dst_port FROM ipforwards WHERE session = ?
`

func (q *Queries) GetIpforwardsForSession(ctx context.Context, session string) ([]Ipforward, error) {
	rows, err := q.db.QueryContext(ctx, getIpforwardsForSession, session)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Ipforward
	for rows.Next() {
		var i Ipforward
		if err := rows.Scan(
			&i.ID,
			&i.Session,
			&i.Timestamp,
			&i.DstIp,
			&i.DstPort,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getIpforwardsdataForSession = `-- name: GetIpforwardsdataForSession :many
SELECT id, session, timestamp, dst_ip, dst_port, data FROM ipforwardsdata WHERE session = ?
`

func (q *Queries) GetIpforwardsdataForSession(ctx context.Context, session string) ([]Ipforwardsdatum, error) {
	rows, err := q.db.QueryContext(ctx, getIpforwardsdataForSession, session)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Ipforwardsdatum
	for rows.Next() {
		var i Ipforwardsdatum
		if err := rows.Scan(
			&i.ID,
			&i.Session,
			&i.Timestamp,
			&i.DstIp,
			&i.DstPort,
			&i.Data,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getKeyfingerprintsForSession = `-- name: GetKeyfingerprintsForSession :many
SELECT id, session, username, fingerprint FROM keyfingerprints WHERE session = ?
`

func (q *Queries) GetKeyfingerprintsForSession(ctx context.Context, session string) ([]Keyfingerprint, error) {
	rows, err := q.db.QueryContext(ctx, getKeyfingerprintsForSession, session)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Keyfingerprint
	for rows.Next() {
		var i Keyfingerprint
		if err := rows.Scan(
			&i.ID,
			&i.Session,
			&i.Username,
			&i.Fingerprint,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getParamsForSession = `-- name: GetParamsForSession :many
SELECT id, session, arch FROM params WHERE session = ?
`

func (q *Queries) GetParamsForSession(ctx context.Context, session string) ([]Param, error) {
	rows, err := q.db.QueryContext(ctx, getParamsForSession, session)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Param
	for rows.Next() {
		var i Param
		if err := rows.Scan(&i.ID, &i.Session, &i.Arch); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getSession = `-- name: GetSession :one
SELECT 
    sessions.id, sessions.starttime, sessions.endtime, sessions.sensor, sessions.ip, sessions.termsize, sessions.client,
    sensors.ip AS sensor_ip,
    clients.version AS client_version
FROM sessions
LEFT JOIN sensors ON sessions.sensor = sensors.id
LEFT JOIN clients ON sessions.client = clients.id
WHERE
    sessions.id = ?1
`

type GetSessionRow struct {
	ID            string
	Starttime     time.Time
	Endtime       sql.NullTime
	Sensor        int64
	Ip            string
	Termsize      sql.NullString
	Client        sql.NullInt64
	SensorIp      sql.NullString
	ClientVersion sql.NullString
}

func (q *Queries) GetSession(ctx context.Context, id string) (GetSessionRow, error) {
	row := q.db.QueryRowContext(ctx, getSession, id)
	var i GetSessionRow
	err := row.Scan(
		&i.ID,
		&i.Starttime,
		&i.Endtime,
		&i.Sensor,
		&i.Ip,
		&i.Termsize,
		&i.Client,
		&i.SensorIp,
		&i.ClientVersion,
	)
	return i, err
}

const getTtylogsForSession = `-- name: GetTtylogsForSession :many
SELECT id, session, ttylog, size FROM ttylog WHERE session = ?
`

func (q *Queries) GetTtylogsForSession(ctx context.Context, session string) ([]Ttylog, error) {
	rows, err := q.db.QueryContext(ctx, getTtylogsForSession, session)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Ttylog
	for rows.Next() {
		var i Ttylog
		if err := rows.Scan(
			&i.ID,
			&i.Session,
			&i.Ttylog,
			&i.Size,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}