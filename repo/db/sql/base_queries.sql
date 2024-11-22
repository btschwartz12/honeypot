-- name: GetSessionIds :many
SELECT
    id
FROM sessions
WHERE
    (COALESCE(:ip, '') = '' OR ip = :ip OR ip IS NULL)
    AND (COALESCE(:start_time_lt, '') = '' OR starttime < :start_time_lt)
    AND (COALESCE(:start_time_gt, '') = '' OR starttime > :start_time_gt)
ORDER BY idx ASC
LIMIT COALESCE(:limit, -1) OFFSET COALESCE(:offset, 0);

-- name: SessionExists :one
SELECT 
    id
FROM sessions
WHERE
    id = ?;

-- name: InsertSession :one
INSERT INTO 
    sessions (id, starttime, ip) 
VALUES 
    (?, ?, ?)
RETURNING 
    id;

-- name: DeleteAllSessions :exec
DELETE FROM sessions;

-- name: GetLastSlackUpdate :one
SELECT 
    last_update
FROM last_slack_update
LIMIT 1;

-- name: UpdateLastSlackUpdate :one
INSERT OR REPLACE INTO 
    last_slack_update (id, last_update)
VALUES 
    (1, ?)
RETURNING
    last_update;

-- name: AlreadySynced :one
SELECT 
    session_id
FROM slack_synced_messages
WHERE
    session_id = ?;

-- name: InsertSyncedMessage :exec
INSERT INTO 
    slack_synced_messages (session_id)
VALUES 
    (?);
