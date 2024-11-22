-- name: GetAuths :many
SELECT 
    auth.*,
    sessions.starttime,
    sessions.endtime,
    sessions.ip AS session_ip,
    sensors.ip AS sensor_ip
FROM auth
LEFT JOIN sessions ON auth.session = sessions.id
LEFT JOIN sensors ON sessions.sensor = sensors.id;

-- name: GetSession :one
SELECT 
    sessions.*,
    sensors.ip AS sensor_ip,
    clients.version AS client_version
FROM sessions
LEFT JOIN sensors ON sessions.sensor = sensors.id
LEFT JOIN clients ON sessions.client = clients.id
WHERE
    sessions.id = :id;

-- name: GetAllSessions :many
SELECT 
    id,
    starttime,
    ip
FROM sessions
ORDER BY starttime ASC;

-- name: GetAuthsForSession :many
SELECT * FROM auth WHERE session = ?;

-- name: GetInputsForSession :many
SELECT * FROM input WHERE session = ?;

-- name: GetTtylogsForSession :many
SELECT * FROM ttylog WHERE session = ?;

-- name: GetDownloadsForSession :many
SELECT * FROM downloads WHERE session = ?;

-- name: GetKeyfingerprintsForSession :many
SELECT * FROM keyfingerprints WHERE session = ?;

-- name: GetIpforwardsForSession :many
SELECT * FROM ipforwards WHERE session = ?;

-- name: GetIpforwardsdataForSession :many
SELECT * FROM ipforwardsdata WHERE session = ?;

-- name: GetParamsForSession :many
SELECT * FROM params WHERE session = ?;

-- name: DeleteAllAuth :exec
DELETE FROM auth;

-- name: DeleteAllSessions :exec
DELETE FROM sessions;

-- name: DeleteAllSensors :exec
DELETE FROM sensors;

-- name: DeleteAllClients :exec
DELETE FROM clients;

-- name: DeleteAllInputs :exec
DELETE FROM input;

-- name: DeleteAllTtylogs :exec
DELETE FROM ttylog;

-- name: DeleteAllDownloads :exec
DELETE FROM downloads;

-- name: DeleteAllKeyfingerprints :exec
DELETE FROM keyfingerprints;

-- name: DeleteAllIpforwards :exec
DELETE FROM ipforwards;

-- name: DeleteAllIpforwardsdata :exec
DELETE FROM ipforwardsdata;

-- name: DeleteAllParams :exec
DELETE FROM params;


