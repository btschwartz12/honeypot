// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0

package db

type LastSlackUpdate struct {
	ID         int64
	LastUpdate string
}

type Session struct {
	Idx       int64
	ID        string
	Starttime string
	Ip        string
}

type SlackSyncedMessage struct {
	SessionID string
}
