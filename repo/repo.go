package repo

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/btschwartz12/honeypot/repo/db"
)

const (
	cowrieDbName = "cowrie.db"
	mainDbName   = "main.db"
)

type Repo struct {
	cowrieDb     *sql.DB
	mainDb       *sql.DB
	varDir       string
	cowrieDbPath string
}

func NewRepo(cowrieDbPath, varDir string) (*Repo, error) {
	r := &Repo{
		varDir:       varDir,
		cowrieDbPath: cowrieDbPath,
	}

	if err := os.MkdirAll(r.varDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create var directory: %w", err)
	}

	conn, err := sql.Open("sqlite", cowrieDbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}
	if _, err := conn.Exec(string(db.CowrieSchema)); err != nil {
		return nil, fmt.Errorf("failed to execute schema: %w", err)
	}
	r.cowrieDb = conn

	conn, err = sql.Open("sqlite", filepath.Join(r.varDir, mainDbName))
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}
	if _, err := conn.Exec(string(db.MainSchema)); err != nil {
		return nil, fmt.Errorf("failed to execute schema: %w", err)
	}
	r.mainDb = conn

	return r, nil
}
