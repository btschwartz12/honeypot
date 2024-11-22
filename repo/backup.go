package repo

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	maindb "github.com/btschwartz12/honeypot/repo/db"
	cowriedb "github.com/btschwartz12/honeypot/repo/db/cowrie"
)

const (
	backupFormat = "2006-01-02T150405"
)

func (r *Repo) BackupCowrieDb(ctx context.Context) (string, error) {
	backupDir := filepath.Join(r.varDir, "cowrie_backups")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	sourceFile, err := os.Open(r.cowrieDbPath)
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	timeStr := time.Now().UTC().Format(backupFormat)
	backupPath := filepath.Join(backupDir, fmt.Sprintf("cowrie-%s.db", timeStr))
	backupFile, err := os.Create(backupPath)
	if err != nil {
		return "", fmt.Errorf("failed to create backup file: %w", err)
	}
	defer backupFile.Close()

	_, err = io.Copy(backupFile, sourceFile)
	if err != nil {
		return "", fmt.Errorf("failed to copy file: %w", err)
	}

	err = r.clearCowrieDb(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to clear cowrie db: %w", err)
	}

	err = r.InvalidateParsedSessions(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to invalidate parsed sessions: %w", err)
	}

	return backupPath, nil
}

func (r *Repo) InvalidateParsedSessions(ctx context.Context) error {
	qM := maindb.New(r.mainDb)
	if err := qM.DeleteAllSessions(ctx); err != nil {
		return fmt.Errorf("failed to reset main db: %w", err)
	}
	return nil
}

func (r *Repo) RestoreBackup(filename string) (string, error) {

	backupPath := filepath.Join(r.varDir, "cowrie_backups", filename)
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return "", fmt.Errorf("backup does not exist: %w", err)
	}

	r.cowrieDb.Close()

	sourceFile, err := os.Open(backupPath)
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(r.cowrieDbPath)
	if err != nil {
		return "", fmt.Errorf("failed to create dest file: %w", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return "", fmt.Errorf("failed to copy file: %w", err)
	}

	conn, err := sql.Open("sqlite", r.cowrieDbPath)
	if err != nil {
		return "", fmt.Errorf("failed to open sqlite db: %w", err)
	}

	err = r.InvalidateParsedSessions(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to invalidate parsed sessions: %w", err)
	}

	r.cowrieDb = conn
	return backupPath, nil
}

func (r *Repo) clearCowrieDb(ctx context.Context) error {
	qC := cowriedb.New(r.cowrieDb)
	if err := qC.DeleteAllAuth(ctx); err != nil {
		return fmt.Errorf("failed to delete all auth: %w", err)
	}
	if err := qC.DeleteAllInputs(ctx); err != nil {
		return fmt.Errorf("failed to delete all input: %w", err)
	}
	if err := qC.DeleteAllSessions(ctx); err != nil {
		return fmt.Errorf("failed to delete all sessions: %w", err)
	}
	if err := qC.DeleteAllTtylogs(ctx); err != nil {
		return fmt.Errorf("failed to delete all ttylogs: %w", err)
	}
	if err := qC.DeleteAllDownloads(ctx); err != nil {
		return fmt.Errorf("failed to delete all downloads: %w", err)
	}
	if err := qC.DeleteAllKeyfingerprints(ctx); err != nil {
		return fmt.Errorf("failed to delete all keyfingerprints: %w", err)
	}
	if err := qC.DeleteAllIpforwards(ctx); err != nil {
		return fmt.Errorf("failed to delete all ipforwards: %w", err)
	}
	if err := qC.DeleteAllIpforwardsdata(ctx); err != nil {
		return fmt.Errorf("failed to delete all ipforwardsdata: %w", err)
	}
	if err := qC.DeleteAllParams(ctx); err != nil {
		return fmt.Errorf("failed to delete all params: %w", err)
	}
	if err := qC.DeleteAllClients(ctx); err != nil {
		return fmt.Errorf("failed to delete all clients: %w", err)
	}
	if err := qC.DeleteAllSensors(ctx); err != nil {
		return fmt.Errorf("failed to delete all sensors: %w", err)
	}
	return nil
}
