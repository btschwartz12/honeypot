package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/btschwartz12/honeypot/repo"
	"github.com/go-chi/chi/v5"
	"github.com/samber/mo"
)

// getSessions godoc
// @Summary Get all sessions
// @Description Get the sessions
// @Tags sessions
// @Produce json
// @Param limit query int false "Limit the number of sessions returned" default(10)
// @Param offset query int false "Offset for pagination" default(0)
// @Param include_failed_logins query bool false "Include failed logins" default(false)
// @Router /api/sessions [get]
// @Security Bearer
// @Success 200
func (s *ApiServer) getSessionsHandler(w http.ResponseWriter, r *http.Request) {
	limit := int64(10)
	offset := int64(0)

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if n, err := strconv.ParseInt(limitStr, 10, 64); err == nil && n > 0 {
			limit = n
		} else {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if n, err := strconv.ParseInt(offsetStr, 10, 64); err == nil && n >= 0 {
			offset = n
		} else {
			http.Error(w, "invalid offset", http.StatusBadRequest)
			return
		}
	}

	includeFailedLogins := false
	if includeFailedLoginsStr := r.URL.Query().Get("include_failed_logins"); includeFailedLoginsStr != "" {
		if b, err := strconv.ParseBool(includeFailedLoginsStr); err == nil {
			includeFailedLogins = b
		} else {
			http.Error(w, "invalid include_failed_logins", http.StatusBadRequest)
		}
	}

	// Define the filter for fetching sessions
	filter := &repo.GetSessionsFilter{
		StartTimeLt:     mo.None[time.Time](),
		StartTimeGt:     mo.None[time.Time](),
		Ip:              mo.None[string](),
		Limit:           mo.Some(limit),
		Offset:          mo.Some(offset),
		SuccessfulLogin: mo.Some(!includeFailedLogins),
	}

	sessions, err := s.rpo.GetSessions(r.Context(), filter)
	if err != nil {
		s.logger.Errorw("failed to get sessions", "error", err)
		http.Error(w, "failed to get sessions", http.StatusInternalServerError)
		return
	}

	next := ""
	if len(sessions) >= 0 {
		nextLimit := limit
		nextOffset := offset + limit
		next = fmt.Sprintf("?limit=%d&offset=%d", nextLimit, nextOffset)
	}

	response := struct {
		Sessions  []repo.Session `json:"sessions"`
		TotalSize int            `json:"total_size"`
		Next      string         `json:"next"`
	}{
		Sessions:  sessions,
		TotalSize: len(sessions),
		Next:      next,
	}

	resp, err := json.MarshalIndent(response, "", "\t")
	if err != nil {
		s.logger.Errorw("failed to marshal response", "error", err)
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

// getSession godoc
// @Summary Get a session
// @Description Get a session
// @Tags sessions
// @Produce json
// @Router /api/sessions/{id} [get]
// @Param id path string true "Session ID"
// @Security Bearer
// @Success 200
func (s *ApiServer) getSessionHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	session, err := s.rpo.GetSession(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		s.logger.Errorw("failed to get session", "error", err)
		http.Error(w, "failed to get session", http.StatusInternalServerError)
		return
	}

	resp, err := json.MarshalIndent(session, "", "\t")
	if err != nil {
		s.logger.Errorw("failed to marshal", "error", err)
		http.Error(w, "failed to marshal", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

// getAllAuths godoc
// @Summary Get all auths
// @Description Get the auths
// @Tags auths
// @Produce json
// @Router /api/auths [get]
// @Security Bearer
// @Success 200
func (s *ApiServer) getAllAuthsHandler(w http.ResponseWriter, r *http.Request) {
	auths, err := s.rpo.GetAllAuths(r.Context())
	if err != nil {
		s.logger.Errorw("failed to get auths", "error", err)
		http.Error(w, "failed to get auths", http.StatusInternalServerError)
		return
	}

	resp, err := json.MarshalIndent(auths, "", "\t")
	if err != nil {
		s.logger.Errorw("failed to marshal", "error", err)
		http.Error(w, "failed to marshal", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

// backupCowrieDatabaseHandler godoc
// @Summary Backup the cowrie database
// @Description Backup the cowrie database
// @Tags backup
// @Produce json
// @Router /api/backup [post]
// @Security Bearer
// @Success 200
func (s *ApiServer) backupCowrieDatabaseHandler(w http.ResponseWriter, r *http.Request) {
	backupPath, err := s.rpo.BackupCowrieDb(r.Context())
	if err != nil {
		s.logger.Errorw("failed to backup cowrie db", "error", err)
		http.Error(w, "failed to backup cowrie db", http.StatusInternalServerError)
		return
	}
	s.logger.Infow("backup created", "path", backupPath)
	w.Write([]byte("Backup created at " + backupPath))
}

// restoreCowrieDatabaseHandler godoc
// @Summary Restore the cowrie database
// @Description Restore the cowrie database
// @Tags restore
// @Produce json
// @Router /api/restore/{filename} [post]
// @Param filename path string true "Backup filename"
// @Security Bearer
// @Success 200
func (s *ApiServer) restoreCowrieDatabaseHandler(w http.ResponseWriter, r *http.Request) {
	filename := chi.URLParam(r, "filename")

	backupPath, err := s.rpo.RestoreBackup(filename)
	if err != nil {
		s.logger.Errorw("failed to restore cowrie db", "error", err)
		http.Error(w, "failed to restore cowrie db", http.StatusInternalServerError)
		return
	}
	s.logger.Infow("backup restored", "path", backupPath)
	w.Write([]byte("Backup restored from " + backupPath))
}

// serveReportHandler will simply just return the html file at the env variable REPORT_PATH
func (s *ApiServer) serveReportHandler(w http.ResponseWriter, r *http.Request) {
	reportPath := s.rb.GetReportPath()
	if _, err := os.Stat(reportPath); os.IsNotExist(err) {
		http.Error(w, "report does not exist", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, reportPath)
}

// generateReportHandler godoc
// @Summary Generate a report
// @Description Generate a report
// @Tags report
// @Router /api/report [post]
// @Security Bearer
// @Success 200
func (s *ApiServer) generateReportHandler(w http.ResponseWriter, r *http.Request) {
	stdout, stderr, err := s.rb.Generate()
	if err != nil {
		s.logger.Errorw("failed to generate report", "error", err, "stdout", stdout, "stderr", stderr)
		http.Error(w, "failed to generate report", http.StatusInternalServerError)
		return
	}
	s.logger.Infow("generated report", "output", s.rb.GetReportPath())
	w.Write([]byte("report successfully generated"))
}
