package api

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	httpSwagger "github.com/swaggo/http-swagger/v2"
	"go.uber.org/zap"

	"github.com/btschwartz12/honeypot/api/swagger"
	"github.com/btschwartz12/honeypot/repo"
	"github.com/btschwartz12/honeypot/report"
)

type ApiServer struct {
	router *chi.Mux
	logger *zap.SugaredLogger
	rpo    *repo.Repo
	rb     *report.ReportBuilder
	token  string
}

func (s *ApiServer) Init(
	logger *zap.SugaredLogger,
	rpo *repo.Repo,
	rb *report.ReportBuilder,
	authToken string,
	prefix string) error {

	s.logger = logger
	s.router = chi.NewRouter()
	s.rpo = rpo
	s.rb = rb
	s.token = authToken

	s.router.Get("/", http.RedirectHandler(fmt.Sprintf("%s/swagger/index.html", prefix), http.StatusMovedPermanently).ServeHTTP)
	s.router.Get("/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(swagger.SwaggerJSON)
	})
	s.router.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL(fmt.Sprintf("%s/swagger.json", prefix))))

	s.router.Group(func(rr chi.Router) {
		rr.Use(s.tokenMiddleware)
		rr.Get("/sessions", s.getSessionsHandler)
		rr.Get("/sessions/{id}", s.getSessionHandler)
		rr.Get("/auths", s.getAllAuthsHandler)
		rr.Post("/backup", s.backupCowrieDatabaseHandler)
		rr.Post("/restore/{filename}", s.restoreCowrieDatabaseHandler)
		rr.Get("/report", s.serveReportHandler)
		rr.Post("/report", s.generateReportHandler)
	})

	return nil
}

func (s *ApiServer) GetRouter() chi.Router {
	return s.router
}
