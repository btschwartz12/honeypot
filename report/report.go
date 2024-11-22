package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/btschwartz12/honeypot/report/python/data"
	"github.com/kluctl/go-embed-python/embed_util"
	"github.com/kluctl/go-embed-python/python"
)

//go:embed python/script.py
var pythonScript []byte

type ReportBuilder struct {
	cmd        *exec.Cmd
	tmpDir     string
	reportPath string
	mu         sync.Mutex
}

func (r *ReportBuilder) Init(apiUrl, apiKey, tmpDir string) error {
	if err := os.RemoveAll(tmpDir); err != nil {
		return fmt.Errorf("failed to clean temporary directory: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	r.tmpDir = tmpDir

	scriptPath := filepath.Join(tmpDir, "script.py")
	if err := os.WriteFile(scriptPath, pythonScript, 0644); err != nil {
		return fmt.Errorf("failed to write script to temporary directory: %w", err)
	}

	pythonDir := filepath.Join(tmpDir, "python")

	ep, err := python.NewEmbeddedPythonWithTmpDir(pythonDir, true)
	if err != nil {
		return fmt.Errorf("failed to initialize embedded Python interpreter: %w", err)
	}

	embeddedFiles, err := embed_util.NewEmbeddedFilesWithTmpDir(data.Data, pythonDir, true)
	if err != nil {
		return fmt.Errorf("failed to load embedded Python dependencies: %w", err)
	}

	ep.AddPythonPath(embeddedFiles.GetExtractedPath())

	r.reportPath = filepath.Join(tmpDir, "report.html")

	r.cmd, err = ep.PythonCmd(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to create Python command: %w", err)
	}
	r.cmd.Env = append(r.cmd.Env,
		"API_URL="+apiUrl,
		"API_KEY="+apiKey,
		"OUTPUT_FILE="+r.reportPath,
	)
	return nil
}

func (r *ReportBuilder) Generate() (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// clone r.Cmd to avoid a 'exec: already started' error
	cmd := exec.Command(r.cmd.Path, r.cmd.Args[1:]...)
	cmd.Env = append(os.Environ(), r.cmd.Env...)
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &bytes.Buffer{}

	err := cmd.Run()
	stdout := cmd.Stdout.(*bytes.Buffer).String()
	stderr := cmd.Stderr.(*bytes.Buffer).String()

	if err != nil {
		return stdout, stderr, fmt.Errorf("failed to generate report: %w", err)
	}
	return stdout, stderr, nil
}

func (r *ReportBuilder) GetReportPath() string {
	return r.reportPath
}

func (r *ReportBuilder) Cleanup() {
	os.RemoveAll(r.tmpDir)
}

func (r *ReportBuilder) GetTmpDir() string {
	return r.tmpDir
}
