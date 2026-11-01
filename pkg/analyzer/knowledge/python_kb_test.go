package knowledge

import (
	"testing"
)

func TestResolvePipPackage(t *testing.T) {
	tests := []struct {
		module   string
		expected string
	}{
		{"yaml", "PyYAML"},
		{"cv2", "opencv-python"},
		{"PIL", "Pillow"},
		{"psycopg2", "psycopg2-binary"},
		{"pydantic_core", "pydantic"},
		{"unknown_module", "unknown_module"},
	}

	for _, tt := range tests {
		got := ResolvePipPackage(tt.module)
		if got != tt.expected {
			t.Errorf("ResolvePipPackage(%q) = %q, expected %q", tt.module, got, tt.expected)
		}
	}
}

func TestAnalyzePythonDeepCrash_ChainedException(t *testing.T) {
	logs := `
Traceback (most recent call last):
  File "/app/services/db.py", line 45, in connect_db
    raise ConnectionRefusedError("Failed to connect to postgres:5432")
ConnectionRefusedError: Failed to connect to postgres:5432

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/app/main.py", line 88, in startup_event
    connect_db()
  File "/app/services/db.py", line 48, in connect_db
    raise RuntimeError("Application bootstrap failed due to database connectivity")
RuntimeError: Application bootstrap failed due to database connectivity
`
	analysis := AnalyzePythonDeepCrash(logs)
	if analysis == nil {
		t.Fatalf("expected non-nil analysis")
	}

	if !analysis.IsChained {
		t.Errorf("expected IsChained to be true")
	}
	if analysis.InitialCauseClass != "ConnectionRefusedError" {
		t.Errorf("expected InitialCauseClass 'ConnectionRefusedError', got %q", analysis.InitialCauseClass)
	}
	if analysis.ExceptionClass != "RuntimeError" {
		t.Errorf("expected ExceptionClass 'RuntimeError', got %q", analysis.ExceptionClass)
	}
	if analysis.CulpritCode == nil || analysis.CulpritCode.File != "db.py" {
		t.Errorf("expected culprit file 'db.py', got %+v", analysis.CulpritCode)
	}
}

func TestAnalyzePythonDeepCrash_CircularImport(t *testing.T) {
	logs := `
Traceback (most recent call last):
  File "app.py", line 3, in <module>
    from models import User
  File "/app/models.py", line 2, in <module>
    from services import UserService
  File "/app/services.py", line 1, in <module>
    from models import User
ImportError: cannot import name 'User' from partially initialized module 'models' (most likely due to a circular import)
`
	analysis := AnalyzePythonDeepCrash(logs)
	if analysis == nil {
		t.Fatalf("expected non-nil analysis")
	}

	if analysis.ExceptionClass != "CircularImportError" {
		t.Errorf("expected CircularImportError, got %q", analysis.ExceptionClass)
	}
	if analysis.CircularImportPair[0] != "User" || analysis.CircularImportPair[1] != "models" {
		t.Errorf("expected circular import pair User <-> models, got %v", analysis.CircularImportPair)
	}
}

func TestAnalyzePythonDeepCrash_MissingModule(t *testing.T) {
	logs := `
Traceback (most recent call last):
  File "/app/worker.py", line 12, in <module>
    import yaml
ModuleNotFoundError: No module named 'yaml'
`
	analysis := AnalyzePythonDeepCrash(logs)
	if analysis == nil {
		t.Fatalf("expected non-nil analysis")
	}
	if analysis.MissingPackage != "PyYAML" {
		t.Errorf("expected missing package 'PyYAML', got %q", analysis.MissingPackage)
	}
}
