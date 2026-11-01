package knowledge

import (
	"testing"
)

func TestAnalyzePHPDeepCrash_MemoryLimit(t *testing.T) {
	logs := `
[02-Nov-2026 02:40:00] NOTICE: PHP message: PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in /var/www/html/app/Reports/Exporter.php on line 142
`
	res := AnalyzePHPDeepCrash(logs)
	if res == nil {
		t.Fatal("expected non-nil result for PHP memory limit")
	}
	if res.ErrorClass != "PHPMemoryLimitExceeded" {
		t.Fatalf("expected PHPMemoryLimitExceeded, got %s", res.ErrorClass)
	}
	if res.CulpritCode == nil || res.CulpritCode.File != "/var/www/html/app/Reports/Exporter.php" || res.CulpritCode.Line != 142 {
		t.Fatalf("unexpected CulpritCode: %+v", res.CulpritCode)
	}
}

func TestAnalyzePHPDeepCrash_MaxExecutionTime(t *testing.T) {
	logs := `
Fatal error: Maximum execution time of 30 seconds exceeded in /var/www/html/services/sync.php on line 88
`
	res := AnalyzePHPDeepCrash(logs)
	if res == nil {
		t.Fatal("expected non-nil result for PHP max execution time")
	}
	if res.ErrorClass != "PHPMaxExecutionTimeExceeded" {
		t.Fatalf("expected PHPMaxExecutionTimeExceeded, got %s", res.ErrorClass)
	}
	if res.CulpritCode == nil || res.CulpritCode.Line != 88 {
		t.Fatalf("unexpected CulpritCode: %+v", res.CulpritCode)
	}
}

func TestAnalyzePHPDeepCrash_UndefinedFunction(t *testing.T) {
	logs := `
Fatal error: Uncaught Error: Call to undefined function curl_init() in /var/www/html/lib/Http.php on line 25
`
	res := AnalyzePHPDeepCrash(logs)
	if res == nil {
		t.Fatal("expected non-nil result for undefined function")
	}
	if res.ErrorClass != "PHPUndefinedFunction" {
		t.Fatalf("expected PHPUndefinedFunction, got %s", res.ErrorClass)
	}
	if res.CulpritCode.Function != "curl_init" {
		t.Fatalf("expected curl_init, got %s", res.CulpritCode.Function)
	}
}

func TestAnalyzePHPDeepCrash_FPMChildren(t *testing.T) {
	logs := `
[02-Nov-2026 02:40:01] WARNING: [pool www] server reached max_children setting (50), consider raising it
`
	res := AnalyzePHPDeepCrash(logs)
	if res == nil {
		t.Fatal("expected non-nil result for PHP-FPM max children")
	}
	if res.ErrorClass != "PHPFPMChildrenExhausted" {
		t.Fatalf("expected PHPFPMChildrenExhausted, got %s", res.ErrorClass)
	}
	if !res.IsFPM {
		t.Fatal("expected IsFPM to be true")
	}
}

func TestAnalyzePHPDeepCrash_FPMChildSignal(t *testing.T) {
	logs := `
[02-Nov-2026 02:40:02] WARNING: [pool www] child 1045 exited on signal 11 (SIGSEGV) after 30.123456 seconds from start
`
	res := AnalyzePHPDeepCrash(logs)
	if res == nil {
		t.Fatal("expected non-nil result for PHP-FPM child signal")
	}
	if res.ErrorClass != "PHPFPMChildSignalCrash" {
		t.Fatalf("expected PHPFPMChildSignalCrash, got %s", res.ErrorClass)
	}
}

func TestAnalyzePHPDeepCrash_PDO(t *testing.T) {
	logs := `
PDOException: SQLSTATE[HY000] [2002] Connection refused in /var/www/html/config/db.php on line 19
`
	res := AnalyzePHPDeepCrash(logs)
	if res == nil {
		t.Fatal("expected non-nil result for PDO exception")
	}
	if res.ErrorClass != "PHPPDOException" {
		t.Fatalf("expected PHPPDOException, got %s", res.ErrorClass)
	}
	if res.CulpritCode == nil || res.CulpritCode.Line != 19 {
		t.Fatalf("unexpected CulpritCode: %+v", res.CulpritCode)
	}
}
