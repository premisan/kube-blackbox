package knowledge

import (
	"testing"
)

func TestAnalyzeDataInfraLogs_ClickHouseParts(t *testing.T) {
	logs := `2026.11.02 02:00:00.123456 [ 123 ] {} <Error> default.events (01234567-89ab-cdef-0123-456789abcdef): DB::Exception: Too many parts (302) in all data parts in table. Merges are processing significantly slower than inserts.`

	res := AnalyzeDataInfraLogs(logs)
	if res == nil {
		t.Fatalf("expected DataInfraAnalysis, got nil")
	}
	if res.RootCause != "ClickHouseTooManyParts" {
		t.Fatalf("expected ClickHouseTooManyParts, got %s", res.RootCause)
	}
}

func TestAnalyzeDataInfraLogs_ZooKeeperDiskFull(t *testing.T) {
	logs := `2026-11-02 02:00:00,123 [myid:1] - ERROR [SyncThread:1:FileTxnLog@214] - Failed to write snap: java.io.IOException: No space left on device`

	res := AnalyzeDataInfraLogs(logs)
	if res == nil {
		t.Fatalf("expected DataInfraAnalysis, got nil")
	}
	if res.RootCause != "ZooKeeperDiskFull" {
		t.Fatalf("expected ZooKeeperDiskFull, got %s", res.RootCause)
	}
}

func TestAnalyzeDataInfraLogs_PostgresTxid(t *testing.T) {
	logs := `2026-11-02 02:00:00.000 UTC [1234] FATAL:  database is not accepting commands to avoid wraparound data loss in database "production"
HINT:  Stop the postmaster and vacuum that database in single-user mode.`

	res := AnalyzeDataInfraLogs(logs)
	if res == nil {
		t.Fatalf("expected DataInfraAnalysis, got nil")
	}
	if res.RootCause != "PostgresTxidExhaustion" {
		t.Fatalf("expected PostgresTxidExhaustion, got %s", res.RootCause)
	}
}
