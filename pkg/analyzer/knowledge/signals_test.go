package knowledge

import (
	"testing"
)

func TestLookupSignalByExitCode(t *testing.T) {
	tests := []struct {
		exitCode    int
		expectedSig string
		expectFound bool
	}{
		{exitCode: 137, expectedSig: "SIGKILL", expectFound: true},
		{exitCode: 143, expectedSig: "SIGTERM", expectFound: true},
		{exitCode: 139, expectedSig: "SIGSEGV", expectFound: true},
		{exitCode: 134, expectedSig: "SIGABRT", expectFound: true},
		{exitCode: 135, expectedSig: "SIGBUS", expectFound: true},
		{exitCode: 132, expectedSig: "SIGILL", expectFound: true},
		{exitCode: 136, expectedSig: "SIGFPE", expectFound: true},
		{exitCode: 141, expectedSig: "SIGPIPE", expectFound: true},
		{exitCode: 1, expectedSig: "", expectFound: false},
		{exitCode: 0, expectedSig: "", expectFound: false},
	}

	for _, tt := range tests {
		info, found := LookupSignalByExitCode(tt.exitCode)
		if found != tt.expectFound {
			t.Errorf("LookupSignalByExitCode(%d) found = %v, expected %v", tt.exitCode, found, tt.expectFound)
		}
		if found && info.SignalName != tt.expectedSig {
			t.Errorf("LookupSignalByExitCode(%d) signalName = %s, expected %s", tt.exitCode, info.SignalName, tt.expectedSig)
		}
	}
}

func TestLookupExitCode(t *testing.T) {
	info, found := LookupExitCode(126)
	if !found || info.Category != "Configuration" {
		t.Errorf("expected exitCode 126 to be Configuration, got %v (%s)", found, info.Category)
	}

	info137, found137 := LookupExitCode(137)
	if !found137 || info137.Name != "SIGKILL" {
		t.Errorf("expected exitCode 137 to map to SIGKILL, got %v (%s)", found137, info137.Name)
	}
}

func TestEmbeddedSignatures(t *testing.T) {
	if len(EmbeddedSignatures) == 0 {
		t.Fatalf("expected embedded signatures to be populated")
	}

	for _, sig := range EmbeddedSignatures {
		if sig.Pattern == nil {
			t.Errorf("signature %s has nil pattern", sig.ID)
		}
		if sig.SummaryKo == "" || sig.SummaryEn == "" {
			t.Errorf("signature %s missing localization", sig.ID)
		}
	}
}
