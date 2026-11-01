package knowledge

import (
	"testing"
)

func TestAnalyzeGCPSDKLogs_DefaultCreds(t *testing.T) {
	logs := `Traceback (most recent call last):
  File "app.py", line 12, in <module>
    client = storage.Client()
google.auth.exceptions.DefaultCredentialsError: Could not automatically determine credentials. Please set GOOGLE_APPLICATION_CREDENTIALS or heading to gcloud auth application-default login`

	res := AnalyzeGCPSDKLogs(logs)
	if res == nil {
		t.Fatalf("expected GCPSDKAnalysis, got nil")
	}
	if res.RootCause != "GCPAuthDefaultCredentialsMissing" {
		t.Fatalf("expected GCPAuthDefaultCredentialsMissing, got %s", res.RootCause)
	}
}

func TestAnalyzeGCPSDKLogs_GeminiQuota(t *testing.T) {
	logs := `google.genai.errors.APIError: 429 RESOURCE_EXHAUSTED. Quota exceeded for quota metric 'Generate Content API requests' and limit 'Generate Content API requests per minute' of service 'generativelanguage.googleapis.com'`

	res := AnalyzeGCPSDKLogs(logs)
	if res == nil {
		t.Fatalf("expected GCPSDKAnalysis, got nil")
	}
	if res.RootCause != "GCPGeminiQuotaExceeded" {
		t.Fatalf("expected GCPGeminiQuotaExceeded, got %s", res.RootCause)
	}
}

func TestAnalyzeGCPSDKLogs_BigQueryQuota(t *testing.T) {
	logs := `google.cloud.exceptions.GoogleCloudError: 400 Query exceeded limit for bytes billed: 10737418240. 21474836480 bytes required.`

	res := AnalyzeGCPSDKLogs(logs)
	if res == nil {
		t.Fatalf("expected GCPSDKAnalysis, got nil")
	}
	if res.RootCause != "GCPBigQueryQuotaExceeded" {
		t.Fatalf("expected GCPBigQueryQuotaExceeded, got %s", res.RootCause)
	}
}
