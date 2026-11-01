package synthesizer

import (
	"context"
	"strings"
	"testing"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
)

func TestSynthesizer_Korean(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(137)

	incident := IncidentContext{
		Namespace:     "default",
		PodName:       "payment-service-1234",
		ContainerName: "payment-worker",
		ExitCode:      &exitCode,
		RootCause:     "OOMKilled",
		Category:      "Infrastructure",
		Confidence:    "High",
		Language:      "ko",
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Analyzed {
		t.Fatalf("expected Analyzed=true")
	}
	if result.Engine != EngineIdentifier {
		t.Fatalf("expected Engine=%s, got %s", EngineIdentifier, result.Engine)
	}
	if result.Language != "ko" {
		t.Fatalf("expected Language=ko, got %s", result.Language)
	}
	if len(result.RootCauseChain) == 0 {
		t.Fatalf("expected non-empty RootCauseChain")
	}
	if result.InferredContext == "" || result.SuggestedFix == "" {
		t.Fatalf("expected InferredContext and SuggestedFix, got empty")
	}
}

func TestSynthesizer_UnsupportedLanguageFallback(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(137)

	incident := IncidentContext{
		Namespace:     "default",
		PodName:       "app",
		ContainerName: "app",
		ExitCode:      &exitCode,
		RootCause:     "OOMKilled",
		Language:      "cn", // Unsupported language
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Language, "fallback from cn") {
		t.Fatalf("expected fallback record in language, got: %s", result.Language)
	}
}

func TestSynthesizer_CulpritCode(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(2)

	incident := IncidentContext{
		Namespace:     "default",
		PodName:       "go-worker",
		ContainerName: "worker",
		ExitCode:      &exitCode,
		RootCause:     "GoPanic",
		Category:      "Application",
		Confidence:    "High",
		Language:      "en",
		CulpritCode: &observerv1alpha1.CulpritCode{
			Language: "Go",
			File:     "process.go",
			Line:     77,
		},
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	foundCulprit := false
	for _, step := range result.RootCauseChain {
		if strings.Contains(step.Description, "process.go:77") {
			foundCulprit = true
			break
		}
	}
	if !foundCulprit {
		t.Fatalf("expected culprit code mentioned in RootCauseChain, got: %v", result.RootCauseChain)
	}
}

func TestSynthesizer_SidecarCascade(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(1)

	incident := IncidentContext{
		Namespace:     "production",
		PodName:       "payment-api",
		ContainerName: "payment-api",
		ExitCode:      &exitCode,
		RootCause:     "SidecarCascadeFailure",
		Category:      "Dependency",
		Confidence:    "High",
		Language:      "ko",
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RootCauseChain) == 0 {
		t.Fatalf("expected RootCauseChain for SidecarCascadeFailure")
	}
	if !strings.Contains(result.InferredContext, "사이드카") {
		t.Fatalf("expected InferredContext to mention sidecar, got: %s", result.InferredContext)
	}
}

func TestSynthesizer_GracefulShutdownTimeout(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(137)
	grace := true

	incident := IncidentContext{
		Namespace:           "production",
		PodName:             "web-server",
		ContainerName:       "web-server",
		ExitCode:            &exitCode,
		RootCause:           "GracefulShutdownTimeout",
		Category:            "Infrastructure",
		Confidence:          "High",
		Language:            "ko",
		GracePeriodExceeded: grace,
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RootCauseChain) == 0 {
		t.Fatalf("expected RootCauseChain for GracefulShutdownTimeout")
	}
	if !strings.Contains(result.InferredContext, "terminationGracePeriodSeconds") {
		t.Fatalf("expected InferredContext to mention terminationGracePeriodSeconds, got: %s", result.InferredContext)
	}
}

func TestSynthesizer_PythonUnhandledException(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(1)

	incident := IncidentContext{
		Namespace:     "default",
		PodName:       "sample-python-crash",
		ContainerName: "python-worker",
		ExitCode:      &exitCode,
		RootCause:     "PythonUnhandledException",
		Category:      "Application",
		Confidence:    "High",
		ErrorClass:    "ValueError",
		Language:      "ko",
		CulpritCode: &observerv1alpha1.CulpritCode{
			Language: "Python",
			File:     "<string>",
			Line:     11,
			Function: "process_record",
		},
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RootCauseChain) < 3 {
		t.Fatalf("expected at least 3 detailed steps in RootCauseChain, got %d", len(result.RootCauseChain))
	}

	step1 := result.RootCauseChain[0].Description
	if !strings.Contains(step1, "process_record") || !strings.Contains(step1, "ValueError") {
		t.Fatalf("expected Step 1 to describe function and ValueError, got: %s", step1)
	}

	if !strings.Contains(result.SuggestedFix, "ValueError") || !strings.Contains(result.SuggestedFix, "try-except") {
		t.Fatalf("expected SuggestedFix to mention ValueError and try-except, got: %s", result.SuggestedFix)
	}
}

func TestSynthesizer_NodeTypeError(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(1)

	incident := IncidentContext{
		Namespace:     "default",
		PodName:       "sample-nodejs-crash",
		ContainerName: "nodejs-api",
		ExitCode:      &exitCode,
		RootCause:     "NodeTypeError",
		Category:      "Application",
		Confidence:    "High",
		ErrorClass:    "TypeError",
		Language:      "ko",
		CulpritCode: &observerv1alpha1.CulpritCode{
			Language: "JavaScript/TypeScript",
			File:     "order_service.js",
			Line:     84,
			Function: "processOrder",
		},
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RootCauseChain) < 3 {
		t.Fatalf("expected at least 3 detailed steps in RootCauseChain, got %d", len(result.RootCauseChain))
	}

	step1 := result.RootCauseChain[0].Description
	if !strings.Contains(step1, "order_service.js:84") || !strings.Contains(step1, "undefined") {
		t.Fatalf("expected Step 1 to describe order_service.js:84 and undefined, got: %s", step1)
	}

	if !strings.Contains(result.SuggestedFix, "옵셔널 체이닝") {
		t.Fatalf("expected SuggestedFix to recommend optional chaining, got: %s", result.SuggestedFix)
	}
}

func TestSynthesizer_LazyInitializationException(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(1)

	incident := IncidentContext{
		Namespace:     "default",
		PodName:       "sample-java-crash",
		ContainerName: "java-backend",
		ExitCode:      &exitCode,
		RootCause:     "LazyInitializationException",
		Category:      "Application",
		Confidence:    "High",
		ErrorClass:    "org.hibernate.LazyInitializationException",
		Language:      "ko",
		CulpritCode: &observerv1alpha1.CulpritCode{
			Language:  "Java",
			Framework: "Spring",
			File:      "OrderService.java",
			Line:      52,
			Function:  "com.app.service.OrderService.getOrderDetails",
		},
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RootCauseChain) < 3 {
		t.Fatalf("expected at least 3 detailed steps in RootCauseChain, got %d", len(result.RootCauseChain))
	}

	step1 := result.RootCauseChain[0].Description
	if !strings.Contains(step1, "OrderService.java:52") || !strings.Contains(step1, "지연 로딩") {
		t.Fatalf("expected Step 1 to describe OrderService.java:52 and lazy loading, got: %s", step1)
	}

	if !strings.Contains(result.SuggestedFix, "JOIN FETCH") {
		t.Fatalf("expected SuggestedFix to recommend JOIN FETCH, got: %s", result.SuggestedFix)
	}
}

func TestSynthesizer_MeshCircuitBreaker(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(0)

	incident := IncidentContext{
		Namespace:     "production",
		PodName:       "checkout-service-789",
		ContainerName: "istio-proxy",
		ExitCode:      &exitCode,
		RootCause:     "EnvoyCircuitBreakerOverflow",
		Category:      "Dependency",
		Confidence:    "High",
		ErrorClass:    "Envoy_UO_Flag",
		Language:      "ko",
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RootCauseChain) < 3 {
		t.Fatalf("expected at least 3 steps, got %d", len(result.RootCauseChain))
	}
	if !strings.Contains(result.SuggestedFix, "maxConnections") {
		t.Fatalf("expected fix to recommend maxConnections, got: %s", result.SuggestedFix)
	}
	if !strings.Contains(result.InferredContext, "서킷 브레이커") {
		t.Fatalf("expected context to mention 서킷 브레이커, got: %s", result.InferredContext)
	}
}

func TestSynthesizer_EnterpriseCoreDNSLoop(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(2)

	incident := IncidentContext{
		Namespace:     "kube-system",
		PodName:       "coredns-5dd5756b68-xyz",
		ContainerName: "coredns",
		ExitCode:      &exitCode,
		RootCause:     "CoreDNSLoopDetected",
		Category:      "Infrastructure",
		Confidence:    "High",
		ErrorClass:    "CoreDNSLoop",
		Language:      "ko",
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RootCauseChain) < 3 {
		t.Fatalf("expected at least 3 steps, got %d", len(result.RootCauseChain))
	}
	if !strings.Contains(result.SuggestedFix, "127.0.0.53") {
		t.Fatalf("expected fix to recommend removing 127.0.0.53, got: %s", result.SuggestedFix)
	}
}

func TestSynthesizer_GCPGeminiQuota(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(1)

	incident := IncidentContext{
		Namespace:     "default",
		PodName:       "ai-chatbot-123",
		ContainerName: "chatbot",
		ExitCode:      &exitCode,
		RootCause:     "GCPGeminiQuotaExceeded",
		Category:      "Dependency",
		Confidence:    "High",
		ErrorClass:    "Gemini_ResourceExhausted_429",
		Language:      "ko",
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RootCauseChain) < 3 {
		t.Fatalf("expected at least 3 steps, got %d", len(result.RootCauseChain))
	}
	if !strings.Contains(result.SuggestedFix, "할당량") {
		t.Fatalf("expected fix to mention 할당량, got: %s", result.SuggestedFix)
	}
	if !strings.Contains(result.InferredContext, "속도 제한") {
		t.Fatalf("expected context to mention 속도 제한, got: %s", result.InferredContext)
	}
}

func TestSynthesizer_ClickHouseParts(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(1)

	incident := IncidentContext{
		Namespace:     "analytics",
		PodName:       "clickhouse-0",
		ContainerName: "clickhouse",
		ExitCode:      &exitCode,
		RootCause:     "ClickHouseTooManyParts",
		Category:      "Application",
		Confidence:    "High",
		ErrorClass:    "ClickHouse_TooManyParts",
		Language:      "ko",
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RootCauseChain) < 3 {
		t.Fatalf("expected at least 3 steps, got %d", len(result.RootCauseChain))
	}
	if !strings.Contains(result.SuggestedFix, "parts_to_delay_insert") {
		t.Fatalf("expected fix to mention parts_to_delay_insert, got: %s", result.SuggestedFix)
	}
}

func TestSynthesizer_SquidAuthRequired(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(1)

	incident := IncidentContext{
		Namespace:     "default",
		PodName:       "web-scraper-12",
		ContainerName: "scraper",
		ExitCode:      &exitCode,
		RootCause:     "ProxyAuthenticationRequired",
		Category:      "Dependency",
		Confidence:    "High",
		ErrorClass:    "Squid_407_AuthRequired",
		Language:      "ko",
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RootCauseChain) < 3 {
		t.Fatalf("expected at least 3 steps, got %d", len(result.RootCauseChain))
	}
	if !strings.Contains(result.SuggestedFix, "HTTP_PROXY") {
		t.Fatalf("expected fix to mention HTTP_PROXY, got: %s", result.SuggestedFix)
	}
}

func TestSynthesizer_TLSUntrustedCA(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(1)

	incident := IncidentContext{
		Namespace:     "default",
		PodName:       "payment-gateway",
		ContainerName: "gateway",
		ExitCode:      &exitCode,
		RootCause:     "TLSUntrustedCA",
		Category:      "Configuration",
		Confidence:    "High",
		ErrorClass:    "TLS_Certificate_UnknownCA",
		Language:      "ko",
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RootCauseChain) < 3 {
		t.Fatalf("expected at least 3 steps, got %d", len(result.RootCauseChain))
	}
	if !strings.Contains(result.SuggestedFix, "update-ca-certificates") {
		t.Fatalf("expected fix to mention update-ca-certificates, got: %s", result.SuggestedFix)
	}
}




func TestSynthesizer_MySQLDeadlock(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(1)

	incident := IncidentContext{
		Namespace:     "default",
		PodName:       "sample-mysql-deadlock",
		ContainerName: "order-service",
		ExitCode:      &exitCode,
		RootCause:     "MySQLDeadlock",
		Category:      "Dependency",
		Confidence:    "High",
		ErrorClass:    "MySQL_1213_Deadlock",
		Language:      "ko",
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RootCauseChain) < 3 {
		t.Fatalf("expected at least 3 steps, got %d", len(result.RootCauseChain))
	}
	if !strings.Contains(result.SuggestedFix, "@Retryable") {
		t.Fatalf("expected fix to mention @Retryable, got: %s", result.SuggestedFix)
	}
}

func TestSynthesizer_PostgresInFailedSQLTransaction(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(1)

	incident := IncidentContext{
		Namespace:     "default",
		PodName:       "sample-postgres-failed-tx",
		ContainerName: "backend",
		ExitCode:      &exitCode,
		RootCause:     "PostgresInFailedSQLTransaction",
		Category:      "Dependency",
		Confidence:    "High",
		ErrorClass:    "PostgreSQL_25P02_InFailedTx",
		Language:      "ko",
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RootCauseChain) < 3 {
		t.Fatalf("expected at least 3 steps, got %d", len(result.RootCauseChain))
	}
	if !strings.Contains(result.SuggestedFix, "ROLLBACK") {
		t.Fatalf("expected fix to mention ROLLBACK, got: %s", result.SuggestedFix)
	}
}
