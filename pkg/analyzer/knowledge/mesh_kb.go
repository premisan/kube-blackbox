package knowledge

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// EnvoyFlagDetail describes the meaning and remediation of an Envoy response flag.
type EnvoyFlagDetail struct {
	Flag        string
	Name        string
	SummaryKo   string
	SummaryEn   string
	ActionKo    string
	ActionEn    string
	RootCause   string
}

// EnvoyResponseFlagsMap catalog of all standard Envoy / Istio response flags.
var EnvoyResponseFlagsMap = map[string]EnvoyFlagDetail{
	"UH": {
		Flag:      "UH",
		Name:      "NoHealthyUpstream",
		RootCause: "EnvoyNoHealthyUpstream",
		SummaryKo: "Envoy/Istio 프록시: 대상 업스트림 엔드포인트(Pod) 중 준비 완료(Ready) 상태인 정상 인스턴스 없음 (UH: No Healthy Upstream)",
		SummaryEn: "Envoy/Istio proxy: no healthy upstream endpoints available in cluster (UH: No Healthy Upstream)",
		ActionKo:  "1) 대상 서비스 파드가 Running 및 Readiness Probe를 통과했는지 확인하세요. 2) Istio DestinationRule 및 ServiceEntry 엔드포인트 설정을 점검하세요.",
		ActionEn:  "1) Verify destination pods are Running and passing readiness probes. 2) Check Istio DestinationRule and ServiceEntry definitions.",
	},
	"UO": {
		Flag:      "UO",
		Name:      "UpstreamOverflow",
		RootCause: "EnvoyCircuitBreakerOverflow",
		SummaryKo: "Envoy/Istio 서킷 브레이커 트립: 업스트림 동시 연결/대기열 한도 초과 (UO: Upstream Overflow)",
		SummaryEn: "Envoy/Istio circuit breaker tripped: upstream connection pool limit exceeded (UO: Upstream Overflow)",
		ActionKo:  "1) Istio DestinationRule의 connectionPool (maxConnections, maxPendingRequests) 한도를 확장하세요. 2) 대상 백엔드 복제본(Replicas)을 스케일 아웃하세요.",
		ActionEn:  "1) Increase connectionPool (maxConnections, maxPendingRequests) in DestinationRule. 2) Scale out backend replicas.",
	},
	"UF": {
		Flag:      "UF",
		Name:      "UpstreamConnectionFailure",
		RootCause: "EnvoyUpstreamConnectionFailure",
		SummaryKo: "Envoy 프록시가 대상 업스트림 서버와의 TCP 연결 생성에 실패함 (UF: Upstream Connection Failure)",
		SummaryEn: "Envoy proxy failed to establish TCP connection to upstream backend (UF: Upstream Connection Failure)",
		ActionKo:  "대상 파드의 수신 포트 번호가 Kubernetes Service의 targetPort와 정확히 일치하는지, 로컬 방화벽이나 NetworkPolicy에 의해 차단되지 않았는지 점검하세요.",
		ActionEn:  "Verify targetPort matches backend container listen port and ensure NetworkPolicy allows ingress traffic.",
	},
	"NR": {
		Flag:      "NR",
		Name:      "NoRouteConfigured",
		RootCause: "EnvoyNoRouteConfigured",
		SummaryKo: "Envoy/Gateway API: 요청 호스트 또는 URL 경로와 일치하는 라우트 규칙이 설정되지 않음 (NR: No Route)",
		SummaryEn: "Envoy/Gateway API: no matching route rule for request host or URL path (NR: No Route)",
		ActionKo:  "1) Istio VirtualService 또는 Gateway API HTTPRoute의 hosts 및 match URI 경로 설정을 확인하세요. 2) 게이트웨이 리스너 바인딩 상태를 점검하세요.",
		ActionEn:  "1) Verify hosts and match URI prefix in VirtualService or HTTPRoute. 2) Inspect Gateway listener attachments.",
	},
	"UC": {
		Flag:      "UC",
		Name:      "UpstreamConnectionTermination",
		RootCause: "EnvoyTLSHandshakeFailed",
		SummaryKo: "Envoy/Istio mTLS 핸드셰이크 실패: 업스트림과의 TLS 연결이 비정상 종료됨 (UC: Upstream Connection Termination)",
		SummaryEn: "Envoy/Istio mTLS handshake failed: upstream TLS connection terminated prematurely (UC)",
		ActionKo:  "1) PeerAuthentication(STRICT vs PERMISSIVE) 모드 불일치를 점검하세요. 2) 사이드카 없는 파드와의 평문 통신 여부 또는 인증서 유효기간을 확인하세요.",
		ActionEn:  "1) Check PeerAuthentication mTLS mode compatibility. 2) Ensure client has sidecar injected or use PERMISSIVE mode.",
	},
	"UT": {
		Flag:      "UT",
		Name:      "UpstreamRequestTimeout",
		RootCause: "EnvoyUpstreamTimeout",
		SummaryKo: "Envoy/Istio: 백엔드 서비스 응답 지연으로 업스트림 요청 타임아웃 발생 (UT: Upstream Timeout, 504)",
		SummaryEn: "Envoy/Istio upstream request timed out awaiting backend response (UT: 504 Gateway Timeout)",
		ActionKo:  "1) VirtualService 또는 HTTPRoute의 timeout 설정(기본 15s)을 늘리세요. 2) 백엔드 애플리케이션의 느린 쿼리나 스레드 정체를 해결하세요.",
		ActionEn:  "1) Increase timeout in VirtualService/HTTPRoute. 2) Profile slow queries or latency spikes in backend application.",
	},
	"URX": {
		Flag:      "URX",
		Name:      "UpstreamRetryLimitExceeded",
		RootCause: "EnvoyRetryLimitExceeded",
		SummaryKo: "Envoy 프록시: 업스트림 재시도 횟수 한도 초과 (URX: Upstream Retry Limit Exceeded)",
		SummaryEn: "Envoy proxy exceeded configured retry attempts to upstream (URX)",
		ActionKo:  "백엔드 서비스의 연속 실패 원인(CrashLoop, 5xx)을 확인하고 VirtualService retry 정책을 점검하세요.",
		ActionEn:  "Inspect upstream backend failure reasons and verify retry budget in VirtualService.",
	},
	"LH": {
		Flag:      "LH",
		Name:      "LocalHealthCheckFailed",
		RootCause: "EnvoyLocalHealthCheckFailed",
		SummaryKo: "Envoy 프록시: 로컬 서비스 헬스체크 실패로 수신 트래픽 차단 (LH: Local Service Failed Health Check)",
		SummaryEn: "Envoy proxy blocked request because local container failed active health check (LH)",
		ActionKo:  "메인 애플리케이션의 헬스체크(/healthz) 응답 상태를 확인하세요.",
		ActionEn:  "Verify local application health check endpoint response.",
	},
}

// MeshAnalysisResult stores detected findings from Envoy, Istio, Nginx, or Gateway logs.
type MeshAnalysisResult struct {
	Component         string // envoy, istio, nginx, ingress-nginx, envoy-gateway
	RootCause         string
	ErrorClass        string
	SummaryKo         string
	SummaryEn         string
	SuggestedFixKo    string
	SuggestedFixEn    string
	MatchedFlag       string
	NginxDirective    string
	NginxLine         int
	NginxConfFile     string
	PayloadSize       int64
	MaxAllowedSize    int64
}

// Regex patterns for Envoy, Nginx, and Istio
var (
	// Envoy access log: matches response flag after HTTP status code, e.g., "HTTP/1.1" 503 UO 
	envoyLogFlagRegex = regexp.MustCompile(`" [1-5]\d{2} ([A-Z]{2,3})(?:,[A-Z]{2,3})* \d+`)
	// Nginx [emerg] configuration errors
	nginxEmergRegex   = regexp.MustCompile(`(?m)(?:nginx:\s*)?\[emerg\]\s*(?:\d+#\d+:\s*)?(.+?)(?:\s+in\s+([^:\s]+):(\d+))?\s*$`)
	// Nginx client intended to send too large body
	nginxBodySizeRegex = regexp.MustCompile(`(?i)client intended to send too large body:\s*(\d+)\s*bytes`)
	// Istio 15021 readiness probe failure
	istio15021Regex   = regexp.MustCompile(`(?i)(?:Envoy proxy is not ready yet|Failed to connect to (?:localhost|127\.0\.0\.1) port 15021)`)
	// Istio mTLS handshake errors
	istioMTLSRegex    = regexp.MustCompile(`(?i)(?:OPENSSL_internal:WRONG_VERSION_NUMBER|tlsv1 alert unknown ca|SSL: error:.*?SSL routines:.*?tlsv1 alert)`)
	// Envoy Gateway / Gateway API xDS NACK & translation errors
	egNackRegex       = regexp.MustCompile(`(?i)(?:NACK received from envoy for type|error initializing configuration|failed to translate HTTPRoute|BackendRef.*?(?:not found|invalid))`)
)

// AnalyzeMeshLogs inspects logs for Envoy flags, Istio sidecar errors, Ingress-Nginx syntax/buffer errors, and Envoy Gateway xDS issues.
func AnalyzeMeshLogs(logs string) *MeshAnalysisResult {
	if strings.TrimSpace(logs) == "" {
		return nil
	}

	// 1. Detect Envoy Access Log Response Flags (UH, UO, UF, NR, UC, UT, etc.)
	if flagMatch := envoyLogFlagRegex.FindStringSubmatch(logs); len(flagMatch) >= 2 {
		flag := flagMatch[1]
		if detail, ok := EnvoyResponseFlagsMap[flag]; ok {
			return &MeshAnalysisResult{
				Component:      "envoy",
				RootCause:      detail.RootCause,
				ErrorClass:     "EnvoyFlag_" + flag,
				MatchedFlag:    flag,
				SummaryKo:      detail.SummaryKo,
				SummaryEn:      detail.SummaryEn,
				SuggestedFixKo: detail.ActionKo,
				SuggestedFixEn: detail.ActionEn,
			}
		}
	}

	// 2. Detect Ingress-Nginx [emerg] Configuration Syntax Failure
	if emergMatch := nginxEmergRegex.FindStringSubmatch(logs); len(emergMatch) >= 2 {
		errMsg := emergMatch[1]
		confFile := ""
		lineNum := 0
		if len(emergMatch) >= 4 {
			confFile = emergMatch[2]
			lineNum, _ = strconv.Atoi(emergMatch[3])
		}
		locStrKo := ""
		locStrEn := ""
		if confFile != "" && lineNum > 0 {
			locStrKo = fmt.Sprintf(" [%s:%d]", confFile, lineNum)
			locStrEn = fmt.Sprintf(" in %s line %d", confFile, lineNum)
		}

		return &MeshAnalysisResult{
			Component:      "ingress-nginx",
			RootCause:      "NginxConfigSyntaxError",
			ErrorClass:     "NginxConfigSyntaxError",
			NginxConfFile:  confFile,
			NginxLine:      lineNum,
			SummaryKo:      fmt.Sprintf("Nginx 설정 문법 오류(nginx: [emerg])로 인해 프로세스 기동/리로드 실패%s: %s", locStrKo, errMsg),
			SummaryEn:      fmt.Sprintf("Nginx configuration syntax error (nginx: [emerg]) halted reload%s: %s", locStrEn, errMsg),
			SuggestedFixKo: "1) Ingress 리소스의 'configuration-snippet' 또는 'server-snippet' 어노테이션 문법을 점검하세요. 2) 'nginx -t' 명령어로 유효성을 사전 검증하세요.",
			SuggestedFixEn: "1) Inspect 'configuration-snippet' or 'server-snippet' annotations on Ingress resources. 2) Test syntax with 'nginx -t'.",
		}
	}

	// 3. Detect Nginx 413 Payload Body Size Exceeded
	if bodyMatch := nginxBodySizeRegex.FindStringSubmatch(logs); len(bodyMatch) >= 2 {
		size, _ := strconv.ParseInt(bodyMatch[1], 10, 64)
		mbSize := float64(size) / (1024 * 1024)
		return &MeshAnalysisResult{
			Component:      "nginx",
			RootCause:      "NginxClientBodySizeExceeded",
			ErrorClass:     "ClientBodyTooLarge_413",
			PayloadSize:    size,
			SummaryKo:      fmt.Sprintf("Nginx 클라이언트 요청 본문(Payload) 크기 한도 초과: 요청 크기 %.2fMB (client intended to send too large body)", mbSize),
			SummaryEn:      fmt.Sprintf("Nginx client request body size exceeded: %.2fMB payload (413 Request Entity Too Large)", mbSize),
			SuggestedFixKo: "1) Ingress 리소스에 'nginx.ingress.kubernetes.io/proxy-body-size: \"50m\"' 어노테이션을 추가하세요. 2) nginx.conf의 'client_max_body_size' 설정을 늘리세요.",
			SuggestedFixEn: "1) Add 'nginx.ingress.kubernetes.io/proxy-body-size: \"50m\"' annotation to Ingress. 2) Increase 'client_max_body_size' in nginx.conf.",
		}
	}

	// 4. Detect Istio 15021 Readiness Probe Failure / Startup Race
	if istio15021Regex.MatchString(logs) {
		return &MeshAnalysisResult{
			Component:      "istio",
			RootCause:      "IstioProxyNotReady",
			ErrorClass:     "IstioProxyNotReady",
			SummaryKo:      "Istio 사이드카 프록시(istio-proxy) 헬스체크 포트(15021) 준비 전 연결 시도로 인한 기동 실패",
			SummaryEn:      "Istio sidecar proxy (istio-proxy) not ready on port 15021 during startup connection attempt",
			SuggestedFixKo: "1) 파드 어노테이션에 'proxy.istio.io/config: \"{ holdApplicationUntilProxyStarts: true }\"'를 추가하세요. 2) 쿠버네티스 1.28+ 네이티브 사이드카(initContainers에 restartPolicy: Always)를 적용하세요.",
			SuggestedFixEn: "1) Add 'proxy.istio.io/config: \"{ holdApplicationUntilProxyStarts: true }\"' annotation to Pod. 2) Use K8s 1.28+ native sidecar containers.",
		}
	}

	// 5. Detect Istio STRICT mTLS Handshake Mismatch
	if istioMTLSRegex.MatchString(logs) {
		return &MeshAnalysisResult{
			Component:      "istio",
			RootCause:      "IstioStrictMTLSMismatch",
			ErrorClass:     "Istio_mTLS_Failed",
			SummaryKo:      "Istio mTLS 핸드셰이크 실패: STRICT 상호 TLS 모드와 클라이언트 평문(Plaintext) 통신 불일치",
			SummaryEn:      "Istio mTLS handshake failed: STRICT mutual TLS mode rejected plaintext request",
			SuggestedFixKo: "1) 호출 클라이언트 파드에 Istio 사이드카가 주입(sidecar.istio.io/inject: \"true\")되었는지 확인하세요. 2) PeerAuthentication 모드를 임시로 'PERMISSIVE'로 변경하여 트래픽을 복구하세요.",
			SuggestedFixEn: "1) Ensure client pod has Istio sidecar injected. 2) Temporarily switch PeerAuthentication mode to 'PERMISSIVE' to restore connectivity.",
		}
	}

	// 6. Detect Envoy Gateway / Gateway API xDS Translation Failure
	if egNackRegex.MatchString(logs) {
		return &MeshAnalysisResult{
			Component:      "envoy-gateway",
			RootCause:      "EnvoyGatewayTranslationFailed",
			ErrorClass:     "GatewayAPI_NACK",
			SummaryKo:      "Envoy Gateway / Gateway API 설정 변환(Translation) 실패 또는 xDS NACK 수신",
			SummaryEn:      "Envoy Gateway / Gateway API route translation failed or xDS NACK received",
			SuggestedFixKo: "1) 'kubectl get httproute <name> -o yaml'에서 status.parents의 'ResolvedRefs: True' 여부를 확인하세요. 2) BackendRef에 지정된 Service 이름과 포트가 올바른지 점검하세요.",
			SuggestedFixEn: "1) Check 'kubectl get httproute <name> -o yaml' for status 'ResolvedRefs: True'. 2) Verify BackendRef Service name and port exist.",
		}
	}

	return nil
}
