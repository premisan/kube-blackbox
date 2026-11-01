package knowledge

import (
	"regexp"
	"strings"
)

// ClusterInfraAnalysis stores findings from NFS provisioner, Kube-DNS, Metrics-Server, and LiteLLM crashes.
type ClusterInfraAnalysis struct {
	Component      string // nfs, kube-dns, metrics-server, litellm
	RootCause      string
	ErrorClass     string
	SummaryKo      string
	SummaryEn      string
	SuggestedFixKo string
	SuggestedFixEn string
}

var (
	// NFS
	nfsAccessDeniedRegex = regexp.MustCompile(`(?i)(?:mount\.nfs:\s*access denied by server while mounting|mount\.nfs4:\s*access denied by server|Permission denied.*?: mount\.nfs)`)
	nfsConnTimeoutRegex  = regexp.MustCompile(`(?i)(?:mount\.nfs:\s*Connection timed out|mount\.nfs:\s*Connection refused|mount\.nfs:\s*server .*? not responding)`)
	nfsStaleHandleRegex  = regexp.MustCompile(`(?i)(?:mount\.nfs:\s*Stale file handle|Stale file handle.*?: nfs|ESTALE)`)

	// Kube-DNS
	kubeDNSNXDomainRegex = regexp.MustCompile(`(?i)(?:skydns:\s*Server failure: NXDOMAIN storm|query\[\w+\]\s*failed:\s*upstream server error.*?: dnsmasq|kube-dns.*?: failed to reach upstream DNS)`)
	kubeDNSHealthRegex   = regexp.MustCompile(`(?i)(?:kube-dns healthcheck failed on 10054|sidecar health check failed.*?: kube-dns)`)

	// Metrics-Server
	metricsScrapeRegex = regexp.MustCompile(`(?i)(?:unable to fully scrape metrics from node.*?: dial tcp .*?:10250:\s*(?:i/o timeout|connect: connection refused)|x509:\s*cannot validate certificate for .*? because it doesn't contain any IP SANs.*?: metrics-server|no metrics returned from Kubelet)`)

	// LiteLLM
	litellmRateLimitRegex = regexp.MustCompile(`(?i)(?:litellm\.exceptions\.RateLimitError|RateLimitError:\s*LLM Provider returned rate limit error|litellm.*?: 429 Too Many Requests|litellm.*?: TPM/RPM limit exceeded)`)
	litellmBudgetRegex    = regexp.MustCompile(`(?i)(?:litellm\.exceptions\.BudgetExceededError|BudgetExceededError:\s*User / Team / Key has exceeded their budget|Max budget reached.*?: litellm)`)
	litellmContextRegex   = regexp.MustCompile(`(?i)(?:litellm\.exceptions\.ContextWindowExceededError|ContextWindowExceededError:\s*This model's maximum context length is|maximum context length exceeded)`)
	litellmAuthRegex      = regexp.MustCompile(`(?i)(?:litellm\.exceptions\.AuthenticationError|AuthenticationError:\s*LLM Provider Authentication Error|APIKeyError.*?: litellm)`)
)

// AnalyzeClusterInfraLogs inspects logs for NFS, Kube-DNS, Metrics-Server, and LiteLLM failures.
func AnalyzeClusterInfraLogs(logs string) *ClusterInfraAnalysis {
	if strings.TrimSpace(logs) == "" {
		return nil
	}

	// 1. NFS Subdirectory External Provisioner
	if nfsAccessDeniedRegex.MatchString(logs) {
		return &ClusterInfraAnalysis{
			Component:      "nfs",
			RootCause:      "NFSMountAccessDenied",
			ErrorClass:     "NFS_Mount_AccessDenied",
			SummaryKo:      "NFS 서버의 익스포트(Export) 디렉토리 마운트 권한 거절 (접근 제어 또는 no_root_squash 누락)",
			SummaryEn:      "NFS server denied mount access (export IP restriction or missing no_root_squash)",
			SuggestedFixKo: "1) NFS 서버의 '/etc/exports' 설정에서 클러스터 워커 노드 CIDR 대역 허용 및 'no_root_squash' 옵션을 확인하세요. 2) 'exportfs -rav'로 설정을 갱신하세요.",
			SuggestedFixEn: "1) Check '/etc/exports' on NFS server for worker node CIDR and 'no_root_squash'. 2) Reload exports with 'exportfs -rav'.",
		}
	}
	if nfsConnTimeoutRegex.MatchString(logs) {
		return &ClusterInfraAnalysis{
			Component:      "nfs",
			RootCause:      "NFSConnectionTimeout",
			ErrorClass:     "NFS_Mount_ConnectionTimeout",
			SummaryKo:      "NFS 스토리지 서버 연결 타임아웃 또는 포트(2049/RPC 111) 연결 거부",
			SummaryEn:      "NFS storage server connection timed out or port 2049/111 unreachable",
			SuggestedFixKo: "1) NFS 서버 호스트의 가동 상태를 확인하세요. 2) 워커 노드와 NFS 서버 간 방화벽에서 TCP/UDP 2049(NFS) 및 111(rpcbind) 포트가 허용되었는지 점검하세요.",
			SuggestedFixEn: "1) Verify NFS server host is running. 2) Ensure firewall permits TCP/UDP ports 2049 (NFS) and 111 (rpcbind).",
		}
	}
	if nfsStaleHandleRegex.MatchString(logs) {
		return &ClusterInfraAnalysis{
			Component:      "nfs",
			RootCause:      "NFSStaleFileHandle",
			ErrorClass:     "NFS_StaleFileHandle_ESTALE",
			SummaryKo:      "NFS 서버에서 마운트된 디렉토리/파일이 재배치 또는 삭제되어 파일 핸들이 무효화됨 (ESTALE)",
			SummaryEn:      "NFS stale file handle (ESTALE): mounted directory was removed or relocated on the server",
			SuggestedFixKo: "1) 노드에서 해당 NFS 마운트를 언마운트('umount -l /var/lib/kubelet/pods/...') 후 파드를 재배치하세요. 2) NFS 서버 디렉토리 무결성을 확인하세요.",
			SuggestedFixEn: "1) Lazy unmount the stale mount ('umount -l') on the host node and recreate the pod. 2) Verify NFS server directory integrity.",
		}
	}

	// 2. Kube-DNS
	if kubeDNSNXDomainRegex.MatchString(logs) {
		return &ClusterInfraAnalysis{
			Component:      "kube-dns",
			RootCause:      "KubeDNSNXDomainStorm",
			ErrorClass:     "KubeDNS_NXDomainStorm",
			SummaryKo:      "kube-dns 업스트림 네임서버 장애 또는 과도한 NXDOMAIN 쿼리 폭주로 도메인 해석 실패",
			SummaryEn:      "kube-dns upstream nameserver failure or excessive NXDOMAIN query storm",
			SuggestedFixKo: "1) kube-dns의 upstreamNameservers ConfigMap 설정을 점검하세요. 2) 파드의 ndots:5 설정으로 인한 검색 도메인 반복 질의 과부하를 최적화하세요.",
			SuggestedFixEn: "1) Verify kube-dns upstreamNameservers in ConfigMap. 2) Optimize pod dnsConfig ndots setting to reduce redundant domain searches.",
		}
	}
	if kubeDNSHealthRegex.MatchString(logs) {
		return &ClusterInfraAnalysis{
			Component:      "kube-dns",
			RootCause:      "KubeDNSHealthCheckFailed",
			ErrorClass:     "KubeDNS_SidecarHealthFailed",
			SummaryKo:      "kube-dns 사이드카 헬스체크(10054) 실패로 인한 파드 비정상 재시작",
			SummaryEn:      "kube-dns sidecar container health check on port 10054 failed",
			SuggestedFixKo: "1) kube-dns 파드의 CPU/메모리 스펙을 증설하세요. 2) dnsmasq 및 skydns 컨테이너의 가동 상태를 점검하세요.",
			SuggestedFixEn: "1) Increase CPU and memory limits for kube-dns pods. 2) Check dnsmasq and skydns container status.",
		}
	}

	// 3. Metrics-Server
	if metricsScrapeRegex.MatchString(logs) {
		return &ClusterInfraAnalysis{
			Component:      "metrics-server",
			RootCause:      "MetricsServerKubeletScrapeFailed",
			ErrorClass:     "MetricsServer_KubeletScrapeFailed",
			SummaryKo:      "metrics-server가 노드 Kubelet(10250) 메트릭 스크랩 실패 (방화벽 차단 또는 Kubelet 인증서 검증 실패)",
			SummaryEn:      "metrics-server failed to scrape Kubelet metrics on port 10250 (firewall or TLS SAN mismatch)",
			SuggestedFixKo: "1) Kubelet 자체 서명 인증서 사용 환경인 경우 metrics-server 디플로이먼트 인수에 '--kubelet-insecure-tls'를 추가하세요. 2) 제어 평면과 워커 노드 간 10250 포트 방화벽을 허용하세요.",
			SuggestedFixEn: "1) Add '--kubelet-insecure-tls' to metrics-server container args for self-signed Kubelet certificates. 2) Open port 10250 between control plane and worker nodes.",
		}
	}

	// 4. LiteLLM (Open-source LLM Proxy)
	if litellmRateLimitRegex.MatchString(logs) {
		return &ClusterInfraAnalysis{
			Component:      "litellm",
			RootCause:      "LiteLLMRateLimitExceeded",
			ErrorClass:     "LiteLLM_Upstream_RateLimit",
			SummaryKo:      "LiteLLM 프록시 연결 업스트림 LLM 프로바이더(OpenAI/Anthropic/Gemini)의 TPM/RPM 한도 초과",
			SummaryEn:      "LiteLLM upstream LLM provider rate limit (TPM/RPM) exceeded (HTTP 429)",
			SuggestedFixKo: "1) LiteLLM 설정에 모델 폴백(fallback) 라우팅을 구성하세요. 2) 클라이언트 요청에 지수 백오프(Exponential Backoff) 재시도를 적용하거나 캐싱(Redis/Valkey)을 활성화하세요.",
			SuggestedFixEn: "1) Configure model fallbacks in LiteLLM config.yaml. 2) Enable Redis/Valkey response caching in LiteLLM to reduce upstream load.",
		}
	}
	if litellmBudgetRegex.MatchString(logs) {
		return &ClusterInfraAnalysis{
			Component:      "litellm",
			RootCause:      "LiteLLMBudgetExceeded",
			ErrorClass:     "LiteLLM_BudgetExceeded",
			SummaryKo:      "LiteLLM 사용자/팀/가상 키에 할당된 비용 예산(Budget) 한도 도달",
			SummaryEn:      "LiteLLM user/team/key budget limit exceeded; further requests rejected",
			SuggestedFixKo: "1) LiteLLM 관리자 UI 또는 API에서 해당 사용자/키의 'max_budget' 한도를 증설하거나 리셋하세요. 2) 월간 예산 리셋 주기를 확인하세요.",
			SuggestedFixEn: "1) Increase or reset 'max_budget' for the user/key via LiteLLM Admin API or UI. 2) Verify budget reset duration settings.",
		}
	}
	if litellmContextRegex.MatchString(logs) {
		return &ClusterInfraAnalysis{
			Component:      "litellm",
			RootCause:      "LiteLLMContextWindowExceeded",
			ErrorClass:     "LiteLLM_ContextLengthExceeded",
			SummaryKo:      "요청된 프롬프트와 생성 토큰의 합계가 선택된 LLM 모델의 최대 컨텍스트 윈도우 길이를 초과함",
			SummaryEn:      "Prompt and generation tokens exceeded LLM model maximum context window length",
			SuggestedFixKo: "1) 대화 히스토리 슬라이딩 윈도우 또는 텍스트 요약(Summarization)을 적용하여 프롬프트를 압축하세요. 2) 더 큰 컨텍스트 윈도우를 지원하는 모델(Gemini 1.5, Claude 3.5 등)로 전환하세요.",
			SuggestedFixEn: "1) Truncate or summarize prompt history to fit within the context window. 2) Switch to a larger context window model.",
		}
	}
	if litellmAuthRegex.MatchString(logs) {
		return &ClusterInfraAnalysis{
			Component:      "litellm",
			RootCause:      "LiteLLMAuthenticationError",
			ErrorClass:     "LiteLLM_AuthenticationFailed",
			SummaryKo:      "LiteLLM 프록시 가상 키 인증 실패 또는 업스트림 LLM 프로바이더 API 키 무효",
			SummaryEn:      "LiteLLM virtual key authentication failed or upstream LLM provider API key invalid",
			SuggestedFixKo: "1) 클라이언트의 Authorization Bearer 토큰이 LiteLLM 마스터/가상 키와 일치하는지 확인하세요. 2) 환경변수(OPENAI_API_KEY, GEMINI_API_KEY 등)가 올바른지 점검하세요.",
			SuggestedFixEn: "1) Verify client Bearer token matches LiteLLM virtual key. 2) Check upstream API key environment variables.",
		}
	}

	return nil
}
