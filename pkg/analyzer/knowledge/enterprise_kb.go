package knowledge

import (
	"regexp"
	"strings"
)

// EnterpriseOSSAnalysis stores findings from popular enterprise Kubernetes software crashes.
type EnterpriseOSSAnalysis struct {
	Component      string // vault, coredns, cert-manager, prometheus, fluentbit, elasticsearch, patroni, argocd
	RootCause      string
	ErrorClass     string
	SummaryKo      string
	SummaryEn      string
	SuggestedFixKo string
	SuggestedFixEn string
}

var (
	// Vault
	vaultSealedRegex    = regexp.MustCompile(`(?i)(?:core:\s*vault is sealed|Vault is sealed|Error making API request.*?: 503.*?: Vault is sealed)`)
	vaultTokenRegex     = regexp.MustCompile(`(?i)(?:permission denied.*?: error authenticating|token has expired|failed to renew token|client token not found)`)
	// CoreDNS
	coreDNSLoopRegex    = regexp.MustCompile(`(?i)(?:plugin/loop:\s*Loop\s*\(127\.0\.0\.1:53\s*->\s*:53\)\s*detected for zone|Loop\s*\(.+?:53\s*->\s*:53\)\s*detected)`)
	// Cert-Manager
	certMgrWebhookRegex = regexp.MustCompile(`(?i)(?:Internal error occurred:\s*failed calling webhook "webhook\.cert-manager\.io"|failed calling webhook.*?: context deadline exceeded|x509:\s*certificate has expired or is not yet valid.*?: cert-manager)`)
	acmeRateLimitRegex  = regexp.MustCompile(`(?i)(?:urn:ietf:params:acme:error:rateLimited|too many certificates already issued)`)
	// Prometheus & Alertmanager
	promWALRegex        = regexp.MustCompile(`(?i)(?:opening storage failed:\s*corrupted WAL|corrupted segment.*?: wal|corrupted checkpoint)`)
	promCardinalityRegex = regexp.MustCompile(`(?i)(?:out of memory: cannot allocate.*?: prometheus|failed to allocate chunk.*?: tsdb)`)
	// Fluent Bit / Fluentd
	fluentBufferRegex   = regexp.MustCompile(`(?i)(?:\[buffer\]\s*(?:ring buffer is full|queue is full|failed to flush chunk)|\[engine\]\s*chunk\s*.+?\s*paused)`)
	// Elasticsearch / OpenSearch
	esDiskFloodRegex    = regexp.MustCompile(`(?i)(?:flood_stage disk watermark \[\d+%\] exceeded on|read-only-allow-delete)`)
	esCircuitRegex      = regexp.MustCompile(`(?i)(?:circuit_breaking_exception:\s*\[parent\]\s*Data too large|Data too large, data for \[\S+\] would be)`)
	// Patroni / PostgreSQL
	patroniLeaseRegex   = regexp.MustCompile(`(?i)(?:demoting self because lost leader lease|lost DCS leader lock|heartbeat timeout on leader)`)
	pgWALDiskRegex      = regexp.MustCompile(`(?i)(?:could not write to file "pg_wal/|PANIC:\s*could not locate a valid checkpoint record|could not write to file .*?pg_xlog.*?No space left on device)`)
	// Argo CD
	argoRepoOOMRegex    = regexp.MustCompile(`(?i)(?:failed to generate manifests.*?: signal: killed|rpc error: code = ResourceExhausted.*?: grpc: received message larger than max)`)
	gitRateLimitRegex   = regexp.MustCompile(`(?i)(?:API rate limit exceeded for user|secondary rate limit.*?: github|429 Too Many Requests.*?: git)`)
)

// AnalyzeEnterpriseOSSLogs inspects container logs for widespread enterprise open-source crash signatures.
func AnalyzeEnterpriseOSSLogs(logs string) *EnterpriseOSSAnalysis {
	if strings.TrimSpace(logs) == "" {
		return nil
	}

	// 1. HashiCorp Vault (P0)
	if vaultSealedRegex.MatchString(logs) {
		return &EnterpriseOSSAnalysis{
			Component:      "vault",
			RootCause:      "VaultSealedFailure",
			ErrorClass:     "VaultSealed_503",
			SummaryKo:      "HashiCorp Vault 클러스터 봉인(Sealed) 상태로 인한 시크릿 조회 실패",
			SummaryEn:      "HashiCorp Vault cluster is sealed; secret lookup returned 503",
			SuggestedFixKo: "1) 'vault operator unseal' 명령어로 Vault 샤미르 키(Shamir keys)를 입력하여 봉인을 해제하세요. 2) 클라우드 KMS 기반 Auto-unseal 설정을 확인하세요.",
			SuggestedFixEn: "1) Execute 'vault operator unseal' with Shamir unseal keys. 2) Verify Cloud KMS auto-unseal configuration.",
		}
	}
	if vaultTokenRegex.MatchString(logs) {
		return &EnterpriseOSSAnalysis{
			Component:      "vault-agent",
			RootCause:      "VaultTokenExpired",
			ErrorClass:     "VaultAuthExpired",
			SummaryKo:      "Vault Agent 인증 토큰 만료 또는 갱신 실패 (Permission Denied)",
			SummaryEn:      "Vault Agent authentication token expired or renewal failed",
			SuggestedFixKo: "1) AppRole의 secret_id 유효기간을 점검하세요. 2) Vault Agent auto-auth 설정과 Kubernetes ServiceAccount 토큰 검증 권한을 확인하세요.",
			SuggestedFixEn: "1) Check AppRole secret_id expiration. 2) Verify Vault Agent auto-auth and Kubernetes ServiceAccount token reviewer permissions.",
		}
	}

	// 2. CoreDNS (P0)
	if coreDNSLoopRegex.MatchString(logs) {
		return &EnterpriseOSSAnalysis{
			Component:      "coredns",
			RootCause:      "CoreDNSLoopDetected",
			ErrorClass:     "DNSLoopDetected",
			SummaryKo:      "CoreDNS DNS 루프(Loop: 127.0.0.1:53 -> :53) 감지로 인한 CrashLoopBackOff",
			SummaryEn:      "CoreDNS loop detected (127.0.0.1:53 -> :53) causing CrashLoopBackOff",
			SuggestedFixKo: "1) 노드의 '/etc/resolv.conf'가 127.0.0.1(로컬호스트)을 가리키지 않도록 외부 DNS(8.8.8.8 등) 또는 VPC DNS로 수정하세요. 2) Corefile의 'forward . /etc/resolv.conf'를 점검하세요.",
			SuggestedFixEn: "1) Ensure node '/etc/resolv.conf' does not point nameserver to 127.0.0.1 (use external/VPC DNS). 2) Check 'forward . /etc/resolv.conf' in Corefile.",
		}
	}

	// 3. Cert-Manager (P0)
	if certMgrWebhookRegex.MatchString(logs) {
		return &EnterpriseOSSAnalysis{
			Component:      "cert-manager",
			RootCause:      "CertManagerWebhookFailure",
			ErrorClass:     "CertManagerWebhookDeadlock",
			SummaryKo:      "Cert-Manager Webhook 통신 실패로 인한 클러스터 리소스 배포 중단",
			SummaryEn:      "Cert-Manager Webhook communication failure blocking resource admissions",
			SuggestedFixKo: "1) 'cert-manager-webhook' 파드가 정상 실행 중인지 확인하세요. 2) Webhook 인증서 만료 여부를 점검하고 cert-manager 파드를 재기동하여 내부 CA를 갱신하세요.",
			SuggestedFixEn: "1) Check if 'cert-manager-webhook' pod is healthy. 2) Verify webhook CA certificate validity and restart cert-manager pods.",
		}
	}
	if acmeRateLimitRegex.MatchString(logs) {
		return &EnterpriseOSSAnalysis{
			Component:      "cert-manager",
			RootCause:      "ACMERateLimitExceeded",
			ErrorClass:     "ACME_RateLimited",
			SummaryKo:      "Let's Encrypt ACME 인증서 발급 주간 발급 한도(Rate Limit) 초과",
			SummaryEn:      "Let's Encrypt ACME certificate generation rate limit exceeded",
			SuggestedFixKo: "1) 개발/테스트 환경인 경우 Let's Encrypt Staging 발급자(ClusterIssuer)를 사용하세요. 2) 슬라이딩 윈도우 한도(1주일) 만료 후 재시도하세요.",
			SuggestedFixEn: "1) Use Let's Encrypt Staging ClusterIssuer for testing. 2) Wait for weekly sliding rate limit window to reset.",
		}
	}

	// 4. Prometheus & Alertmanager (P1)
	if promWALRegex.MatchString(logs) {
		return &EnterpriseOSSAnalysis{
			Component:      "prometheus",
			RootCause:      "PrometheusWALCorruption",
			ErrorClass:     "TSDB_WAL_Corrupted",
			SummaryKo:      "Prometheus TSDB Write-Ahead-Log (WAL) 손상으로 인한 기동 실패",
			SummaryEn:      "Prometheus TSDB Write-Ahead-Log (WAL) corruption prevented startup",
			SuggestedFixKo: "1) 손상된 WAL 세그먼트 디렉토리를 정리하거나 백업에서 복구하세요. 2) 파드 스펙에 '--storage.tsdb.wal-compression'을 활성화하세요.",
			SuggestedFixEn: "1) Remove corrupted WAL segment or restore from volume snapshot. 2) Enable '--storage.tsdb.wal-compression'.",
		}
	}
	if promCardinalityRegex.MatchString(logs) {
		return &EnterpriseOSSAnalysis{
			Component:      "prometheus",
			RootCause:      "PrometheusCardinalityOOM",
			ErrorClass:     "TSDB_CardinalityOOM",
			SummaryKo:      "Prometheus 메트릭 시계열 카디널리티(Cardinality) 폭발로 인한 메모리 고갈 OOMKilled",
			SummaryEn:      "Prometheus metric time-series cardinality explosion triggered OOMKilled",
			SuggestedFixKo: "1) 'metric_relabel_configs'로 고유 ID(User ID, UUID) 라벨을 제거(drop)하세요. 2) Prometheus 파드 메모리 제한을 증설하세요.",
			SuggestedFixEn: "1) Drop high-cardinality labels (user IDs, request paths) via 'metric_relabel_configs'. 2) Increase Prometheus memory limit.",
		}
	}

	// 5. Fluent Bit / Fluentd (P1)
	if fluentBufferRegex.MatchString(logs) {
		return &EnterpriseOSSAnalysis{
			Component:      "fluent-bit",
			RootCause:      "FluentBitBufferExhaustion",
			ErrorClass:     "BufferRingFull",
			SummaryKo:      "Fluent Bit / Fluentd 로그 버퍼 큐 포화 및 백프레셔로 인한 수집 중단",
			SummaryEn:      "Fluent Bit / Fluentd log buffer queue exhausted due to backend backpressure",
			SuggestedFixKo: "1) 'storage.type filesystem'을 적용하여 디스크 기반 버퍼링으로 전환하세요. 2) 로그 수신 백엔드(Elasticsearch, Loki)의 인제스트 지연을 해소하세요.",
			SuggestedFixEn: "1) Configure 'storage.type filesystem' for durable disk buffering. 2) Address ingestion bottlenecks in target backend (Elasticsearch, Loki).",
		}
	}

	// 6. Elasticsearch / OpenSearch (P1)
	if esDiskFloodRegex.MatchString(logs) {
		return &EnterpriseOSSAnalysis{
			Component:      "elasticsearch",
			RootCause:      "ElasticsearchDiskFloodStage",
			ErrorClass:     "FloodStageDiskWatermark",
			SummaryKo:      "Elasticsearch 디스크 사용량 임계치(95%) 초과로 전체 인덱스 읽기 전용(Read-Only) 잠금",
			SummaryEn:      "Elasticsearch 95% flood stage disk watermark exceeded; indices locked in read-only mode",
			SuggestedFixKo: "1) 노드 디스크 볼륨을 증설하거나 불필요한 오래된 인덱스를 삭제하세요. 2) 'PUT /_all/_settings {\"index.blocks.read_only_allow_delete\": null}'로 잠금을 해제하세요.",
			SuggestedFixEn: "1) Increase disk storage or delete obsolete indices. 2) Unlock indices with 'PUT /_all/_settings {\"index.blocks.read_only_allow_delete\": null}'.",
		}
	}
	if esCircuitRegex.MatchString(logs) {
		return &EnterpriseOSSAnalysis{
			Component:      "elasticsearch",
			RootCause:      "ElasticsearchCircuitBreaker",
			ErrorClass:     "CircuitBreakingException",
			SummaryKo:      "Elasticsearch 힙 메모리 서킷 브레이커 발동: 쿼리 메모리 한도 초과 (Data too large)",
			SummaryEn:      "Elasticsearch circuit breaker tripped: query memory exceeded limit (Data too large)",
			SuggestedFixKo: "1) 대규모 집계(Aggregation) 쿼리의 bucket_size를 제한하세요. 2) Elasticsearch JVM 힙 메모리(-Xmx)를 증설하세요.",
			SuggestedFixEn: "1) Limit bucket size in aggregation queries. 2) Increase Elasticsearch JVM heap size (-Xmx).",
		}
	}

	// 7. Patroni / PostgreSQL (P2)
	if patroniLeaseRegex.MatchString(logs) {
		return &EnterpriseOSSAnalysis{
			Component:      "patroni",
			RootCause:      "PatroniLeaderLeaseLost",
			ErrorClass:     "DCS_LeaderLeaseLost",
			SummaryKo:      "Patroni 분산 합의(DCS) 리더 임차권 상실로 인한 Primary 노드 자동 강등 및 재시작",
			SummaryEn:      "Patroni lost DCS leader lease lock, demoting primary node and restarting",
			SuggestedFixKo: "1) DCS(etcd/consul) 클러스터 응답 지연 및 네트워크 파티션을 점검하세요. 2) Patroni 설정의 'loop_wait' 및 'ttl' 타임아웃을 늘리세요.",
			SuggestedFixEn: "1) Check etcd/consul DCS cluster latency and network health. 2) Increase 'loop_wait' and 'ttl' in Patroni configuration.",
		}
	}
	if pgWALDiskRegex.MatchString(logs) {
		return &EnterpriseOSSAnalysis{
			Component:      "postgresql",
			RootCause:      "PostgresWALDiskFull",
			ErrorClass:     "pg_wal_NoSpaceLeft",
			SummaryKo:      "PostgreSQL pg_wal 트랜잭션 로그 디스크 공간 고갈로 인한 비정상 셧다운",
			SummaryEn:      "PostgreSQL pg_wal transaction log directory exhausted disk space, causing shutdown",
			SuggestedFixKo: "1) 'archive_command'가 실패하여 WAL 파일이 삭제되지 않고 누적되었는지 확인하세요. 2) PostgreSQL PV 디스크 용량을 증설하세요.",
			SuggestedFixEn: "1) Check if 'archive_command' is failing and accumulating WAL segments. 2) Increase PostgreSQL PV storage.",
		}
	}

	// 8. Argo CD (P2)
	if argoRepoOOMRegex.MatchString(logs) {
		return &EnterpriseOSSAnalysis{
			Component:      "argocd-repo-server",
			RootCause:      "ArgoCDRepoServerOOM",
			ErrorClass:     "RepoServerOOMKilled",
			SummaryKo:      "Argo CD Repo-Server 매니페스트 생성(Helm/Kustomize) 중 메모리 고갈로 크래시",
			SummaryEn:      "Argo CD Repo-Server crashed due to memory exhaustion during manifest generation",
			SuggestedFixKo: "1) 'argocd-repo-server' 디플로이먼트의 메모리 리밋을 증설하세요. 2) 'ARGOCD_EXEC_TIMEOUT' 설정을 점검하세요.",
			SuggestedFixEn: "1) Increase memory limit on 'argocd-repo-server' deployment. 2) Tune 'ARGOCD_EXEC_TIMEOUT'.",
		}
	}
	if gitRateLimitRegex.MatchString(logs) {
		return &EnterpriseOSSAnalysis{
			Component:      "argocd",
			RootCause:      "GitRateLimitExceeded",
			ErrorClass:     "GitHub_RateLimited_429",
			SummaryKo:      "Git 호스팅 제공자(GitHub/GitLab) API 요청 한도 초과(429 Rate Limit)",
			SummaryEn:      "Git hosting provider API rate limit exceeded (429 Too Many Requests)",
			SuggestedFixKo: "1) Argo CD Repository 설정에 인증된 Personal Access Token(PAT) 또는 SSH Key를 등록하세요. 2) Git 폴링 간격을 조정하세요.",
			SuggestedFixEn: "1) Configure authenticated Personal Access Token (PAT) or SSH credentials in Argo CD. 2) Increase Git polling interval.",
		}
	}

	return nil
}
