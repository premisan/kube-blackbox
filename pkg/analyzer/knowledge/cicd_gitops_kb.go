package knowledge

import (
	"regexp"
	"strings"
)

// CICDGitOpsAnalysis stores findings from Jenkins, Nexus, Argo Workflows, and Argo Rollouts crashes.
type CICDGitOpsAnalysis struct {
	Component      string // jenkins, nexus, argo-workflows, argo-rollouts
	RootCause      string
	ErrorClass     string
	SummaryKo      string
	SummaryEn      string
	SuggestedFixKo string
	SuggestedFixEn string
}

var (
	// Jenkins
	jenkinsDiskExhaustedRegex = regexp.MustCompile(`(?i)(?:Disk space is below threshold of \S+ GiB|Disk space is too low.*?: jenkins|java\.io\.IOException:\s*No space left on device.*?: jenkins|hudson\.util\.IOException2:\s*No space left on device)`)
	jenkinsAgentChannelRegex  = regexp.MustCompile(`(?i)(?:hudson\.remoting\.Channel\$OrderlyShutdown|Remoting channel closed|Connection refused.*?: jenkins-agent|slave agent was terminated)`)

	// Nexus
	nexusBlobStoreFullRegex = regexp.MustCompile(`(?i)(?:StorageException:\s*Blob store .*? is full|Blob store ".*?" has no space left|BlobStoreQuotaExceededException|No space left on device.*?: sonatype-work)`)
	nexusDbLockedRegex      = regexp.MustCompile(`(?i)(?:Database is locked|DatabaseLockedException|OStorageException:.*?database is locked|H2 database.*?locked)`)

	// Argo Workflows
	argoWorkflowDeadlineRegex = regexp.MustCompile(`(?i)(?:WorkflowDeadlineExceeded|pod exceeded activeDeadlineSeconds|Step exceeded its deadline|Task activeDeadlineSeconds exceeded)`)
	argoArtifactSaveRegex     = regexp.MustCompile(`(?i)(?:Failed to save outputs|artifact repository connection failed|Failed to upload artifact.*?: RequestTimeout|failed to save artifact to s3)`)

	// Argo Rollouts
	argoRolloutAnalysisRegex = regexp.MustCompile(`(?i)(?:AnalysisRun failed|Metric ".*?" failed evaluation|Metric.*?: failureLimit exceeded|Rollout aborted: analysis failed)`)
	argoTrafficRoutingRegex  = regexp.MustCompile(`(?i)(?:traffic routing plugin error|failed to update canary weight|failed to set canary routing: 500|RolloutTrafficRoutingError)`)
)

// AnalyzeCICDGitOpsLogs inspects logs for Jenkins, Nexus, Argo Workflows, and Argo Rollouts failures.
func AnalyzeCICDGitOpsLogs(logs string) *CICDGitOpsAnalysis {
	if strings.TrimSpace(logs) == "" {
		return nil
	}

	// 1. Jenkins
	if jenkinsDiskExhaustedRegex.MatchString(logs) {
		return &CICDGitOpsAnalysis{
			Component:      "jenkins",
			RootCause:      "JenkinsDiskSpaceExhausted",
			ErrorClass:     "Jenkins_WorkspaceDiskFull",
			SummaryKo:      "Jenkins 컨트롤러 또는 에이전트 노드의 디스크 가용 공간이 임계치 미만으로 고갈됨",
			SummaryEn:      "Jenkins controller or agent workspace disk space exhausted below threshold",
			SuggestedFixKo: "1) Jenkins 홈/워크스페이스 볼륨 PVC 용량을 확장하세요. 2) 파이프라인 후처리 단계에 'cleanWs()'를 추가하거나 오래된 빌드 이력 정리 정책을 설정하세요.",
			SuggestedFixEn: "1) Expand Jenkins home/workspace PVC volume. 2) Add 'cleanWs()' in pipeline post-actions or prune old build histories.",
		}
	}
	if jenkinsAgentChannelRegex.MatchString(logs) {
		return &CICDGitOpsAnalysis{
			Component:      "jenkins",
			RootCause:      "JenkinsAgentRemotingChannelClosed",
			ErrorClass:     "Jenkins_AgentRemotingClosed",
			SummaryKo:      "Jenkins 마스터와 빌드 에이전트 간의 Remoting 통신 채널이 단절됨 (네트워크 단절 또는 에이전트 크래시)",
			SummaryEn:      "Jenkins remoting channel closed between controller and build agent",
			SuggestedFixKo: "1) Kubernetes Jenkins 에이전트 파드의 OOMKilled 여부 및 리소스 Limit을 확인하세요. 2) 컨트롤러의 JNLP(50000) 포트 서비스 접근성을 점검하세요.",
			SuggestedFixEn: "1) Check if agent pod was OOMKilled and increase memory limits. 2) Verify JNLP (port 50000) service connectivity.",
		}
	}

	// 2. Nexus Repository
	if nexusBlobStoreFullRegex.MatchString(logs) {
		return &CICDGitOpsAnalysis{
			Component:      "nexus",
			RootCause:      "NexusBlobStoreFull",
			ErrorClass:     "Nexus_BlobStoreFull",
			SummaryKo:      "Nexus Repository 블롭 저장소(Blob Store) 저장 공간 고갈로 아티팩트 업로드 실패",
			SummaryEn:      "Nexus Repository blob store ran out of disk space, rejecting artifact uploads",
			SuggestedFixKo: "1) Nexus PVC 스토리지 용량을 즉시 증설하세요. 2) Nexus 관리자 화면에서 'Compact blob store' 및 'Purge unused docker/npm/maven' 태스크를 실행하세요.",
			SuggestedFixEn: "1) Expand Nexus PVC storage. 2) Run 'Compact blob store' and clean up unused artifacts in Nexus administration.",
		}
	}
	if nexusDbLockedRegex.MatchString(logs) {
		return &CICDGitOpsAnalysis{
			Component:      "nexus",
			RootCause:      "NexusDatabaseLocked",
			ErrorClass:     "Nexus_DatabaseLocked",
			SummaryKo:      "Nexus 내부 임베디드 데이터베이스(OrientDB/H2) 락 충돌로 트랜잭션 중단",
			SummaryEn:      "Nexus internal database (OrientDB/H2) locked, blocking database transactions",
			SuggestedFixKo: "1) Nexus 파드를 안전하게 재시작하여 고아 락(Orphan lock)을 해제하세요. 2) H2/OrientDB 리빌드 도구를 점검하세요.",
			SuggestedFixEn: "1) Restart Nexus pod gracefully to clear orphan locks. 2) Run database repair utilities if corruption persists.",
		}
	}

	// 3. Argo Workflows
	if argoWorkflowDeadlineRegex.MatchString(logs) {
		return &CICDGitOpsAnalysis{
			Component:      "argo-workflows",
			RootCause:      "ArgoWorkflowDeadlineExceeded",
			ErrorClass:     "Argo_WorkflowDeadlineExceeded",
			SummaryKo:      "Argo Workflow 파이프라인 또는 태스크 단계가 'activeDeadlineSeconds' 제한 시간을 초과함",
			SummaryEn:      "Argo Workflow task or step exceeded activeDeadlineSeconds timeout",
			SuggestedFixKo: "1) 워크플로우 템플릿의 'activeDeadlineSeconds' 값을 늘리세요. 2) 긴 대기 시간이나 외부 서비스 I/O 병목을 프로파일링하세요.",
			SuggestedFixEn: "1) Increase 'activeDeadlineSeconds' in the workflow template. 2) Profile task execution for slow I/O or deadlocks.",
		}
	}
	if argoArtifactSaveRegex.MatchString(logs) {
		return &CICDGitOpsAnalysis{
			Component:      "argo-workflows",
			RootCause:      "ArgoArtifactSaveFailed",
			ErrorClass:     "Argo_ArtifactSaveFailed",
			SummaryKo:      "Argo Workflow 빌드 출력물(Artifact)을 원격 아티팩트 리포지토리(S3/GCS/MinIO)에 저장 실패",
			SummaryEn:      "Argo Workflow failed to upload step output artifacts to remote repository",
			SuggestedFixKo: "1) artifactRepository 설정의 버킷 자격 증명(Secret/IAM)을 점검하세요. 2) S3/GCS 엔드포인트 네트워크 연결성 및 타임아웃을 확인하세요.",
			SuggestedFixEn: "1) Verify artifactRepository secret credentials and bucket IAM permissions. 2) Check network connectivity to object storage.",
		}
	}

	// 4. Argo Rollouts
	if argoRolloutAnalysisRegex.MatchString(logs) {
		return &CICDGitOpsAnalysis{
			Component:      "argo-rollouts",
			RootCause:      "ArgoRolloutAnalysisFailed",
			ErrorClass:     "Argo_AnalysisRunFailed",
			SummaryKo:      "Argo Rollouts 카나리 배포 검증(AnalysisRun) 지표 측정 실패로 배포 자동 롤백",
			SummaryEn:      "Argo Rollouts canary AnalysisRun metrics evaluation failed, triggering automated abort/rollback",
			SuggestedFixKo: "1) AnalysisTemplate의 Prometheus 쿼리 성공률(success-rate) 또는 레이턴시 지표를 점검하세요. 2) 카나리 파드의 직전 에러 로그를 확인하세요.",
			SuggestedFixEn: "1) Inspect Prometheus queries in the AnalysisTemplate. 2) Review recent application error logs from canary pods.",
		}
	}
	if argoTrafficRoutingRegex.MatchString(logs) {
		return &CICDGitOpsAnalysis{
			Component:      "argo-rollouts",
			RootCause:      "ArgoRolloutTrafficRoutingFailed",
			ErrorClass:     "Argo_TrafficRoutingError",
			SummaryKo:      "Argo Rollouts 트래픽 라우팅 플러그인(ALB/Istio/SMI) 가중치 분할 업데이트 실패",
			SummaryEn:      "Argo Rollouts failed to update traffic routing split weights via mesh or ingress plugin",
			SuggestedFixKo: "1) Ingress 또는 VirtualService와 Rollout 간의 연결 매핑을 확인하세요. 2) 트래픽 라우팅 컨트롤러 권한(RBAC)을 점검하세요.",
			SuggestedFixEn: "1) Verify Rollout trafficRouting spec matches Ingress/VirtualService resource names. 2) Check controller RBAC.",
		}
	}

	return nil
}
