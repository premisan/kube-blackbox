package knowledge

import (
	"regexp"
	"strings"
)

// SecurityPolicyAnalysis stores findings from Kyverno, OPA/Gatekeeper, VSO, and Secrets Store CSI Driver crashes.
type SecurityPolicyAnalysis struct {
	Component      string // kyverno, gatekeeper, vso, secrets-store-csi
	RootCause      string
	ErrorClass     string
	SummaryKo      string
	SummaryEn      string
	SuggestedFixKo string
	SuggestedFixEn string
}

var (
	// Kyverno
	kyvernoPolicyViolationRegex = regexp.MustCompile(`(?i)(?:admission webhook ".*?\bkypolicy\b.*?" denied the request|admission webhook "validate\.kyverno\.svc" denied the request|policy .*? failed on resource|kyverno:\s*admission policy violation)`)
	kyvernoWebhookTimeoutRegex  = regexp.MustCompile(`(?i)(?:failed calling webhook ".*?kyverno.*?":\s*context deadline exceeded|failed calling webhook ".*?kyverno.*?":\s*connection refused|x509:\s*certificate has expired.*?: kyverno)`)

	// OPA / Gatekeeper
	gatekeeperViolationRegex = regexp.MustCompile(`(?i)(?:admission webhook "validation\.gatekeeper\.sh" denied the request|admission webhook ".*?\bgatekeeper\b.*?" denied the request: \[.*?\]|ConstraintTemplate compilation error)`)
	gatekeeperWebhookRegex   = regexp.MustCompile(`(?i)(?:failed calling webhook "validation\.gatekeeper\.sh":\s*context deadline exceeded|failed calling webhook.*?: gatekeeper-controller-manager|gatekeeper webhook connection refused)`)

	// Vault Secrets Operator (VSO)
	vsoSyncFailedRegex  = regexp.MustCompile(`(?i)(?:VaultStaticSecret error syncing secret|VaultDynamicSecret error.*?: 404|VaultPKISecret error syncing|VaultAuth error authenticating: 403)`)
	vsoRoleMissingRegex = regexp.MustCompile(`(?i)(?:VaultAuth failed.*?: role not found|role ".*?" not found in vault kubernetes auth|invalid role name.*?: vault)`)

	// Secrets Store CSI Driver
	secretsCSIClassMissingRegex = regexp.MustCompile(`(?i)(?:failed to get SecretProviderClass|SecretProviderClass ".*?" not found|secretproviderclasses\.secrets-store\.csi\.x-k8s\.io ".*?" not found)`)
	secretsCSIMountFailedRegex  = regexp.MustCompile(`(?i)(?:failed to mount secrets store.*?: rpc error|provider-gcp.*?: rpc error: code = PermissionDenied|provider-vault.*?: rpc error: code = PermissionDenied|provider-azure.*?: failed to get keyvault secret)`)
)

// AnalyzeSecurityPolicyLogs inspects logs for Kyverno, Gatekeeper, VSO, and Secrets Store CSI Driver failures.
func AnalyzeSecurityPolicyLogs(logs string) *SecurityPolicyAnalysis {
	if strings.TrimSpace(logs) == "" {
		return nil
	}

	// 1. Kyverno
	if kyvernoPolicyViolationRegex.MatchString(logs) {
		return &SecurityPolicyAnalysis{
			Component:      "kyverno",
			RootCause:      "KyvernoAdmissionPolicyViolation",
			ErrorClass:     "Kyverno_PolicyViolation_Denied",
			SummaryKo:      "Kyverno 보안/거버넌스 어드미션 정책(ClusterPolicy) 위반으로 파드 생성 차단",
			SummaryEn:      "Pod creation denied by Kyverno ClusterPolicy validation rule",
			SuggestedFixKo: "1) 거부 메시지에 명시된 Kyverno 정책 요구사항(보안 컨텍스트, 라벨, 이미지 태그 등)을 파드 스펙에 보강하세요. 2) 'kubectl get cpol'로 해당 정책을 확인하세요.",
			SuggestedFixEn: "1) Update pod spec to satisfy the violated Kyverno ClusterPolicy (e.g. securityContext, image tags). 2) Run 'kubectl get cpol' to inspect active policies.",
		}
	}
	if kyvernoWebhookTimeoutRegex.MatchString(logs) {
		return &SecurityPolicyAnalysis{
			Component:      "kyverno",
			RootCause:      "KyvernoWebhookTimeout",
			ErrorClass:     "Kyverno_Webhook_Timeout",
			SummaryKo:      "Kyverno 어드미션 웹훅 컨트롤러 응답 지연(타임아웃) 또는 웹훅 TLS 인증서 만료",
			SummaryEn:      "Kyverno admission webhook timed out or TLS certificate expired",
			SuggestedFixKo: "1) kyverno 파드의 CPU/메모리 부하 및 가동 상태를 점검하세요. 2) API 서버와 kyverno 서비스 간 9443 포트 통신 및 Webhook TLS Secret 갱신을 확인하세요.",
			SuggestedFixEn: "1) Check kyverno controller pod resource usage and health. 2) Verify port 9443 connectivity and webhook TLS secret validity.",
		}
	}

	// 2. OPA / Gatekeeper
	if gatekeeperViolationRegex.MatchString(logs) {
		return &SecurityPolicyAnalysis{
			Component:      "gatekeeper",
			RootCause:      "GatekeeperConstraintViolation",
			ErrorClass:     "Gatekeeper_Constraint_Denied",
			SummaryKo:      "OPA Gatekeeper 제약 조건(Constraint) 위반으로 쿠버네티스 리소스 생성 거부",
			SummaryEn:      "Resource creation rejected by OPA Gatekeeper constraint violation",
			SuggestedFixKo: "1) 에러 로그에 명시된 Gatekeeper Constraint의 규정 위반 항목(privileged 컨테이너, CPU/메모리 제한 누락 등)을 수정하세요. 2) 'kubectl get constraints'로 위반 내역을 조회하세요.",
			SuggestedFixEn: "1) Update resource manifest to comply with the Gatekeeper constraint rules. 2) Run 'kubectl get constraints' to view violations.",
		}
	}
	if gatekeeperWebhookRegex.MatchString(logs) {
		return &SecurityPolicyAnalysis{
			Component:      "gatekeeper",
			RootCause:      "GatekeeperWebhookFailure",
			ErrorClass:     "Gatekeeper_Webhook_Failure",
			SummaryKo:      "Gatekeeper 검증 웹훅(validation.gatekeeper.sh) 호출 실패 또는 타임아웃",
			SummaryEn:      "Gatekeeper validation webhook call failed or timed out",
			SuggestedFixKo: "1) gatekeeper-controller-manager 파드가 정상 실행 중인지 확인하세요. 2) 웹훅 실패 정책(failurePolicy: Fail)으로 인한 클러스터 배포 차단 시 긴급 점검을 수행하세요.",
			SuggestedFixEn: "1) Inspect gatekeeper-controller-manager pods health. 2) Verify webhook firewall rules and failurePolicy behavior.",
		}
	}

	// 3. Vault Secrets Operator (VSO)
	if vsoRoleMissingRegex.MatchString(logs) {
		return &SecurityPolicyAnalysis{
			Component:      "vso",
			RootCause:      "VaultAuthRoleNotFound",
			ErrorClass:     "VSO_AuthRoleNotFound",
			SummaryKo:      "Vault Secrets Operator의 VaultAuth 인증 역할(Role)이 Vault 서버에 존재하지 않음",
			SummaryEn:      "Vault Secrets Operator VaultAuth role not found on the Vault server",
			SuggestedFixKo: "1) Vault 서버의 Kubernetes Auth 설정에 해당 role이 등록되어 있는지 확인하세요 ('vault read auth/kubernetes/role/<role-name>'). 2) VSO VaultAuth spec의 role 매핑을 수정하세요.",
			SuggestedFixEn: "1) Verify role exists in Vault ('vault read auth/kubernetes/role/<role>'). 2) Correct role mapping in the VaultAuth CRD.",
		}
	}
	if vsoSyncFailedRegex.MatchString(logs) {
		return &SecurityPolicyAnalysis{
			Component:      "vso",
			RootCause:      "VaultSecretSyncFailed",
			ErrorClass:     "VSO_SecretSyncFailed",
			SummaryKo:      "Vault Secrets Operator가 Vault 시크릿 경로를 찾지 못하거나(404) 시크릿 동기화 권한 거부",
			SummaryEn:      "Vault Secrets Operator secret synchronization failed (404 Not Found or Permission Denied)",
			SuggestedFixKo: "1) VaultStaticSecret에 명시된 시크릿 경로(path)와 마운트 포인트(mount)가 실제 존재하는지 확인하세요. 2) Vault 정책(Policy)의 읽기 권한을 점검하세요.",
			SuggestedFixEn: "1) Confirm the secret path and mount point exist in Vault. 2) Verify Vault token read capabilities in the assigned policy.",
		}
	}

	// 4. Secrets Store CSI Driver
	if secretsCSIClassMissingRegex.MatchString(logs) {
		return &SecurityPolicyAnalysis{
			Component:      "secrets-store-csi",
			RootCause:      "SecretProviderClassNotFound",
			ErrorClass:     "CSI_SecretProviderClassNotFound",
			SummaryKo:      "Secrets Store CSI Driver가 참조하는 SecretProviderClass 리소스를 찾을 수 없음",
			SummaryEn:      "Secrets Store CSI Driver referenced SecretProviderClass resource not found in namespace",
			SuggestedFixKo: "1) 파드와 동일한 네임스페이스에 SecretProviderClass 리소스가 생성되어 있는지 확인하세요 ('kubectl get secretproviderclass -n <ns>'). 2) 볼륨 spec의 secretProviderClass 이름 오탈자를 수정하세요.",
			SuggestedFixEn: "1) Ensure SecretProviderClass exists in the same namespace as the pod. 2) Check secretProviderClass name spelling in volume spec.",
		}
	}
	if secretsCSIMountFailedRegex.MatchString(logs) {
		return &SecurityPolicyAnalysis{
			Component:      "secrets-store-csi",
			RootCause:      "SecretsStoreCSIMountFailed",
			ErrorClass:     "CSI_MountFailed_PermissionDenied",
			SummaryKo:      "Secrets Store CSI 드라이버 프로바이더(GCP/Vault/Azure/AWS) 시크릿 마운트 권한 거절",
			SummaryEn:      "Secrets Store CSI Driver provider mount failed due to permission denied or invalid credentials",
			SuggestedFixKo: "1) 클라우드 프로바이더 IAM 권한(GCP Secret Manager Secret Accessor, Vault Token, AWS SecretsManager)을 확인하세요. 2) Workload Identity 바인딩 상태를 점검하세요.",
			SuggestedFixEn: "1) Verify provider IAM credentials (e.g. Secret Manager Secret Accessor, Vault Token). 2) Check Workload Identity federation bindings.",
		}
	}

	return nil
}
