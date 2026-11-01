package knowledge

import (
	"regexp"
	"strings"
)

// GCPSDKAnalysis stores findings from Google Cloud SDK crashes across multiple languages.
type GCPSDKAnalysis struct {
	Component      string // bigquery, gemini, gcs, gcp-auth
	RootCause      string
	ErrorClass     string
	SummaryKo      string
	SummaryEn      string
	SuggestedFixKo string
	SuggestedFixEn string
}

var (
	// GCP Auth / ADC
	gcpDefaultCredsRegex = regexp.MustCompile(`(?i)(?:DefaultCredentialsError:\s*Could not automatically determine credentials|google:\s*could not find default credentials|com\.google\.auth\.oauth2\.GoogleCredentials.*?: DefaultCredentialsProvider|Default credentials not found|GOOGLE_APPLICATION_CREDENTIALS\s*environment variable is not set|metadata\.google\.internal.*?: connection timed out)`)

	// BigQuery
	bqQuotaExceededRegex = regexp.MustCompile(`(?i)(?:Query exceeded limit for bytes billed|quotaExceeded.*?: Exceeded rate limits|BigQueryException:\s*Quota exceeded|ResponseTooLargeError.*?: response too large to return)`)
	bqQueryFailedRegex   = regexp.MustCompile(`(?i)(?:NotFound:\s*404 Not found: Table|BigQueryException:\s*Not found: Dataset|Access Denied:\s*Table.*?: Permission bigquery\.tables\.getData denied|com\.google\.cloud\.bigquery\.BigQueryException)`)

	// Gemini API
	geminiQuotaRegex     = regexp.MustCompile(`(?i)(?:ResourceExhausted.*?: 429\s*(?:Quota exceeded|Rate limit exceeded|Too Many Requests)|google\.genai\.errors\.APIError.*?: 429|generateContent.*?: 429\s*RESOURCE_EXHAUSTED|Gemini API rate limit reached)`)
	geminiSafetyRegex    = regexp.MustCompile(`(?i)(?:finish_reason:\s*SAFETY|Candidate was blocked due to SAFETY|Prompt was blocked due to safety|GoogleGenerativeAIError.*?: Candidate was blocked)`)
	geminiAuthRegex      = regexp.MustCompile(`(?i)(?:API_KEY_INVALID|API key not valid\. Please pass a valid API key|google\.genai\.errors\.APIError.*?: 400\s*API_KEY_INVALID|UNAUTHENTICATED.*?: 401)`)

	// Google Cloud Storage (GCS)
	gcsAccessDeniedRegex = regexp.MustCompile(`(?i)(?:google\.cloud\.exceptions\.Forbidden:\s*403.*?: Caller does not have storage\.objects|StorageException:\s*403.*?: Access denied|storage\.objects\.get access to.*?: denied|com\.google\.cloud\.storage\.StorageException)`)
	gcsChecksumRegex     = regexp.MustCompile(`(?i)(?:DataCorruption:\s*Checksum mismatch|md5 checksum does not match|crc32c checksum does not match|ResumableUploadException)`)
)

// AnalyzeGCPSDKLogs inspects application logs for Google Cloud SDK failures (Python, Java, Node, Go).
func AnalyzeGCPSDKLogs(logs string) *GCPSDKAnalysis {
	if strings.TrimSpace(logs) == "" {
		return nil
	}

	// 1. GCP Auth / Application Default Credentials
	if gcpDefaultCredsRegex.MatchString(logs) {
		return &GCPSDKAnalysis{
			Component:      "gcp-auth",
			RootCause:      "GCPAuthDefaultCredentialsMissing",
			ErrorClass:     "GCP_DefaultCredentialsMissing",
			SummaryKo:      "Google Cloud SDK 애플리케이션 기본 자격 증명(ADC) 부재 또는 메타데이터 서버 연결 실패",
			SummaryEn:      "Google Cloud SDK Application Default Credentials (ADC) missing or metadata server unreachable",
			SuggestedFixKo: "1) 파드에 GOOGLE_APPLICATION_CREDENTIALS 환경변수로 서비스 어카운트 키 Secret을 마운트하세요. 2) GKE Workload Identity를 사용하는 경우 ServiceAccount 어노테이션('iam.gke.io/gcp-service-account')이 올바른지 확인하세요.",
			SuggestedFixEn: "1) Mount a GCP service account JSON key and set GOOGLE_APPLICATION_CREDENTIALS. 2) For GKE Workload Identity, verify the ServiceAccount annotation 'iam.gke.io/gcp-service-account'.",
		}
	}

	// 2. Gemini API
	if geminiQuotaRegex.MatchString(logs) {
		return &GCPSDKAnalysis{
			Component:      "gemini",
			RootCause:      "GCPGeminiQuotaExceeded",
			ErrorClass:     "Gemini_ResourceExhausted_429",
			SummaryKo:      "Google Gemini API 호출 속도 제한(Rate Limit) 또는 프로젝트 할당량(Quota) 초과 (HTTP 429)",
			SummaryEn:      "Google Gemini API rate limit or project quota exceeded (HTTP 429 ResourceExhausted)",
			SuggestedFixKo: "1) Google Cloud Console의 Vertex AI / Gemini API 할당량(TPM, RPM) 상향을 요청하세요. 2) 지수 백오프(Exponential Backoff) 재시도 로직을 적용하거나 LiteLLM/프록시로 요청을 버퍼링하세요.",
			SuggestedFixEn: "1) Request a quota increase for Gemini API (TPM, RPM) in Google Cloud Console. 2) Implement exponential backoff retry logic.",
		}
	}
	if geminiSafetyRegex.MatchString(logs) {
		return &GCPSDKAnalysis{
			Component:      "gemini",
			RootCause:      "GCPGeminiSafetyBlocked",
			ErrorClass:     "Gemini_SafetyFilter_Blocked",
			SummaryKo:      "Google Gemini 모델 안전성 필터(Safety Ratings)에 의해 콘텐츠 생성이 차단됨",
			SummaryEn:      "Google Gemini response candidate or prompt blocked by safety filters",
			SuggestedFixKo: "1) generationConfig의 safetySettings(HARM_CATEGORY_HARASSMENT 등) 임계값을 BLOCK_ONLY_HIGH로 완화하세요. 2) 프롬프트 전처리 필터를 보강하세요.",
			SuggestedFixEn: "1) Adjust Gemini safetySettings thresholds (e.g. BLOCK_ONLY_HIGH). 2) Sanitize prompt inputs.",
		}
	}
	if geminiAuthRegex.MatchString(logs) {
		return &GCPSDKAnalysis{
			Component:      "gemini",
			RootCause:      "GCPGeminiAuthFailed",
			ErrorClass:     "Gemini_APIKey_Invalid",
			SummaryKo:      "Google Gemini API Key가 유효하지 않거나 인증 실패 (HTTP 401/400)",
			SummaryEn:      "Google Gemini API Key is invalid or unauthenticated (HTTP 401/400)",
			SuggestedFixKo: "1) GEMINI_API_KEY 환경변수의 키 값이 올바른지 확인하세요. 2) Google AI Studio 또는 GCP Console에서 API 키 활성화 상태를 점검하세요.",
			SuggestedFixEn: "1) Verify GEMINI_API_KEY environment variable. 2) Check API key status in Google AI Studio or GCP Console.",
		}
	}

	// 3. BigQuery
	if bqQuotaExceededRegex.MatchString(logs) {
		return &GCPSDKAnalysis{
			Component:      "bigquery",
			RootCause:      "GCPBigQueryQuotaExceeded",
			ErrorClass:     "BigQuery_QuotaExceeded",
			SummaryKo:      "BigQuery 쿼리 바이트 청구 한도(bytes billed) 초과 또는 동시 쿼리 API 쿼터 도달",
			SummaryEn:      "BigQuery query exceeded bytes billed limit or rate limit quota",
			SuggestedFixKo: "1) 쿼리 설정의 'maximum_bytes_billed' 한도를 상향하거나 파티션/클러스터링 필터를 적용해 스캔 용량을 줄이세요. 2) GCP BigQuery 슬롯 예약을 점검하세요.",
			SuggestedFixEn: "1) Increase 'maximum_bytes_billed' or optimize query with partition/cluster filters. 2) Check BigQuery slot reservations.",
		}
	}
	if bqQueryFailedRegex.MatchString(logs) {
		return &GCPSDKAnalysis{
			Component:      "bigquery",
			RootCause:      "GCPBigQueryQueryFailed",
			ErrorClass:     "BigQuery_QueryExecutionError",
			SummaryKo:      "BigQuery 데이터세트/테이블 접근 권한 부재(403) 또는 대상 테이블 부재(404)",
			SummaryEn:      "BigQuery table/dataset permission denied (403) or not found (404)",
			SuggestedFixKo: "1) 서비스 어카운트에 'roles/bigquery.dataViewer' 및 'roles/bigquery.jobUser' IAM 역할을 부여하세요. 2) 프로젝트 ID 및 데이터세트/테이블 이름 오탈자를 점검하세요.",
			SuggestedFixEn: "1) Grant 'roles/bigquery.dataViewer' and 'roles/bigquery.jobUser' to the service account. 2) Verify dataset and table names.",
		}
	}

	// 4. Google Cloud Storage (GCS)
	if gcsChecksumRegex.MatchString(logs) {
		return &GCPSDKAnalysis{
			Component:      "gcs",
			RootCause:      "GCPStorageChecksumMismatch",
			ErrorClass:     "GCS_DataCorruption_Checksum",
			SummaryKo:      "Google Cloud Storage 업로드/다운로드 중 데이터 무결성 체크섬(CRC32c/MD5) 불일치",
			SummaryEn:      "Google Cloud Storage data corruption: CRC32c or MD5 checksum mismatch during transfer",
			SuggestedFixKo: "1) 네트워크 프록시 또는 MTU 단편화로 인한 패킷 손상 여부를 확인하세요. 2) GCS 멀티파트 업로드 청크 크기를 조정하세요.",
			SuggestedFixEn: "1) Check network MTU and proxy integrity. 2) Tune GCS multipart upload chunk sizes.",
		}
	}
	if gcsAccessDeniedRegex.MatchString(logs) {
		return &GCPSDKAnalysis{
			Component:      "gcs",
			RootCause:      "GCPStorageAccessDenied",
			ErrorClass:     "GCS_AccessDenied_403",
			SummaryKo:      "Google Cloud Storage 버킷/객체 접근 권한 거절 (HTTP 403 Forbidden)",
			SummaryEn:      "Google Cloud Storage bucket or object access denied (HTTP 403 Forbidden)",
			SuggestedFixKo: "1) 서비스 어카운트에 'roles/storage.objectViewer' 또는 'roles/storage.objectAdmin' IAM 역할을 부여하세요. 2) 버킷의 Uniform Bucket-Level Access 설정을 점검하세요.",
			SuggestedFixEn: "1) Grant 'roles/storage.objectViewer' or 'roles/storage.objectAdmin' to the service account. 2) Verify bucket IAM policies.",
		}
	}

	return nil
}
