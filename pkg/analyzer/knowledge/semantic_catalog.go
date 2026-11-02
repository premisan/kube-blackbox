package knowledge

import (
	"fmt"
	"strings"
)

// SemanticCatalogEntry holds the deep diagnostic intelligence for a specific error class or condition.
type SemanticCatalogEntry struct {
	ErrorClass     string // KeyError, NullPointerException, TypeError, etc.
	Language       string // Python, Java, Node.js, Go, System
	Category       string // Application, Dependency, Configuration, Infrastructure
	RootCause      string // Standardized diagnostic root cause code
	SummaryKo      string // Deep diagnostic summary in Korean (LLM-grade clarity)
	ActionKo       string // Actionable 2-3 step resolution guide in Korean
	SummaryEn      string // Diagnostic summary in English
	ActionEn       string // Actionable resolution guide in English
}

// SemanticCatalog is the high-performance O(1) in-memory knowledge base containing hundreds of
// pre-indexed runtime exceptions, framework faults, and operational failure modes.
var SemanticCatalog = map[string]SemanticCatalogEntry{}

func init() {
	loadPythonCatalog()
	loadJavaCatalog()
	loadNodeCatalog()
	loadGoCatalog()
	loadSystemCatalog()
}

// LookupSemanticCatalog performs an O(1) microsecond lookup by language and error class,
// falling back to generic error class lookup.
func LookupSemanticCatalog(lang, errorClass string) (SemanticCatalogEntry, bool) {
	key := strings.ToLower(lang) + ":" + strings.ToLower(errorClass)
	if entry, found := SemanticCatalog[key]; found {
		return entry, true
	}

	// Fallback to error class alone
	if entry, found := SemanticCatalog[strings.ToLower(errorClass)]; found {
		return entry, true
	}

	return SemanticCatalogEntry{}, false
}

// ==================== Python Catalog ====================
func loadPythonCatalog() {
	entries := []SemanticCatalogEntry{
		{
			ErrorClass: "KeyError",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "PythonKeyError",
			SummaryKo:  "딕셔너리에 존재하지 않는 키를 직접 참조하여 KeyError 예외가 발생했습니다.",
			ActionKo:   "1) 딕셔너리 직접 접근(dict[key]) 대신 'dict.get(key, default)' 메소드를 사용하여 기본값을 제공하세요. 2) 사전 참조 전 'if key in dict:' 구문으로 키 존재 유무를 확인하거나 Pydantic 유효성 검증을 적용하세요.",
			SummaryEn:  "Python KeyError: attempt to access a non-existent dictionary key.",
			ActionEn:   "1) Replace direct indexing 'dict[key]' with 'dict.get(key, default)'. 2) Validate key existence using 'if key in dict:' or Pydantic models.",
		},
		{
			ErrorClass: "AttributeError",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "PythonAttributeError",
			SummaryKo:  "None 또는 해당 속성/메소드가 정의되지 않은 객체에 접근하여 AttributeError가 발생했습니다 (NoneType 객체 참조 빈번).",
			ActionKo:   "1) 호출 전 'if obj is not None:' 검증을 추가하거나 옵셔널 체이닝 형태의 가드 구문을 적용하세요. 2) 상위 함수에서 None을 반환하는 조건(DB 조회 실패, 파싱 실패)을 점검하세요.",
			SummaryEn:  "Python AttributeError: object has no attribute or attempted attribute access on None.",
			ActionEn:   "1) Ensure object is not None before accessing attributes ('if obj is not None:'). 2) Trace upstream functions that may return None upon lookup failure.",
		},
		{
			ErrorClass: "TypeError",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "PythonTypeError",
			SummaryKo:  "호환되지 않는 자료형 간의 연산(예: str과 int 결합) 또는 잘못된 함수 인자 전달로 인해 TypeError가 발생했습니다.",
			ActionKo:   "1) 연산 전 명시적 타입 변환(int(), str())을 적용하세요. 2) 함수 시그니처와 호출 시 전달된 인자 개수/키워드 인자를 점검하세요.",
			SummaryEn:  "Python TypeError: unsupported operand types or invalid function arguments.",
			ActionEn:   "1) Apply explicit type casting (int(), str()). 2) Verify function signature and argument count/types.",
		},
		{
			ErrorClass: "ValueError",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "PythonValueError",
			SummaryKo:  "올바른 자료형이지만 유효하지 않은 값(부적절한 포맷, int() 변환 불가 문자열 등)이 전달되어 ValueError가 발생했습니다.",
			ActionKo:   "1) int(), float(), json.loads() 호출 지점에 try-except ValueError 예외 핸들링을 추가하세요. 2) 입력값 검증 로직을 강화하세요.",
			SummaryEn:  "Python ValueError: argument has the right type but an inappropriate value.",
			ActionEn:   "1) Wrap conversion calls (int(), float(), datetime.strptime()) in try-except blocks. 2) Add input validation.",
		},
		{
			ErrorClass: "IndexError",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "PythonIndexError",
			SummaryKo:  "리스트 또는 튜플의 범위를 벗어난 인덱스(Index out of range)에 접근하여 프로세스가 중단되었습니다.",
			ActionKo:   "1) 인덱스 참조 전 'if len(arr) > index:' 경계 검사를 수행하세요. 2) 빈 리스트(Empty List)가 반환될 수 있는 쿼리/슬라이싱 결과를 사전에 검증하세요.",
			SummaryEn:  "Python IndexError: list index out of range.",
			ActionEn:   "1) Validate array length before indexing ('if len(arr) > i:'). 2) Handle empty list cases gracefully.",
		},
		{
			ErrorClass: "ZeroDivisionError",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "PythonZeroDivisionError",
			SummaryKo:  "숫자를 0으로 나누려고 시도하여 ZeroDivisionError가 발생했습니다.",
			ActionKo:   "나눗셈(/, //, %) 연산 수행 전 분모가 0인지 확인('if denominator != 0:')하고 0일 경우 기본값(0.0 등)을 할당하세요.",
			SummaryEn:  "Python ZeroDivisionError: division or modulo by zero.",
			ActionEn:   "Ensure the divisor is non-zero before division ('if denominator != 0:') or set a fallback.",
		},
		{
			ErrorClass: "FileNotFoundError",
			Language:   "Python",
			Category:   "Configuration",
			RootCause:  "PythonFileNotFoundError",
			SummaryKo:  "컨테이너 내부 경로에 지정된 파일 또는 디렉토리가 존재하지 않습니다.",
			ActionKo:   "1) Dockerfile에서 COPY 또는 WORKDIR 설정 경로를 점검하세요. 2) K8s volumeMounts 마운트 경로 및 ConfigMap/Secret 경로가 올바른지 확인하세요.",
			SummaryEn:  "Python FileNotFoundError: no such file or directory.",
			ActionEn:   "1) Check Dockerfile COPY/WORKDIR paths. 2) Verify K8s volumeMounts, ConfigMap, and Secret paths.",
		},
		{
			ErrorClass: "PermissionError",
			Language:   "Python",
			Category:   "Configuration",
			RootCause:  "PythonPermissionError",
			SummaryKo:  "파일 또는 디렉토리에 대한 읽기/쓰기/실행 권한(EACCES)이 거부되었습니다.",
			ActionKo:   "1) 컨테이너의 securityContext(runAsUser, fsGroup) 설정을 점검하세요. 2) 타겟 볼륨의 소유자(chmod/chown) 권한을 확인하세요.",
			SummaryEn:  "Python PermissionError: permission denied.",
			ActionEn:   "1) Verify container securityContext (runAsUser, fsGroup). 2) Check volume directory permissions.",
		},
		{
			ErrorClass: "OperationalError",
			Language:   "Python",
			Category:   "Dependency",
			RootCause:  "PythonDBOperationalError",
			SummaryKo:  "데이터베이스 연결 실패, 커넥션 풀 고갈 또는 트랜잭션 타임아웃으로 인한 DB 오류가 발생했습니다.",
			ActionKo:   "1) DB_HOST, DB_PORT 환경변수 및 K8s Service DNS 연결성을 점검하세요. 2) SQLAlchemy pool_size, max_overflow 설정을 확인하세요.",
			SummaryEn:  "Python OperationalError: database connection or transaction failure.",
			ActionEn:   "1) Verify database host/port connectivity and K8s Service DNS. 2) Adjust SQLAlchemy connection pool parameters.",
		},
		{
			ErrorClass: "IntegrityError",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "PythonDBIntegrityError",
			SummaryKo:  "데이터베이스 고유 키(Unique Key) 위반, 외래 키(Foreign Key) 누락 또는 NOT NULL 제약 조건 위반이 발생했습니다.",
			ActionKo:   "1) 중복 레코드 삽입 방지를 위해 upsert() 구문을 사용하거나 사전에 중복 여부를 조회하세요. 2) 외래 키 참조 무결성을 확인하세요.",
			SummaryEn:  "Python IntegrityError: relational constraint violation (unique or foreign key).",
			ActionEn:   "1) Use upsert / ON CONFLICT statements to handle unique collisions. 2) Verify foreign key integrity.",
		},
		{
			ErrorClass: "ConnectionRefusedError",
			Language:   "Python",
			Category:   "Dependency",
			RootCause:  "PythonConnectionRefused",
			SummaryKo:  "외부 또는 클러스터 내부 대상 서비스 포트가 열려있지 않거나 프로세스가 죽어 있어 연결이 즉시 거부되었습니다.",
			ActionKo:   "1) 대상 서비스 파드가 Running 및 Ready 상태인지 확인하세요. 2) K8s Service의 targetPort와 실제 컨테이너 포트 일치 여부를 점검하세요.",
			SummaryEn:  "Python ConnectionRefusedError: target endpoint refused connection.",
			ActionEn:   "1) Ensure target pod is healthy and ready. 2) Verify K8s Service port and targetPort alignment.",
		},
		{
			ErrorClass: "TimeoutError",
			Language:   "Python",
			Category:   "Dependency",
			RootCause:  "PythonTimeoutError",
			SummaryKo:  "외부 API, 소켓 또는 데이터베이스 쿼리 응답이 지정된 타임아웃 제한 시간을 초과했습니다.",
			ActionKo:   "1) 요청 클라이언트(requests, httpx, aiohttp)의 timeout 값을 상향하거나 재시도(Exponential Backoff)를 적용하세요. 2) 대상 서버의 응답 지연 원인을 점검하세요.",
			SummaryEn:  "Python TimeoutError: network or socket timeout exceeded.",
			ActionEn:   "1) Adjust client timeout and implement exponential backoff retries. 2) Check upstream service latency.",
		},
		{
			ErrorClass: "RecursionError",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "PythonRecursionError",
			SummaryKo:  "재귀 함수의 종료 조건(Base Case)이 누락되어 최대 호출 스택 깊이(sys.getrecursionlimit())를 초과했습니다.",
			ActionKo:   "1) 재귀 호출 함수의 기저 조건(탈출 조건)을 점검하세요. 2) 깊은 재귀를 반복문(while, for) 또는 스택 기반 탐색으로 전환하세요.",
			SummaryEn:  "Python RecursionError: maximum recursion depth exceeded.",
			ActionEn:   "1) Verify recursive function base cases. 2) Refactor deep recursion into iterative loops.",
		},
		{
			ErrorClass: "UnboundLocalError",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "PythonUnboundLocalError",
			SummaryKo:  "지역 변수에 값이 할당되기 전에 해당 변수를 참조하여 UnboundLocalError가 발생했습니다.",
			ActionKo:   "1) 조건문(if/else)의 모든 분기에서 변수가 초기화되도록 기본값을 선언하세요. 2) 전역 변수를 수정할 경우 'global' 키워드를 명시하세요.",
			SummaryEn:  "Python UnboundLocalError: local variable referenced before assignment.",
			ActionEn:   "1) Ensure variable is initialized in all conditional branches. 2) Use 'global' keyword if modifying global scope.",
		},
		{
			ErrorClass: "JSONDecodeError",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "PythonJSONDecodeError",
			SummaryKo:  "HTTP 응답 본문 또는 파일 내용이 올바른 JSON 포맷이 아니어서 역직렬화(json.loads)가 실패했습니다 (HTML 에러 페이지 수신 빈번).",
			ActionKo:   "1) json.loads() 호출 전 수신된 텍스트 내용과 HTTP 상태 코드를 확인하세요. 2) try-except json.JSONDecodeError 예외 처리를 추가하세요.",
			SummaryEn:  "Python JSONDecodeError: failed to parse invalid JSON string.",
			ActionEn:   "1) Inspect raw response body and HTTP status code before parsing. 2) Wrap parsing in try-except JSONDecodeError.",
		},
		{
			ErrorClass: "ModuleNotFoundError",
			Language:   "Python",
			Category:   "Configuration",
			RootCause:  "PythonModuleNotFound",
			SummaryKo:  "파이썬 패키지 또는 모듈을 찾을 수 없어 임포트(import) 단계에서 실행이 중단되었습니다.",
			ActionKo:   "1) Dockerfile 또는 requirements.txt에 누락된 패키지를 추가하세요. 2) PYTHONPATH 환경변수 설정을 점검하세요.",
			SummaryEn:  "Python ModuleNotFoundError: No module named target.",
			ActionEn:   "1) Add missing package to Dockerfile or requirements.txt. 2) Verify PYTHONPATH environment variable.",
		},
		{
			ErrorClass: "ImportError",
			Language:   "Python",
			Category:   "Configuration",
			RootCause:  "PythonImportError",
			SummaryKo:  "모듈 내부에서 지정된 함수, 클래스 또는 변수를 임포트하지 못했습니다 (순환 참조 또는 버전 비호환).",
			ActionKo:   "1) 두 모듈 간의 순환 임포트(Circular Import) 구조를 점검하세요. 2) 패키지 버전 업데이트로 인한 인터페이스 변경 여부를 확인하세요.",
			SummaryEn:  "Python ImportError: cannot import name from module.",
			ActionEn:   "1) Check for circular imports between modules. 2) Verify package version compatibility and API deprecation.",
		},
		{
			ErrorClass: "AssertionError",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "PythonAssertionError",
			SummaryKo:  "assert 조건식이 False로 평가되어 런타임 무결성 검증이 실패했습니다.",
			ActionKo:   "1) assert 조건식의 전제 조건과 실제 전달된 인자 값을 디버깅하세요. 2) 비즈니스 로직에서는 assert 대신 명시적 ValueError 발생을 권장합니다.",
			SummaryEn:  "Python AssertionError: assert statement failed.",
			ActionEn:   "1) Debug violated precondition assertion. 2) Replace assert with explicit exception raising in production code.",
		},
		{
			ErrorClass: "NotImplementedError",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "PythonNotImplementedError",
			SummaryKo:  "추상 베이스 클래스의 필수 메소드가 서브클래스에서 구현되지 않은 채 호출되었습니다.",
			ActionKo:   "파생 클래스에서 해당 인터페이스 메소드를 온전히 구현하거나 호출 대상을 점검하세요.",
			SummaryEn:  "Python NotImplementedError: abstract method not implemented by derived class.",
			ActionEn:   "Implement the required abstract method in the derived class or verify caller target.",
		},
		{
			ErrorClass: "UnicodeDecodeError",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "PythonUnicodeDecodeError",
			SummaryKo:  "바이트 스트림을 문자열로 디코딩하는 중 지정된 인코딩(주로 UTF-8)으로 해석할 수 없는 바이트를 만났습니다.",
			ActionKo:   "1) open() 또는 .decode() 시 올바른 인코딩(euc-kr, cp949 등)을 지정하세요. 2) 'errors=\"replace\"' 또는 'errors=\"ignore\"'를 적용하세요.",
			SummaryEn:  "Python UnicodeDecodeError: codec unable to decode byte in specified position.",
			ActionEn:   "1) Specify correct encoding in open() or .decode(). 2) Use 'errors=\"replace\"' for resilient parsing.",
		},
		{
			ErrorClass: "RequestValidationError",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "FastAPIValidationError",
			SummaryKo:  "클라이언트가 전달한 요청 JSON 페이로드가 FastAPI/Pydantic 모델 스키마 검증을 통과하지 못했습니다.",
			ActionKo:   "1) 필수 필드 누락 및 데이터 타입(int vs str) 일치 여부를 점검하세요. 2) 커스텀 ExceptionHandler를 등록하여 422 상태 코드로 친절한 에러를 반환하세요.",
			SummaryEn:  "FastAPI RequestValidationError: request payload violated Pydantic schema.",
			ActionEn:   "1) Check client payload for missing required fields and type mismatches. 2) Handle with custom 422 exception handler.",
		},
		{
			ErrorClass: "DisallowedHost",
			Language:   "Python",
			Category:   "Configuration",
			RootCause:  "DjangoDisallowedHost",
			SummaryKo:  "Django의 settings.ALLOWED_HOSTS에 요청받은 HTTP Host 헤더 도메인이 등록되어 있지 않습니다.",
			ActionKo:   "settings.py의 ALLOWED_HOSTS 목록에 인그레스 도메인, K8s Service DNS(예: '.default.svc.cluster.local') 또는 IP를 추가하세요.",
			SummaryEn:  "Django DisallowedHost: invalid HTTP Host header rejected by ALLOWED_HOSTS.",
			ActionEn:   "Add ingress hostname, cluster DNS, or '*' to settings.ALLOWED_HOSTS in settings.py.",
		},
		{
			ErrorClass: "NoResultFound",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "SQLAlchemyNoResultFound",
			SummaryKo:  "SQLAlchemy 'one()' 또는 'one_or_none()' 쿼리 실행 결과 레코드가 존재하지 않습니다.",
			ActionKo:   "1) 'query.one()' 대신 'query.first()' 또는 'query.one_or_none()'을 사용하여 None 반환을 허용하세요. 2) 결과 부재 시 404 Not Found를 반환하도록 처리하세요.",
			SummaryEn:  "SQLAlchemy NoResultFound: one() query produced no database rows.",
			ActionEn:   "1) Replace 'query.one()' with 'query.one_or_none()' or 'query.first()'. 2) Return 404 on absent record.",
		},
		{
			ErrorClass: "MultipleResultsFound",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "SQLAlchemyMultipleResultsFound",
			SummaryKo:  "단일 레코드 반환을 기대한 쿼리('one()')에서 둘 이상의 중복 행이 조회되었습니다.",
			ActionKo:   "1) 쿼리 조건절(WHERE)에 고유 식별자(PK, Unique Key)를 정확히 지정하세요. 2) 'limit(1)'을 적용하세요.",
			SummaryEn:  "SQLAlchemy MultipleResultsFound: one() query returned multiple database rows.",
			ActionEn:   "1) Ensure query WHERE clause targets a unique key. 2) Apply limit(1) to constrain result set.",
		},
		{
			ErrorClass: "DetachedInstanceError",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "SQLAlchemyDetachedInstance",
			SummaryKo:  "데이터베이스 세션이 이미 종료(closed)된 후 분리된(detached) 엔티티 객체의 지연 로딩(lazy loading) 속성에 접근했습니다.",
			ActionKo:   "1) 세션이 열려있는 동안 'joinedload()'를 사용하여 필요한 관계를 즉시 페치하세요. 2) 세션 설정에 'expire_on_commit=False'를 지정하세요.",
			SummaryEn:  "SQLAlchemy DetachedInstanceError: lazy load operation failed on detached instance.",
			ActionEn:   "1) Use joinedload() to eagerly load relationships before session closes. 2) Set expire_on_commit=False.",
		},
		{
			ErrorClass: "MaxRetriesExceededError",
			Language:   "Python",
			Category:   "Dependency",
			RootCause:  "HTTPMaxRetriesExceeded",
			SummaryKo:  "외부 HTTP API 요청 시 재시도 횟수 한도를 초과할 때까지 원격 호스트 연결에 실패했습니다.",
			ActionKo:   "1) 대상 서비스 도메인의 DNS 해석 및 방화벽/NetworkPolicy를 점검하세요. 2) 재시도 간격(Backoff) 및 타임아웃을 상향하세요.",
			SummaryEn:  "HTTP MaxRetriesExceededError: connection attempts exceeded maximum retries.",
			ActionEn:   "1) Verify target endpoint DNS resolution and network egress policies. 2) Adjust retry backoff and timeout.",
		},
		{
			ErrorClass: "SSLError",
			Language:   "Python",
			Category:   "Configuration",
			RootCause:  "PythonSSLError",
			SummaryKo:  "SSL/TLS 인증서 검증(Certificate Verify Failed)이 만료되었거나 신뢰할 수 없는 CA 인증서로 인해 거부되었습니다.",
			ActionKo:   "1) 컨테이너 베이스 이미지의 ca-certificates 패키지를 업데이트하세요. 2) 사내 프라이빗 CA 인증서 경로를 'REQUESTS_CA_BUNDLE' 환경변수에 지정하세요.",
			SummaryEn:  "Python SSLError: SSL certificate verification failed.",
			ActionEn:   "1) Update ca-certificates in container base image. 2) Set REQUESTS_CA_BUNDLE to internal root CA path.",
		},
		{
			ErrorClass: "NoBrokersAvailable",
			Language:   "Python",
			Category:   "Dependency",
			RootCause:  "KafkaNoBrokersAvailable",
			SummaryKo:  "Kafka 클러스터의 부트스트랩 브로커(Bootstrap Servers) 중 활성화된 브로커에 접속할 수 없습니다.",
			ActionKo:   "1) KAFKA_BOOTSTRAP_SERVERS 환경변수 및 K8s Service 주소를 점검하세요. 2) Kafka 파드의 가동 상태와 PLAINTEXT/SSL 포트 설정을 확인하세요.",
			SummaryEn:  "Kafka NoBrokersAvailable: unable to connect to any Kafka bootstrap brokers.",
			ActionEn:   "1) Verify KAFKA_BOOTSTRAP_SERVERS address and cluster DNS. 2) Check Kafka pod health and listener ports.",
		},
	}

	for _, e := range entries {
		key1 := "python:" + strings.ToLower(e.ErrorClass)
		SemanticCatalog[key1] = e
	}
}

// ==================== Java / Spring Catalog ====================
func loadJavaCatalog() {
	entries := []SemanticCatalogEntry{
		{
			ErrorClass: "NullPointerException",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "JavaNullPointerException",
			SummaryKo:  "null 객체의 메소드를 호출하거나 필드에 접근하여 NullPointerException이 발생했습니다.",
			ActionKo:   "1) Optional<T> 패턴 또는 Objects.requireNonNull()을 적용하세요. 2) 메소드 호출 전 'if (obj != null)' 널 체크 가드를 추가하거나 Lombok @NonNull을 적용하세요.",
			SummaryEn:  "Java NullPointerException: dereferencing a null object reference.",
			ActionEn:   "1) Adopt Optional<T> or Objects.requireNonNull(). 2) Add explicit null-checks before method invocation.",
		},
		{
			ErrorClass: "BeanCreationException",
			Language:   "Java",
			Category:   "Configuration",
			RootCause:  "SpringBeanCreationException",
			SummaryKo:  "Spring 애플리케이션 컨텍스트 초기화 중 빈(@Bean, @Component, @Service) 생성에 실패했습니다.",
			ActionKo:   "1) 빈 생성자 또는 @PostConstruct 메소드 내부의 예외 스택(Caused by:)을 확인하세요. 2) 의존성 주입 실패 또는 application.yml 환경변수 누락 여부를 점검하세요.",
			SummaryEn:  "Spring BeanCreationException: error instantiating application context bean.",
			ActionEn:   "1) Inspect nested 'Caused by:' exception chain. 2) Verify dependency injection and required application.yml properties.",
		},
		{
			ErrorClass: "NoSuchBeanDefinitionException",
			Language:   "Java",
			Category:   "Configuration",
			RootCause:  "SpringNoSuchBeanDefinition",
			SummaryKo:  "주입하려는 빈 정의(Bean definition)를 Spring 컨텍스트에서 찾을 수 없습니다.",
			ActionKo:   "1) 대상 클래스에 @Component, @Service, @Repository 애노테이션이 붙어 있는지 확인하세요. 2) @ComponentScan 패키지 경로에 포함되어 있는지 확인하세요.",
			SummaryEn:  "Spring NoSuchBeanDefinitionException: no qualifying bean of required type found.",
			ActionEn:   "1) Ensure target class is annotated with @Service/@Component. 2) Verify @ComponentScan package scanning configuration.",
		},
		{
			ErrorClass: "LazyInitializationException",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "HibernateLazyInitializationException",
			SummaryKo:  "영속성 컨텍스트(Hibernate Session)가 이미 종료된 트랜잭션 외부에서 지연 로딩(FetchType.LAZY) 연관 엔티티에 접근했습니다.",
			ActionKo:   "1) 서비스 계층 메소드에 @Transactional(readOnly = true)을 선언하세요. 2) JPQL 'JOIN FETCH' 또는 엔티티 그래프(@EntityGraph)를 사용하여 필요한 연관 관계를 즉시 페치하세요.",
			SummaryEn:  "Hibernate LazyInitializationException: failed to lazily initialize a collection outside session.",
			ActionEn:   "1) Ensure method is wrapped in @Transactional. 2) Use JPQL 'JOIN FETCH' or @EntityGraph to eagerly fetch associations.",
		},
		{
			ErrorClass: "CommunicationsException",
			Language:   "Java",
			Category:   "Dependency",
			RootCause:  "JDBCCommunicationsException",
			SummaryKo:  "데이터베이스 서버와의 통신 링크가 단절되었거나 연결 수립에 실패했습니다 (MySQL/MariaDB JDBC).",
			ActionKo:   "1) DB 호스트 주소, 포트(3306), K8s Service 및 NetworkPolicy를 점검하세요. 2) HikariCP 커넥션 풀의 maxLifetime(DB wait_timeout보다 작게) 및 connectionTimeout을 설정하세요.",
			SummaryEn:  "JDBC CommunicationsException: communications link failure to database server.",
			ActionEn:   "1) Verify database host, port, and network policies. 2) Configure HikariCP maxLifetime below DB wait_timeout.",
		},
		{
			ErrorClass: "SQLTransientConnectionException",
			Language:   "Java",
			Category:   "Dependency",
			RootCause:  "HikariPoolTimeout",
			SummaryKo:  "HikariCP 커넥션 풀에 가용한 유휴 커넥션이 고갈되어 대기 시간(connectionTimeout) 초과로 실패했습니다.",
			ActionKo:   "1) 'maximum-pool-size' 설정을 트래픽에 맞춰 상향(예: 10 -> 30)하세요. 2) 트랜잭션(@Transactional) 내에서 외부 API 호출 등 장시간 블로킹 작업이 수행되고 있는지 점검하세요.",
			SummaryEn:  "HikariCP ConnectionTimeout: connection is not available, request timed out.",
			ActionEn:   "1) Increase HikariCP maximum-pool-size. 2) Avoid long-running blocking operations (e.g. external REST calls) inside @Transactional.",
		},
		{
			ErrorClass: "ClassCastException",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "JavaClassCastException",
			SummaryKo:  "호환되지 않는 클래스 타입으로 객체를 강제 캐스팅(Downcasting)하려 시도하여 실패했습니다.",
			ActionKo:   "1) 캐스팅 전 'instanceof' 연산자로 객체 타입을 검증하세요. 2) 제네릭(Generics) 타입을 명시하여 컴파일 타임에 타입 불일치를 감지하세요.",
			SummaryEn:  "Java ClassCastException: attempted to cast an object to an incompatible subclass.",
			ActionEn:   "1) Verify object type using 'instanceof' before casting. 2) Use explicit generic types to enforce compile-time safety.",
		},
		{
			ErrorClass: "DataIntegrityViolationException",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "SpringDataIntegrityViolation",
			SummaryKo:  "데이터베이스 무결성 제약 조건(Unique Key, Foreign Key, Not Null) 위반으로 쿼리 실행이 거절되었습니다.",
			ActionKo:   "1) 중복 레코드 삽입 방지를 위해 저장 전 엔티티 존재 여부를 확인하거나 유니크 인덱스를 점검하세요. 2) 필수 필드에 null이 전달되지 않도록 유효성 검증을 추가하세요.",
			SummaryEn:  "Spring DataIntegrityViolationException: relational constraint violation in SQL execution.",
			ActionEn:   "1) Handle duplicate insertions with uniqueness validation or upsert. 2) Validate non-null column requirements.",
		},
		{
			ErrorClass: "NoClassDefFoundError",
			Language:   "Java",
			Category:   "Configuration",
			RootCause:  "JavaNoClassDefFoundError",
			SummaryKo:  "컴파일 시점에는 존재했던 클래스를 런타임 클래스패스(Classpath)에서 찾을 수 없습니다.",
			ActionKo:   "1) 배포된 fat-jar / war 내에 해당 의존성 라이브러리가 올바르게 패키징되었는지 확인하세요. 2) Gradle/Maven 의존성 스코프('provided' -> 'implementation')를 점검하세요.",
			SummaryEn:  "Java NoClassDefFoundError: class was available at compile-time but missing at runtime.",
			ActionEn:   "1) Verify packaged jar/war contains the required dependency. 2) Check dependency scope in build tool (Gradle/Maven).",
		},
		{
			ErrorClass: "MethodArgumentNotValidException",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "SpringValidationFailure",
			SummaryKo:  "클라이언트가 전달한 요청 DTO가 @Valid / @NotNull / @Size 유효성 검증 규칙을 충족하지 못했습니다.",
			ActionKo:   "1) @ControllerAdvice의 @ExceptionHandler(MethodArgumentNotValidException.class)에서 필드별 오류 메시지를 400 Bad Request로 반환하도록 설정하세요. 2) 클라이언트 요청 페이로드를 점검하세요.",
			SummaryEn:  "Spring MethodArgumentNotValidException: validation on an argument annotated with @Valid failed.",
			ActionEn:   "1) Implement @ExceptionHandler to catch and return detailed 400 Bad Request responses. 2) Verify client payload against DTO constraints.",
		},
		{
			ErrorClass: "UnsatisfiedDependencyException",
			Language:   "Java",
			Category:   "Configuration",
			RootCause:  "SpringUnsatisfiedDependency",
			SummaryKo:  "Spring 빈 생성 중 생성자 또는 필드에 필요한 의존성 주입 대상 빈을 생성하지 못했습니다.",
			ActionKo:   "1) 중첩된 Caused by: 예외를 확인하여 의존성 체인 중 어느 하위 빈이 실패했는지 추적하세요. 2) 해당 빈의 설정값(@Value)을 점검하세요.",
			SummaryEn:  "Spring UnsatisfiedDependencyException: error creating bean with dependencies unsatisfied.",
			ActionEn:   "1) Inspect nested Caused by: chain to find the failed dependency. 2) Verify missing configuration properties.",
		},
		{
			ErrorClass: "ArrayIndexOutOfBoundsException",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "JavaIndexOutOfBounds",
			SummaryKo:  "배열 크기를 초과하거나 음수인 인덱스에 접근하여 실행이 중단되었습니다.",
			ActionKo:   "1) 인덱스 참조 전 'if (index >= 0 && index < array.length)' 경계 검사를 수행하세요. 2) 컬렉션 반복 시 for-each 루프를 사용하세요.",
			SummaryEn:  "Java ArrayIndexOutOfBoundsException: array index out of bounds.",
			ActionEn:   "1) Add index boundary checks before access. 2) Adopt enhanced for-each loops.",
		},
		{
			ErrorClass: "NumberFormatException",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "JavaNumberFormatException",
			SummaryKo:  "숫자로 변환할 수 없는 문자열(빈 문자열, 특수문자, 영문 등)을 Integer.parseInt() 또는 Long.parseLong()으로 파싱하려 시도했습니다.",
			ActionKo:   "1) 파싱 전 정규식(\\d+) 또는 NumberUtils.isDigits()로 숫자 여부를 검증하세요. 2) try-catch NumberFormatException을 적용하세요.",
			SummaryEn:  "Java NumberFormatException: attempted to convert a non-numeric string to numeric type.",
			ActionEn:   "1) Validate string with NumberUtils.isCreatable() before parsing. 2) Wrap parsing in try-catch block.",
		},
		{
			ErrorClass: "StackOverflowError",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "JavaStackOverflowError",
			SummaryKo:  "무한 재귀 호출 또는 양방향 엔티티 관계(toString/equals)의 순환 참조로 JVM 스레드 스택 메모리가 고갈되었습니다.",
			ActionKo:   "1) 재귀 함수의 탈출 조건을 점검하세요. 2) JPA 양방향 연관 관계 엔티티의 Lombok @ToString(exclude=...) 및 Jackson @JsonIgnore를 설정하여 순환 참조를 차단하세요.",
			SummaryEn:  "Java StackOverflowError: recursion too deep or bidirectional entity circular reference.",
			ActionEn:   "1) Check recursive function base cases. 2) Exclude bidirectional entity relations in @ToString / Jackson serialization.",
		},
		{
			ErrorClass: "ConcurrentModificationException",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "JavaConcurrentModification",
			SummaryKo:  "단일 스레드 또는 다중 스레드에서 컬렉션(List, Map)을 순회(Iterator)하는 도중 요소를 직접 수정/삭제했습니다.",
			ActionKo:   "1) Iterator.remove()를 사용하거나 'removeIf()' 메소드를 사용하세요. 2) 멀티스레드 환경에서는 CopyOnWriteArrayList 또는 ConcurrentHashMap을 사용하세요.",
			SummaryEn:  "Java ConcurrentModificationException: collection modified during iteration.",
			ActionEn:   "1) Use Iterator.remove() or collection.removeIf(). 2) Adopt ConcurrentHashMap / CopyOnWriteArrayList in concurrent contexts.",
		},
		{
			ErrorClass: "IllegalStateException",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "JavaIllegalStateException",
			SummaryKo:  "객체가 부적절한 라이프사이클 상태에서 메소드 호출을 수신했습니다 (예: 이미 닫힌 스트림 재사용 등).",
			ActionKo:   "1) 호출 전 객체 상태(isClosed(), isConnected())를 확인하세요. 2) 재사용 불가능한 자원(Stream, Channel)의 생명주기를 점검하세요.",
			SummaryEn:  "Java IllegalStateException: method invoked at an illegal or inappropriate state.",
			ActionEn:   "1) Verify object lifecycle state before method invocation. 2) Ensure streams are not consumed multiple times.",
		},
		{
			ErrorClass: "IllegalArgumentException",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "JavaIllegalArgumentException",
			SummaryKo:  "메소드에 부적절하거나 잘못된 인자(음수 값, 허용되지 않는 포맷 등)가 전달되었습니다.",
			ActionKo:   "호출 지점에서 전달하는 파라미터 값의 범위를 점검하고 검증 로직을 추가하세요.",
			SummaryEn:  "Java IllegalArgumentException: method passed an illegal or inappropriate argument.",
			ActionEn:   "Check caller arguments against parameter validation requirements.",
		},
		{
			ErrorClass: "OptimisticLockingFailureException",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "JPAOptimisticLockFailure",
			SummaryKo:  "동일한 엔티티 레코드에 대해 두 개 이상의 트랜잭션이 동시 수정을 시도하여 낙관적 락(@Version) 충돌이 발생했습니다.",
			ActionKo:   "1) Spring Retry(@Retryable)를 적용하여 버전 충돌 시 트랜잭션을 재시도하도록 구성하세요. 2) 충돌이 빈번한 경우 비관적 락(LockModeType.PESSIMISTIC_WRITE)을 검토하세요.",
			SummaryEn:  "Spring OptimisticLockingFailureException: concurrent modification detected on versioned entity.",
			ActionEn:   "1) Implement @Retryable on concurrent update methods. 2) Consider pessimistic locking for hot records.",
		},
		{
			ErrorClass: "CannotCreateTransactionException",
			Language:   "Java",
			Category:   "Dependency",
			RootCause:  "SpringCannotCreateTransaction",
			SummaryKo:  "데이터베이스 서버 연결 불가 또는 커넥션 풀 고갈로 인해 스프링 트랜잭션을 시작할 수 없습니다.",
			ActionKo:   "1) 데이터베이스 서비스 가동 상태 및 K8s Service DNS를 확인하세요. 2) HikariCP 커넥션 풀 최대 크기와 DB 서버의 max_connections 설정을 확인하세요.",
			SummaryEn:  "Spring CannotCreateTransactionException: failed to open transaction due to database connection failure.",
			ActionEn:   "1) Verify database service status and network reachability. 2) Inspect HikariCP pool and database max_connections.",
		},
		{
			ErrorClass: "BadSqlGrammarException",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "SpringBadSqlGrammar",
			SummaryKo:  "SQL 문법 오류, 예약어 충돌 또는 데이터베이스에 존재하지 않는 컬럼/테이블을 조회하려 시도했습니다.",
			ActionKo:   "1) 실행된 SQL 쿼리 문법 및 테이블/컬럼 매핑을 점검하세요. 2) DB 마이그레이션(Flyway/Liquibase)이 누락되었는지 확인하세요.",
			SummaryEn:  "Spring BadSqlGrammarException: SQL syntax error or missing table/column.",
			ActionEn:   "1) Inspect SQL query syntax and ORM column mappings. 2) Ensure database migrations (Flyway/Liquibase) are up to date.",
		},
		{
			ErrorClass: "DuplicateKeyException",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "SpringDuplicateKeyException",
			SummaryKo:  "기본 키(Primary Key) 또는 고유 인덱스(Unique Index) 제약 조건을 위반하는 중복 레코드 삽입 시도가 차단되었습니다.",
			ActionKo:   "1) 고유 식별자 생성 로직(UUID, 시퀀스)을 점검하세요. 2) 'INSERT ... ON DUPLICATE KEY UPDATE' 구문 또는 upsert 로직을 적용하세요.",
			SummaryEn:  "Spring DuplicateKeyException: duplicate key or unique constraint violation.",
			ActionEn:   "1) Verify ID generation strategy. 2) Handle unique key conflicts gracefully with upsert logic.",
		},
		{
			ErrorClass: "JsonMappingException",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "JacksonJsonMappingException",
			SummaryKo:  "Jackson 라이브러리가 JSON 데이터를 Java DTO 클래스로 역직렬화하는 중 필드 타입 불일치 또는 생성자 누락으로 실패했습니다.",
			ActionKo:   "1) DTO 클래스에 기본 생성자(기본 생성자 없으면 @NoArgsConstructor)가 있는지 확인하세요. 2) 날짜 포맷에 @JsonFormat(pattern=\"...\")을 명시하세요.",
			SummaryEn:  "Jackson JsonMappingException: failed to map JSON structure to Java object model.",
			ActionEn:   "1) Ensure DTO has a default constructor (@NoArgsConstructor). 2) Annotate date fields with @JsonFormat.",
		},
		{
			ErrorClass: "ConnectException",
			Language:   "Java",
			Category:   "Dependency",
			RootCause:  "JavaConnectException",
			SummaryKo:  "원격 서버 대상 포트에 TCP 연결을 수립하지 못하고 거부되었습니다 (포트 리스닝 부재 또는 방화벽).",
			ActionKo:   "1) 대상 서비스 파드 상태와 K8s Service 포트를 점검하세요. 2) NetworkPolicy 설정을 확인하세요.",
			SummaryEn:  "Java ConnectException: connection refused to target endpoint.",
			ActionEn:   "1) Verify target pod health and K8s Service port. 2) Inspect NetworkPolicy rules.",
		},
		{
			ErrorClass: "SocketTimeoutException",
			Language:   "Java",
			Category:   "Dependency",
			RootCause:  "JavaSocketTimeoutException",
			SummaryKo:  "원격 서버 연결(Connect Timeout) 또는 데이터 읽기(Read Timeout) 중 응답 지연으로 소켓 타임아웃이 발생했습니다.",
			ActionKo:   "1) RestTemplate / WebClient / FeignClient의 connectTimeout 및 readTimeout 설정을 상향하세요. 2) 대상 서버의 지연 원인을 점검하세요.",
			SummaryEn:  "Java SocketTimeoutException: read or connect timeout expired on remote socket.",
			ActionEn:   "1) Increase connectTimeout and readTimeout in HTTP clients. 2) Investigate upstream service latency.",
		},
		{
			ErrorClass: "UnknownHostException",
			Language:   "Java",
			Category:   "Configuration",
			RootCause:  "JavaUnknownHostException",
			SummaryKo:  "DNS 서버(CoreDNS)에서 대상 도메인 또는 K8s Service 이름을 IP 주소로 해석하지 못했습니다.",
			ActionKo:   "1) 도메인명 오탈자 및 K8s 네임스페이스 접미사(예: '<service>.<namespace>.svc.cluster.local')를 확인하세요. 2) kube-system의 coredns 파드 상태를 점검하세요.",
			SummaryEn:  "Java UnknownHostException: DNS resolution failed for hostname.",
			ActionEn:   "1) Check hostname spelling and K8s Service FQDN. 2) Verify CoreDNS pod status in kube-system.",
		},
	}

	for _, e := range entries {
		key1 := "java:" + strings.ToLower(e.ErrorClass)
		SemanticCatalog[key1] = e
	}
}

// ==================== Node.js Catalog ====================
func loadNodeCatalog() {
	entries := []SemanticCatalogEntry{
		{
			ErrorClass: "TypeError",
			Language:   "JavaScript/TypeScript",
			Category:   "Application",
			RootCause:  "NodeTypeError",
			SummaryKo:  "undefined 또는 null의 속성을 읽으려 하거나 함수가 아닌 대상을 호출하여 TypeError가 발생했습니다.",
			ActionKo:   "1) 옵셔널 체이닝(obj?.property) 및 널 병합 연산자(??)를 적용하세요. 2) 비동기 호출 반환값이 undefined인지 확인하세요.",
			SummaryEn:  "Node.js TypeError: cannot read property of undefined or null, or invalid invocation.",
			ActionEn:   "1) Apply optional chaining (obj?.prop) and nullish coalescing (??). 2) Ensure async functions resolve valid objects.",
		},
		{
			ErrorClass: "ReferenceError",
			Language:   "JavaScript/TypeScript",
			Category:   "Application",
			RootCause:  "NodeReferenceError",
			SummaryKo:  "선언되지 않은 변수를 참조하거나 스코프 외부의 식별자에 접근하여 ReferenceError가 발생했습니다.",
			ActionKo:   "1) 변수명 오탈자 및 const/let 선언 여부를 확인하세요. 2) 모듈 import/export 구문이 누락되었는지 확인하세요.",
			SummaryEn:  "Node.js ReferenceError: reference to an undeclared or out-of-scope variable.",
			ActionEn:   "1) Check for typos and ensure variable is declared with let/const. 2) Verify module imports.",
		},
		{
			ErrorClass: "RangeError",
			Language:   "JavaScript/TypeScript",
			Category:   "Application",
			RootCause:  "NodeRangeError",
			SummaryKo:  "호출 스택 최대 한도 초과(Maximum call stack size exceeded) 또는 잘못된 배열 길이 설정으로 RangeError가 발생했습니다.",
			ActionKo:   "1) 재귀 함수의 탈출 조건을 점검하여 무한 루프를 방지하세요. 2) 반복문으로 리팩토링하세요.",
			SummaryEn:  "Node.js RangeError: maximum call stack size exceeded or invalid array length.",
			ActionEn:   "1) Verify recursive function termination conditions. 2) Refactor into iterative algorithms.",
		},
		{
			ErrorClass: "UnhandledPromiseRejection",
			Language:   "JavaScript/TypeScript",
			Category:   "Application",
			RootCause:  "NodeUnhandledPromiseRejection",
			SummaryKo:  "비동기 Promise가 거절(Reject)되었으나 .catch() 핸들러 또는 await try-catch 블록이 누락되어 프로세스가 중단되었습니다.",
			ActionKo:   "1) 모든 async 함수 호출에 'await'를 붙이고 try-catch 블록으로 감싸세요. 2) Promise 체인 끝에 반드시 '.catch(err => ...)'를 연결하세요.",
			SummaryEn:  "Node.js UnhandledPromiseRejection: unhandled promise rejection caused process termination.",
			ActionEn:   "1) Ensure all async calls are awaited inside try-catch blocks. 2) Attach '.catch()' error handlers to promise chains.",
		},
		{
			ErrorClass: "ERR_HTTP_HEADERS_SENT",
			Language:   "JavaScript/TypeScript",
			Category:   "Application",
			RootCause:  "NodeHeadersAlreadySent",
			SummaryKo:  "클라이언트에 이미 응답 헤더가 전송된 후 중복으로 res.send() 또는 res.json()을 호출했습니다.",
			ActionKo:   "라우터 핸들러에서 응답 전송 시 'return res.json(...)'과 같이 return 문을 명시하여 이후 코드의 중복 실행을 차단하세요.",
			SummaryEn:  "Node.js ERR_HTTP_HEADERS_SENT: cannot set headers after they are sent to client.",
			ActionEn:   "Ensure response calls use 'return res.json(...)' or 'return res.send(...)' to prevent subsequent code execution.",
		},
		{
			ErrorClass: "ECONNREFUSED",
			Language:   "JavaScript/TypeScript",
			Category:   "Dependency",
			RootCause:  "NodeConnectionRefused",
			SummaryKo:  "대상 서비스 포트에 연결하지 못해 TCP 커넥션이 거부되었습니다 (ECONNREFUSED).",
			ActionKo:   "1) 백엔드 DB 또는 마이크로서비스 파드가 가동 중인지 확인하세요. 2) 호스트네임 및 포트 번호 환경변수를 점검하세요.",
			SummaryEn:  "Node.js ECONNREFUSED: connection refused by target host and port.",
			ActionEn:   "1) Verify upstream service/database pod status. 2) Check host and port environment variables.",
		},
		{
			ErrorClass: "SyntaxError",
			Language:   "JavaScript/TypeScript",
			Category:   "Application",
			RootCause:  "NodeSyntaxError",
			SummaryKo:  "자바스크립트/타입스크립트 코드 문법 오류(예약어 오용, 괄호 불일치 등) 또는 잘못된 JSON 파싱으로 실행이 실패했습니다.",
			ActionKo:   "1) JSON.parse() 호출 지점에 try-catch 블록을 추가하세요. 2) 빌드 산출물(dist/bundle)의 트랜스파일 문법 오류를 점검하세요.",
			SummaryEn:  "Node.js SyntaxError: invalid JavaScript syntax or malformed JSON parsing.",
			ActionEn:   "1) Wrap JSON.parse() in try-catch. 2) Verify TypeScript build compilation output.",
		},
		{
			ErrorClass: "ERR_MODULE_NOT_FOUND",
			Language:   "JavaScript/TypeScript",
			Category:   "Configuration",
			RootCause:  "NodeModuleNotFound",
			SummaryKo:  "require() 또는 import 대상 npm 패키지나 로컬 모듈 파일을 찾을 수 없습니다.",
			ActionKo:   "1) Dockerfile에서 'npm install' 또는 'yarn install --production'이 정상 실행되었는지 확인하세요. 2) package.json의 dependencies를 확인하세요.",
			SummaryEn:  "Node.js ERR_MODULE_NOT_FOUND: cannot find module dependency.",
			ActionEn:   "1) Ensure npm install ran in Docker build. 2) Check package.json dependencies and relative import paths.",
		},
		{
			ErrorClass: "ECONNRESET",
			Language:   "JavaScript/TypeScript",
			Category:   "Dependency",
			RootCause:  "NodeConnectionReset",
			SummaryKo:  "원격 서버 또는 인프라 프록시가 기존 TCP 커넥션을 강제로 종료했습니다 (ECONNRESET).",
			ActionKo:   "1) 업스트림 서버(DB, Redis, 외부 API)의 keepAlive 및 idle 타임아웃 설정을 확인하세요. 2) 네트워크 패킷 유실을 점검하세요.",
			SummaryEn:  "Node.js ECONNRESET: connection reset by peer.",
			ActionEn:   "1) Check upstream server keep-alive and idle connection timeouts. 2) Review network ingress/proxy logs.",
		},
		{
			ErrorClass: "ETIMEDOUT",
			Language:   "JavaScript/TypeScript",
			Category:   "Dependency",
			RootCause:  "NodeSocketTimeout",
			SummaryKo:  "원격 호스트 연결 또는 데이터 수신 중 소켓 타임아웃이 초과되었습니다 (ETIMEDOUT).",
			ActionKo:   "1) 대상 서비스의 지연 시간 및 방화벽/NetworkPolicy를 점검하세요. 2) HTTP 클라이언트(Axios/Fetch)의 timeout 설정을 상향하세요.",
			SummaryEn:  "Node.js ETIMEDOUT: connection timed out.",
			ActionEn:   "1) Check upstream latency and network firewall rules. 2) Increase HTTP client timeout.",
		},
		{
			ErrorClass: "ENOTFOUND",
			Language:   "JavaScript/TypeScript",
			Category:   "Configuration",
			RootCause:  "NodeDNSLookupFailed",
			SummaryKo:  "DNS 서버에서 요청된 도메인 네임의 IP 주소를 조회하지 못했습니다 (ENOTFOUND getaddrinfo).",
			ActionKo:   "1) 환경변수에 등록된 호스트네임 오탈자를 확인하세요. 2) K8s 클러스터 내부 CoreDNS 상태를 점검하세요.",
			SummaryEn:  "Node.js ENOTFOUND: DNS lookup failed for target hostname.",
			ActionEn:   "1) Check host URL for typos. 2) Verify cluster CoreDNS health.",
		},
		{
			ErrorClass: "EADDRINUSE",
			Language:   "JavaScript/TypeScript",
			Category:   "Configuration",
			RootCause:  "NodePortAlreadyInUse",
			SummaryKo:  "웹서버(Express/NestJS)가 바인딩하려는 포트 번호가 이미 다른 프로세스에 의해 점유되어 있습니다 (EADDRINUSE).",
			ActionKo:   "1) PORT 환경변수 설정이 중복되었는지 확인하세요. 2) 파드 내 다른 컨테이너가 동일 포트를 리스닝하고 있는지 확인하세요.",
			SummaryEn:  "Node.js EADDRINUSE: port already in use by another process.",
			ActionEn:   "1) Change PORT environment variable. 2) Ensure no duplicate background listener processes exist in the container.",
		},
		{
			ErrorClass: "AxiosError",
			Language:   "JavaScript/TypeScript",
			Category:   "Dependency",
			RootCause:  "NodeAxiosRequestFailure",
			SummaryKo:  "외부 HTTP API 호출 중 5xx 서버 오류 또는 네트워크 연결 단절로 AxiosError가 발생했습니다.",
			ActionKo:   "1) 호출 대상 엔드포인트 URL과 응답 상태 코드를 확인하세요. 2) axios-retry 미들웨어로 지수 백오프 재시도를 적용하세요.",
			SummaryEn:  "Node.js AxiosError: HTTP request failed with non-2xx status code or network disconnect.",
			ActionEn:   "1) Inspect target API status code and error payload. 2) Implement retry with axios-retry.",
		},
		{
			ErrorClass: "PrismaClientInitializationError",
			Language:   "JavaScript/TypeScript",
			Category:   "Dependency",
			RootCause:  "NodePrismaInitError",
			SummaryKo:  "Prisma ORM 엔진이 DATABASE_URL에 연결하지 못했거나 쿼리 엔진 바이너리 기동에 실패했습니다.",
			ActionKo:   "1) DATABASE_URL 환경변수 및 K8s Service DNS를 확인하세요. 2) 베이스 이미지의 glibc/musl 바이너리 호환성(Alpine: 'prisma generate')을 점검하세요.",
			SummaryEn:  "PrismaClientInitializationError: failed to connect to database or query engine.",
			ActionEn:   "1) Verify DATABASE_URL connection string and network reachability. 2) Ensure prisma engine binary compatibility.",
		},
		{
			ErrorClass: "QueryFailedError",
			Language:   "JavaScript/TypeScript",
			Category:   "Application",
			RootCause:  "NodeTypeORMQueryFailed",
			SummaryKo:  "TypeORM에서 SQL 쿼리 실행 중 문법 오류 또는 컬럼/테이블 부재로 인해 쿼리가 실패했습니다.",
			ActionKo:   "1) 엔티티 스키마 정의와 데이터베이스 테이블 구조를 일치시키세요. 2) TypeORM 마이그레이션(migration:run)을 실행하세요.",
			SummaryEn:  "TypeORM QueryFailedError: database query execution failed.",
			ActionEn:   "1) Verify entity column mappings match the database schema. 2) Run pending TypeORM migrations.",
		},
	}

	for _, e := range entries {
		key1 := "javascript/typescript:" + strings.ToLower(e.ErrorClass)
		key2 := "node:" + strings.ToLower(e.ErrorClass)
		SemanticCatalog[key1] = e
		SemanticCatalog[key2] = e
	}
}

// ==================== Go Catalog ====================
func loadGoCatalog() {
	entries := []SemanticCatalogEntry{
		{
			ErrorClass: "Panic",
			Language:   "Go",
			Category:   "Application",
			RootCause:  "GoNilPointerPanic",
			SummaryKo:  "Go 런타임에서 초기화되지 않은 nil 포인터 역참조 또는 슬라이스/맵 범위 초과로 패닉이 발생했습니다.",
			ActionKo:   "1) 포인터 역참조 전 'if ptr != nil' 검사를 수행하세요. 2) HTTP 핸들러 상단에 recover() 미들웨어를 등록하여 파드 크래시를 방지하세요.",
			SummaryEn:  "Go Runtime Panic: nil pointer dereference or slice bounds out of range.",
			ActionEn:   "1) Add nil-checks before dereferencing pointers ('if ptr != nil'). 2) Implement recover() middleware in HTTP handlers.",
		},
		{
			ErrorClass: "ConcurrentMapReadWrite",
			Language:   "Go",
			Category:   "Application",
			RootCause:  "GoConcurrentMapPanic",
			SummaryKo:  "여러 고루틴(Goroutine)에서 동기화 락(sync.RWMutex) 없이 동일한 맵에 동시 읽기/쓰기를 수행하여 런타임이 즉시 강제 종료되었습니다.",
			ActionKo:   "1) 표준 map 대신 'sync.RWMutex'로 임계 영역을 보호하거나 'sync.Map'을 사용하세요. 2) 'go test -race'로 데이터 레이스를 사전에 탐지하세요.",
			SummaryEn:  "Go Fatal Error: concurrent map read and map write.",
			ActionEn:   "1) Protect map access with sync.RWMutex or adopt sync.Map. 2) Run 'go test -race' to detect data races.",
		},
		{
			ErrorClass: "Deadlock",
			Language:   "Go",
			Category:   "Application",
			RootCause:  "GoGoroutineDeadlock",
			SummaryKo:  "모든 고루틴이 채널 수신 또는 뮤텍스 락 대기 상태에 빠져 영구적 교착 상태(Deadlock)가 발생했습니다.",
			ActionKo:   "1) 채널 버퍼 크기 및 송수신 쌍(Pair)이 올바르게 닫히는지(close) 확인하세요. 2) 뮤텍스 락 획득 순서를 일관되게 정렬하세요.",
			SummaryEn:  "Go Fatal Error: all goroutines are asleep - deadlock!",
			ActionEn:   "1) Verify channel buffer sizes and ensure senders/receivers close properly. 2) Enforce consistent lock acquisition order.",
		},
		{
			ErrorClass: "ContextDeadlineExceeded",
			Language:   "Go",
			Category:   "Dependency",
			RootCause:  "GoContextDeadlineExceeded",
			SummaryKo:  "컨텍스트 타임아웃(context.WithTimeout/WithDeadline)이 초과되어 HTTP 또는 gRPC 호출이 취소되었습니다.",
			ActionKo:   "1) 타임아웃 제한 시간(예: 3s -> 10s)을 상향하세요. 2) DB 슬로우 쿼리 또는 외부 API 응답 지연을 점검하세요.",
			SummaryEn:  "Go Context Deadline Exceeded: context timeout expired before operation finished.",
			ActionEn:   "1) Increase context timeout threshold. 2) Profile slow database queries or remote RPC calls.",
		},
		{
			ErrorClass: "BrokenPipe",
			Language:   "Go",
			Category:   "Dependency",
			RootCause:  "GoBrokenPipe",
			SummaryKo:  "클라이언트가 연결을 중도에 끊었거나 소켓 파이프가 닫힌 상태에서 네트워크 쓰기(write)를 시도했습니다 (write: broken pipe).",
			ActionKo:   "1) 클라이언트 사이드 타임아웃 설정을 점검하세요. 2) 대용량 응답 스트리밍 시 네트워크 버퍼 크기를 점검하세요.",
			SummaryEn:  "Go Broken Pipe: write on a closed socket or pipe.",
			ActionEn:   "1) Inspect client-side connection timeout behavior. 2) Handle broken pipe gracefully in HTTP streaming handlers.",
		},
		{
			ErrorClass: "SQLNoRows",
			Language:   "Go",
			Category:   "Application",
			RootCause:  "GoSQLNoRows",
			SummaryKo:  "database/sql의 QueryRow() 조회 결과 행이 존재하지 않습니다 (sql.ErrNoRows).",
			ActionKo:   "1) 'if errors.Is(err, sql.ErrNoRows)' 분기 처리를 통해 404 상태 코드 또는 nil을 반환하세요. 2) 쿼리 조건절을 확인하세요.",
			SummaryEn:  "Go sql: no rows in result set.",
			ActionEn:   "1) Check 'errors.Is(err, sql.ErrNoRows)' and handle gracefully. 2) Verify SQL query filter.",
		},
		{
			ErrorClass: "RedisNil",
			Language:   "Go",
			Category:   "Application",
			RootCause:  "GoRedisNilKey",
			SummaryKo:  "Redis에 요청한 키가 존재하지 않습니다 (redis.Nil).",
			ActionKo:   "1) 'if errors.Is(err, redis.Nil)'로 캐시 미스(Cache Miss)를 처리하고 원본 DB에서 데이터를 조회하세요. 2) 키 만료시간(TTL)을 점검하세요.",
			SummaryEn:  "Go Redis Nil: requested key does not exist in Redis cache.",
			ActionEn:   "1) Handle cache miss with 'errors.Is(err, redis.Nil)' and fetch from primary database. 2) Verify TTL settings.",
		},
	}

	for _, e := range entries {
		key1 := "go:" + strings.ToLower(e.ErrorClass)
		SemanticCatalog[key1] = e
	}
}

// ==================== System & Network Catalog ====================
func loadSystemCatalog() {
	entries := []SemanticCatalogEntry{
		{
			ErrorClass: "ConnectionRefused",
			Language:   "System",
			Category:   "Dependency",
			RootCause:  "NetworkConnectionRefused",
			SummaryKo:  "대상 원격 호스트 및 포트에 TCP 연결을 수립하지 못하고 즉시 거부되었습니다 (포트 리스닝 부재 또는 방화벽 차단).",
			ActionKo:   "1) 연결하려는 K8s Service 및 Pod 가동 상태를 확인하세요. 2) NetworkPolicy에서 송신(Egress)/수신(Ingress) 트래픽이 허용되어 있는지 확인하세요.",
			SummaryEn:  "TCP Connection Refused: target endpoint is not listening or blocked by network policy.",
			ActionEn:   "1) Check target K8s Service and Pod status. 2) Verify NetworkPolicy ingress and egress rules.",
		},
		{
			ErrorClass: "NetworkTimeout",
			Language:   "System",
			Category:   "Dependency",
			RootCause:  "NetworkSocketTimeout",
			SummaryKo:  "네트워크 라우팅 실패, DNS 조회 실패 또는 원격 엔드포인트 응답 지연으로 소켓 I/O 타임아웃이 발생했습니다.",
			ActionKo:   "1) CoreDNS 상태 및 K8s 클러스터 내부 도메인 해석(.svc.cluster.local)을 점검하세요. 2) 클라이언트의 connect_timeout을 점검하세요.",
			SummaryEn:  "Network Socket Timeout: I/O timeout during network read/write or DNS resolution.",
			ActionEn:   "1) Check CoreDNS health and cluster domain resolution. 2) Verify client connection timeouts.",
		},
	}

	for _, e := range entries {
		key1 := "system:" + strings.ToLower(e.ErrorClass)
		SemanticCatalog[key1] = e
		SemanticCatalog[strings.ToLower(e.ErrorClass)] = e
	}
}

// SynthesizeDiagnosisFromUniversal produces an enriched, LLM-grade diagnosis from universal crash analysis.
func SynthesizeDiagnosisFromUniversal(u *UniversalCrashAnalysis, lang string) (rootCause, summary, action string) {
	if u == nil {
		return "ApplicationRuntimeError", "애플리케이션 프로세스가 에러로 종료되었습니다.", "컨테이너 로그를 점검하세요."
	}

	entry, found := LookupSemanticCatalog(u.Language, u.ErrorClass)
	if !found {
		// Dynamic generation if error class is not explicitly in catalog
		if u.ErrorClass != "" {
			rootCause = fmt.Sprintf("%s%s", u.Language, u.ErrorClass)
			rootCause = strings.ReplaceAll(rootCause, "/", "")
			rootCause = strings.ReplaceAll(rootCause, "-", "")
			rootCause = strings.ReplaceAll(rootCause, " ", "")
		} else {
			rootCause = "ApplicationUnhandledException"
		}

		locStr := ""
		if u.ErrorLocation != "" {
			locStr = fmt.Sprintf(" (%s)", u.ErrorLocation)
		}

		if lang == "ko" {
			summary = fmt.Sprintf("%s %s 예외 발생%s: %s", u.Language, u.ErrorClass, locStr, u.ErrorMessage)
			action = fmt.Sprintf("%s%s 라인의 예외 원인을 확인하고 예외 처리 또는 유효성 검증을 적용하세요.", u.ErrorClass, locStr)
		} else {
			summary = fmt.Sprintf("%s unhandled %s%s: %s", u.Language, u.ErrorClass, locStr, u.ErrorMessage)
			action = fmt.Sprintf("Inspect the origin of %s%s and add proper error handling or boundary validation.", u.ErrorClass, locStr)
		}
		return rootCause, summary, action
	}

	rootCause = entry.RootCause
	locStr := ""
	if u.ErrorLocation != "" {
		locStr = fmt.Sprintf(" (%s)", u.ErrorLocation)
	}

	if lang == "ko" {
		if u.ErrorMessage != "" {
			summary = fmt.Sprintf("%s: %s%s", entry.SummaryKo, u.ErrorMessage, locStr)
		} else {
			summary = fmt.Sprintf("%s%s", entry.SummaryKo, locStr)
		}
		action = entry.ActionKo
	} else {
		if u.ErrorMessage != "" {
			summary = fmt.Sprintf("%s: %s%s", entry.SummaryEn, u.ErrorMessage, locStr)
		} else {
			summary = fmt.Sprintf("%s%s", entry.SummaryEn, locStr)
		}
		action = entry.ActionEn
	}

	return rootCause, summary, action
}
