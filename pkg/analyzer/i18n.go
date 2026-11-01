package analyzer

import (
	"strings"
)

type LocalizedText struct {
	SummaryTpl        string
	RecommendedAction string
}

// i18nRegistry stores localized messages keyed by [lang][rootCause]
var i18nRegistry = map[string]map[string]LocalizedText{
	"ko": {
		"OOMKilled": {
			SummaryTpl:        "컨테이너 메모리 제한(Limit)을 초과하여 Linux 커널 OOM Killer(cgroup 메모리 고갈)에 의해 강제 종료되었습니다.",
			RecommendedAction: "파드 스펙의 메모리 제한(resources.limits.memory)을 증설하거나 애플리케이션의 메모리 누수를 프로파일링하세요.",
		},
		"ProbableOOMKilled": {
			SummaryTpl:        "메모리 제한이 설정된 상태에서 메모리 고갈 관련 에러와 함께 프로세스가 강제 사살(SIGKILL/137)되었습니다.",
			RecommendedAction: "파드 메모리 제한을 증설하거나 힙 덤프를 통해 메모리 소비를 최적화하세요.",
		},
		"SystemOOMKilled": {
			SummaryTpl:        "호스트 또는 cgroup에서 Linux 커널 OOM Killer가 호출되었습니다: %s",
			RecommendedAction: "노드 메모리 사용률을 점검하고 파드 컨테이너의 메모리 Limit을 증설하세요.",
		},
		"NodeMemoryPressure": {
			SummaryTpl:        "노드 수준에서 메모리 부족 상태(MemoryPressure)가 발생했습니다: %s",
			RecommendedAction: "노드 풀의 메모리 용량을 증설하거나 노드에 과도하게 할당된 워크로드를 분산하세요.",
		},
		"NodeDiskPressure": {
			SummaryTpl:        "노드 루트 디스크 또는 임시 스토리지 부족(DiskPressure)이 발생했습니다: %s",
			RecommendedAction: "노드의 사용하지 않는 도커 이미지/컨테이너를 정리하거나 노드 디스크 용량을 확장하세요.",
		},
		"SidecarCascadeFailure": {
			SummaryTpl:        "파드 내 연관 사이드카/프록시 컨테이너('%s')의 장애로 인해 메인 컨테이너가 연쇄 실패했습니다.",
			RecommendedAction: "사이드카 컨테이너('%s')의 로그 및 상태를 점검하고 의존성 기동 순서를 조정하세요.",
		},
		"InitContainerFailed": {
			SummaryTpl:        "초기화 컨테이너(initContainer '%s')가 실패하여 메인 애플리케이션 컨테이너가 기동되지 못했습니다.",
			RecommendedAction: "초기화 컨테이너 '%s'의 로그 및 종료 코드를 확인하여 DB 마이그레이션 또는 사전 설정을 수정하세요.",
		},
		"PermissionDenied": {
			SummaryTpl:        "컨테이너 진입점 바이너리/스크립트의 실행 권한이 없습니다 (Exit code 126).",
			RecommendedAction: "Dockerfile 또는 진입점 스크립트에 실행 권한(chmod +x)을 부여하세요.",
		},
		"CommandNotFound": {
			SummaryTpl:        "컨테이너 진입점 실행 파일이나 셸 명령어를 이미지 PATH에서 찾을 수 없습니다 (Exit code 127).",
			RecommendedAction: "Dockerfile의 ENTRYPOINT/CMD 경로를 확인하고 베이스 이미지에 필요한 셸 및 바이너리가 존재하는지 확인하세요.",
		},
		"GracefulShutdownTimeout": {
			SummaryTpl:        "프로세스가 SIGTERM 수신 후 종료 유예시간(terminationGracePeriodSeconds: %s) 내에 정상 종료되지 않아 SIGKILL(137)로 강제 사살되었습니다.",
			RecommendedAction: "SIGTERM 신호 핸들러의 커넥션 드레인 로직을 점검하거나 파드 스펙의 terminationGracePeriodSeconds를 늘리세요.",
		},
		"ReadOnlyRootFilesystem": {
			SummaryTpl:        "읽기 전용 파일시스템(readOnlyRootFilesystem) 제약 상태에서 파일 쓰기 시도로 인해 프로세스가 실패했습니다.",
			RecommendedAction: "파드 SecurityContext를 확인하고, 임시 쓰기가 필요한 디렉토리(/tmp 등)를 emptyDir 볼륨으로 마운트하세요.",
		},
		"HeapCorruption": {
			SummaryTpl:        "glibc 힙 메모리 손상 (Double Free 또는 잘못된 포인터 해제)으로 인해 비정상 종료되었습니다.",
			RecommendedAction: "C/C++ 네이티브 확장 모듈 또는 CGO/JNI 바인딩의 메모리 할당 및 해제 로직을 점검하세요.",
		},
		"NodeV8FatalError": {
			SummaryTpl:        "Node.js V8 엔진에서 JavaScript 힙 메모리 고갈로 치명적 오류가 발생했습니다.",
			RecommendedAction: "NODE_OPTIONS에 '--max-old-space-size'를 확장하거나 객체 캐시 누수를 프로파일링하세요.",
		},
		"LivenessProbeFailure": {
			SummaryTpl:        "Liveness Probe(활성도 검사)가 반복 실패하여 Kubelet이 컨테이너를 재시작했습니다.",
			RecommendedAction: "헬스체크 엔드포인트(/healthz)의 지연 시간을 점검하고 probe의 timeoutSeconds/failureThreshold를 조정하세요.",
		},
		"StartupProbeFailure": {
			SummaryTpl:        "애플리케이션 초기화 시간이 지정된 시간 내에 완료되지 않아 Startup Probe가 실패했습니다.",
			RecommendedAction: "startupProbe의 initialDelaySeconds 또는 failureThreshold를 늘려 초기화 시간을 충분히 확보하세요.",
		},
		"NodeEviction": {
			SummaryTpl:        "노드의 가용 리소스(메모리 또는 디스크) 부족으로 인해 파드가 노드에서 축출(Eviction)되었습니다.",
			RecommendedAction: "노드의 리소스 사용량을 점검하거나 파드를 여유 있는 다른 노드로 스케줄링하세요.",
		},
		"Preempted": {
			SummaryTpl:        "더 높은 우선순위(PriorityClass)를 가진 파드에게 리소스를 양보하기 위해 선점(Preemption)되었습니다.",
			RecommendedAction: "파드의 PriorityClass를 검토하거나 노드 풀 용량을 증설하세요.",
		},
		"SigkillTerminated": {
			SummaryTpl:        "프로세스가 강제 종료 신호(SIGKILL, 137)를 수신했습니다. 기록되지 않은 OOM, Probe 타임아웃 또는 강제 축출 가능성이 높습니다.",
			RecommendedAction: "노드 dmesg 로그에서 OOM Killer 발생 여부를 확인하거나 Liveness Probe 타임아웃을 점검하세요.",
		},
		"SigtermShutdown": {
			SummaryTpl:        "배포 롤아웃, 오토스케일링, 노드 드레인 등의 이유로 정상 종료 신호(SIGTERM, 143)를 수신하고 종료되었습니다.",
			RecommendedAction: "배포 작업 중 발생한 정상 재시작인지 확인하고, 예상치 못한 경우 Deployment 이력을 점검하세요.",
		},
		"SegmentationFault": {
			SummaryTpl:        "잘못된 메모리 주소 참조(Segmentation Fault, SIGSEGV, 139)로 인해 프로세스가 비정상 종료되었습니다.",
			RecommendedAction: "네이티브 C/C++ 라이브러리, Unsafe 포인터 또는 손상된 공유 메모리 객체를 점검하세요.",
		},
		"BusError": {
			SummaryTpl:        "정렬되지 않은 메모리 접근 또는 mmap 파일 오류로 인해 Bus Error(SIGBUS, 135)가 발생했습니다.",
			RecommendedAction: "메모리 매핑(mmap) 크기 한도 또는 볼륨 마운트된 공유 메모리 상태를 점검하세요.",
		},
		"NativeAbort": {
			SummaryTpl:        "프로세스가 SIGABRT(134) 신호 또는 네이티브 assert 실패로 인해 강제 중단되었습니다.",
			RecommendedAction: "C/C++ 수준의 assert문 조건 또는 네이티브 라이브러리 초기화 실패 여부를 점검하세요.",
		},
		"JVMHeapOOM": {
			SummaryTpl:        "JVM 힙 메모리가 고갈되었습니다 (java.lang.OutOfMemoryError: Java heap space).",
			RecommendedAction: "JVM 힙 제한(-Xmx) 및 파드 메모리 제한을 증설하거나 힙 덤프를 분석하여 메모리 누수를 해결하세요.",
		},
		"JVMMetaspaceOOM": {
			SummaryTpl:        "JVM 메타스페이스(Metaspace) 메모리가 고갈되었습니다.",
			RecommendedAction: "-XX:MaxMetaspaceSize를 증설하거나 동적 프록시/클래스로더 누수를 점검하세요.",
		},
		"JVMDirectMemoryOOM": {
			SummaryTpl:        "JVM 다이렉트 버퍼(Direct Memory) 메모리가 고갈되었습니다.",
			RecommendedAction: "NIO / Netty의 ByteBuf 해제 누락 여부를 확인하거나 -XX:MaxDirectMemorySize를 조정하세요.",
		},
		"JVMThreadExhaustion": {
			SummaryTpl:        "OS 네이티브 스레드 생성 한도에 도달하여 JVM 스레드 생성이 실패했습니다.",
			RecommendedAction: "스레드 풀 누수를 점검하거나 -Xss(스택 크기) 축소 및 cgroup pids.max를 증설하세요.",
		},
		"JVMGCOverheadOOM": {
			SummaryTpl:        "JVM GC 오버헤드 한도를 초과했습니다 (GC가 CPU 시간의 대부분을 소비함).",
			RecommendedAction: "루프 내 객체 과다 생성을 최적화하거나 JVM 힙 크기(-Xmx)를 확장하세요.",
		},
		"JVMCompressedClassSpaceOOM": {
			SummaryTpl:        "JVM 압축 클래스 공간(Compressed Class Space) 메모리가 고갈되었습니다.",
			RecommendedAction: "-XX:CompressedClassSpaceSize를 증설하거나 불필요한 동적 클래스 생성을 점검하세요.",
		},
		"JVMStackOverflow": {
			SummaryTpl:        "과도한 재귀 호출로 인해 JVM 호출 스택이 오버플로우되었습니다 (StackOverflowError).",
			RecommendedAction: "호출 스택의 무한 재귀 함수 로직을 점검하거나 스레드 스택 크기(-Xss)를 검토하세요.",
		},
		"JVMNullPointer": {
			SummaryTpl:        "JVM NullPointerException 예외가 발생하여 프로세스가 중단되었습니다.",
			RecommendedAction: "오류 발생 소스코드 위치의 Null 검증 및 객체 초기화 로직을 보완하세요.",
		},
		"JVMClassNotFound": {
			SummaryTpl:        "JVM 클래스패스에서 필요한 클래스나 라이브러리를 찾을 수 없습니다: %s",
			RecommendedAction: "Jar 패키징 및 의존성 설정을 확인하여 누락된 라이브러리를 추가하세요.",
		},
		"SpringPortInUse": {
			SummaryTpl:        "스프링 부트 웹 서버 포트가 이미 다른 프로세스에 의해 점유되어 있습니다.",
			RecommendedAction: "application.yml에서 server.port를 변경하거나 동일 포트를 사용하는 프로세스를 종료하세요.",
		},
		"SpringHikariPoolExhaustion": {
			SummaryTpl:        "HikariCP 데이터베이스 커넥션 풀이 고갈되어 연결 대기 시간이 초과되었습니다.",
			RecommendedAction: "spring.datasource.hikari.maximum-pool-size를 늘리거나 긴 트랜잭션을 최적화하세요.",
		},
		"SpringBootStartupFailure": {
			SummaryTpl:        "스프링 부트 애플리케이션 컨텍스트 초기화 실패 (BeanCreationException 등).",
			RecommendedAction: "설정 파일(application.yml)의 프로퍼티 값 및 누락된 빈(Bean) 의존성을 확인하세요.",
		},
		"JVMSegfaultCrash": {
			SummaryTpl:        "JVM 네이티브 영역(JNI, C++ 내부 엔진)에서 SIGSEGV 치명적 충돌이 발생했습니다.",
			RecommendedAction: "hs_err_pid 로그 파일의 네이티브 프레임을 분석하거나 JNI 드라이버/JDK 버전을 업데이트하세요.",
		},
		"KafkaBrokerUnavailable": {
			SummaryTpl:        "Kafka 브로커 연결 실패 또는 클러스터 메타데이터 갱신 타임아웃이 발생했습니다.",
			RecommendedAction: "Kafka bootstrap 서버 주소, 브로커 파드 가동 상태 및 네트워크 라우팅을 점검하세요.",
		},
		"ElasticsearchConnectTimeout": {
			SummaryTpl:        "엘라스틱서치(Elasticsearch) 클러스터 연결 시간이 초과되었습니다.",
			RecommendedAction: "Elasticsearch 호스트 가용성 및 클라이언트 타임아웃 설정을 점검하세요.",
		},
		"GoPanic": {
			SummaryTpl:        "Go 런타임 패닉(Panic) 크래시: %s",
			RecommendedAction: "콜스택을 분석하여 Nil 포인터 역참조 또는 슬라이스 범위 초과(Index out of range)를 예외 처리하세요.",
		},
		"GoDeadlock": {
			SummaryTpl:        "Go 런타임에서 모든 고루틴이 영구 대기 상태에 빠진 교착 상태(Deadlock)를 감지했습니다.",
			RecommendedAction: "뮤텍스 Lock/Unlock 순서와 채널 송수신 동기화 로직을 점검하세요.",
		},
		"GoConcurrentMapAccess": {
			SummaryTpl:        "동기화 락 없이 표준 맵에 동시 읽기/쓰기가 발생하여 Go 프로세스가 충돌했습니다.",
			RecommendedAction: "sync.RWMutex로 맵 접근을 보호하거나 sync.Map으로 대체하세요.",
		},
		"GoNilPointerDereference": {
			SummaryTpl:        "Go 런타임 Nil 포인터 역참조 패닉(nil pointer dereference)이 발생했습니다.",
			RecommendedAction: "구조체 포인터 또는 인터페이스를 참조하기 전에 nil 검사 조건을 추가하세요.",
		},
		"GoIndexOutOfRange": {
			SummaryTpl:        "Go 슬라이스 또는 배열의 인덱스 범위를 초과하여 패닉이 발생했습니다.",
			RecommendedAction: "인덱스로 접근하기 전에 len() 길이를 사전에 확인하세요.",
		},
		"GoSliceBoundsOutOfRange": {
			SummaryTpl:        "Go 서브 슬라이스 범위([low:high])가 용량을 초과하여 패닉이 발생했습니다.",
			RecommendedAction: "슬라이싱 인덱스가 len() 및 cap() 범위를 넘지 않도록 검증하세요.",
		},
		"GoRuntimeOOM": {
			SummaryTpl:        "Go 런타임 메모리 할당자 고갈(out of memory)로 인해 프로세스가 강제 중단되었습니다.",
			RecommendedAction: "pprof 힙 프로파일을 점검하거나 파드 메모리 제한을 증설하세요.",
		},
		"GoStackOverflow": {
			SummaryTpl:        "Go 고루틴 호출 스택이 오버플로우되었습니다 (무한 재귀 호출).",
			RecommendedAction: "스택트레이스에 반복 호출되는 함수의 종료 조건을 확인하세요.",
		},
		"GoPortInUse": {
			SummaryTpl:        "Go HTTP/TCP 리스너 바인딩 실패 (address already in use).",
			RecommendedAction: "서버 설정 포트를 변경하거나 포트를 선점한 프로세스를 확인하세요.",
		},
		"PythonUnhandledException": {
			SummaryTpl:        "처리되지 않은 파이썬 예외(%s)로 인해 프로세스가 종료되었습니다.",
			RecommendedAction: "오류 발생 위치에 try-except 예외 처리를 보강하고 입력 데이터 유효성을 검증하세요.",
		},
		"AppUnhandledException": {
			SummaryTpl:        "처리되지 않은 애플리케이션 예외(%s)로 인해 프로세스가 종료되었습니다.",
			RecommendedAction: "오류 스니펫의 스택 트레이스를 확인하여 예외 핸들러를 보강하세요.",
		},
		"PythonMemoryError": {
			SummaryTpl:        "파이썬 프로세스의 메모리 허용량을 초과했습니다 (MemoryError).",
			RecommendedAction: "대용량 데이터프레임/배치 로딩을 분할 처리하거나 파드 메모리 제한을 증설하세요.",
		},
		"PythonModuleNotFound": {
			SummaryTpl:        "파이썬 모듈 의존성을 찾을 수 없습니다: %s",
			RecommendedAction: "requirements.txt에 누락된 패키지를 추가하고 이미지를 다시 빌드하세요.",
		},
		"PythonRecursionError": {
			SummaryTpl:        "파이썬 최대 재귀 깊이 한도를 초과했습니다 (RecursionError).",
			RecommendedAction: "재귀 함수의 탈출 조건을 검증하거나 반복문 기반 로직으로 전환하세요.",
		},
		"PythonSyntaxError": {
			SummaryTpl:        "파이썬 문법 또는 인덴테이션(들여쓰기) 오류로 인해 스크립트 실행이 중단되었습니다.",
			RecommendedAction: "소스코드 인덴테이션 공백 및 파이썬 버전별 문법 호환성을 확인하세요.",
		},
		"PythonAttributeError": {
			SummaryTpl:        "파이썬 NoneType 객체 속성 참조 오류(AttributeError): %s",
			RecommendedAction: "함수나 쿼리 반환값이 None인지 검증한 후 속성에 접근하세요.",
		},
		"PythonKeyOrIndexError": {
			SummaryTpl:        "파이썬 딕셔너리 키 누락(KeyError) 또는 리스트 범위 초과(IndexError)가 발생했습니다.",
			RecommendedAction: "dict.get(key, default)를 사용하거나 리스트 길이를 사전에 점검하세요.",
		},
		"PythonWorkerTimeout": {
			SummaryTpl:        "Gunicorn/Uvicorn 워커 프로세스 타임아웃으로 인해 관리자에 의해 강제 사살되었습니다.",
			RecommendedAction: "Gunicorn --timeout 파라미터를 늘리거나 이벤트 루프를 블로킹하는 긴 작업을 최적화하세요.",
		},
		"PythonDjangoDBConnRefused": {
			SummaryTpl:        "Django / Psycopg2 데이터베이스 서버 연결이 거부되었습니다.",
			RecommendedAction: "데이터베이스 컨테이너의 가동 상태, 포트, 호스트 설정을 확인하세요.",
		},
		"PythonSQLAlchemyPoolExhausted": {
			SummaryTpl:        "SQLAlchemy 커넥션 풀 용량이 고갈되었습니다 (QueuePool limit reached).",
			RecommendedAction: "pool_size 및 max_overflow 설정을 확장하고 세션 해제(close) 누락을 점검하세요.",
		},
		"PyTorchCUDA_OOM": {
			SummaryTpl:        "PyTorch CUDA GPU VRAM 메모리가 고갈되었습니다 (CUDA out of memory).",
			RecommendedAction: "배치 크기(batch size)를 줄이거나 GPU VRAM 용량이 큰 노드로 이전하세요.",
		},
		"NodeHeapOOM": {
			SummaryTpl:        "Node.js V8 엔진의 자바스크립트 힙 메모리가 고갈되었습니다.",
			RecommendedAction: "NODE_OPTIONS=\"--max-old-space-size=4096\"으로 힙 크기를 늘리거나 메모리 누수를 프로파일링하세요.",
		},
		"NodeCallStackExceeded": {
			SummaryTpl:        "Node.js 최대 호출 스택 크기를 초과했습니다 (Maximum call stack size exceeded).",
			RecommendedAction: "재귀 함수의 종료 조건을 확인하여 무한 루프를 해결하세요.",
		},
		"NodeTypeError": {
			SummaryTpl:        "Node.js TypeError: undefined 또는 null의 속성을 읽을 수 없습니다.",
			RecommendedAction: "옵셔널 체이닝(?.)을 적용하거나 데이터 유효성을 검증하세요.",
		},
		"NodeModuleNotFound": {
			SummaryTpl:        "Node.js 모듈 의존성을 찾을 수 없습니다: %s",
			RecommendedAction: "package.json 의존성을 확인하고 빌드 시 npm/yarn install이 정상 실행되었는지 확인하세요.",
		},
		"NodePortInUse": {
			SummaryTpl:        "Node.js 서버 포트가 이미 사용 중입니다 (EADDRINUSE).",
			RecommendedAction: "PORT 환경변수를 다른 번호로 변경하세요.",
		},
		"NodePrismaInitFailed": {
			SummaryTpl:        "Prisma 클라이언트 데이터베이스 연결 초기화가 실패했습니다.",
			RecommendedAction: "DATABASE_URL 환경변수 및 DB 서버의 네트워크 접근을 확인하세요.",
		},
		"NodeMongooseTimeout": {
			SummaryTpl:        "Mongoose MongoDB 레플리카셋 연결 시간이 초과되었습니다.",
			RecommendedAction: "MongoDB 접속 URI 및 네트워크 보안 그룹을 점검하세요.",
		},
		"NodeUnhandledPromiseRejection": {
			SummaryTpl:        "처리되지 않은 프로미스 거부(Unhandled Promise Rejection)로 충돌했습니다.",
			RecommendedAction: "비동기 Promise 호출에 .catch() 핸들러를 추가하거나 try/catch 블록으로 감싸세요.",
		},
		"CircularImportError": {
			SummaryTpl:        "Python 모듈 상호 순환 참조(Circular Import)가 발생했습니다: %s",
			RecommendedAction: "함수 내부 로컬 임포트를 적용하거나 공유 모델을 별도 모듈로 분리하세요.",
		},
		"SpringCircularDependency": {
			SummaryTpl:        "Spring Boot 빈 상호 순환 참조(Circular Dependency)로 인해 컨텍스트 초기화에 실패했습니다.",
			RecommendedAction: "상호 의존 빈 주입 지점에 @Lazy를 부여하거나 의존성을 리팩토링하세요.",
		},
		"LazyInitializationException": {
			SummaryTpl:        "JPA/Hibernate LazyInitializationException: 세션 종료 후 지연 로딩 접근으로 실패했습니다.",
			RecommendedAction: "JPQL에 JOIN FETCH 또는 @EntityGraph를 적용하거나 @Transactional 스코프를 확장하세요.",
		},
		"TransientPropertyValueException": {
			SummaryTpl:        "JPA TransientPropertyValueException: 영속화되지 않은 자식 엔티티를 참조했습니다.",
			RecommendedAction: "엔티티 관계에 cascade = CascadeType.ALL을 추가하거나 자식 엔티티를 먼저 저장하세요.",
		},
		"NodeESMMismatch": {
			SummaryTpl:        "Node.js 모듈 시스템(ESM vs CommonJS) 불일치 오류가 발생했습니다.",
			RecommendedAction: "package.json에 '\"type\": \"module\"'을 설정하거나 .cjs 파일 확장자를 사용하세요.",
		},
		"NodePrismaError": {
			SummaryTpl:        "Prisma ORM 데이터베이스 오류가 발생했습니다: %s",
			RecommendedAction: "Prisma 스키마 정의 및 유니크 제약/연결 설정을 점검하세요.",
		},
		"RustUnwrapNone": {
			SummaryTpl:        "Rust 패닉: None 상태의 Option 객체에 unwrap()을 호출했습니다.",
			RecommendedAction: ".unwrap() 대신 match 또는 if let 패턴 매칭으로 None 케이스를 처리하세요.",
		},
		"RustUnwrapErr": {
			SummaryTpl:        "Rust 패닉: Err 상태의 Result 객체에 unwrap()을 호출했습니다.",
			RecommendedAction: "에러를 '?' 연산자로 전파하거나 match를 통해 Err 처리를 구현하세요.",
		},
		"RustAllocFailed": {
			SummaryTpl:        "Rust 글로벌 메모리 할당자 오류 (메모리 부족으로 할당 실패).",
			RecommendedAction: "컨테이너 메모리 제한을 증설하거나 대용량 벡터 할당을 최적화하세요.",
		},
		"RustPanic": {
			SummaryTpl:        "Rust 스레드 패닉: %s",
			RecommendedAction: "소스코드 위치의 unwrap()/expect() 및 슬라이스 인덱스 접근을 확인하세요.",
		},
		"DotNetNullReference": {
			SummaryTpl:        ".NET NullReferenceException: 객체 참조가 인스턴스로 설정되지 않았습니다.",
			RecommendedAction: "Null 조건 연산자(?.)를 사용하거나 C# 8.0+ Nullable 참조 형식을 활성화하세요.",
		},
		"DotNetOOM": {
			SummaryTpl:        ".NET CLR 런타임 메모리 고갈 (OutOfMemoryException).",
			RecommendedAction: "LOH(대형 객체 힙) 메모리 할당을 최적화하거나 파드 메모리 제한을 증설하세요.",
		},
		"DotNetConnectionPoolExhausted": {
			SummaryTpl:        ".NET ADO.NET 데이터베이스 커넥션 풀이 고갈되었습니다.",
			RecommendedAction: "연결 문자열의 'Max Pool Size'를 늘리고 SqlConnection을 using 블록으로 닫으세요.",
		},
		"DotNetPortInUse": {
			SummaryTpl:        ".NET Kestrel 웹 서버 포트 충돌 (Address already in use).",
			RecommendedAction: "ASPNETCORE_URLS 환경변수의 포트를 변경하세요.",
		},
		"DotNetAssemblyNotFound": {
			SummaryTpl:        ".NET 어셈블리(DLL) 종속성을 찾을 수 없습니다.",
			RecommendedAction: "배포 출력 디렉터리에 모든 참조 DLL이 정상 빌드되었는지 확인하세요.",
		},
		"DotNetStackOverflow": {
			SummaryTpl:        ".NET CLR 호출 스택 오버플로우가 발생했습니다 (StackOverflowException).",
			RecommendedAction: "재귀 호출 탈출 조건을 점검하세요.",
		},
		"DotNetUnhandledException": {
			SummaryTpl:        ".NET 미처리 예외 크래시: %s",
			RecommendedAction: "스택트레이스를 분석하여 전역 예외 필터를 보강하세요.",
		},
		"PHPMemoryExhausted": {
			SummaryTpl:        "PHP 메모리 제한이 고갈되었습니다: %s",
			RecommendedAction: "php.ini의 memory_limit을 증설하거나 대용량 루프 메모리를 최적화하세요.",
		},
		"PHPExecutionTimeout": {
			SummaryTpl:        "PHP 최대 실행 시간 한도를 초과했습니다: %s",
			RecommendedAction: "php.ini의 max_execution_time을 늘리거나 지연되는 외부 호출을 최적화하세요.",
		},
		"PHPCallOnNull": {
			SummaryTpl:        "PHP null 객체에 대한 메서드 호출 오류 (Call to a member function on null).",
			RecommendedAction: "메서드를 호출하기 전 변수가 null인지 사전에 검증하세요.",
		},
		"PHPUncaughtError": {
			SummaryTpl:        "PHP 처리되지 않은 치명적 오류: %s",
			RecommendedAction: "try-catch 블록으로 예외를 처리하거나 전역 에러 핸들러를 등록하세요.",
		},
		"RubyNoMemoryError": {
			SummaryTpl:        "Ruby 프로세스 메모리 할당 실패 (NoMemoryError).",
			RecommendedAction: "Jemalloc 메모리 할당자를 적용하거나 컨테이너 메모리 제한을 증설하세요.",
		},
		"RubySystemStackError": {
			SummaryTpl:        "Ruby 호출 스택 깊이 초과 (SystemStackError: stack level too deep).",
			RecommendedAction: "ActiveRecord 콜백 및 재귀 로직의 종료 조건을 확인하세요.",
		},
		"RubyActiveRecordPoolExhausted": {
			SummaryTpl:        "ActiveRecord DB 커넥션 풀이 고갈되었습니다 (ConnectionTimeoutError).",
			RecommendedAction: "database.yml의 pool 크기를 Puma 스레드 수에 맞추어 증설하세요.",
		},
		"PostgresMaxConnections": {
			SummaryTpl:        "PostgreSQL 최대 클라이언트 연결 수(max_connections)가 초과되었습니다.",
			RecommendedAction: "PgBouncer 커넥션 풀러를 도입하거나 postgresql.conf의 max_connections를 늘리세요.",
		},
		"PostgresDeadlock": {
			SummaryTpl:        "PostgreSQL 트랜잭션 상호 교착 상태(Deadlock)가 감지되어 트랜잭션이 중단되었습니다 (SQLState 40P01).",
			RecommendedAction: "복수 행 갱신 시 기본키 순으로 정렬하여 락을 획득하고 SELECT FOR UPDATE 잠금 범위를 최소화하세요.",
		},
		"MySQLTooManyConnections": {
			SummaryTpl:        "MySQL 서버의 최대 동시 연결 수(max_connections)를 초과하여 신규 커넥션이 거부되었습니다 (Error 1040).",
			RecommendedAction: "MySQL max_connections 설정 상향 및 클라이언트 커넥션 풀 크기(maximum-pool-size, pool_size)를 파드 수에 맞게 제한하세요.",
		},
		"MySQLDeadlock": {
			SummaryTpl:        "MySQL InnoDB 트랜잭션 상호 잠금(Deadlock)이 감지되어 트랜잭션이 강제 롤백되었습니다 (Error 1213).",
			RecommendedAction: "트랜잭션 내 테이블/행 접근 순서를 일관되게 정렬하고 트랜잭션 길이를 축소하며 자동 재시도(@Retryable)를 구현하세요.",
		},
		"RedisOOM": {
			SummaryTpl:        "Redis 메모리가 maxmemory 제한에 도달하여 쓰기 명령이 거부되었습니다.",
			RecommendedAction: "Redis maxmemory를 늘리거나 allkeys-lru 등의 키 만료 정책을 설정하세요.",
		},
		"RedisReadOnlyReplica": {
			SummaryTpl:        "Redis 읽기 전용 복제본(ReadOnly Replica)에 쓰기를 시도했습니다.",
			RecommendedAction: "쓰기 트래픽을 마스터(Primary) 엔드포인트로 전송하도록 클라이언트 설정을 변경하세요.",
		},
		"MongoServerSelectionTimeout": {
			SummaryTpl:        "MongoDB 서버 선택 타임아웃 (클러스터 노드에 접근할 수 없음).",
			RecommendedAction: "MongoDB 네트워크 피어링, IP 화이트리스트 및 DB 상태를 점검하세요.",
		},
		"RabbitMQChannelPreconditionFailed": {
			SummaryTpl:        "RabbitMQ 채널 오류: PRECONDITION_FAILED (큐 선언 속성 불일치).",
			RecommendedAction: "프로듀서와 컨슈머 간 큐의 durability, auto-delete, x-arguments 속성을 일치시키세요.",
		},
		"NginxWorkerConnections": {
			SummaryTpl:        "Nginx 워커 커넥션 한도 고갈 (worker_connections are not enough).",
			RecommendedAction: "nginx.conf의 worker_connections 및 worker_processes를 확장하세요.",
		},
		"NginxBadGatewayUpstream": {
			SummaryTpl:        "Nginx 502 Bad Gateway: 업스트림 백엔드 애플리케이션 연결 거부.",
			RecommendedAction: "업스트림 컨테이너가 정상 기동 중인지, 포트 설정이 올바른지 점검하세요.",
		},
		"NginxUpstreamTimedOut": {
			SummaryTpl:        "Nginx 504 Gateway Timeout: 업스트림 백엔드가 시간 내에 응답하지 않음.",
			RecommendedAction: "nginx.conf의 proxy_read_timeout을 늘리거나 백엔드 병목을 최적화하세요.",
		},
		"EnvoyNoHealthyUpstream": {
			SummaryTpl:        "Envoy / Istio 프록시가 가용한 업스트림 엔드포인트를 찾을 수 없습니다.",
			RecommendedAction: "목적지 파드가 정상 구동 중인지, 서비스 엔드포인트(Endpoints)가 등록되었는지 확인하세요.",
		},
		"EnvoyCircuitBreakerOverflow": {
			SummaryTpl:        "Envoy 서킷 브레이커(UO/최대 커넥션/펜딩 요청 수) 한도를 초과하여 연결이 차단되었습니다.",
			RecommendedAction: "DestinationRule의 connectionPool maxConnections/maxPendingRequests 한도를 확장하거나 백엔드 파드를 스케일아웃하세요.",
		},
		"EnvoyUpstreamConnectionFailure": {
			SummaryTpl:        "Envoy 프록시가 업스트림 서비스에 TCP/mTLS 연결을 실패했습니다 (UF).",
			RecommendedAction: "업스트림 서비스의 리슨 포트, 네트워크 정책(NetworkPolicy) 및 mTLS 설정을 확인하세요.",
		},
		"EnvoyNoRouteConfigured": {
			SummaryTpl:        "Envoy 가상 호스트 또는 라우팅 규칙(NR)을 찾을 수 없습니다.",
			RecommendedAction: "VirtualService 또는 Ingress의 Host 헤더와 라우팅 경로 매칭 설정을 점검하세요.",
		},
		"EnvoyTLSHandshakeFailed": {
			SummaryTpl:        "Envoy 업스트림과의 TLS 핸드셰이크가 실패했습니다 (UC).",
			RecommendedAction: "DestinationRule의 tls 모드(ISTIO_MUTUAL vs DISABLE)와 대상 포트의 mTLS 지원 여부를 확인하세요.",
		},
		"EnvoyUpstreamTimeout": {
			SummaryTpl:        "Envoy 업스트림 서비스 응답 대기 시간이 초과되었습니다 (UT).",
			RecommendedAction: "VirtualService의 timeout 설정을 늘리거나 업스트림 애플리케이션의 처리 지연을 최적화하세요.",
		},
		"NginxConfigSyntaxError": {
			SummaryTpl:        "Nginx 설정 파일 문법 오류로 인해 프로세스 기동에 실패했습니다: %s",
			RecommendedAction: "Ingress-Nginx의 snippet 어노테이션 또는 ConfigMap의 nginx.conf 문법 오탈자를 수정하세요.",
		},
		"NginxClientBodySizeExceeded": {
			SummaryTpl:        "요청 본문(Body) 크기가 Nginx client_max_body_size 한도를 초과했습니다 (413 Request Entity Too Large).",
			RecommendedAction: "Ingress에 'nginx.ingress.kubernetes.io/proxy-body-size: \"50m\"' 어노테이션을 설정하여 허용 용량을 늘리세요.",
		},
		"IstioProxyNotReady": {
			SummaryTpl:        "Istio 파일럿(Pilot)과의 xDS 동기화 지연 또는 15021 준비 상태 검사(Readiness) 실패.",
			RecommendedAction: "istiod 컨트롤 플레인 상태 및 istio-proxy 컨테이너의 CPU/메모리 스펙을 확인하세요.",
		},
		"IstioStartupRaceCondition": {
			SummaryTpl:        "istio-proxy 사이드카가 준비 상태(15021)에 도달하기 전 메인 앱이 기동되어 외부 통신에 실패했습니다.",
			RecommendedAction: "파드 어노테이션에 'proxy.istio.io/config: holdApplicationUntilProxyStarts: true'를 추가하거나 K8s 1.28+ 네이티브 사이드카를 적용하세요.",
		},
		"IstioStrictMTLSMismatch": {
			SummaryTpl:        "Istio STRICT mTLS 네임스페이스에 프록시가 주입되지 않은 평문(Plaintext) 트래픽이 인입되어 거부되었습니다.",
			RecommendedAction: "클라이언트 파드에 Istio 사이드카를 주입하거나 PeerAuthentication의 mTLS 모드를 PERMISSIVE로 변경하세요.",
		},
		"EnvoyGatewayTranslationFailed": {
			SummaryTpl:        "Envoy Gateway xDS 변환 실패 또는 Gateway API BackendRef 해석 실패 (ResolvedRefs: False).",
			RecommendedAction: "Gateway API HTTPRoute의 backendRefs 대상 Service 이름 및 네임스페이스 ReferenceGrant를 확인하세요.",
		},
		"VaultSealedFailure": {
			SummaryTpl:        "HashiCorp Vault 인스턴스가 잠김(Sealed) 상태로 Secret을 조회할 수 없습니다 (HTTP 503).",
			RecommendedAction: "'vault operator unseal' 명령을 실행하여 키 샤드로 Vault 잠금을 해제하세요.",
		},
		"VaultTokenExpired": {
			SummaryTpl:        "Vault 토큰이 만료(Expired)되었거나 서비스 어카운트의 Vault Kube Auth 권한이 거부되었습니다.",
			RecommendedAction: "Vault 역할(Role)의 token_ttl 및 Kube Auth 바인딩 서비스어카운트 권한을 점검하세요.",
		},
		"CoreDNSLoopDetected": {
			SummaryTpl:        "CoreDNS 루프(Loop) 플러그인이 무한 DNS 포워딩 루프를 감지하고 중단되었습니다.",
			RecommendedAction: "노드의 /etc/resolv.conf에서 루프백 주소(127.0.0.53/127.0.0.1)를 제거하고 업스트림 퍼블릭 DNS(8.8.8.8)를 지정하세요.",
		},
		"CertManagerWebhookFailure": {
			SummaryTpl:        "Cert-Manager Webhook 서비스 호출 타임아웃 또는 연결 거부로 리소스 검증에 실패했습니다.",
			RecommendedAction: "cert-manager-webhook 파드의 상태를 확인하고 방화벽/CNI가 10250/6443/webhook 포트를 차단하는지 점검하세요.",
		},
		"ACMERateLimitExceeded": {
			SummaryTpl:        "Let's Encrypt ACME API의 인증서 발급 요청 속도 제한(Rate Limit)을 초과했습니다.",
			RecommendedAction: "개발/스테이징 환경에서는 ACME Staging Issuer(acme-staging-v02)를 사용하고 만료 30일 전 갱신 주기를 유지하세요.",
		},
		"PrometheusWALCorruption": {
			SummaryTpl:        "Prometheus TSDB WAL(Write-Ahead Log) 파일 손상으로 데이터베이스 복구에 실패했습니다.",
			RecommendedAction: "Prometheus 파드에 '--storage.tsdb.wal-compression'을 점검하고, 필요 시 손상된 WAL 세그먼트를 제거하거나 PV 볼륨 백업을 복원하세요.",
		},
		"PrometheusCardinalityOOM": {
			SummaryTpl:        "고유 라벨(Cardinality) 폭증으로 인한 Prometheus TSDB 메모리 고갈 (OOMKilled).",
			RecommendedAction: "고카디널리티 라벨(userId, timestamp, guid 등)을 metric_relabel_configs에서 drop 처리하거나 scrape_interval을 조정하세요.",
		},
		"FluentBitBufferExhaustion": {
			SummaryTpl:        "Fluent Bit 청크 버퍼가 가득 차 신규 로그 인제스천이 중단되었습니다 ([input:tail] ring buffer full / [engine] chunk ... paused).",
			RecommendedAction: "storage.type을 filesystem으로 전환(배압 디스크 버퍼링)하거나 storage.max_chunks_up 한도를 늘리세요.",
		},
		"ElasticsearchDiskFloodStage": {
			SummaryTpl:        "Elasticsearch 노드 디스크 사용량이 95%%(Flood Stage Watermark)를 초과하여 모든 인덱스가 읽기 전용으로 잠겼습니다.",
			RecommendedAction: "노드 디스크 용량을 증설하고 오래된 인덱스를 삭제(ILM 정책)한 뒤 'read_only_allow_delete: null'로 인덱스 잠금을 해제하세요.",
		},
		"ElasticsearchCircuitBreaker": {
			SummaryTpl:        "Elasticsearch 메모리 서킷 브레이커([parent]/[fielddata])가 발동하여 쿼리 처리가 차단되었습니다.",
			RecommendedAction: "ES_JAVA_OPTS 힙 크기를 확장(최대 31GB)하고 indices.breaker.total.use_real_memory 설정을 점검하세요.",
		},
		"PatroniLeaderLeaseLost": {
			SummaryTpl:        "Patroni PostgreSQL이 DCS(etcd/k8s) 리더 임차권(Lease)을 상실하여 Primary에서 강등(Demote)되었습니다.",
			RecommendedAction: "etcd 클러스터 지연 시간, 쿠버네티스 API 서버 부하 및 patroni lease_duration 설정을 확인하세요.",
		},
		"PostgresWALDiskFull": {
			SummaryTpl:        "PostgreSQL pg_wal 디스크 저장 공간이 고갈되어 쓰기 트랜잭션이 중단되었습니다 (PANIC: could not write to log file).",
			RecommendedAction: "archive_command 실패 여부 및 복제 슬롯(pg_replication_slots) 지연으로 인한 WAL 잔여분을 확인하고 디스크 볼륨을 확장하세요.",
		},
		"ArgoCDRepoServerOOM": {
			SummaryTpl:        "Argo CD repo-server가 대규모 Helm/Kustomize 템플릿 빌드 중 메모리 한도를 초과하여 OOMKilled되었습니다.",
			RecommendedAction: "argocd-repo-server의 resources.limits.memory를 증설(최소 2GiB 이상)하고 'ARGOCD_EXEC_TIMEOUT'을 조정하세요.",
		},
		"GitRateLimitExceeded": {
			SummaryTpl:        "GitHub/GitLab 원격 저장소 API 호출 속도 제한(Rate Limit)을 초과했습니다.",
			RecommendedAction: "Argo CD 설정에 Personal Access Token(PAT) 또는 GitHub App 자격 증명을 등록하여 API 쿼터 한도를 확장하세요.",
		},
		"GCPAuthDefaultCredentialsMissing": {
			SummaryTpl:        "Google Cloud SDK 애플리케이션 기본 자격 증명(ADC) 부재 또는 메타데이터 서버 연결 실패.",
			RecommendedAction: "GOOGLE_APPLICATION_CREDENTIALS 환경변수를 설정하거나 GKE Workload Identity 서비스어카운트 어노테이션을 확인하세요.",
		},
		"GCPGeminiQuotaExceeded": {
			SummaryTpl:        "Google Gemini API 호출 속도 제한(TPM/RPM) 또는 할당량 초과 (HTTP 429 ResourceExhausted).",
			RecommendedAction: "Google Cloud Console에서 Gemini API 할당량 증설을 요청하거나 지수 백오프 재시도 로직을 적용하세요.",
		},
		"GCPGeminiSafetyBlocked": {
			SummaryTpl:        "Google Gemini 모델 안전성 필터(Safety Ratings)에 의해 콘텐츠 생성이 차단되었습니다.",
			RecommendedAction: "safetySettings 임계값을 BLOCK_ONLY_HIGH로 완화하거나 프롬프트 입력을 정제하세요.",
		},
		"GCPGeminiAuthFailed": {
			SummaryTpl:        "Google Gemini API Key가 유효하지 않거나 인증 실패 (HTTP 401/400).",
			RecommendedAction: "GEMINI_API_KEY 환경변수 및 Google AI Studio/GCP Console API 키 활성화 상태를 점검하세요.",
		},
		"GCPBigQueryQuotaExceeded": {
			SummaryTpl:        "BigQuery 쿼리 바이트 청구 한도(bytes billed) 초과 또는 동시 쿼리 API 쿼터 도달.",
			RecommendedAction: "쿼리 maximum_bytes_billed 설정을 증설하거나 파티션/클러스터링 필터를 적용해 스캔 용량을 줄이세요.",
		},
		"GCPBigQueryQueryFailed": {
			SummaryTpl:        "BigQuery 데이터세트/테이블 접근 권한 부재(403) 또는 대상 테이블 부재(404).",
			RecommendedAction: "서비스 어카운트에 'roles/bigquery.dataViewer' 및 'roles/bigquery.jobUser' 권한을 부여하세요.",
		},
		"GCPStorageChecksumMismatch": {
			SummaryTpl:        "Google Cloud Storage 업로드/다운로드 중 데이터 무결성 체크섬(CRC32c/MD5) 불일치.",
			RecommendedAction: "네트워크 프록시 및 MTU 단편화 패킷 손상 여부를 확인하고 멀티파트 청크 크기를 조정하세요.",
		},
		"GCPStorageAccessDenied": {
			SummaryTpl:        "Google Cloud Storage 버킷/객체 접근 권한 거절 (HTTP 403 Forbidden).",
			RecommendedAction: "서비스 어카운트에 'roles/storage.objectViewer' 또는 'roles/storage.objectAdmin' 역할을 부여하세요.",
		},
		"ClickHouseTooManyParts": {
			SummaryTpl:        "ClickHouse 테이블 데이터 파트(parts) 수 한도 초과 (소규모 INSERT 과다로 인한 머지 지연).",
			RecommendedAction: "클라이언트에서 10,000건 이상 단위로 벌크(배치) INSERT를 수행하거나 Buffer 엔진 테이블을 사용하세요.",
		},
		"ClickHouseMemoryLimit": {
			SummaryTpl:        "ClickHouse 서버 또는 쿼리 메모리 한도(max_server_memory_usage) 초과.",
			RecommendedAction: "max_server_memory_usage 및 파드 메모리를 증설하고 'max_bytes_before_external_group_by' 디스크 오프로딩을 설정하세요.",
		},
		"ClickHouseZooKeeperSessionLost": {
			SummaryTpl:        "ClickHouse가 ZooKeeper 클러스터와의 세션 하트비트를 상실하여 복제본이 중단됨.",
			RecommendedAction: "ZooKeeper 파드 가동 상태를 점검하고 clickhouse 설정의 'session_timeout_ms'를 상향 조정하세요.",
		},
		"ClickHouseReadOnlyReplica": {
			SummaryTpl:        "ClickHouse 복제본 메타데이터 동기화 실패로 테이블이 읽기 전용(Readonly) 모드로 전환됨.",
			RecommendedAction: "'SYSTEM RESTART REPLICA <table_name>'을 실행하여 복제 세션을 재초기화하세요.",
		},
		"ZooKeeperDiskFull": {
			SummaryTpl:        "ZooKeeper 트랜잭션 로그(dataLogDir) 또는 스냅샷(dataDir) 디스크 공간 고갈.",
			RecommendedAction: "스토리지 PVC 볼륨 용량을 증설하고 'autopurge.purgeInterval=1' 설정을 활성화하세요.",
		},
		"ZooKeeperQuorumLost": {
			SummaryTpl:        "ZooKeeper 앙상블 리더 선출 실패 또는 과반수 쿼럼 상실.",
			RecommendedAction: "과반수(N/2 + 1)의 ZooKeeper 노드가 정상 실행 중인지 확인하고 2888/3888 포트 통신을 점검하세요.",
		},
		"ZooKeeperSessionExpired": {
			SummaryTpl:        "ZooKeeper 클라이언트 세션 만료 (네트워크 파티션 또는 GC 일시정지로 인한 하트비트 누락).",
			RecommendedAction: "클라이언트 JVM GC 튜닝으로 긴 일시정지를 방지하고 tickTime/maxSessionTimeout을 상향 조정하세요.",
		},
		"ValkeyOOM": {
			SummaryTpl:        "Valkey 인메모리 사용량이 maxmemory 한도에 도달하여 신규 쓰기 거부.",
			RecommendedAction: "valkey.conf의 maxmemory 한도를 늘리거나 'maxmemory-policy allkeys-lru' 키 축출 정책을 설정하세요.",
		},
		"ValkeyReadOnlyReplica": {
			SummaryTpl:        "Valkey 읽기 전용 복제본(ReadOnly Replica)에 쓰기 명령 실행 시도.",
			RecommendedAction: "쓰기 트래픽을 Valkey 마스터(Primary) 엔드포인트로 전송하도록 클라이언트 설정을 변경하세요.",
		},
		"ValkeyClusterDown": {
			SummaryTpl:        "Valkey 클러스터 슬롯 미할당 또는 마스터 노드 과반수 다운 (CLUSTERDOWN).",
			RecommendedAction: "'valkey-cli cluster check'로 슬롯 커버리지를 점검하고 다운된 마스터를 복구하세요.",
		},
		"PostgresTxidExhaustion": {
			SummaryTpl:        "PostgreSQL 트랜잭션 ID 래핑(TXID Wraparound) 방지를 위해 데이터베이스가 비상 잠금(읽기 전용)됨.",
			RecommendedAction: "단일 사용자 모드로 진입하여 'VACUUM FREEZE ANALYZE'를 즉시 수행하고 autovacuum 설정을 점검하세요.",
		},
		"PostgresLockTimeout": {
			SummaryTpl:        "PostgreSQL 테이블/행 락(Lock) 획득 대기 시간 초과로 쿼리가 취소됨.",
			RecommendedAction: "pg_stat_activity에서 블로킹 트랜잭션을 점검하고 배타적 DDL/DML 락 경합을 해소하세요.",
		},
		"PostgresStatementTimeout": {
			SummaryTpl:        "PostgreSQL 쿼리 실행 시간이 statement_timeout 임계값을 초과하여 강제 취소되었습니다 (SQLState 57014).",
			RecommendedAction: "EXPLAIN ANALYZE로 쿼리 실행 계획을 점검하여 누락된 인덱스를 추가하고 순차 스캔을 방지하세요.",
		},
		"JenkinsDiskSpaceExhausted": {
			SummaryTpl:        "Jenkins 컨트롤러 또는 에이전트 노드의 디스크 가용 공간이 임계치 미만으로 고갈됨.",
			RecommendedAction: "Jenkins 홈/워크스페이스 PVC 용량을 확장하고 파이프라인 후처리에 'cleanWs()'를 추가하세요.",
		},
		"JenkinsAgentRemotingChannelClosed": {
			SummaryTpl:        "Jenkins 마스터와 빌드 에이전트 간의 Remoting 통신 채널이 단절됨.",
			RecommendedAction: "에이전트 파드의 OOMKilled 여부를 확인하고 컨트롤러의 JNLP(50000) 포트 연결성을 점검하세요.",
		},
		"NexusBlobStoreFull": {
			SummaryTpl:        "Nexus Repository 블롭 저장소(Blob Store) 저장 공간 고갈로 아티팩트 업로드 실패.",
			RecommendedAction: "Nexus PVC 스토리지를 증설하고 'Compact blob store' 및 오래된 아티팩트 정리 작업을 실행하세요.",
		},
		"NexusDatabaseLocked": {
			SummaryTpl:        "Nexus 내부 임베디드 데이터베이스(OrientDB/H2) 락 충돌로 트랜잭션 중단.",
			RecommendedAction: "Nexus 파드를 재시작하여 고아 락을 해제하고 필요 시 DB 복구 유틸리티를 실행하세요.",
		},
		"ArgoWorkflowDeadlineExceeded": {
			SummaryTpl:        "Argo Workflow 파이프라인 또는 태스크가 'activeDeadlineSeconds' 제한 시간을 초과함.",
			RecommendedAction: "워크플로우 템플릿의 'activeDeadlineSeconds'를 상향 조정하거나 I/O 병목을 프로파일링하세요.",
		},
		"ArgoArtifactSaveFailed": {
			SummaryTpl:        "Argo Workflow 빌드 출력물(Artifact)을 원격 아티팩트 저장소(S3/GCS)에 저장 실패.",
			RecommendedAction: "artifactRepository 설정의 버킷 자격 증명(Secret/IAM) 및 네트워크 연결성을 점검하세요.",
		},
		"ArgoRolloutAnalysisFailed": {
			SummaryTpl:        "Argo Rollouts 카나리 배포 검증(AnalysisRun) 지표 측정 실패로 배포 자동 롤백.",
			RecommendedAction: "AnalysisTemplate의 Prometheus 쿼리 성공률/레이턴시 지표 및 카나리 파드 로그를 점검하세요.",
		},
		"ArgoRolloutTrafficRoutingFailed": {
			SummaryTpl:        "Argo Rollouts 트래픽 라우팅 플러그인(ALB/Istio/SMI) 가중치 분할 업데이트 실패.",
			RecommendedAction: "Ingress 또는 VirtualService 매핑 spec 및 컨트롤러 RBAC 권한을 점검하세요.",
		},
		"KyvernoAdmissionPolicyViolation": {
			SummaryTpl:        "Kyverno 보안/거버넌스 어드미션 정책(ClusterPolicy) 위반으로 파드 생성 차단.",
			RecommendedAction: "에러 메시지의 정책 요구사항(보안 컨텍스트, 라벨, 이미지 태그 등)을 파드 스펙에 보강하세요.",
		},
		"KyvernoWebhookTimeout": {
			SummaryTpl:        "Kyverno 어드미션 웹훅 컨트롤러 응답 지연(타임아웃) 또는 웹훅 TLS 인증서 만료.",
			RecommendedAction: "kyverno 파드의 리소스 부하를 점검하고 9443 포트 통신 및 Webhook TLS Secret을 확인하세요.",
		},
		"GatekeeperConstraintViolation": {
			SummaryTpl:        "OPA Gatekeeper 제약 조건(Constraint) 위반으로 쿠버네티스 리소스 생성 거부.",
			RecommendedAction: "Gatekeeper Constraint 규정 위반 항목을 수정하고 'kubectl get constraints'로 위반 내역을 조회하세요.",
		},
		"GatekeeperWebhookFailure": {
			SummaryTpl:        "Gatekeeper 검증 웹훅(validation.gatekeeper.sh) 호출 실패 또는 타임아웃.",
			RecommendedAction: "gatekeeper-controller-manager 파드 상태 및 웹훅 방화벽/failurePolicy 설정을 점검하세요.",
		},
		"VaultAuthRoleNotFound": {
			SummaryTpl:        "Vault Secrets Operator의 VaultAuth 인증 역할(Role)이 Vault 서버에 존재하지 않음.",
			RecommendedAction: "Vault 서버의 Kubernetes Auth 설정에 해당 role이 등록되어 있는지 확인하세요 ('vault read auth/kubernetes/role/<role>').",
		},
		"VaultSecretSyncFailed": {
			SummaryTpl:        "Vault Secrets Operator가 Vault 시크릿 경로를 찾지 못하거나(404) 시크릿 동기화 권한 거부.",
			RecommendedAction: "VaultStaticSecret의 시크릿 경로(path) 및 Vault 정책(Policy) 읽기 권한을 점검하세요.",
		},
		"SecretProviderClassNotFound": {
			SummaryTpl:        "Secrets Store CSI Driver가 참조하는 SecretProviderClass 리소스를 찾을 수 없음.",
			RecommendedAction: "동일 네임스페이스에 SecretProviderClass가 존재하는지 확인하고 볼륨 spec의 이름 오탈자를 수정하세요.",
		},
		"SecretsStoreCSIMountFailed": {
			SummaryTpl:        "Secrets Store CSI 드라이버 프로바이더(GCP/Vault/Azure/AWS) 시크릿 마운트 권한 거절.",
			RecommendedAction: "클라우드 프로바이더 IAM 권한 및 Workload Identity 바인딩 상태를 점검하세요.",
		},
		"NFSMountAccessDenied": {
			SummaryTpl:        "NFS 서버의 익스포트(Export) 디렉토리 마운트 권한 거절 (접근 제어 또는 no_root_squash 누락).",
			RecommendedAction: "NFS 서버의 /etc/exports에서 워커 노드 CIDR 허용 및 'no_root_squash' 옵션을 확인하세요.",
		},
		"NFSConnectionTimeout": {
			SummaryTpl:        "NFS 스토리지 서버 연결 타임아웃 또는 포트(2049/RPC 111) 연결 거부.",
			RecommendedAction: "NFS 서버 가동 상태를 확인하고 방화벽에서 TCP/UDP 2049 및 111 포트를 허용하세요.",
		},
		"NFSStaleFileHandle": {
			SummaryTpl:        "NFS 서버에서 마운트된 디렉토리/파일이 재배치 또는 삭제되어 파일 핸들이 무효화됨 (ESTALE).",
			RecommendedAction: "노드에서 해당 NFS 마운트를 언마운트('umount -l') 후 파드를 재생성하세요.",
		},
		"KubeDNSNXDomainStorm": {
			SummaryTpl:        "kube-dns 업스트림 네임서버 장애 또는 과도한 NXDOMAIN 쿼리 폭주로 도메인 해석 실패.",
			RecommendedAction: "kube-dns upstreamNameservers 설정을 점검하고 파드 ndots 검색 도메인 설정을 최적화하세요.",
		},
		"KubeDNSHealthCheckFailed": {
			SummaryTpl:        "kube-dns 사이드카 헬스체크(10054) 실패로 인한 파드 비정상 재시작.",
			RecommendedAction: "kube-dns 파드의 CPU/메모리 스펙을 증설하고 dnsmasq/skydns 컨테이너 상태를 점검하세요.",
		},
		"MetricsServerKubeletScrapeFailed": {
			SummaryTpl:        "metrics-server가 노드 Kubelet(10250) 메트릭 스크랩 실패 (방화벽 차단 또는 Kubelet 인증서 검증 실패).",
			RecommendedAction: "metrics-server 인수에 '--kubelet-insecure-tls'를 추가하거나 10250 포트 방화벽을 허용하세요.",
		},
		"LiteLLMRateLimitExceeded": {
			SummaryTpl:        "LiteLLM 프록시 연결 업스트림 LLM 프로바이더의 TPM/RPM 속도 제한 초과 (HTTP 429).",
			RecommendedAction: "LiteLLM에 모델 폴백(fallback) 라우팅을 구성하거나 Redis/Valkey 캐싱을 활성화하세요.",
		},
		"LiteLLMBudgetExceeded": {
			SummaryTpl:        "LiteLLM 사용자/팀/가상 키에 할당된 비용 예산(Budget) 한도 도달.",
			RecommendedAction: "LiteLLM Admin API/UI에서 해당 사용자/키의 'max_budget' 한도를 증설하거나 리셋하세요.",
		},
		"LiteLLMContextWindowExceeded": {
			SummaryTpl:        "요청된 프롬프트와 생성 토큰의 합계가 LLM 모델의 최대 컨텍스트 윈도우 길이를 초과함.",
			RecommendedAction: "대화 히스토리를 슬라이딩 윈도우로 압축하거나 더 큰 컨텍스트 윈도우를 지원하는 모델로 전환하세요.",
		},
		"LiteLLMAuthenticationError": {
			SummaryTpl:        "LiteLLM 프록시 가상 키 인증 실패 또는 업스트림 LLM 프로바이더 API 키 무효.",
			RecommendedAction: "클라이언트의 Bearer 토큰 및 LiteLLM 환경변수의 프로바이더 API 키를 점검하세요.",
		},
		"TCPConnectionReset": {
			SummaryTpl:        "피어 서버 또는 중간 방화벽/L4에 의해 TCP 연결이 강제 리셋됨 (ECONNRESET / connection reset by peer).",
			RecommendedAction: "원격 서비스 파드의 비정상 크래시 여부 및 L4 로드밸런서 유휴 세션 타임아웃(Idle timeout)을 확인하세요.",
		},
		"TCPConnectionRefused": {
			SummaryTpl:        "대상 서비스 포트가 열려있지 않거나 프로세스가 다운되어 TCP 연결이 거절됨 (ECONNREFUSED).",
			RecommendedAction: "대상 파드가 정상 기동 중인지, 서비스 targetPort 설정 및 NetworkPolicy 인입 허용을 점검하세요.",
		},
		"TCPConnectionTimeout": {
			SummaryTpl:        "TCP 3-Way Handshake SYN 패킷 응답 대기 시간 초과 (ETIMEDOUT / i/o timeout).",
			RecommendedAction: "보안 그룹(Security Group), 클러스터 방화벽 또는 NetworkPolicy가 SYN 패킷을 드롭하지 않는지 점검하세요.",
		},
		"NetworkUnreachable": {
			SummaryTpl:        "네트워크 라우팅 경로 부재 또는 서브넷 게이트웨이 연결 불가 (No route to host / ENETUNREACH).",
			RecommendedAction: "노드 CNI 라우팅 테이블, VPC 서브넷 라우팅 및 NAT 게이트웨이 가동 상태를 점검하세요.",
		},
		"EphemeralPortExhaustion": {
			SummaryTpl:        "아웃바운드 임시 포트(Ephemeral Port) 고갈로 신규 소켓 바인딩 실패 (EADDRNOTAVAIL).",
			RecommendedAction: "HTTP 커넥션 풀을 적용하고 sysctl 'net.ipv4.ip_local_port_range' 확장 및 'net.ipv4.tcp_tw_reuse=1'을 활성화하세요.",
		},
		"DNSResolutionTimeout": {
			SummaryTpl:        "DNS 쿼리 타임아웃 또는 도메인 해석 실패 (EAI_AGAIN / UnknownHostException).",
			RecommendedAction: "CoreDNS 파드 부하 상태를 점검하고 파드 dnsConfig의 ndots 값을 2 이하로 최적화하세요.",
		},
		"BrokenPipe": {
			SummaryTpl:        "이미 닫힌 TCP 소켓 연결에 데이터를 쓰려다 파이프가 단절됨 (EPIPE / Broken pipe).",
			RecommendedAction: "클라이언트 요청 타임아웃이 서버 응답 시간보다 짧아 조기 연결 종료되었는지 확인하세요.",
		},
		"TLSUntrustedCA": {
			SummaryTpl:        "TLS/HTTPS 인증서가 신뢰할 수 없는 CA에 의해 서명됨 (x509: certificate signed by unknown authority).",
			RecommendedAction: "컨테이너의 CA 신뢰 저장소(/etc/ssl/certs, Java cacerts)에 사설 CA 인증서를 마운트하고 'update-ca-certificates'를 실행하세요.",
		},
		"TLSCertificateExpired": {
			SummaryTpl:        "TLS 인증서가 만료되었거나 시스템 시계가 동기화되지 않음 (CERT_HAS_EXPIRED).",
			RecommendedAction: "대상 서버의 TLS 인증서를 즉시 갱신하고 노드 NTP 시간 동기화 상태를 점검하세요.",
		},
		"TLSHostnameMismatch": {
			SummaryTpl:        "TLS 인증서의 주체 대체 이름(SAN)과 접속 대상 호스트명/IP 불일치 (ERR_TLS_CERT_ALTNAME_INVALID).",
			RecommendedAction: "접속 대상 FQDN이 인증서의 SAN 목록에 포함되어 있는지 확인하고 IP 대신 도메인명으로 접속하세요.",
		},
		"TLSHandshakeProtocolMismatch": {
			SummaryTpl:        "TLS 프로토콜 버전 또는 암호화 스위트(Cipher Suite) 불일치 (HANDSHAKE_FAILURE).",
			RecommendedAction: "클라이언트와 서버의 지원 TLS 버전(최소 TLS 1.2 이상) 및 공통 암호화 스위트 설정을 점검하세요.",
		},
		"TLSClientCertRequired": {
			SummaryTpl:        "상호 TLS(mTLS) 클라이언트 인증서가 누락되었거나 거부됨 (ssl alert certificate required).",
			RecommendedAction: "클라이언트 요청에 유효한 mTLS 클라이언트 인증서 및 개인키를 등록하세요.",
		},
		"TLSIncompleteChain": {
			SummaryTpl:        "서버가 중간 CA(Intermediate CA) 인증서를 누락하여 인증서 체인 검증 실패 (unable to get local issuer certificate).",
			RecommendedAction: "웹서버 또는 Ingress에 중간 인증서가 포함된 전체 체인(fullchain.pem)을 번들링하세요.",
		},
		"ProxyAuthenticationRequired": {
			SummaryTpl:        "Squid HTTP 프록시 인증 필요 (HTTP 407 Proxy Authentication Required).",
			RecommendedAction: "HTTP_PROXY 환경변수에 프록시 인증 자격 증명(http://user:pass@proxy:3128)을 포함하세요.",
		},
		"ProxyAccessDeniedACL": {
			SummaryTpl:        "Squid 프록시 접근 제어 목록(ACL) 차단 (HTTP 403 Forbidden - ERR_ACCESS_DENIED).",
			RecommendedAction: "squid.conf에서 클라이언트 소스 IP 또는 대상 도메인에 대한 'http_access allow' 규칙을 추가하세요.",
		},
		"ProxyConnectTunnelFailed": {
			SummaryTpl:        "Squid HTTPS CONNECT 터널링 거절 (비표준 포트 또는 Safe_ports 차단).",
			RecommendedAction: "squid.conf의 'SSL_ports' 및 'Safe_ports'에 목적지 포트를 추가하세요.",
		},
		"ProxyDNSResolutionFailed": {
			SummaryTpl:        "Squid 프록시의 업스트림 도메인 DNS 해석 실패 (HTTP 502 Bad Gateway - ERR_DNS_FAIL).",
			RecommendedAction: "Squid 프록시 서버의 /etc/resolv.conf 네임서버 설정 및 외부 DNS 연결성을 점검하세요.",
		},
		"ProxyGatewayTimeout": {
			SummaryTpl:        "Squid 프록시의 업스트림 서버 응답 대기 시간 초과 (HTTP 504 Gateway Timeout - ERR_READ_TIMEOUT).",
			RecommendedAction: "Squid 설정의 'read_timeout'을 늘리거나 업스트림 서버 처리 지연을 최적화하세요.",
		},
		"ProxyConnectionRefused": {
			SummaryTpl:        "Squid 프록시가 업스트림 서버 TCP 연결에 실패함 (HTTP 503 Service Unavailable - ERR_CONNECT_FAIL).",
			RecommendedAction: "대상 서버의 포트 개방 상태 및 프록시 서버와 대상 사이의 방화벽을 점검하세요.",
		},
		"ProxySSLBumpFailure": {
			SummaryTpl:        "Squid SslBump 동적 인증서 생성 실패 (ERR_SECURE_ACCEPT_FAIL).",
			RecommendedAction: "Squid ssl_crtd 헬퍼 권한 및 캐시 크기를 확인하고 사설 루트 CA 유효기간을 점검하세요.",
		},
		"MySQLLockWaitTimeout": {
			SummaryTpl:        "MySQL InnoDB 행 락 획득 대기 시간(innodb_lock_wait_timeout)이 초과되었습니다 (Error 1205).",
			RecommendedAction: "장기 실행 트랜잭션을 점검하고 미커밋 세션을 정리하거나 innodb_lock_wait_timeout을 튜닝하세요.",
		},
		"MySQLPacketTooLarge": {
			SummaryTpl:        "MySQL 네트워크 패킷 크기가 서버의 max_allowed_packet 한도를 초과했습니다 (Error 1153).",
			RecommendedAction: "my.cnf의 max_allowed_packet 설정을 64M 이상으로 상향하고 클라이언트 드라이버 설정도 일치시키세요.",
		},
		"MySQLCommunicationsLinkFailure": {
			SummaryTpl:        "MySQL 유휴 연결 시간(wait_timeout) 초과 또는 원격 소켓 강제 종료로 통신 링크가 단절되었습니다.",
			RecommendedAction: "커넥션 풀의 maxLifetime/idleTimeout을 MySQL wait_timeout보다 짧게 설정하고 validationQuery('SELECT 1')를 활성화하세요.",
		},
		"MySQLReadOnlyMode": {
			SummaryTpl:        "MySQL 서버가 읽기 전용(--read-only) 상태에서 쓰기 쿼리를 거절했습니다 (클러스터 페일오버 동기화 지연).",
			RecommendedAction: "애플리케이션 접속 정보가 클러스터의 Writer 엔드포인트를 가리키는지 확인하고 DNS TTL을 낮추세요.",
		},
		"PostgresTooManyConnections": {
			SummaryTpl:        "PostgreSQL 연결 슬롯이 고갈되어 접속이 거절되었습니다 (SQLState 53300: sorry, too many clients already).",
			RecommendedAction: "PgBouncer 등 커넥션 풀러를 도입하고 postgresql.conf의 max_connections 및 각 파드의 커넥션 풀 한도를 축소하세요.",
		},
		"PostgresInFailedSQLTransaction": {
			SummaryTpl:        "PostgreSQL 트랜잭션 내 이전 쿼리 실패 후 ROLLBACK 없이 후속 명령이 실행되어 거절되었습니다 (SQLState 25P02).",
			RecommendedAction: "트랜잭션 블록 내 오류 발생 시 반드시 명시적 ROLLBACK을 호출하거나 SAVEPOINT를 사용하세요.",
		},
		"PostgresCannotConnectNow": {
			SummaryTpl:        "PostgreSQL 인스턴스가 복구 모드(Recovery) 또는 기동/종료 중이어서 연결할 수 없습니다 (SQLState 57P03).",
			RecommendedAction: "PostgreSQL 파드의 WAL 리플레이 진행 상태를 확인하고 프라이머리 승격 완료 후 애플리케이션을 연결하세요.",
		},
		"PostgresDiskFull": {
			SummaryTpl:        "PostgreSQL 데이터 또는 WAL 볼륨의 디스크 용량이 고갈되었습니다 (SQLState 53100: No space left on device).",
			RecommendedAction: "PostgreSQL PVC 볼륨을 즉시 확장하고 비정상 누적된 pg_wal 아카이브 및 임시 테이블스페이스를 정리하세요.",
		},
		"ClickHouseSimultaneousQueries": {
			SummaryTpl:        "ClickHouse 서버의 최대 동시 쿼리 수(max_concurrent_queries) 한도를 초과했습니다 (Code 202).",
			RecommendedAction: "config.xml의 max_concurrent_queries 설정을 상향하거나 클라이언트 측에서 쿼리 동시 유입량을 제어하세요.",
		},
		"ClickHouseTimeoutExceeded": {
			SummaryTpl:        "ClickHouse 쿼리 실행 시간(max_execution_time)이 초과되어 취소되었습니다 (Code 159).",
			RecommendedAction: "max_execution_time 설정을 조정하고 WHERE 절에 파티션 키 및 기본 정렬 키(ORDER BY)를 포함하세요.",
		},
		"ClickHouseConnectionPoolExhausted": {
			SummaryTpl:        "ClickHouse 클라이언트 드라이버 커넥션 풀(Connection Pool)이 고갈되었습니다.",
			RecommendedAction: "클라이언트 max_open_connections/pool_size를 상향하고 쿼리 완료 후 연결/응답 스트림 반환을 확인하세요.",
		},
		"BigQueryBytesBilledLimitExceeded": {
			SummaryTpl:        "BigQuery 쿼리 스캔 바이트 청구 한도(maximum_bytes_billed)를 초과했습니다.",
			RecommendedAction: "작업 옵션의 maximum_bytes_billed를 상향하거나 파티션 및 클러스터링 필터를 추가하여 스캔 용량을 축소하세요.",
		},
		"BigQueryPartitionFilterRequired": {
			SummaryTpl:        "BigQuery 파티션 테이블 쿼리 시 필수 파티션 필터가 누락되었습니다 (requirePartitionFilter=true).",
			RecommendedAction: "WHERE 절에 파티션 컬럼(_PARTITIONDATE, _PARTITIONTIME 또는 일자/타임스탬프 필드) 조건을 반드시 명시하세요.",
		},
		"BigQueryResponseTooLarge": {
			SummaryTpl:        "BigQuery 인라인 반환 응답 크기 제한을 초과했습니다 (대용량 결과 집합).",
			RecommendedAction: "destinationTable을 지정하여 결과를 테이블에 저장하거나 BigQuery Storage Read API를 사용하세요.",
		},
		"BigQueryStreamingInsertQuota": {
			SummaryTpl:        "BigQuery 스트리밍 인서트(insertAll) API 속도 제한 및 할당량을 초과했습니다.",
			RecommendedAction: "BigQuery Storage Write API로 전환하거나 Cloud Storage 경유 일괄 적재(Load Job)로 전환하세요.",
		},
		"BigQueryTableNotFoundInLocation": {
			SummaryTpl:        "BigQuery 데이터셋/테이블 위치(리전)가 일치하지 않아 쿼리를 실행할 수 없습니다.",
			RecommendedAction: "클라이언트 쿼리 작업의 location 설정이 대상 데이터셋의 생성 리전과 일치하는지 점검하세요.",
		},
		"PHPMemoryLimitExceeded": {
			SummaryTpl:        "PHP 스크립트 실행 메모리 한도(memory_limit)를 초과하여 프로세스가 중단되었습니다.",
			RecommendedAction: "php.ini에서 memory_limit를 256M 이상으로 증설하거나 대용량 데이터 쿼리를 chunk 단위로 분할하세요.",
		},
		"PHPMaxExecutionTimeExceeded": {
			SummaryTpl:        "PHP 스크립트 최대 실행 시간(max_execution_time)이 초과되어 강제 종료되었습니다.",
			RecommendedAction: "php.ini의 max_execution_time을 늘리거나 백그라운드 작업에 set_time_limit(0)을 설정하세요.",
		},
		"PHPUndefinedFunction": {
			SummaryTpl:        "정의되지 않은 PHP 함수 호출로 치명적 오류가 발생했습니다 (익스텐션 누락 또는 오탈자).",
			RecommendedAction: "Dockerfile에서 필요한 PHP 확장 모듈(docker-php-ext-install)을 설치 및 활성화하세요.",
		},
		"PHPClassNotFound": {
			SummaryTpl:        "PHP 클래스를 찾을 수 없습니다 (Composer 오토로더 누락 또는 네임스페이스 오류).",
			RecommendedAction: "composer dump-autoload -o를 실행하여 클래스맵을 갱신하고 vendor/autoload.php 포함 여부를 확인하세요.",
		},
		"PHPFPMChildrenExhausted": {
			SummaryTpl:        "PHP-FPM 워커 풀(pm.max_children)이 고갈되어 신규 웹 요청 처리가 차단되었습니다.",
			RecommendedAction: "php-fpm.d/www.conf에서 pm.max_children을 증설하고 느린 쿼리를 최적화하여 워커 점유 시간을 단축하세요.",
		},
		"PHPFPMChildSignalCrash": {
			SummaryTpl:        "PHP-FPM 워커가 네이티브 C 확장 모듈의 메모리 침범(SIGSEGV/SIGBUS)으로 충돌 종료되었습니다.",
			RecommendedAction: "PHP C 확장 모듈 버전 호환성을 점검하고 코어 덤프를 분석하세요.",
		},
		"PHPPDOException": {
			SummaryTpl:        "PHP PDO 데이터베이스 연결 실패 또는 SQL 실행 오류가 발생했습니다.",
			RecommendedAction: "DB 접속 환경변수(호스트, 포트, 계정) 및 K8s Service 연결 상태를 점검하세요.",
		},
		"PHPUnhandledException": {
			SummaryTpl:        "PHP 미처리 예외가 발생하여 스크립트가 비정상 종료되었습니다.",
			RecommendedAction: "예외 발생 소스코드 위치를 확인하고 try-catch 블록으로 예외 처리를 추가하세요.",
		},
		"PHPSyntaxError": {
			SummaryTpl:        "PHP 구문 오류(Syntax Error)로 인해 스크립트 파싱에 실패했습니다.",
			RecommendedAction: "오류 발생 파일의 문법을 수정하고 빌드 파이프라인에서 'php -l' 린트를 수행하세요.",
		},
		"DiskNoSpaceLeft": {
			SummaryTpl:        "컨테이너 로컬 파일시스템의 저장 공간이 고갈되었습니다 (ENOSPC).",
			RecommendedAction: "임시 파일을 정리하거나 파드의 ephemeral-storage 할당량을 증설하세요.",
		},
		"FileDescriptorExhaustion": {
			SummaryTpl:        "시스템 또는 컨테이너 파일 디스크립터 한도가 고갈되었습니다 (too many open files).",
			RecommendedAction: "파일/소켓 해제 누수를 확인하거나 ulimit nofile 설정을 늘리세요.",
		},
		"PortConflict": {
			SummaryTpl:        "네트워크 포트 바인딩 충돌: %s",
			RecommendedAction: "컨테이너의 리슨 포트를 변경하거나 포트를 선점하고 있는 프로세스를 종료하세요.",
		},
		"DNSLookupFailed": {
			SummaryTpl:        "도메인 DNS 조회 실패: %s",
			RecommendedAction: "CoreDNS 파드 가동 상태 및 쿠버네티스 서비스 이름 오탈자를 확인하세요.",
		},
		"DatabaseAuthFailure": {
			SummaryTpl:        "데이터베이스 접속 인증(아이디/비밀번호)에 실패했습니다.",
			RecommendedAction: "데이터베이스 접속 Secret의 사용자명 및 패스워드를 재검증하세요.",
		},
		"TLSValidationFailed": {
			SummaryTpl:        "종속 서비스 연결 중 TLS 인증서 검증에 실패했습니다.",
			RecommendedAction: "사설 CA 인증서를 컨테이너에 마운트하거나 인증서 만료일을 확인하세요.",
		},
		"ConnectionRefused": {
			SummaryTpl:        "종속 서비스 또는 사이드카 연결이 거부되었습니다 (Connection Refused).",
			RecommendedAction: "대상 서비스가 실행 중인지, 포트가 일치하는지 네트워크 정책을 확인하세요.",
		},
		"ArchitectureMismatch": {
			SummaryTpl:        "바이너리 CPU 아키텍처 불일치 (amd64 vs arm64)",
			RecommendedAction: "노드 아키텍처에 맞게 멀티 아키텍처(buildx --platform linux/amd64,linux/arm64)로 이미지를 다시 빌드하세요.",
		},
		"EntrypointScriptNotFound": {
			SummaryTpl:        "컨테이너 진입점 바이너리/스크립트 파일을 찾을 수 없습니다: %s",
			RecommendedAction: "Dockerfile의 ENTRYPOINT 경로 및 실행 파일 존재 여부를 확인하세요.",
		},
		"AppFatalError": {
			SummaryTpl:        "치명적인 애플리케이션 오류 발생: %s",
			RecommendedAction: "로그 스니펫의 초기화 파라미터 및 의존성 연결 상태를 확인하세요.",
		},
		"VolumeMountFailure": {
			SummaryTpl:        "볼륨 마운트 실패: %s",
			RecommendedAction: "PVC 상태, 스토리지 클래스 및 노드 디스크 연결 한도를 점검하세요.",
		},
		"PodSandboxConfigFailure": {
			SummaryTpl:        "파드 샌드박스 생성 실패: %s",
			RecommendedAction: "CNI 플러그인 상태, 노드 서브넷 IP 고갈 여부를 확인하세요.",
		},
		"ApplicationRuntimeError": {
			SummaryTpl:        "애플리케이션 프로세스가 에러 코드 1로 종료되었습니다.",
			RecommendedAction: "컨테이너 표준 에러 로그의 예외 트레이스를 점검하세요.",
		},
		"ProcessExitedNormally": {
			SummaryTpl:        "메인 프로세스가 포그라운드 데몬을 유지하지 않고 코드 0으로 정상 종료되었습니다.",
			RecommendedAction: "엔트리포인트 명령어가 포그라운드(예: nginx -g 'daemon off;')로 실행되는지 확인하세요.",
		},
		"UnclassifiedExitCode": {
			SummaryTpl:        "%s",
			RecommendedAction: "%s",
		},
		"Unknown": {
			SummaryTpl:        "수집된 지표, 이벤트, 로그에서 원인을 특정할 수 없습니다.",
			RecommendedAction: "컨테이너의 디버그 로깅을 활성화하고 클러스터 모니터링을 점검하세요.",
		},
	},
	"en": {
		"OOMKilled": {
			SummaryTpl:        "Container exceeded memory limit and was killed by Linux kernel OOM killer (cgroup memory exhaustion).",
			RecommendedAction: "Increase memory limit in pod spec (resources.limits.memory) or analyze memory leaks.",
		},
		"ProbableOOMKilled": {
			SummaryTpl:        "Container killed with SIGKILL (137) with memory limit defined and memory exhaustion indicators in log.",
			RecommendedAction: "Increase pod memory limit (resources.limits.memory) or optimize memory consumption.",
		},
		"SystemOOMKilled": {
			SummaryTpl:        "Kernel or system OOM killer invoked: %s",
			RecommendedAction: "Host or cgroup ran out of memory. Review node memory utilization and container memory limits.",
		},
		"SidecarCascadeFailure": {
			SummaryTpl:        "Application container failed due to cascade failure of peer container/sidecar '%s'.",
			RecommendedAction: "Check health, logs, and configuration of sidecar '%s'.",
		},
		"InitContainerFailed": {
			SummaryTpl:        "Application container unable to start due to initContainer '%s' failure.",
			RecommendedAction: "Inspect logs and termination reason of initContainer '%s'.",
		},
		"GracefulShutdownTimeout": {
			SummaryTpl:        "Process failed to terminate within terminationGracePeriodSeconds (%s) after SIGTERM and was killed by SIGKILL (137).",
			RecommendedAction: "Optimize application SIGTERM handler connection draining or increase terminationGracePeriodSeconds in pod spec.",
		},
		"ReadOnlyRootFilesystem": {
			SummaryTpl:        "Application crashed attempting to write to read-only filesystem (readOnlyRootFilesystem violation).",
			RecommendedAction: "Inspect pod securityContext and mount emptyDir volumes for writable locations such as /tmp.",
		},
		"HeapCorruption": {
			SummaryTpl:        "Native glibc heap corruption detected (Double free or corrupted pointer).",
			RecommendedAction: "Inspect C/C++ native modules or CGO/JNI bindings with AddressSanitizer (ASan).",
		},
		"NodeV8FatalError": {
			SummaryTpl:        "Node.js V8 engine crashed due to JavaScript heap out of memory.",
			RecommendedAction: "Expand '--max-old-space-size' in NODE_OPTIONS or profile memory leaks.",
		},
		"PythonUnhandledException": {
			SummaryTpl:        "Python unhandled exception crash (%s).",
			RecommendedAction: "Inspect traceback location and add try/except error handling or validate input data.",
		},
		"AppUnhandledException": {
			SummaryTpl:        "Unhandled application exception crash (%s).",
			RecommendedAction: "Inspect error traceback and implement proper exception handling.",
		},
		"CircularImportError": {
			SummaryTpl:        "Python circular module import detected: %s.",
			RecommendedAction: "Refactor shared models or move import inside function scope.",
		},
		"SpringCircularDependency": {
			SummaryTpl:        "Spring Boot circular bean dependency detected.",
			RecommendedAction: "Apply @Lazy annotation or refactor bean dependencies.",
		},
		"LazyInitializationException": {
			SummaryTpl:        "JPA/Hibernate LazyInitializationException: no active session.",
			RecommendedAction: "Apply JOIN FETCH or @EntityGraph, or extend @Transactional scope.",
		},
		"TransientPropertyValueException": {
			SummaryTpl:        "JPA TransientPropertyValueException: unsaved transient instance.",
			RecommendedAction: "Configure cascade = CascadeType.ALL or persist child entity first.",
		},
		"NodeESMMismatch": {
			SummaryTpl:        "Node.js module system mismatch (ESM vs CommonJS).",
			RecommendedAction: "Configure '\"type\": \"module\"' in package.json or use .cjs extensions.",
		},
		"NodePrismaError": {
			SummaryTpl:        "Prisma ORM database error: %s.",
			RecommendedAction: "Verify Prisma schema mappings and database connectivity.",
		},
		"EnvoyNoHealthyUpstream": {
			SummaryTpl:        "Envoy / Istio proxy cannot find any healthy upstream endpoint (UH flag).",
			RecommendedAction: "Check target pods health and verify Kubernetes Endpoints registration.",
		},
		"EnvoyCircuitBreakerOverflow": {
			SummaryTpl:        "Envoy circuit breaker connection/request limit exceeded (UO flag).",
			RecommendedAction: "Increase maxConnections/maxPendingRequests in DestinationRule or scale out backend pods.",
		},
		"EnvoyUpstreamConnectionFailure": {
			SummaryTpl:        "Envoy failed to establish upstream connection or TLS handshake (UF flag).",
			RecommendedAction: "Verify target port, network policies, and mTLS configuration.",
		},
		"EnvoyNoRouteConfigured": {
			SummaryTpl:        "Envoy could not match route for the request host/path (NR flag).",
			RecommendedAction: "Verify VirtualService host and URI route matching match the ingress traffic.",
		},
		"EnvoyTLSHandshakeFailed": {
			SummaryTpl:        "Envoy upstream TLS handshake failed or connection reset (UC flag).",
			RecommendedAction: "Inspect DestinationRule tls settings and upstream certificate validity.",
		},
		"EnvoyUpstreamTimeout": {
			SummaryTpl:        "Envoy upstream request timed out (UT flag).",
			RecommendedAction: "Increase VirtualService timeout or optimize upstream service latency.",
		},
		"NginxConfigSyntaxError": {
			SummaryTpl:        "Nginx configuration syntax error failed reload or startup: %s.",
			RecommendedAction: "Fix syntax error in Ingress snippet or ConfigMap nginx.conf.",
		},
		"NginxClientBodySizeExceeded": {
			SummaryTpl:        "Client request body exceeded Nginx client_max_body_size (413 Request Entity Too Large).",
			RecommendedAction: "Add annotation 'nginx.ingress.kubernetes.io/proxy-body-size: \"50m\"' to your Ingress.",
		},
		"IstioProxyNotReady": {
			SummaryTpl:        "Istio sidecar proxy failed readiness probe on port 15021.",
			RecommendedAction: "Check istiod control plane health and istio-proxy container CPU/memory limits.",
		},
		"IstioStartupRaceCondition": {
			SummaryTpl:        "Application started and attempted external/DB egress before istio-proxy reached Ready state.",
			RecommendedAction: "Configure 'proxy.istio.io/config: holdApplicationUntilProxyStarts: true' or adopt K8s 1.28+ native sidecars.",
		},
		"IstioStrictMTLSMismatch": {
			SummaryTpl:        "Plaintext traffic rejected by Istio STRICT mTLS peer authentication policy.",
			RecommendedAction: "Inject Istio sidecar into caller or set PeerAuthentication mode to PERMISSIVE.",
		},
		"EnvoyGatewayTranslationFailed": {
			SummaryTpl:        "Envoy Gateway xDS translation failed or Gateway API BackendRef unresolved.",
			RecommendedAction: "Check Gateway API HTTPRoute backendRefs service and ReferenceGrant.",
		},
		"VaultSealedFailure": {
			SummaryTpl:        "HashiCorp Vault instance is sealed (HTTP 503).",
			RecommendedAction: "Unseal Vault using 'vault operator unseal' with unseal keys.",
		},
		"VaultTokenExpired": {
			SummaryTpl:        "Vault token expired or service account authentication failed.",
			RecommendedAction: "Renew token or check Vault role token_ttl and Kubernetes Auth binding.",
		},
		"CoreDNSLoopDetected": {
			SummaryTpl:        "CoreDNS loop plugin detected forwarding loop and stopped.",
			RecommendedAction: "Remove loopback IP (127.0.0.1/127.0.0.53) from node /etc/resolv.conf and set upstream DNS (8.8.8.8).",
		},
		"CertManagerWebhookFailure": {
			SummaryTpl:        "Cert-Manager webhook connection refused or timed out.",
			RecommendedAction: "Check cert-manager-webhook pod status and verify webhook firewall/CNI port 10250/6443.",
		},
		"ACMERateLimitExceeded": {
			SummaryTpl:        "Let's Encrypt ACME API rate limit exceeded.",
			RecommendedAction: "Use Let's Encrypt staging environment (acme-staging-v02) for non-production clusters.",
		},
		"PrometheusWALCorruption": {
			SummaryTpl:        "Prometheus TSDB Write-Ahead Log (WAL) corruption detected.",
			RecommendedAction: "Check disk integrity, enable WAL compression, or restore corrupted segments from backup.",
		},
		"PrometheusCardinalityOOM": {
			SummaryTpl:        "High-cardinality label explosion caused Prometheus TSDB OOMKilled.",
			RecommendedAction: "Drop high-cardinality labels (userId, timestamps) using metric_relabel_configs.",
		},
		"FluentBitBufferExhaustion": {
			SummaryTpl:        "Fluent Bit ring buffer full or storage chunk paused.",
			RecommendedAction: "Switch storage.type to filesystem for persistent backpressure buffering.",
		},
		"ElasticsearchDiskFloodStage": {
			SummaryTpl:        "Elasticsearch disk usage exceeded flood stage watermark (95%%); indexes set to read-only.",
			RecommendedAction: "Expand disk volume, delete stale indices, and reset 'read_only_allow_delete' to null.",
		},
		"ElasticsearchCircuitBreaker": {
			SummaryTpl:        "Elasticsearch memory circuit breaker tripped ([parent]/[fielddata]).",
			RecommendedAction: "Increase JVM heap (ES_JAVA_OPTS up to 31GB) or optimize memory-heavy queries.",
		},
		"PatroniLeaderLeaseLost": {
			SummaryTpl:        "Patroni lost DCS leader lease and demoted PostgreSQL primary to replica.",
			RecommendedAction: "Check etcd DCS latency, kube-apiserver load, and patroni lease_duration.",
		},
		"PostgresWALDiskFull": {
			SummaryTpl:        "PostgreSQL pg_wal disk full (PANIC: could not write to log file).",
			RecommendedAction: "Verify archive_command status, drop inactive replication slots, and enlarge storage volume.",
		},
		"ArgoCDRepoServerOOM": {
			SummaryTpl:        "Argo CD repo-server OOMKilled during large Helm/Kustomize manifest rendering.",
			RecommendedAction: "Increase memory limit on argocd-repo-server and tune ARGOCD_EXEC_TIMEOUT.",
		},
		"GitRateLimitExceeded": {
			SummaryTpl:        "Git provider API rate limit exceeded.",
			RecommendedAction: "Configure GitHub App or Personal Access Token (PAT) with higher API quotas.",
		},
		"GCPAuthDefaultCredentialsMissing": {
			SummaryTpl:        "Google Cloud SDK Application Default Credentials (ADC) missing or metadata server unreachable.",
			RecommendedAction: "Set GOOGLE_APPLICATION_CREDENTIALS or verify GKE Workload Identity service account annotations.",
		},
		"GCPGeminiQuotaExceeded": {
			SummaryTpl:        "Google Gemini API rate limit or project quota exceeded (HTTP 429 ResourceExhausted).",
			RecommendedAction: "Request a quota increase for Gemini API (TPM, RPM) or implement exponential backoff retry.",
		},
		"GCPGeminiSafetyBlocked": {
			SummaryTpl:        "Google Gemini response candidate or prompt blocked by safety filters.",
			RecommendedAction: "Adjust Gemini safetySettings thresholds or sanitize prompt inputs.",
		},
		"GCPGeminiAuthFailed": {
			SummaryTpl:        "Google Gemini API Key is invalid or unauthenticated (HTTP 401/400).",
			RecommendedAction: "Verify GEMINI_API_KEY environment variable and API key status in GCP Console.",
		},
		"GCPBigQueryQuotaExceeded": {
			SummaryTpl:        "BigQuery query exceeded bytes billed limit or rate limit quota.",
			RecommendedAction: "Increase 'maximum_bytes_billed' or optimize query with partition/cluster filters.",
		},
		"GCPBigQueryQueryFailed": {
			SummaryTpl:        "BigQuery table/dataset permission denied (403) or not found (404).",
			RecommendedAction: "Grant 'roles/bigquery.dataViewer' and 'roles/bigquery.jobUser' to the service account.",
		},
		"GCPStorageChecksumMismatch": {
			SummaryTpl:        "Google Cloud Storage data corruption: CRC32c or MD5 checksum mismatch during transfer.",
			RecommendedAction: "Check network MTU/proxy and tune GCS multipart upload chunk sizes.",
		},
		"GCPStorageAccessDenied": {
			SummaryTpl:        "Google Cloud Storage bucket or object access denied (HTTP 403 Forbidden).",
			RecommendedAction: "Grant 'roles/storage.objectViewer' or 'roles/storage.objectAdmin' to the service account.",
		},
		"ClickHouseTooManyParts": {
			SummaryTpl:        "ClickHouse too many unmerged data parts in table due to high-frequency small inserts.",
			RecommendedAction: "Batch inserts into larger chunks (10,000+ rows) or use the Buffer table engine.",
		},
		"ClickHouseMemoryLimit": {
			SummaryTpl:        "ClickHouse memory limit exceeded for query or server total.",
			RecommendedAction: "Increase max_server_memory_usage and pod memory limit, or enable spill-to-disk external group by.",
		},
		"ClickHouseZooKeeperSessionLost": {
			SummaryTpl:        "ClickHouse lost ZooKeeper coordination session, halting replicated engine tables.",
			RecommendedAction: "Check ZooKeeper cluster status and increase session_timeout_ms in ClickHouse config.",
		},
		"ClickHouseReadOnlyReplica": {
			SummaryTpl:        "ClickHouse table switched to read-only mode due to replica synchronization failure.",
			RecommendedAction: "Run 'SYSTEM RESTART REPLICA <table_name>' to reinitialize the replica session.",
		},
		"ZooKeeperDiskFull": {
			SummaryTpl:        "ZooKeeper transaction log (dataLogDir) or snapshot disk space exhausted.",
			RecommendedAction: "Expand ZooKeeper storage PVC and enable autopurge.purgeInterval=1.",
		},
		"ZooKeeperQuorumLost": {
			SummaryTpl:        "ZooKeeper ensemble quorum lost or leader election failure.",
			RecommendedAction: "Ensure a majority (N/2 + 1) of ZooKeeper nodes are healthy and ports 2888/3888 are reachable.",
		},
		"ZooKeeperSessionExpired": {
			SummaryTpl:        "ZooKeeper client session expired due to network partition or long JVM GC pauses.",
			RecommendedAction: "Tune client JVM GC to eliminate long Stop-The-World pauses and increase tickTime.",
		},
		"ValkeyOOM": {
			SummaryTpl:        "Valkey maxmemory limit reached; write commands rejected with OOM.",
			RecommendedAction: "Increase 'maxmemory' in valkey.conf or configure eviction policy (maxmemory-policy allkeys-lru).",
		},
		"ValkeyReadOnlyReplica": {
			SummaryTpl:        "Attempted write command against a read-only Valkey replica.",
			RecommendedAction: "Direct write traffic to the Valkey Primary endpoint.",
		},
		"ValkeyClusterDown": {
			SummaryTpl:        "Valkey cluster is down; hash slots not fully covered or quorum lost.",
			RecommendedAction: "Run 'valkey-cli cluster check' to inspect slot allocation and restart failed masters.",
		},
		"PostgresTxidExhaustion": {
			SummaryTpl:        "PostgreSQL stopped accepting writes to prevent catastrophic TXID wraparound data loss.",
			RecommendedAction: "Run 'VACUUM FREEZE ANALYZE' in single-user mode immediately and tune autovacuum settings.",
		},
		"PostgresLockTimeout": {
			SummaryTpl:        "PostgreSQL query canceled due to lock_timeout waiting for table or row lock.",
			RecommendedAction: "Check 'pg_stat_activity' for blocking transactions holding conflicting locks.",
		},
		"PostgresStatementTimeout": {
			SummaryTpl:        "PostgreSQL query execution canceled due to statement_timeout limit (SQLState 57014).",
			RecommendedAction: "Analyze execution plan with EXPLAIN ANALYZE, add missing indexes, and adjust statement_timeout for batch jobs.",
		},
		"JenkinsDiskSpaceExhausted": {
			SummaryTpl:        "Jenkins controller or agent workspace disk space exhausted below threshold.",
			RecommendedAction: "Expand Jenkins PVC volume and add 'cleanWs()' in pipeline post-actions.",
		},
		"JenkinsAgentRemotingChannelClosed": {
			SummaryTpl:        "Jenkins remoting channel closed between controller and build agent.",
			RecommendedAction: "Check if agent pod was OOMKilled and verify JNLP (port 50000) connectivity.",
		},
		"NexusBlobStoreFull": {
			SummaryTpl:        "Nexus Repository blob store ran out of disk space, rejecting artifact uploads.",
			RecommendedAction: "Expand Nexus PVC storage and run 'Compact blob store' task.",
		},
		"NexusDatabaseLocked": {
			SummaryTpl:        "Nexus internal database (OrientDB/H2) locked, blocking database transactions.",
			RecommendedAction: "Restart Nexus pod gracefully to clear orphan locks.",
		},
		"ArgoWorkflowDeadlineExceeded": {
			SummaryTpl:        "Argo Workflow task or step exceeded activeDeadlineSeconds timeout.",
			RecommendedAction: "Increase 'activeDeadlineSeconds' in the workflow template.",
		},
		"ArgoArtifactSaveFailed": {
			SummaryTpl:        "Argo Workflow failed to upload step output artifacts to remote repository.",
			RecommendedAction: "Verify artifactRepository secret credentials and network connectivity to object storage.",
		},
		"ArgoRolloutAnalysisFailed": {
			SummaryTpl:        "Argo Rollouts canary AnalysisRun metrics evaluation failed, triggering automated abort/rollback.",
			RecommendedAction: "Inspect Prometheus queries in the AnalysisTemplate and check canary pod error logs.",
		},
		"ArgoRolloutTrafficRoutingFailed": {
			SummaryTpl:        "Argo Rollouts failed to update traffic routing split weights via mesh or ingress plugin.",
			RecommendedAction: "Verify Rollout trafficRouting spec matches Ingress/VirtualService resource names.",
		},
		"KyvernoAdmissionPolicyViolation": {
			SummaryTpl:        "Pod creation denied by Kyverno ClusterPolicy validation rule.",
			RecommendedAction: "Update pod spec to satisfy the violated Kyverno ClusterPolicy.",
		},
		"KyvernoWebhookTimeout": {
			SummaryTpl:        "Kyverno admission webhook timed out or TLS certificate expired.",
			RecommendedAction: "Check kyverno controller pod health, port 9443 connectivity, and TLS secret validity.",
		},
		"GatekeeperConstraintViolation": {
			SummaryTpl:        "Resource creation rejected by OPA Gatekeeper constraint violation.",
			RecommendedAction: "Update resource manifest to comply with the Gatekeeper constraint rules.",
		},
		"GatekeeperWebhookFailure": {
			SummaryTpl:        "Gatekeeper validation webhook call failed or timed out.",
			RecommendedAction: "Inspect gatekeeper-controller-manager pods health and firewall rules.",
		},
		"VaultAuthRoleNotFound": {
			SummaryTpl:        "Vault Secrets Operator VaultAuth role not found on the Vault server.",
			RecommendedAction: "Verify role exists in Vault ('vault read auth/kubernetes/role/<role>').",
		},
		"VaultSecretSyncFailed": {
			SummaryTpl:        "Vault Secrets Operator secret synchronization failed (404 Not Found or Permission Denied).",
			RecommendedAction: "Confirm the secret path and mount point exist in Vault and check token read capabilities.",
		},
		"SecretProviderClassNotFound": {
			SummaryTpl:        "Secrets Store CSI Driver referenced SecretProviderClass resource not found in namespace.",
			RecommendedAction: "Ensure SecretProviderClass exists in the same namespace as the pod.",
		},
		"SecretsStoreCSIMountFailed": {
			SummaryTpl:        "Secrets Store CSI Driver provider mount failed due to permission denied or invalid credentials.",
			RecommendedAction: "Verify provider IAM credentials and Workload Identity federation bindings.",
		},
		"NFSMountAccessDenied": {
			SummaryTpl:        "NFS server denied mount access (export IP restriction or missing no_root_squash).",
			RecommendedAction: "Check '/etc/exports' on NFS server for worker node CIDR and 'no_root_squash'.",
		},
		"NFSConnectionTimeout": {
			SummaryTpl:        "NFS storage server connection timed out or port 2049/111 unreachable.",
			RecommendedAction: "Verify NFS server host is running and ensure firewall permits ports 2049 and 111.",
		},
		"NFSStaleFileHandle": {
			SummaryTpl:        "NFS stale file handle (ESTALE): mounted directory was removed or relocated on the server.",
			RecommendedAction: "Lazy unmount the stale mount ('umount -l') on the host node and recreate the pod.",
		},
		"KubeDNSNXDomainStorm": {
			SummaryTpl:        "kube-dns upstream nameserver failure or excessive NXDOMAIN query storm.",
			RecommendedAction: "Verify kube-dns upstreamNameservers in ConfigMap and optimize ndots in pod dnsConfig.",
		},
		"KubeDNSHealthCheckFailed": {
			SummaryTpl:        "kube-dns sidecar container health check on port 10054 failed.",
			RecommendedAction: "Increase CPU and memory limits for kube-dns pods.",
		},
		"MetricsServerKubeletScrapeFailed": {
			SummaryTpl:        "metrics-server failed to scrape Kubelet metrics on port 10250 (firewall or TLS SAN mismatch).",
			RecommendedAction: "Add '--kubelet-insecure-tls' to metrics-server container args for self-signed Kubelet certificates.",
		},
		"LiteLLMRateLimitExceeded": {
			SummaryTpl:        "LiteLLM upstream LLM provider rate limit (TPM/RPM) exceeded (HTTP 429).",
			RecommendedAction: "Configure model fallbacks in LiteLLM config.yaml or enable response caching.",
		},
		"LiteLLMBudgetExceeded": {
			SummaryTpl:        "LiteLLM user/team/key budget limit exceeded; further requests rejected.",
			RecommendedAction: "Increase or reset 'max_budget' for the user/key via LiteLLM Admin API or UI.",
		},
		"LiteLLMContextWindowExceeded": {
			SummaryTpl:        "Prompt and generation tokens exceeded LLM model maximum context window length.",
			RecommendedAction: "Truncate or summarize prompt history to fit within the context window.",
		},
		"LiteLLMAuthenticationError": {
			SummaryTpl:        "LiteLLM virtual key authentication failed or upstream LLM provider API key invalid.",
			RecommendedAction: "Verify client Bearer token matches LiteLLM virtual key and check upstream API keys.",
		},
		"TCPConnectionReset": {
			SummaryTpl:        "TCP connection forcibly reset by peer or intermediate firewall (ECONNRESET).",
			RecommendedAction: "Check remote pod crash status and L4 load balancer idle session timeout.",
		},
		"TCPConnectionRefused": {
			SummaryTpl:        "TCP connection refused: target port is not listening or process is down (ECONNREFUSED).",
			RecommendedAction: "Verify the target pod is running and listening on the designated port, and check NetworkPolicy.",
		},
		"TCPConnectionTimeout": {
			SummaryTpl:        "TCP connection timed out waiting for SYN-ACK response (ETIMEDOUT / i/o timeout).",
			RecommendedAction: "Inspect security groups, cluster firewalls, or NetworkPolicies for dropped SYN packets.",
		},
		"NetworkUnreachable": {
			SummaryTpl:        "No routing path to target host or subnet gateway down (EHOSTUNREACH / ENETUNREACH).",
			RecommendedAction: "Verify CNI routing table health, VPC subnet route tables, and NAT gateways.",
		},
		"EphemeralPortExhaustion": {
			SummaryTpl:        "Outbound ephemeral ports exhausted, preventing new TCP socket allocation (EADDRNOTAVAIL).",
			RecommendedAction: "Reuse connections with HTTP Keep-Alive pooling and expand sysctl 'net.ipv4.ip_local_port_range'.",
		},
		"DNSResolutionTimeout": {
			SummaryTpl:        "DNS resolution timed out or temporary failure in name resolution (EAI_AGAIN).",
			RecommendedAction: "Check CoreDNS pod status and reduce ndots in pod dnsConfig to prevent search loops.",
		},
		"BrokenPipe": {
			SummaryTpl:        "Attempted write to an already-closed TCP socket stream (EPIPE / Broken pipe).",
			RecommendedAction: "Check if client prematurely closed connection due to short request timeout.",
		},
		"TLSUntrustedCA": {
			SummaryTpl:        "TLS certificate signed by unknown authority (self-signed or untrusted root CA).",
			RecommendedAction: "Mount private root CA into container trust store (/etc/ssl/certs or Java cacerts) and update-ca-certificates.",
		},
		"TLSCertificateExpired": {
			SummaryTpl:        "TLS certificate has expired or system clock is out of sync (CERT_HAS_EXPIRED).",
			RecommendedAction: "Renew the expired TLS certificate on the target server and verify node NTP synchronization.",
		},
		"TLSHostnameMismatch": {
			SummaryTpl:        "TLS certificate Subject Alternative Name (SAN) does not match target hostname or IP address.",
			RecommendedAction: "Inspect certificate SAN list and connect via designated FQDN instead of raw IP.",
		},
		"TLSHandshakeProtocolMismatch": {
			SummaryTpl:        "TLS protocol version or cipher suite mismatch between client and server (HANDSHAKE_FAILURE).",
			RecommendedAction: "Ensure client and server enable at least TLS 1.2 and share compatible cipher suites.",
		},
		"TLSClientCertRequired": {
			SummaryTpl:        "Mutual TLS (mTLS) handshake failed: client certificate required by server but not provided or rejected.",
			RecommendedAction: "Provide valid client certificate and private key in client request configuration.",
		},
		"TLSIncompleteChain": {
			SummaryTpl:        "Server returned incomplete certificate chain missing intermediate CA certificate.",
			RecommendedAction: "Bundle the full certificate chain (fullchain.pem) including intermediate CAs in server config.",
		},
		"ProxyAuthenticationRequired": {
			SummaryTpl:        "Squid forward proxy authentication required (HTTP 407 Proxy Authentication Required).",
			RecommendedAction: "Include proxy credentials in HTTP_PROXY/HTTPS_PROXY environment variables (http://user:pass@proxy:3128).",
		},
		"ProxyAccessDeniedACL": {
			SummaryTpl:        "Squid forward proxy access denied by ACL (HTTP 403 Forbidden - ERR_ACCESS_DENIED).",
			RecommendedAction: "Add 'http_access allow' rule for client IP or destination domain in squid.conf.",
		},
		"ProxyConnectTunnelFailed": {
			SummaryTpl:        "Squid HTTPS CONNECT tunnel rejected (non-standard SSL port or Safe_ports violation).",
			RecommendedAction: "Add the target destination port to SSL_ports and Safe_ports in squid.conf.",
		},
		"ProxyDNSResolutionFailed": {
			SummaryTpl:        "Squid proxy failed to resolve upstream target domain DNS (HTTP 502 - ERR_DNS_FAIL).",
			RecommendedAction: "Inspect /etc/resolv.conf and upstream DNS connectivity on the Squid proxy host.",
		},
		"ProxyGatewayTimeout": {
			SummaryTpl:        "Squid proxy upstream read timeout (HTTP 504 Gateway Timeout - ERR_READ_TIMEOUT).",
			RecommendedAction: "Increase 'read_timeout' and 'connect_timeout' in squid.conf.",
		},
		"ProxyConnectionRefused": {
			SummaryTpl:        "Squid proxy failed to establish TCP connection to upstream server (HTTP 503 - ERR_CONNECT_FAIL).",
			RecommendedAction: "Verify destination server is running and listening on target port, and check firewalls.",
		},
		"ProxySSLBumpFailure": {
			SummaryTpl:        "Squid SslBump dynamic certificate generation or verification failed (ERR_SECURE_ACCEPT_FAIL).",
			RecommendedAction: "Check squid ssl_crtd helper permissions and private root CA certificate validity.",
		},
		"MySQLTooManyConnections": {
			SummaryTpl:        "MySQL server max_connections limit exceeded, rejecting new client connections (Error 1040).",
			RecommendedAction: "Increase max_connections in MySQL / my.cnf and limit client connection pool sizes per pod.",
		},
		"MySQLDeadlock": {
			SummaryTpl:        "MySQL InnoDB transaction deadlock detected and transaction was automatically rolled back (Error 1213).",
			RecommendedAction: "Acquire locks in consistent order across transactions, shorten transaction duration, and apply automatic retries.",
		},
		"MySQLLockWaitTimeout": {
			SummaryTpl:        "MySQL InnoDB lock wait timeout exceeded while waiting for row lock (Error 1205).",
			RecommendedAction: "Inspect long-running transactions via information_schema.innodb_trx and tune innodb_lock_wait_timeout.",
		},
		"MySQLPacketTooLarge": {
			SummaryTpl:        "MySQL packet bigger than server max_allowed_packet bytes limit (Error 1153).",
			RecommendedAction: "Increase max_allowed_packet to 64M+ in my.cnf and match driver maxAllowedPacket settings.",
		},
		"MySQLCommunicationsLinkFailure": {
			SummaryTpl:        "MySQL communications link failure due to server wait_timeout expiration or closed socket.",
			RecommendedAction: "Set connection pool maxLifetime and idleTimeout shorter than MySQL wait_timeout and enable validation query.",
		},
		"MySQLReadOnlyMode": {
			SummaryTpl:        "MySQL server is in read-only mode, rejecting write queries (cluster failover desynchronization).",
			RecommendedAction: "Ensure connection string targets the cluster primary/writer endpoint and lower DNS caching TTL.",
		},
		"PostgresTooManyConnections": {
			SummaryTpl:        "PostgreSQL connection slots exhausted (SQLState 53300: sorry, too many clients already).",
			RecommendedAction: "Deploy PgBouncer or connection pooler, and increase max_connections in postgresql.conf.",
		},
		"PostgresDeadlock": {
			SummaryTpl:        "PostgreSQL transaction deadlock detected and query was aborted (SQLState 40P01).",
			RecommendedAction: "Sort rows by primary key before updating to acquire locks in consistent order, and reduce SELECT FOR UPDATE scope.",
		},
		"PostgresInFailedSQLTransaction": {
			SummaryTpl:        "PostgreSQL transaction aborted due to earlier query failure, subsequent commands ignored (SQLState 25P02).",
			RecommendedAction: "Issue an explicit ROLLBACK or use SAVEPOINT upon encountering errors within a transaction block.",
		},
		"PostgresCannotConnectNow": {
			SummaryTpl:        "PostgreSQL instance is in recovery mode or starting up, rejecting connections (SQLState 57P03).",
			RecommendedAction: "Verify WAL replay status in PostgreSQL logs and wait until replica promotion to primary completes.",
		},
		"PostgresDiskFull": {
			SummaryTpl:        "PostgreSQL disk full, unable to extend table or WAL logs (SQLState 53100: No space left on device).",
			RecommendedAction: "Expand PostgreSQL PVC volume size immediately and clean up orphan replication slots causing WAL accumulation.",
		},
		"ClickHouseSimultaneousQueries": {
			SummaryTpl:        "ClickHouse max concurrent queries limit reached (Code 202: Too many simultaneous queries).",
			RecommendedAction: "Increase max_concurrent_queries in ClickHouse config.xml or throttle concurrent query submissions from clients.",
		},
		"ClickHouseTimeoutExceeded": {
			SummaryTpl:        "ClickHouse query execution timeout exceeded (Code 159).",
			RecommendedAction: "Adjust max_execution_time and ensure queries filter on partition and primary order-by keys.",
		},
		"ClickHouseConnectionPoolExhausted": {
			SummaryTpl:        "ClickHouse client driver connection pool exhausted.",
			RecommendedAction: "Increase client max_open_connections/pool_size and verify that response streams are closed properly.",
		},
		"BigQueryBytesBilledLimitExceeded": {
			SummaryTpl:        "BigQuery query exceeded configured limit for bytes billed (maximum_bytes_billed).",
			RecommendedAction: "Increase maximum_bytes_billed in job configuration or filter on partitioned and clustered columns.",
		},
		"BigQueryPartitionFilterRequired": {
			SummaryTpl:        "BigQuery partitioned table requires a partition filter over partition columns (requirePartitionFilter=true).",
			RecommendedAction: "Add partition column (_PARTITIONDATE or timestamp column) conditions to the WHERE clause.",
		},
		"BigQueryResponseTooLarge": {
			SummaryTpl:        "BigQuery query response too large to return with inline results.",
			RecommendedAction: "Specify a destinationTable for large results or utilize the BigQuery Storage Read API.",
		},
		"BigQueryStreamingInsertQuota": {
			SummaryTpl:        "BigQuery streaming insert quota or rate limit exceeded.",
			RecommendedAction: "Migrate to BigQuery Storage Write API or batch load via Cloud Storage Load Jobs.",
		},
		"BigQueryTableNotFoundInLocation": {
			SummaryTpl:        "BigQuery table/dataset location mismatch (cross-region queries not allowed).",
			RecommendedAction: "Verify that client query job location matches the BigQuery dataset creation location.",
		},
		"PHPMemoryLimitExceeded": {
			SummaryTpl:        "PHP memory_limit exhausted, terminating script execution.",
			RecommendedAction: "Increase memory_limit in php.ini to 256M+ or chunk large query datasets.",
		},
		"PHPMaxExecutionTimeExceeded": {
			SummaryTpl:        "PHP maximum execution time of script exceeded.",
			RecommendedAction: "Increase max_execution_time in php.ini or call set_time_limit(0) in background workers.",
		},
		"PHPUndefinedFunction": {
			SummaryTpl:        "Fatal error calling undefined PHP function (missing extension or typo).",
			RecommendedAction: "Install missing PHP extensions in Dockerfile using docker-php-ext-install.",
		},
		"PHPClassNotFound": {
			SummaryTpl:        "PHP class not found (missing Composer autoloader or namespace mismatch).",
			RecommendedAction: "Run 'composer dump-autoload -o' and ensure vendor/autoload.php is required.",
		},
		"PHPFPMChildrenExhausted": {
			SummaryTpl:        "PHP-FPM worker pool exhausted (pm.max_children reached), blocking incoming requests.",
			RecommendedAction: "Increase pm.max_children in php-fpm.d/www.conf and optimize slow database queries.",
		},
		"PHPFPMChildSignalCrash": {
			SummaryTpl:        "PHP-FPM worker process crashed on signal SIGSEGV/SIGBUS (native C module memory fault).",
			RecommendedAction: "Check compatibility of PHP native C extensions and inspect core dumps.",
		},
		"PHPPDOException": {
			SummaryTpl:        "PHP PDO database connection error or query execution failure.",
			RecommendedAction: "Verify database credentials, host DNS, port, and Kubernetes Service availability.",
		},
		"PHPUnhandledException": {
			SummaryTpl:        "Unhandled PHP exception caused script termination.",
			RecommendedAction: "Inspect error location and wrap failing operations in try-catch blocks.",
		},
		"PHPSyntaxError": {
			SummaryTpl:        "PHP syntax parse error prevented script compilation.",
			RecommendedAction: "Fix syntax error at the referenced line and validate with 'php -l'.",
		},
	},
}

// Localize resolves localized summary and action for a root cause.
func Localize(rootCause, lang, defaultSummary, defaultAction, detail string) (string, string) {
	if defaultSummary != "" && (strings.HasPrefix(defaultSummary, "[") ||
		strings.HasPrefix(defaultSummary, "PHP") ||
		strings.HasPrefix(defaultSummary, "MySQL") ||
		strings.HasPrefix(defaultSummary, "PostgreSQL") ||
		strings.HasPrefix(defaultSummary, "Python 모듈") ||
		strings.HasPrefix(defaultSummary, "Pydantic") ||
		strings.HasPrefix(defaultSummary, "Spring Boot") ||
		strings.HasPrefix(defaultSummary, "HikariCP") ||
		strings.HasPrefix(defaultSummary, "Hibernate") ||
		strings.HasPrefix(defaultSummary, "JPA") ||
		strings.HasPrefix(defaultSummary, "Node.js 모듈") ||
		strings.HasPrefix(defaultSummary, "Node.js 비동기") ||
		strings.HasPrefix(defaultSummary, "Prisma") ||
		strings.HasPrefix(defaultSummary, "NestJS") ||
		strings.HasPrefix(defaultSummary, "Express") ||
		strings.HasPrefix(defaultSummary, "Envoy") ||
		strings.HasPrefix(defaultSummary, "Istio") ||
		strings.HasPrefix(defaultSummary, "Nginx") ||
		strings.HasPrefix(defaultSummary, "Vault") ||
		strings.HasPrefix(defaultSummary, "CoreDNS") ||
		strings.HasPrefix(defaultSummary, "Cert-Manager") ||
		strings.HasPrefix(defaultSummary, "Prometheus") ||
		strings.HasPrefix(defaultSummary, "Fluent Bit") ||
		strings.HasPrefix(defaultSummary, "Elasticsearch") ||
		strings.HasPrefix(defaultSummary, "Patroni") ||
		strings.HasPrefix(defaultSummary, "PostgreSQL") ||
		strings.HasPrefix(defaultSummary, "Argo CD") ||
		strings.HasPrefix(defaultSummary, "Google") ||
		strings.HasPrefix(defaultSummary, "Gemini") ||
		strings.HasPrefix(defaultSummary, "BigQuery") ||
		strings.HasPrefix(defaultSummary, "ClickHouse") ||
		strings.HasPrefix(defaultSummary, "ZooKeeper") ||
		strings.HasPrefix(defaultSummary, "Valkey") ||
		strings.HasPrefix(defaultSummary, "Jenkins") ||
		strings.HasPrefix(defaultSummary, "Nexus") ||
		strings.HasPrefix(defaultSummary, "Argo Workflow") ||
		strings.HasPrefix(defaultSummary, "Argo Rollouts") ||
		strings.HasPrefix(defaultSummary, "Kyverno") ||
		strings.HasPrefix(defaultSummary, "OPA") ||
		strings.HasPrefix(defaultSummary, "Gatekeeper") ||
		strings.HasPrefix(defaultSummary, "NFS") ||
		strings.HasPrefix(defaultSummary, "kube-dns") ||
		strings.HasPrefix(defaultSummary, "metrics-server") ||
		strings.HasPrefix(defaultSummary, "LiteLLM") ||
		strings.HasPrefix(defaultSummary, "Squid") ||
		strings.HasPrefix(defaultSummary, "TLS") ||
		strings.HasPrefix(defaultSummary, "TCP") ||
		strings.HasPrefix(defaultSummary, "Proxy") ||
		strings.HasPrefix(defaultSummary, "DNS") ||
		strings.HasPrefix(defaultSummary, "피어") ||
		strings.HasPrefix(defaultSummary, "대상") ||
		strings.HasPrefix(defaultSummary, "네트워크")) {
		return defaultSummary, defaultAction
	}
	langDict, ok := i18nRegistry[lang]
	if !ok {
		// Fallback to English, then default
		langDict, ok = i18nRegistry["en"]
		if !ok {
			return defaultSummary, defaultAction
		}
	}

	entry, found := langDict[rootCause]
	if !found {
		// Check Korean if requested was not found
		if lang != "ko" {
			if koDict, hasKo := i18nRegistry["ko"]; hasKo {
				if koEntry, hasKoEntry := koDict[rootCause]; hasKoEntry {
					entry = koEntry
					found = true
				}
			}
		}
		if !found {
			return defaultSummary, defaultAction
		}
	}

	summary := entry.SummaryTpl
	if strings.Contains(summary, "%s") {
		summary = strings.Replace(summary, "%s", detail, 1)
	}

	action := entry.RecommendedAction
	if strings.Contains(action, "%s") {
		action = strings.Replace(action, "%s", detail, 1)
	}

	return summary, action
}
