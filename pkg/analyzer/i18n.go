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
			SummaryTpl:        "PostgreSQL 트랜잭션 간 교착 상태(Deadlock detected)가 발생했습니다.",
			RecommendedAction: "트랜잭션 내에서 테이블/행 락을 획득하는 순서를 동일하게 통일하세요.",
		},
		"MySQLTooManyConnections": {
			SummaryTpl:        "MySQL 서버 연결 수 한계에 도달했습니다 (ERROR 1040: Too many connections).",
			RecommendedAction: "my.cnf의 max_connections를 증설하거나 ProxySQL을 구성하세요.",
		},
		"MySQLDeadlock": {
			SummaryTpl:        "MySQL InnoDB 트랜잭션 교착 상태(Deadlock 1213)가 감지되었습니다.",
			RecommendedAction: "1213 에러 시 트랜잭션 자동 재시도 로직을 적용하거나 쿼리 인덱스를 개선하세요.",
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
	},
}

// Localize resolves localized summary and action for a root cause.
func Localize(rootCause, lang, defaultSummary, defaultAction, detail string) (string, string) {
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
