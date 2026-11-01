package synthesizer

import (
	"context"
	"fmt"
	"strings"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
)

const EngineIdentifier = "rule-synthesizer"

// Synthesizer synthesizes factual causal chains and actionable recommendations
// using verified execution evidence and domain-specific incident rules.
type Synthesizer struct{}

func NewSynthesizer() *Synthesizer {
	return &Synthesizer{}
}

func (s *Synthesizer) Synthesize(ctx context.Context, incident IncidentContext) (*InsightResult, error) {
	reqLang := strings.ToLower(strings.TrimSpace(incident.Language))
	targetLang := "ko" // Default language: Korean
	actualLangRecord := "ko"

	if reqLang == "en" {
		targetLang = "en"
		actualLangRecord = "en"
	} else if reqLang != "" && reqLang != "ko" {
		// Requested unsupported language: record transparent fallback
		targetLang = "ko"
		actualLangRecord = fmt.Sprintf("ko (fallback from %s)", reqLang)
	}

	chain := buildRootCauseChain(incident, targetLang)
	inferredContext := buildInferredContext(incident, targetLang)
	suggestedFix := buildSuggestedFix(incident, targetLang)

	return &InsightResult{
		Engine:          EngineIdentifier,
		Analyzed:        true,
		Language:        actualLangRecord,
		Confidence:      incident.Confidence,
		InferredContext: inferredContext,
		SuggestedFix:    suggestedFix,
		RootCauseChain:  chain,
	}, nil
}

func buildRootCauseChain(inc IncidentContext, lang string) []observerv1alpha1.ChainStep {
	var steps []string
	exitCodeStr := "Unknown"
	if inc.ExitCode != nil {
		exitCodeStr = fmt.Sprintf("%d", *inc.ExitCode)
	}

	culpritStr := ""
	if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
		if inc.CulpritCode.Line > 0 {
			culpritStr = fmt.Sprintf("%s:%d", inc.CulpritCode.File, inc.CulpritCode.Line)
		} else {
			culpritStr = inc.CulpritCode.File
		}
	}

	if lang == "ko" {
		switch inc.RootCause {
		case "GracefulShutdownTimeout":
			steps = append(steps, "쿠버네티스가 파드 종료 또는 롤링 업데이트를 시작하고 프로세스에 SIGTERM(143) 신호를 전달함")
			steps = append(steps, "애플리케이션이 진행 중인 요청 처리 또는 커넥션 정리를 terminationGracePeriodSeconds 동안 완료하지 못함")
			steps = append(steps, fmt.Sprintf("Kubelet의 종료 유예 타이머가 만료되어 Linux 커널이 프로세스를 SIGKILL(Exit code %s)로 강제 사살함", exitCodeStr))
		case "ReadOnlyRootFilesystem", "ReadOnlyFilesystemError":
			steps = append(steps, "파드 SecurityContext에 readOnlyRootFilesystem: true 보안 제약이 활성화됨")
			steps = append(steps, "애플리케이션 또는 서드파티 라이브러리가 로컬 루트 파일시스템 디렉토리에 쓰기를 시도함")
			steps = append(steps, "OS 커널이 EROFS(Read-only file system) 오류를 반환하며 기동 또는 처리가 중단됨")
		case "HeapCorruption":
			steps = append(steps, "네이티브 C/C++ 확장 모듈 또는 JNI/CGO에서 메모리 할당/해제 작업이 수행됨")
			steps = append(steps, "이미 해제된 메모리의 재해제(Double Free) 또는 힙 경계 침범으로 메모리 오염이 발생함")
			steps = append(steps, "glibc 메모리 할당자가 손상을 감지하고 안전을 위해 SIGABRT(134) 신호로 프로세스를 즉시 강제 종료함")
		case "NodeV8FatalError":
			steps = append(steps, "Node.js V8 자바스크립트 엔진의 힙 메모리 사용량이 한계(max-old-space-size)에 도달함")
			steps = append(steps, "V8 가비지 컬렉터가 신규 메모리 할당 요청을 처리하지 못함")
			steps = append(steps, "치명적 오류(FATAL ERROR: JavaScript heap out of memory)가 발생하며 런타임이 비정상 종료됨")
		case "SidecarCascadeFailure":
			steps = append(steps, "파드 내 사이드카 또는 프록시 컨테이너에 장애 또는 재시작이 발생함")
			steps = append(steps, "메인 애플리케이션의 로컬호스트(127.0.0.1) 또는 종속성 연결이 거부됨")
			steps = append(steps, "네트워크 통신 불가로 인해 메인 컨테이너가 연쇄적으로 비정상 종료됨")
		case "InitContainerFailed":
			steps = append(steps, "파드 시작 단계에서 initContainer 작업이 실패 또는 크래시됨")
			steps = append(steps, "Kubelet이 사전 조건 미충족으로 메인 컨테이너 기동을 차단함")
		case "OOMKilled", "ProbableOOMKilled", "SystemOOMKilled":
			steps = append(steps, "컨테이너 내 프로세스의 메모리 사용량이 급증함")
			steps = append(steps, "설정된 cgroup 메모리 한도(Memory Limit)에 도달함")
			steps = append(steps, fmt.Sprintf("Linux 커널 OOM Killer에 의해 프로세스가 SIGKILL(Exit code %s)로 강제 종료됨", exitCodeStr))
			steps = append(steps, "Kubelet이 OOMKilled 상태를 기록하고 파드 재시작 정책에 따라 컨테이너를 재시작함")
		case "LivenessProbeFailure":
			steps = append(steps, "애플리케이션이 지정된 헬스체크 엔드포인트 응답을 시간 내에 반환하지 못함")
			steps = append(steps, "Kubelet의 Liveness Probe 연속 실패 횟수가 failureThreshold 한도를 초과함")
			steps = append(steps, fmt.Sprintf("Kubelet이 비정상 컨테이너로 판정하여 프로세스를 종료(Exit code %s) 및 재기동함", exitCodeStr))
		case "StartupProbeFailure":
			steps = append(steps, "애플리케이션 초기화 시간이 지정된 기동 대기 한도를 초과함")
			steps = append(steps, "Kubelet Startup Probe 실패 횟수가 한도에 도달함")
			steps = append(steps, fmt.Sprintf("Kubelet이 컨테이너 초기화 실패로 판정하여 재기동함 (Exit code %s)", exitCodeStr))
		case "NodeMemoryPressure", "NodeDiskPressure", "NodeEviction":
			steps = append(steps, "쿠버네티스 워커 노드의 가용 리소스(메모리/디스크)가 고갈됨")
			steps = append(steps, "Kubelet eviction 매니저가 리소스 보존을 위해 파드 축출(Eviction)을 결정함")
			steps = append(steps, "파드가 강제 중단되고 노드에서 제거됨")
		case "Preempted":
			steps = append(steps, "더 높은 우선순위(PriorityClass)의 파드가 동일 노드에 스케줄링됨")
			steps = append(steps, "쿠버네티스 스케줄러가 노드 리소스 확보를 위해 현재 파드를 선점(Preemption) 대상으로 선정함")
			steps = append(steps, "현재 파드가 종료되고 고우선순위 파드로 대체됨")
		case "SpringHikariPoolExhaustion":
			steps = append(steps, "동시 트래픽 급증 또는 슬로우 쿼리로 DB 커넥션 풀이 모두 점유됨")
			steps = append(steps, "신규 요청이 HikariPool connectionTimeout 동안 연결을 얻지 못함")
			steps = append(steps, "ConnectionPoolTimeoutException 예외 발생으로 스프링 부트 런타임이 중단됨")
		case "SpringPortInUse", "GoPortInUse", "NodePortInUse", "DotNetPortInUse", "PortConflict":
			steps = append(steps, "애플리케이션이 설정된 네트워크 포트에 소켓 바인딩을 시도함")
			steps = append(steps, "해당 포트가 호스트 또는 파드 네트워크 네임스페이스 내에서 이미 점유되어 있음")
			steps = append(steps, "소켓 bind(EADDRINUSE) 실패로 서버 초기화가 중단되고 종료됨")
		case "SpringBootStartupFailure":
			steps = append(steps, "스프링 부트 기동 중 의존성 주입(DI) 또는 설정 파싱이 수행됨")
			steps = append(steps, "누락된 프로퍼티 또는 빈(Bean) 생성 실패로 BeanCreationException 발생")
			steps = append(steps, "ApplicationContext 기동이 실패하며 프로세스가 종료됨")
		case "JVMHeapOOM":
			steps = append(steps, "JVM 힙 메모리(-Xmx) 한도에 도달함")
			steps = append(steps, "가비지 컬렉터(GC)가 추가 메모리 공간을 확보하지 못함")
			steps = append(steps, "java.lang.OutOfMemoryError: Java heap space 에러가 발생하며 프로세스가 종료됨")
		case "JVMMetaspaceOOM":
			steps = append(steps, "클래스 메타데이터 및 리플렉션 프록시가 계속 증가함")
			steps = append(steps, "설정된 MaxMetaspaceSize 한도에 도달함")
			steps = append(steps, "java.lang.OutOfMemoryError: Metaspace 발생으로 JVM이 중단됨")
		case "JVMDirectMemoryOOM":
			steps = append(steps, "Netty 또는 NIO 다이렉트 버퍼가 할당됨")
			steps = append(steps, "Direct Memory 한도 초과 및 미반환으로 메모리가 고갈됨")
			steps = append(steps, "java.lang.OutOfMemoryError: Direct buffer memory 발생으로 크래시됨")
		case "JVMThreadExhaustion":
			steps = append(steps, "스레드 풀 누수 또는 요청 폭주로 신규 스레드 생성을 시도함")
			steps = append(steps, "OS 커널 thread limit(pids.max) 또는 가상 메모리 한계에 도달함")
			steps = append(steps, "java.lang.OutOfMemoryError: unable to create new native thread 발생으로 중단됨")
		case "JVMNullPointer":
			if culpritStr != "" {
				steps = append(steps, fmt.Sprintf("애플리케이션 소스코드(%s)에서 객체 필드/메서드 참조가 수행됨", culpritStr))
			} else {
				steps = append(steps, "초기화되지 않은 Null 레퍼런스에 대한 접근이 발생함")
			}
			steps = append(steps, "java.lang.NullPointerException 예외가 처리되지 않고 최상위까지 전파됨")
			steps = append(steps, "JVM 프로세스가 비정상 종료됨")
		case "JVMStackOverflow", "NodeCallStackExceeded", "PythonRecursionError", "DotNetStackOverflow", "RubySystemStackError":
			steps = append(steps, "재귀 호출 또는 순환 참조 함수가 반복 실행됨")
			steps = append(steps, "런타임 스레드 호출 스택 깊이 한도를 초과함")
			steps = append(steps, "StackOverflowError 발생으로 스택 프레임이 손상되어 프로세스가 즉시 종료됨")
		case "JVMSegfaultCrash", "SegmentationFault":
			steps = append(steps, "네이티브 C/C++ 라이브러리 또는 JNI 드라이버에서 메모리 접근 수행")
			steps = append(steps, "할당되지 않거나 보호된 가상 메모리 주소(Invalid Pointer) 역참조")
			steps = append(steps, fmt.Sprintf("OS 커널이 SIGSEGV(139) 신호를 전송하여 프로세스를 강제 사살함 (Exit code %s)", exitCodeStr))
		case "GoDeadlock":
			steps = append(steps, "Go 고루틴 간 채널 또는 뮤텍스 동기화 대기가 발생함")
			steps = append(steps, "실행 가능한 고루틴이 모두 대기 상태에 빠져 런큐가 정지됨")
			steps = append(steps, "Go 런타임이 'all goroutines are asleep - deadlock!' 치명적 오류를 출력하고 프로세스를 중단함")
		case "GoConcurrentMapAccess":
			steps = append(steps, "여러 고루틴이 락 동기화 없이 동일한 표준 Go 맵에 동시 접근함")
			steps = append(steps, "Go 런타임의 동시성 감지 검사기가 데이터 레이스를 감지함")
			steps = append(steps, "메모리 오염 방지를 위해 'fatal error: concurrent map writes'로 즉시 강제 종료됨")
		case "GoPanic", "GoNilPointerDereference", "GoIndexOutOfRange", "GoSliceBoundsOutOfRange":
			if culpritStr != "" {
				steps = append(steps, fmt.Sprintf("코드 %s 위치에서 런타임 오류가 발생함", culpritStr))
			} else {
				steps = append(steps, "애플리케이션 내부에서 복구되지 않은 런타임 패닉(Panic)이 발생함")
			}
			steps = append(steps, "상위 핸들러에서 recover()되지 않아 스택 언와인딩이 최상위까지 전파됨")
			steps = append(steps, fmt.Sprintf("Go 프로세스가 표준 에러에 스택트레이스를 출력하고 Exit code %s로 종료됨", exitCodeStr))
		case "PythonModuleNotFound", "NodeModuleNotFound", "JVMClassNotFound", "DotNetAssemblyNotFound":
			steps = append(steps, "애플리케이션 시작 시 모듈 및 라이브러리 로드를 시도함")
			steps = append(steps, "컨테이너 이미지 환경 내에 명시된 종속성 파일이 누락되어 있음")
			steps = append(steps, "임포트/클래스로드 실패로 런타임 부팅이 즉시 중단됨")
		case "PythonWorkerTimeout":
			steps = append(steps, "WSGI/ASGI 워커가 긴 DB 쿼리 또는 외부 HTTP 호출로 블로킹됨")
			steps = append(steps, "Gunicorn/Uvicorn 마스터 프로세스의 하트비트 타임아웃에 도달함")
			steps = append(steps, "마스터 프로세스가 무응답 워커를 SIGKILL로 사살하고 재생성을 시도함")
		case "PythonMemoryError", "NodeHeapOOM", "DotNetOOM", "RubyNoMemoryError", "RustAllocFailed", "PHPMemoryExhausted":
			steps = append(steps, "애플리케이션 런타임 내 객체 할당량이 급격히 증가함")
			steps = append(steps, "언어 런타임 메모리 할당자 한도에 도달함")
			steps = append(steps, "메모리 부족 예외(OutOfMemory)가 발생하며 프로세스가 중단됨")
		case "DotNetNullReference":
			if culpritStr != "" {
				steps = append(steps, fmt.Sprintf("%s에서 초기화되지 않은 Null 객체 참조가 발생함", culpritStr))
			} else {
				steps = append(steps, ".NET 애플리케이션에서 System.NullReferenceException 예외가 발생함")
			}
			steps = append(steps, "예외가 처리되지 않아 CLR 런타임 프로세스가 종료됨")
		case "PostgresMaxConnections":
			steps = append(steps, "클라이언트 연결 수가 데이터베이스 서버의 max_connections 한도에 도달함")
			steps = append(steps, "신규 연결 요청이 거부됨 (FATAL / ERROR 1040)")
			steps = append(steps, "애플리케이션이 DB 연결 실패로 인해 크래시되거나 헬스체크에 실패함")
		case "RedisOOM":
			steps = append(steps, "Redis 인메모리 데이터가 maxmemory 한도에 도달함")
			steps = append(steps, "키 제거(eviction) 정책에 의해 더 이상 메모리를 확보할 수 없음")
			steps = append(steps, "쓰기 명령이 'OOM command not allowed'로 거부되며 앱이 실패함")
		case "NginxWorkerConnections":
			steps = append(steps, "동시 인입 커넥션 수가 worker_connections 한도를 초과함")
			steps = append(steps, "신규 클라이언트 소켓 수락(accept)이 거부됨")
			steps = append(steps, "프록시 요청 처리 지연 및 연결 거부 에러가 발생함")
		case "DiskNoSpaceLeft":
			steps = append(steps, "로그 파일 또는 임시 데이터 저장으로 로컬 파일시스템이 꽉 참")
			steps = append(steps, "OS 커널이 파일 쓰기 요청에 ENOSPC(No space left on device)를 반환함")
			steps = append(steps, "치명적 I/O 오류로 애플리케이션이 비정상 종료됨")
		case "FileDescriptorExhaustion":
			steps = append(steps, "소켓 또는 파일 핸들이 누수되어 프로세스 fd 한도(ulimit -n)에 도달함")
			steps = append(steps, "신규 파일 오픈 및 네트워크 연결(accept/connect)에 실패함 (EMFILE)")
			steps = append(steps, "소켓 디스크립터 고갈로 서버가 작동 불능 상태에 빠짐")
		case "ArchitectureMismatch":
			steps = append(steps, "컨테이너 이미지가 빌드된 CPU 아키텍처와 노드의 아키텍처가 불일치함 (예: amd64 vs arm64)")
			steps = append(steps, "Linux 커널의 execve() 호출 시 ELF 헤더 매직 넘버 검증 실패")
			steps = append(steps, "exec format error 발생으로 프로세스가 시작조차 되지 못하고 즉시 종료됨")
		case "PythonUnhandledException", "AppUnhandledException":
			errName := inc.ErrorClass
			if errName == "" || errName == "PythonException" {
				errName = "미처리 예외(Unhandled Exception)"
			}

			fnStr := ""
			culpritPart := ""
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				if inc.CulpritCode.Function != "" {
					fnStr = fmt.Sprintf(" %s() 함수", inc.CulpritCode.Function)
				}
				culpritPart = fmt.Sprintf("소스코드 [%s:%d%s]에서 ", inc.CulpritCode.File, inc.CulpritCode.Line, fnStr)
			}

			steps = append(steps, fmt.Sprintf("%s런타임 오류로 인해 %s 예외가 발생함", culpritPart, errName))
			steps = append(steps, "상위 호출 스택에 try-except 예외 포획(catch) 핸들러가 누락되어 최상위 모듈까지 예외가 전파됨")
			steps = append(steps, fmt.Sprintf("Python 인터프리터가 stderr에 트레이스백(Traceback)을 출력하고 비정상 종료 코드(Exit code %s)로 프로세스를 종료함", exitCodeStr))
			if len(inc.MatchedEvents) > 0 {
				steps = append(steps, fmt.Sprintf("관련 클러스터 이상 징후: %s", inc.MatchedEvents[0]))
			}
			steps = append(steps, "Kubelet이 컨테이너 비정상 종료를 감지하고 파드 재시작 정책에 따라 재시작함")
		case "CircularImportError":
			steps = append(steps, "Python 모듈 초기화 중 상호 참조(Circular Import) 구조가 감지됨")
			steps = append(steps, "한쪽 모듈이 아직 완전히 로드되지 않은 상태에서 다른 모듈의 심볼을 import 시도함")
			steps = append(steps, fmt.Sprintf("ImportError 발생으로 인터프리터 부트스트랩이 실패하고 프로세스가 종료됨 (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet이 컨테이너 초기화 실패를 감지하고 파드 재시작 정책에 따라 재시작함")
		case "SpringCircularDependency":
			steps = append(steps, "Spring Boot ApplicationContext 기동 중 의존성 주입(DI) 그래프 생성 수행")
			steps = append(steps, "빈(Bean)들 간의 상호 순환 참조 고리(Cycle)가 형성되어 생성 순서를 결정하지 못함")
			steps = append(steps, fmt.Sprintf("BeanCurrentlyInCreationException 발생으로 스프링 부트 컨텍스트 초기화가 중단되고 종료됨 (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet이 프로세스 비정상 종료를 감지하고 재기동함")
		case "LazyInitializationException":
			culpritPart := ""
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				culpritPart = fmt.Sprintf("[%s:%d] ", inc.CulpritCode.File, inc.CulpritCode.Line)
			}
			steps = append(steps, fmt.Sprintf("%s영속성 컨텍스트(Session) 종료 후 트랜잭션 외부에서 JPA 지연 로딩(Lazy) 연관 관계 접근", culpritPart))
			steps = append(steps, "데이터베이스 세션 연결이 단절된 상태에서 프록시 객체 초기화 실패")
			steps = append(steps, fmt.Sprintf("org.hibernate.LazyInitializationException 예외가 전파되며 런타임 스레드 및 프로세스 종료 (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet이 컨테이너 재시작 정책에 따라 재기동함")
		case "TransientPropertyValueException":
			steps = append(steps, "부모 엔티티 저장 시 아직 영속화(persist)되지 않은 자식 엔티티를 참조함")
			steps = append(steps, "JPA/Hibernate 매핑에 cascade 영속성 전이 설정 부재로 DB 외래키 무결성 위반 방지 차원에서 예외 발생")
			steps = append(steps, fmt.Sprintf("org.hibernate.TransientPropertyValueException 발생으로 트랜잭션 롤백 및 종료됨 (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet이 컨테이너를 재시작함")
		case "NodeTypeError":
			culpritPart := ""
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				culpritPart = fmt.Sprintf("소스코드 [%s:%d]에서 ", inc.CulpritCode.File, inc.CulpritCode.Line)
			}
			steps = append(steps, fmt.Sprintf("%s정의되지 않은 객체(undefined 또는 null)의 프로퍼티 또는 메서드 접근 시도", culpritPart))
			steps = append(steps, "V8 자바스크립트 엔진이 런타임 TypeError 예외를 발생시킴")
			steps = append(steps, fmt.Sprintf("상위 호출 스택에 try-catch 에러 핸들러가 누락되어 프로세스가 즉시 비정상 종료됨 (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet이 컨테이너 비정상 종료를 감지하고 파드 재시작 정책에 따라 재기동함")
		case "NodeUnhandledPromiseRejection":
			steps = append(steps, "비동기(async/Promise) 로직 실행 도중 거부(Rejection) 또는 예외가 발생함")
			steps = append(steps, "호출 체인에 await 누락 또는 .catch() 에러 처리 핸들러 부재로 미처리 거부(UnhandledPromiseRejection) 상태가 됨")
			steps = append(steps, fmt.Sprintf("Node.js 15+ 런타임 정책에 따라 비정상 종료 코드(Exit code %s)로 프로세스가 즉시 종료됨", exitCodeStr))
			steps = append(steps, "Kubelet이 컨테이너 비정상 종료를 감지하고 재기동함")
		case "NodeESMMismatch":
			steps = append(steps, "Node.js 모듈 로드 시점 ESM(import/export)과 CommonJS(require/module.exports) 구문 불일치 발생")
			steps = append(steps, "V8 모듈 로더가 현재 스코프에서 모듈 심볼을 해석하지 못해 ReferenceError/SyntaxError 발생")
			steps = append(steps, fmt.Sprintf("모듈 초기화 실패로 애플리케이션이 시작되지 못하고 즉시 종료됨 (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet이 컨테이너를 재시작함")
		case "NodePrismaError", "NodePrismaInitFailed":
			steps = append(steps, "Prisma ORM 클라이언트가 데이터베이스 서버 접속 또는 쿼리 실행을 시도함")
			steps = append(steps, fmt.Sprintf("데이터베이스 오류(유니크 제약 위반, 연결 불가 또는 스키마 불일치: %s) 발생", inc.ErrorClass))
			steps = append(steps, fmt.Sprintf("PrismaClient 에러가 처리되지 않아 서비스 프로세스가 비정상 종료됨 (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet이 컨테이너 재시작 정책에 따라 재기동함")
		case "EnvoyNoHealthyUpstream":
			steps = append(steps, "클라이언트 인입 트래픽이 Envoy/Istio 서비스 프록시로 라우팅됨")
			steps = append(steps, "대상 클러스터 엔드포인트 헬스체크 실패 또는 백엔드 파드가 준비(Ready)되지 않음")
			steps = append(steps, "Envoy가 503 UH (No Healthy Upstream) 응답 플래그를 생성하고 연결을 거부함")
			steps = append(steps, "Kubelet 및 모니터링 시스템이 서비스 다운 및 연속 요청 실패를 감지함")
		case "EnvoyCircuitBreakerOverflow":
			steps = append(steps, "백엔드 대상 동시 요청 수 또는 활성 커넥션 수가 폭증함")
			steps = append(steps, "DestinationRule에 정의된 maxConnections 또는 maxPendingRequests 임계치 도달")
			steps = append(steps, "Envoy 서킷 브레이커가 발동하여 503 UO (Upstream Overflow)로 신규 요청 차단")
			steps = append(steps, "백엔드 과부하 보호를 위해 장애 격리 상태로 진입함")
		case "EnvoyUpstreamConnectionFailure":
			steps = append(steps, "Envoy 프록시가 업스트림 서비스 IP/Port로 TCP 커넥션 또는 mTLS 연결을 시도함")
			steps = append(steps, "대상 파드 포트 미기동(Connection Refused) 또는 네트워크 정책(NetworkPolicy)에 의해 패킷 드롭")
			steps = append(steps, "Envoy가 503 UF (Upstream Connection Failure)를 기록하고 요청을 즉시 중단함")
		case "EnvoyNoRouteConfigured":
			steps = append(steps, "HTTP 요청의 Host 헤더 및 Request URI 경로가 수신됨")
			steps = append(steps, "VirtualService 및 RouteConfiguration 테이블에서 일치하는 라우팅 규칙 검색 실패")
			steps = append(steps, "Envoy가 404 NR (No Route Configured) 상태 코드로 요청을 즉시 거부함")
		case "EnvoyTLSHandshakeFailed":
			steps = append(steps, "Envoy가 업스트림 서비스와 TLS 암호화 세션 협상(Handshake)을 시작함")
			steps = append(steps, "인증서 불일치, 만료 또는 mTLS 모드(ISTIO_MUTUAL vs DISABLE) 설정 충돌 발생")
			steps = append(steps, "Envoy가 503 UC (Upstream Connection Terminated) 플래그를 남기며 연결을 즉시 강제 종료함")
		case "EnvoyUpstreamTimeout":
			steps = append(steps, "Envoy 프록시가 업스트림 백엔드 파드로 요청을 성공적으로 전달함")
			steps = append(steps, "백엔드 애플리케이션의 쿼리 락 또는 병목으로 인해 응답이 지연됨")
			steps = append(steps, "VirtualService에 정의된 timeout 타이머가 만료되어 504 UT (Upstream Timeout) 발생")
		case "NginxConfigSyntaxError":
			steps = append(steps, "Ingress-Nginx 컨트롤러 또는 웹 서버가 설정을 파싱하거나 리로드(Reload)를 시도함")
			steps = append(steps, "nginx.conf 또는 Ingress snippet 어노테이션에서 문법 오류(Syntax error) 발생")
			steps = append(steps, fmt.Sprintf("Nginx 마스터 프로세스가 'nginx: [emerg]' 오류를 출력하고 기동에 실패함 (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet이 설정 오류로 인한 비정상 프로세스 종료를 감지하고 컨테이너를 재시작함")
		case "NginxClientBodySizeExceeded":
			steps = append(steps, "클라이언트가 대용량 파일 또는 JSON 페이로드를 업로드함")
			steps = append(steps, "전송된 HTTP 요청 본문 크기가 Nginx client_max_body_size 한도를 초과함")
			steps = append(steps, "Nginx가 업스트림 전달 없이 413 Request Entity Too Large 오류를 반환하고 연결을 드레인함")
		case "IstioProxyNotReady":
			steps = append(steps, "파드 기동 시 istio-proxy 사이드카 컨테이너가 시작됨")
			steps = append(steps, "istiod 컨트롤 플레인과의 xDS 동기화 지연 또는 CPU 스로틀링 발생")
			steps = append(steps, "15021 준비성 프로브(Readiness Probe) 검사에 연속 실패하여 서비스 엔드포인트 등록이 차단됨")
		case "IstioStartupRaceCondition":
			steps = append(steps, "파드 스케줄링 후 메인 애플리케이션 컨테이너와 istio-proxy 사이드카가 동시 기동됨")
			steps = append(steps, "istio-proxy가 15021 준비 완료 상태에 도달하기 전 메인 컨테이너가 외부 DB/DNS 연결을 시도함")
			steps = append(steps, "iptables 트래픽 리다이렉션으로 인해 로컬 연결이 거절(Connection Refused)되어 메인 앱이 즉시 크래시됨")
			steps = append(steps, fmt.Sprintf("메인 프로세스가 비정상 종료 코드(%s)로 사망하고 Kubelet에 의해 재기동 루프에 빠짐", exitCodeStr))
		case "IstioStrictMTLSMismatch":
			steps = append(steps, "클라이언트 파드가 서비스로 평문(Plaintext HTTP) 연결을 요청함")
			steps = append(steps, "대상 네임스페이스의 PeerAuthentication 정책이 STRICT mTLS로 강제되어 있음")
			steps = append(steps, "Envoy 사이드카가 TLS 핸드셰이크 없는 비보안 트래픽을 거절하고 연결을 리셋함")
		case "EnvoyGatewayTranslationFailed":
			steps = append(steps, "쿠버네티스 Gateway API HTTPRoute 또는 Gateway 리소스가 선언됨")
			steps = append(steps, "backendRefs 서비스 미존재 또는 교차 네임스페이스 ReferenceGrant 권한 누락 발생")
			steps = append(steps, "Envoy Gateway 제어부가 xDS 설정을 NACK 처리하고 라우트 반영에 실패함")
		case "VaultSealedFailure":
			steps = append(steps, "HashiCorp Vault 파드가 재시작되거나 신규 배포됨")
			steps = append(steps, "마스터 키가 메모리에 복원되지 않아 Vault 인스턴스가 봉인(Sealed) 상태로 진입함")
			steps = append(steps, "Vault Agent 및 애플리케이션의 시크릿 조회 요청이 HTTP 503으로 거부됨")
			steps = append(steps, "시크릿 주입 실패로 인해 의존성 애플리케이션 컨테이너가 연쇄 크래시됨")
		case "VaultTokenExpired":
			steps = append(steps, "애플리케이션 또는 사이드카가 Vault Secret 읽기 또는 토큰 갱신을 요청함")
			steps = append(steps, "발급된 Vault 토큰의 TTL이 만료되었거나 Kube Auth 역할 권한 검증에 실패함")
			steps = append(steps, "Vault 서버가 403 Forbidden / Permission Denied를 반환하며 기동이 중단됨")
		case "CoreDNSLoopDetected":
			steps = append(steps, "워커 노드의 /etc/resolv.conf에 로컬 DNS(127.0.0.53/127.0.0.1)가 네임서버로 설정됨")
			steps = append(steps, "CoreDNS forward 플러그인이 쿼리를 전달하면서 무한 순환 포워딩 루프 발생")
			steps = append(steps, "CoreDNS loop 플러그인이 루프를 감지하고 전체 DNS 마비를 막기 위해 파드를 긴급 중단함")
			steps = append(steps, "클러스터 전체 파드의 도메인 이름 해석이 일시적으로 전면 중단됨")
		case "CertManagerWebhookFailure":
			steps = append(steps, "쿠버네티스 API 서버가 Certificate 또는 Issuer 리소스 생성 검증을 시작함")
			steps = append(steps, "cert-manager-webhook 파드 호출 타임아웃 또는 포트(10250/6443) 네트워크 차단 발생")
			steps = append(steps, "ValidatingWebhookConfiguration 호출 실패로 인해 인증서 발급 리소스 배포가 거부됨")
		case "ACMERateLimitExceeded":
			steps = append(steps, "파드 반복 재시작 또는 개발 테스트 중 Let's Encrypt로 대량 인증서 발급 요청 전송")
			steps = append(steps, "Let's Encrypt ACME API의 도메인/계정당 주간 발급 쿼터 한도(Rate Limit) 초과")
			steps = append(steps, "ACME 서버가 HTTP 429 Too Many Requests를 반환하며 신규 인증서 발급이 차단됨")
		case "PrometheusWALCorruption":
			steps = append(steps, "노드 전원 단절 또는 컨테이너 강제 종료(SIGKILL)로 인해 디스크 쓰기 중단")
			steps = append(steps, "Prometheus TSDB의 WAL(Write-Ahead Log) 파일 세그먼트 손상 발생")
			steps = append(steps, fmt.Sprintf("Prometheus 재기동 시 WAL 복구에 실패하고 치명적 에러로 종료됨 (Exit code %s)", exitCodeStr))
			steps = append(steps, "클러스터 메트릭 수집 및 모니터링 파이프라인이 중단됨")
		case "PrometheusCardinalityOOM":
			steps = append(steps, "애플리케이션이 메트릭에 고유 식별자(userId, guid, 타임스탬프) 라벨을 대량 삽입함")
			steps = append(steps, "활성 시계열(Time Series) 데이터가 수백만 개로 급증하여 TSDB 힙 메모리 폭증")
			steps = append(steps, fmt.Sprintf("cgroup 메모리 한도 초과로 Linux 커널 OOM Killer가 프로세스를 사살함 (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet이 OOMKilled 상태를 기록하고 파드를 재시작함")
		case "FluentBitBufferExhaustion":
			steps = append(steps, "로그 방출량 급증 또는 원격 스토리지(ES/Loki) 지연으로 버퍼에 로그가 적체됨")
			steps = append(steps, "Fluent Bit 인메모리 링 버퍼 한도에 도달하여 신규 로그 인제스천 일시 중지")
			steps = append(steps, "로그 수집 지연 및 파이프라인 배압(Backpressure)으로 인한 컨테이너 로그 유실 위험 발생")
		case "ElasticsearchDiskFloodStage":
			steps = append(steps, "Elasticsearch 데이터 노드의 디스크 사용량이 95% (Flood Stage Watermark) 초과")
			steps = append(steps, "인덱스 손상 방지를 위해 클러스터가 모든 인덱스에 'read_only_allow_delete'를 강제 적용")
			steps = append(steps, "신규 도큐먼트 색인 및 쓰기 작업이 전면 거부되어 로그/데이터 적재 파이프라인 중단")
		case "ElasticsearchCircuitBreaker":
			steps = append(steps, "대용량 집계(Aggregation) 또는 비효율적인 와일드카드 쿼리가 노드에 실행됨")
			steps = append(steps, "JVM 힙 메모리가 서킷 브레이커([parent]/[fielddata]) 임계치를 초과함")
			steps = append(steps, "Elasticsearch가 JVM OOM 방지를 위해 CircuitBreakingException을 던지고 쿼리를 거부함")
		case "PatroniLeaderLeaseLost":
			steps = append(steps, "DCS(etcd 또는 k8s API) 네트워크 지연 또는 일시적 파티션 발생")
			steps = append(steps, "Patroni Primary 인스턴스가 하트비트 리더 임차권(Lease) 갱신에 실패함")
			steps = append(steps, "스플릿 브레인(Split-Brain) 방지를 위해 Primary가 자신을 Replica로 즉시 강등(Demote)")
			steps = append(steps, "클러스터가 일시적인 읽기 전용 상태에 진입하고 신규 리더 선출이 진행됨")
		case "PostgresWALDiskFull":
			steps = append(steps, "복제 슬롯(Replication Slot) 지연 또는 아카이빙 실패로 pg_wal 파일이 디스크에 지속 누적됨")
			steps = append(steps, "스토리지 볼륨 용량이 100%에 도달하여 PostgreSQL 트랜잭션 로그 쓰기 불가능")
			steps = append(steps, fmt.Sprintf("PostgreSQL 엔진이 PANIC(could not write to log file)을 일으키며 비정상 종료됨 (Exit code %s)", exitCodeStr))
		case "ArgoCDRepoServerOOM":
			steps = append(steps, "수백 개 서브차트가 포함된 대규모 Helm Chart 또는 Kustomize 매니페스트 템플릿 렌더링 시작")
			steps = append(steps, "argocd-repo-server 프로세스의 인메모리 파싱 메모리 사용량이 컨테이너 Limit을 초과함")
			steps = append(steps, fmt.Sprintf("리눅스 커널 OOM Killer에 의해 SIGKILL(Exit code %s)로 프로세스가 강제 사살됨", exitCodeStr))
			steps = append(steps, "GitOps 애플리케이션 동기화(Sync) 작업이 실패 상태로 중단됨")
		case "GitRateLimitExceeded":
			steps = append(steps, "Argo CD가 다수의 애플리케이션 저장소를 주기적으로 폴링(Polling)함")
			steps = append(steps, "원격 Git 호스팅(GitHub/GitLab) API 속도 제한 쿼터(Rate Limit)가 고갈됨")
			steps = append(steps, "원격 저장소 접근이 HTTP 403/429 오류로 차단되어 지속적 배포 동기화가 중단됨")
		case "GCPAuthDefaultCredentialsMissing":
			steps = append(steps, "Google Cloud 클라이언트 SDK가 초기화되며 자격 증명(ADC) 조회를 시작함")
			steps = append(steps, "GOOGLE_APPLICATION_CREDENTIALS 환경변수 미지정 및 메타데이터 서버 자격 증명 조회 실패")
			steps = append(steps, fmt.Sprintf("DefaultCredentialsError 예외 발생으로 프로세스가 기동 실패함 (Exit code %s)", exitCodeStr))
		case "GCPGeminiQuotaExceeded":
			steps = append(steps, "애플리케이션이 Google Gemini API로 생성(generateContent) 요청을 전송함")
			steps = append(steps, "프로젝트 분당 토큰/요청 한도(TPM/RPM) 초과로 HTTP 429 ResourceExhausted 수신")
			steps = append(steps, "클라이언트 재시도 한도 초과 또는 미처리 APIError로 프로세스가 중단됨")
		case "GCPGeminiSafetyBlocked":
			steps = append(steps, "Google Gemini 모델이 프롬프트 또는 생성 후보군을 분석함")
			steps = append(steps, "유해성 평가(Hate Speech, Harassment 등) 점수가 safetySettings 임계치를 초과함")
			steps = append(steps, "finish_reason: SAFETY로 응답 생성이 차단되고 빈 콘텐츠 반환 또는 예외 발생")
		case "GCPBigQueryQuotaExceeded":
			steps = append(steps, "애플리케이션이 대용량 BigQuery 분석 쿼리를 실행함")
			steps = append(steps, "쿼리가 스캔한 데이터양이 'maximum_bytes_billed' 한도를 초과함")
			steps = append(steps, "BigQuery API가 400 Query exceeded limit 오류를 반환하며 쿼리 작업 실패")
		case "GCPStorageAccessDenied":
			steps = append(steps, "Google Cloud Storage 버킷 또는 객체 읽기/쓰기 API 호출 발생")
			steps = append(steps, "요청한 서비스 어카운트에 'storage.objects.get/create' IAM 권한 부재")
			steps = append(steps, "GCS API가 403 Forbidden을 반환하며 파일 I/O 실패")
		case "ClickHouseTooManyParts":
			steps = append(steps, "ClickHouse 테이블로 고빈도 소규모 데이터 INSERT가 지속 인입됨")
			steps = append(steps, "백그라운드 파트 머지(Merge) 속도가 삽입 속도를 따라가지 못해 파트 수가 300개를 초과함")
			steps = append(steps, "ClickHouse 엔진이 데이터 무결성 보호를 위해 'Too many parts' 예외를 던지고 쓰기를 차단함")
		case "ClickHouseMemoryLimit":
			steps = append(steps, "대규모 집계 또는 복잡한 JOIN 쿼리가 실행되며 RAM 사용량이 급증함")
			steps = append(steps, "설정된 'max_server_memory_usage' 또는 쿼리 메모리 한도에 도달함")
			steps = append(steps, "ClickHouse 메모리 트래커가 쿼리를 강제 중단하거나 프로세스를 보호함")
		case "ClickHouseZooKeeperSessionLost":
			steps = append(steps, "ClickHouse 복제 테이블이 ZooKeeper 앙상블과 하트비트를 유지함")
			steps = append(steps, "네트워크 레이턴시 또는 ZK 부하로 인해 세션 타임아웃(Session expired) 발생")
			steps = append(steps, "복제본 동기화가 중단되고 테이블이 일시적 Readonly 모드로 격리됨")
		case "ZooKeeperDiskFull":
			steps = append(steps, "ZooKeeper 트랜잭션 커밋 로그 및 스냅샷 파일이 지속적으로 생성됨")
			steps = append(steps, "dataDir 또는 dataLogDir 스토리지 볼륨이 100% 가득 참 (ENOSPC)")
			steps = append(steps, fmt.Sprintf("디스크 쓰기 실패(IOException: No space left on device)로 ZooKeeper 데몬이 중단됨 (Exit code %s)", exitCodeStr))
		case "ZooKeeperQuorumLost":
			steps = append(steps, "ZooKeeper 노드 장애 또는 파티션으로 통신 가능한 활성 노드 수 감소")
			steps = append(steps, "클러스터 리더 선출 불가능 및 과반수(Quorum) 정족수 미달 상태 진입")
			steps = append(steps, "앙상블이 모든 클라이언트 요청 처리를 중단하고 동기화 대기에 돌입함")
		case "ValkeyOOM":
			steps = append(steps, "Valkey 인메모리 키/값 데이터 사용량이 'maxmemory' 설정에 도달함")
			steps = append(steps, "키 제거(eviction) 정책으로 신규 메모리를 확보하지 못함")
			steps = append(steps, "신규 쓰기 명령이 'OOM command not allowed' 오류로 거부됨")
		case "PostgresTxidExhaustion":
			steps = append(steps, "PostgreSQL 장시간 트랜잭션 또는 autovacuum 지연으로 TXID가 20억 개 이상 누적됨")
			steps = append(steps, "트랜잭션 ID 래핑(Wraparound)으로 인한 영구적 데이터 손실 위험 감지")
			steps = append(steps, "PostgreSQL 엔진이 비상 안전 모드로 진입하여 모든 쓰기 트랜잭션을 전면 거부함")
		case "JenkinsDiskSpaceExhausted":
			steps = append(steps, "Jenkins 노드에서 빌드 아티팩트 및 도커 캐시가 지속 누적됨")
			steps = append(steps, "워크스페이스 여유 디스크가 시스템 임계치(1.0 GiB) 미만으로 하락")
			steps = append(steps, "Jenkins 마스터가 안전을 위해 해당 에이전트의 빌드 스케줄링을 일시 중단함")
		case "ArgoWorkflowDeadlineExceeded":
			steps = append(steps, "Argo Workflow 파이프라인 태스크가 실행 중 긴 외부 작업 또는 블로킹 대기 발생")
			steps = append(steps, "스펙에 지정된 activeDeadlineSeconds 제한 시간을 초과함")
			steps = append(steps, "workflow-controller가 실행 중인 파드를 종료하고 WorkflowDeadlineExceeded 상태로 마킹함")
		case "ArgoRolloutAnalysisFailed":
			steps = append(steps, "Argo Rollouts가 카나리 트래픽 분할 후 AnalysisRun 지표 측정을 실행함")
			steps = append(steps, "Prometheus 성공률 또는 지연 시간 지표가 failureLimit 임계치를 초과함")
			steps = append(steps, "Rollout 컨트롤러가 이상을 감지하고 안전을 위해 즉시 이전 안정 버전으로 자동 롤백함")
		case "KyvernoAdmissionPolicyViolation":
			steps = append(steps, "쿠버네티스 API 서버가 리소스 생성/변경 요청을 수신함")
			steps = append(steps, "Kyverno 어드미션 웹훅이 ClusterPolicy 유효성 검증(Validation) 규칙을 실행함")
			steps = append(steps, "보안 규정 위반(루트 권한, CPU Limit 누락 등)으로 요청이 차단됨")
		case "KyvernoWebhookTimeout":
			steps = append(steps, "API 서버가 리소스 변형/검증을 위해 Kyverno 웹훅 서비스(9443)를 호출함")
			steps = append(steps, "Kyverno 파드 과부하 또는 인증서 만료로 context deadline exceeded 발생")
			steps = append(steps, "웹훅 호출 실패로 인해 클러스터 리소스 배포 파이프라인이 차단됨")
		case "GatekeeperConstraintViolation":
			steps = append(steps, "OPA Gatekeeper admission webhook이 리소스 명세를 수신함")
			steps = append(steps, "Rego 제약 조건(Constraint) 평가 결과 거부(deny) 규칙에 매칭됨")
			steps = append(steps, "API 서버가 클라이언트에게 403 Forbidden과 함께 제약 위반 에러를 반환함")
		case "SecretProviderClassNotFound":
			steps = append(steps, "Kubelet이 Secrets Store CSI 볼륨 마운트 작업을 시작함")
			steps = append(steps, "해당 네임스페이스에서 지정된 SecretProviderClass CRD 리소스를 찾을 수 없음")
			steps = append(steps, "MountVolume.SetUp 실패로 파드가 ContainerCreating / CrashLoopBackOff 상태에 빠짐")
		case "NFSMountAccessDenied":
			steps = append(steps, "노드가 NFS 서버로 원격 디렉토리 마운트(mount.nfs) 시스템 콜을 실행함")
			steps = append(steps, "NFS 서버가 클라이언트 IP 또는 no_root_squash 권한 불일치로 접근 거부(Access denied)")
			steps = append(steps, "볼륨 마운트 실패로 인해 컨테이너 기동이 차단됨")
		case "NFSConnectionTimeout":
			steps = append(steps, "노드가 NFS 서버 IP의 2049/111 포트로 TCP 연결을 시도함")
			steps = append(steps, "방화벽 포트 차단 또는 스토리지 서버 다운으로 Connection timed out 발생")
			steps = append(steps, "Kubelet의 볼륨 마운트가 타임아웃되며 파드 생성이 지연됨")
		case "MetricsServerKubeletScrapeFailed":
			steps = append(steps, "metrics-server가 워커 노드의 Kubelet(10250) 메트릭 엔드포인트 수집을 시도함")
			steps = append(steps, "Kubelet 자체 서명 인증서 불일치 또는 10250 포트 네트워크 차단 발생")
			steps = append(steps, "노드/파드 리소스 메트릭 수집 불가로 HPA 오토스케일링 기능이 중단됨")
		case "LiteLLMRateLimitExceeded":
			steps = append(steps, "클라이언트 애플리케이션이 LiteLLM 프록시로 LLM 생성 쿼리를 전송함")
			steps = append(steps, "업스트림 LLM 프로바이더(OpenAI/Anthropic/Gemini)의 TPM/RPM 한도에 도달함")
			steps = append(steps, "LiteLLM이 클라이언트에게 429 Too Many Requests (RateLimitError)를 반환함")
		case "LiteLLMBudgetExceeded":
			steps = append(steps, "LiteLLM 프록시가 가상 키의 누적 비용/토큰 사용량을 검증함")
			steps = append(steps, "설정된 'max_budget' 한도를 초과하여 신규 요청이 차단됨 (BudgetExceededError)")
		case "LiteLLMContextWindowExceeded":
			steps = append(steps, "입력 프롬프트와 요청 토큰 수가 모델의 최대 허용 컨텍스트 길이를 초과함")
			steps = append(steps, "LiteLLM이 ContextWindowExceededError를 발생시키며 쿼리 실행을 거부함")
		case "TCPConnectionReset":
			steps = append(steps, "클라이언트 애플리케이션이 원격 서비스와 TCP 소켓 통신을 수행함")
			steps = append(steps, "피어 서버 프로세스 비정상 종료 또는 중간 L4 방화벽 유휴 타임아웃 만료")
			steps = append(steps, "원격 또는 중간 장비로부터 TCP RST(Reset) 패킷이 인입되어 연결이 강제 리셋됨 (ECONNRESET)")
		case "TCPConnectionRefused":
			steps = append(steps, "클라이언트가 목적지 IP/포트로 TCP SYN 패킷을 전송함")
			steps = append(steps, "대상 호스트에서 해당 포트를 수신(Listen) 대기 중인 프로세스가 없거나 NetworkPolicy가 인입 차단")
			steps = append(steps, "커널이 TCP RST/ACK를 응답하며 연결이 즉시 거절됨 (ECONNREFUSED)")
		case "TCPConnectionTimeout":
			steps = append(steps, "클라이언트가 TCP 3-Way Handshake SYN 패킷을 전송하고 응답을 대기함")
			steps = append(steps, "네트워크 패킷 드롭(방화벽 무응답 드롭 또는 잘못된 라우팅)으로 SYN-ACK 수신 실패")
			steps = append(steps, fmt.Sprintf("TCP SYN 재전송 횟수 초과로 소켓 연결이 타임아웃(ETIMEDOUT / i/o timeout)되며 실패함 (Exit code %s)", exitCodeStr))
		case "NetworkUnreachable":
			steps = append(steps, "애플리케이션이 원격 호스트 IP로 소켓 연결 또는 패킷 전송을 시도함")
			steps = append(steps, "로컬 라우팅 테이블에 해당 서브넷 목적지 게이트웨이 경로가 누락됨 (No route to host)")
			steps = append(steps, "커널 IP 스택이 즉시 EHOSTUNREACH / ENETUNREACH 에러를 반환하며 통신 중단")
		case "EphemeralPortExhaustion":
			steps = append(steps, "대량의 아웃바운드 단기 연결(Short-lived HTTP 요청)이 급증함")
			steps = append(steps, "TIME_WAIT 상태 소켓 누적으로 로컬 임시 포트 범위(ip_local_port_range)가 고갈됨")
			steps = append(steps, "커널이 신규 소켓에 로컬 IP/포트를 할당하지 못해 EADDRNOTAVAIL (Cannot assign requested address) 발생")
		case "TLSUntrustedCA":
			steps = append(steps, "클라이언트가 HTTPS/TLS 연결을 맺고 서버 인증서를 수신함")
			steps = append(steps, "서버 인증서의 발급자(Issuer)가 시스템 신뢰 루트 CA 저장소에 등록되지 않음")
			steps = append(steps, "X.509 인증서 유효성 검증 실패(certificate signed by unknown authority / PKIX path building failed)")
		case "TLSCertificateExpired":
			steps = append(steps, "TLS 세션 협상(Handshake) 중 서버 인증서의 유효기간(NotAfter)을 검증함")
			steps = append(steps, "인증서 만료일이 지났거나 노드 시스템 시계(Clock)가 어긋나 유효기간 범위를 벗어남")
			steps = append(steps, "TLS 핸드셰이크가 CERT_HAS_EXPIRED 에러로 즉시 중단됨")
		case "TLSHostnameMismatch":
			steps = append(steps, "클라이언트가 대상 도메인 또는 IP로 TLS 연결을 수립함")
			steps = append(steps, "서버 인증서의 Subject Alternative Name(SAN) 목록에 접속 대상 호스트명이 존재하지 않음")
			steps = append(steps, "클라이언트 TLS 스택이 호스트명 불일치(Hostname mismatch)로 연결을 강제 차단함")
		case "TLSClientCertRequired":
			steps = append(steps, "상호 인증(mTLS) 서버가 핸드셰이크 중 CertificateRequest를 클라이언트에 전송함")
			steps = append(steps, "클라이언트 설정에 유효한 X.509 클라이언트 인증서가 누락되었거나 CA 검증 거부")
			steps = append(steps, "서버가 bad_certificate 또는 certificate_required 치명적 알림(Alert)을 보내며 연결 종료")
		case "ProxyAuthenticationRequired":
			steps = append(steps, "애플리케이션이 Squid HTTP 프록시를 통해 외부 인터넷 접속을 시도함")
			steps = append(steps, "Proxy-Authorization 헤더가 누락되었거나 프록시 사용자명/비밀번호가 일치하지 않음")
			steps = append(steps, "Squid 프록시가 HTTP 407 Proxy Authentication Required 응답을 반환하며 연결 차단")
		case "ProxyAccessDeniedACL":
			steps = append(steps, "Squid 프록시가 클라이언트의 HTTP/HTTPS 요청을 수신함")
			steps = append(steps, "요청한 클라이언트 IP 또는 목적지 도메인이 squid.conf의 http_access 차단 ACL에 매칭됨")
			steps = append(steps, "Squid가 HTTP 403 Forbidden (ERR_ACCESS_DENIED) 오류를 반환하고 요청을 폐기함")
		case "ProxyConnectTunnelFailed":
			steps = append(steps, "클라이언트가 비표준 포트로 HTTPS CONNECT 터널링을 프록시에 요청함")
			steps = append(steps, "대상 포트가 Squid의 'Safe_ports' 또는 'SSL_ports' 허용 목록에 포함되지 않음")
			steps = append(steps, "Squid가 보안 정책 위반으로 CONNECT 터널 생성을 거부하고 연결을 끊음")
		case "ProxyDNSResolutionFailed":
			steps = append(steps, "Squid 프록시가 요청된 목적지 도메인(FQDN)의 IP 주소 해석을 시도함")
			steps = append(steps, "프록시 로컬 네임서버 장애 또는 존재하지 않는 도메인으로 DNS 질의 실패")
			steps = append(steps, "Squid가 HTTP 502 Bad Gateway (ERR_DNS_FAIL)를 반환함")
		case "ProxyGatewayTimeout":
			steps = append(steps, "Squid 프록시가 외부 업스트림 서버로 연결 후 응답을 대기함")
			steps = append(steps, "원격 서버의 응답 지연으로 Squid의 read_timeout 타이머가 만료됨")
			steps = append(steps, "Squid가 클라이언트에게 HTTP 504 Gateway Timeout (ERR_READ_TIMEOUT)을 반환함")
		case "MySQLTooManyConnections":
			steps = append(steps, "애플리케이션 파드가 MySQL 서버에 신규 커넥션 수립을 시도함")
			steps = append(steps, "MySQL 활성 커넥션 수가 서버의 'max_connections' 한도에 도달함")
			steps = append(steps, "MySQL 서버가 Error 1040 (ER_CON_COUNT_ERROR)을 반환하며 접속을 차단함")
		case "MySQLDeadlock":
			steps = append(steps, "복수의 트랜잭션이 서로 다른 순서로 동일한 데이터 행(Row)에 상호 잠금을 요청함")
			steps = append(steps, "InnoDB 엔진이 순환 락 대기 상태(Deadlock)를 감지함")
			steps = append(steps, "InnoDB가 한 트랜잭션을 희생자로 선정하고 Error 1213과 함께 강제 롤백함")
		case "MySQLCommunicationsLinkFailure":
			steps = append(steps, "커넥션 풀이 일정 시간 유휴 상태였던 TCP 데이터베이스 소켓을 재사용 시도함")
			steps = append(steps, "MySQL의 wait_timeout 만료 또는 중간 방화벽에 의해 유휴 소켓이 이미 종료됨")
			steps = append(steps, "드라이버가 Communications link failure 예외를 발생시키며 쿼리가 실패함")
		case "PostgresTooManyConnections":
			steps = append(steps, "다수의 파드 또는 워커가 PostgreSQL 데이터베이스로 동시 연결을 요청함")
			steps = append(steps, "PostgreSQL 서버의 사용 가능한 커넥션 슬롯(max_connections)이 완전히 고갈됨")
			steps = append(steps, "PostgreSQL이 FATAL 53300 (sorry, too many clients already) 오류로 신규 접속을 거절함")
		case "PostgresDeadlock":
			steps = append(steps, "동시 실행 중인 트랜잭션들이 교차로 락(Lock) 획득을 대기함")
			steps = append(steps, "PostgreSQL 락 매니저가 deadlock_timeout 경과 후 순환 의존성을 감지함")
			steps = append(steps, "40P01 deadlock_detected 오류를 발생시키며 현재 트랜잭션을 강제 취소함")
		case "PostgresInFailedSQLTransaction":
			steps = append(steps, "트랜잭션 블록 내 이전 쿼리에서 SQL 오류 또는 제약 조건 위반 예외가 발생함")
			steps = append(steps, "애플리케이션이 ROLLBACK 명령 없이 동일 트랜잭션에서 후속 쿼리 실행을 시도함")
			steps = append(steps, "PostgreSQL이 트랜잭션 오염 방지를 위해 25P02 in_failed_sql_transaction으로 모든 후속 명령을 거절함")
		case "ClickHouseSimultaneousQueries":
			steps = append(steps, "다수의 클라이언트 분석 쿼리가 ClickHouse 서버로 동시 요청됨")
			steps = append(steps, "ClickHouse의 동시 실행 쿼리 한도(max_concurrent_queries)에 도달함")
			steps = append(steps, "서버가 Code 202 (TOO_MANY_SIMULTANEOUS_QUERIES) 오류를 반환하며 쿼리를 거부함")
		case "BigQueryPartitionFilterRequired":
			steps = append(steps, "파티셔닝이 활성화된 BigQuery 테이블을 대상으로 SQL 쿼리를 실행함")
			steps = append(steps, "테이블에 requirePartitionFilter=true가 설정되어 있으나 WHERE 절에 파티션 컬럼 조건이 누락됨")
			steps = append(steps, "BigQuery 엔진이 전체 테이블 스캔 비용을 방지하기 위해 쿼리 실행을 즉시 거절함")
		case "BigQueryBytesBilledLimitExceeded":
			steps = append(steps, "클라이언트 쿼리 옵션에 비용 상한선인 maximum_bytes_billed가 지정됨")
			steps = append(steps, "쿼리가 스캔해야 할 예상 데이터 용량이 설정된 바이트 한도를 초과함")
			steps = append(steps, "BigQuery가 400 Query exceeded limit for bytes billed 오류를 반환하며 쿼리를 중단함")
		default:
			steps = append(steps, fmt.Sprintf("컨테이너 상태 이상이 감지됨 (RootCause: %s, ExitCode: %s)", inc.RootCause, exitCodeStr))
			if len(inc.MatchedEvents) > 0 {
				steps = append(steps, fmt.Sprintf("관련 쿠버네티스 이벤트 확인: %s", inc.MatchedEvents[0]))
			}
			steps = append(steps, "프로세스 종료 후 Kubelet에 의해 컨테이너가 재시작됨")
		}
	} else {
		// English
		switch inc.RootCause {
		case "GracefulShutdownTimeout":
			steps = append(steps, "Kubernetes initiated pod termination and delivered SIGTERM (143) to container")
			steps = append(steps, "Application failed to drain connections and shut down within terminationGracePeriodSeconds")
			steps = append(steps, fmt.Sprintf("Kubelet grace timer expired and Linux kernel killed process with SIGKILL (Exit code %s)", exitCodeStr))
		case "ReadOnlyRootFilesystem", "ReadOnlyFilesystemError":
			steps = append(steps, "Pod securityContext enforced readOnlyRootFilesystem: true")
			steps = append(steps, "Application or runtime attempted write operations to read-only container root")
			steps = append(steps, "Kernel returned EROFS (Read-only file system) halting execution")
		case "HeapCorruption":
			steps = append(steps, "Dynamic memory operations executed in native C/C++ module or JNI/CGO binding")
			steps = append(steps, "Double free or heap chunk boundary corruption occurred")
			steps = append(steps, "glibc allocator detected memory corruption and aborted with SIGABRT (Exit code 134)")
		case "NodeV8FatalError":
			steps = append(steps, "Node.js V8 JavaScript heap allocation reached --max-old-space-size ceiling")
			steps = append(steps, "V8 garbage collector failed to reclaim sufficient memory")
			steps = append(steps, "FATAL ERROR: JavaScript heap out of memory triggered immediate termination")
		case "SidecarCascadeFailure":
			steps = append(steps, "A peer sidecar or proxy container in the pod crashed or entered unready state")
			steps = append(steps, "Localhost (127.0.0.1) or dependent service connection was refused")
			steps = append(steps, "Application container failed due to broken network communication cascade")
		case "InitContainerFailed":
			steps = append(steps, "Pod initContainer execution failed or exited with non-zero status")
			steps = append(steps, "Kubelet prevented application container from starting due to failed prerequisite")
		case "OOMKilled", "ProbableOOMKilled", "SystemOOMKilled":
			steps = append(steps, "Container memory usage increased steadily")
			steps = append(steps, "Exceeded configured cgroup memory limit")
			steps = append(steps, fmt.Sprintf("Linux kernel OOM Killer terminated the process with SIGKILL (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet observed OOMKilled state and restarted the container per policy")
		case "LivenessProbeFailure":
			steps = append(steps, "Application failed to respond to configured liveness probe within timeout")
			steps = append(steps, "Consecutive probe failures exceeded failureThreshold")
			steps = append(steps, fmt.Sprintf("Kubelet restarted the unresponsive container (Exit code %s)", exitCodeStr))
		case "StartupProbeFailure":
			steps = append(steps, "Application startup took longer than allotted initial boot window")
			steps = append(steps, "Kubelet startup probe failed repeatedly reaching failureThreshold")
			steps = append(steps, fmt.Sprintf("Kubelet terminated and restarted the container (Exit code %s)", exitCodeStr))
		case "GoDeadlock":
			steps = append(steps, "Mutual channel or mutex lock contention occurred across all active goroutines")
			steps = append(steps, "No runnable goroutines remained on the Go runtime runqueue")
			steps = append(steps, "Go runtime fatal error triggered: 'all goroutines are asleep - deadlock!'")
		case "GoPanic", "GoNilPointerDereference", "GoIndexOutOfRange":
			if culpritStr != "" {
				steps = append(steps, fmt.Sprintf("Runtime panic encountered at %s", culpritStr))
			} else {
				steps = append(steps, "Unhandled runtime panic occurred in application code")
			}
			steps = append(steps, "Stack unwinding reached top-level without recover()")
			steps = append(steps, fmt.Sprintf("Process exited with code %s", exitCodeStr))
		case "JVMHeapOOM":
			steps = append(steps, "JVM heap limit (-Xmx) was reached")
			steps = append(steps, "Garbage collection failed to reclaim sufficient memory")
			steps = append(steps, "java.lang.OutOfMemoryError: Java heap space thrown; JVM exited")
		case "DotNetNullReference":
			if culpritStr != "" {
				steps = append(steps, fmt.Sprintf("Null object dereference at %s", culpritStr))
			} else {
				steps = append(steps, "System.NullReferenceException thrown in .NET runtime")
			}
			steps = append(steps, "Unhandled exception caused CLR runtime termination")
		case "PythonUnhandledException", "AppUnhandledException":
			errName := inc.ErrorClass
			if errName == "" || errName == "PythonException" {
				errName = "Unhandled Exception"
			}

			fnStr := ""
			culpritPart := ""
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				if inc.CulpritCode.Function != "" {
					fnStr = fmt.Sprintf(" function %s()", inc.CulpritCode.Function)
				}
				culpritPart = fmt.Sprintf("At [%s:%d%s], ", inc.CulpritCode.File, inc.CulpritCode.Line, fnStr)
			}

			steps = append(steps, fmt.Sprintf("%sunhandled %s was raised during runtime execution", culpritPart, errName))
			steps = append(steps, "Exception was not caught by any try-except block, unwinding the call stack to the top-level")
			steps = append(steps, fmt.Sprintf("Python interpreter printed traceback to stderr and terminated with exit code %s", exitCodeStr))
			if len(inc.MatchedEvents) > 0 {
				steps = append(steps, fmt.Sprintf("Correlated cluster anomaly: %s", inc.MatchedEvents[0]))
			}
			steps = append(steps, "Kubelet observed non-zero container exit and restarted the container per restartPolicy")
		case "CircularImportError":
			steps = append(steps, "Python circular module dependency detected during module load")
			steps = append(steps, "Attempted to import attribute from partially initialized module")
			steps = append(steps, fmt.Sprintf("ImportError halted interpreter bootstrap (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet observed container crash and restarted per restartPolicy")
		case "SpringCircularDependency":
			steps = append(steps, "Spring Boot ApplicationContext created bean dependency graph")
			steps = append(steps, "Circular dependency cycle detected between beans preventing initialization")
			steps = append(steps, fmt.Sprintf("BeanCurrentlyInCreationException halted application context (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet restarted container")
		case "LazyInitializationException":
			steps = append(steps, "JPA entity lazy-loading property accessed outside active persistence session")
			steps = append(steps, "org.hibernate.LazyInitializationException unhandled by application layer")
			steps = append(steps, fmt.Sprintf("Thread crashed and JVM terminated (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet restarted container")
		case "TransientPropertyValueException":
			steps = append(steps, "Parent entity references unsaved transient child entity without cascade")
			steps = append(steps, "org.hibernate.TransientPropertyValueException triggered transaction rollback")
			steps = append(steps, fmt.Sprintf("Application terminated with exit code %s", exitCodeStr))
			steps = append(steps, "Kubelet restarted container")
		case "NodeTypeError":
			steps = append(steps, "Attempted property or method access on undefined or null object in JavaScript")
			steps = append(steps, "V8 runtime raised TypeError")
			steps = append(steps, fmt.Sprintf("Missing try-catch handler caused Node.js process to exit (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet restarted container")
		case "NodeUnhandledPromiseRejection":
			steps = append(steps, "Asynchronous Promise rejected without .catch() or await handler")
			steps = append(steps, fmt.Sprintf("Node.js 15+ unhandledRejection policy aborted process (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet restarted container")
		case "NodeESMMismatch":
			steps = append(steps, "Module system mismatch between ES Module (import) and CommonJS (require)")
			steps = append(steps, fmt.Sprintf("V8 module loader threw ReferenceError/SyntaxError (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet restarted container")
		case "NodePrismaError", "NodePrismaInitFailed":
			steps = append(steps, fmt.Sprintf("Prisma ORM failed during database query or connection (%s)", inc.ErrorClass))
			steps = append(steps, fmt.Sprintf("Unhandled PrismaClient error crashed service (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet restarted container")
		case "EnvoyNoHealthyUpstream":
			steps = append(steps, "Incoming request routed to Envoy/Istio proxy")
			steps = append(steps, "Target cluster endpoint health check failed or no endpoints ready")
			steps = append(steps, "Envoy generated 503 UH (No Healthy Upstream) flag and rejected request")
			steps = append(steps, "Monitoring system observed service failure")
		case "EnvoyCircuitBreakerOverflow":
			steps = append(steps, "Concurrent request volume or active connection count spiked")
			steps = append(steps, "DestinationRule maxConnections or maxPendingRequests limit reached")
			steps = append(steps, "Envoy circuit breaker tripped with 503 UO (Upstream Overflow)")
			steps = append(steps, "Traffic sheds to protect backend from cascading overload")
		case "EnvoyUpstreamConnectionFailure":
			steps = append(steps, "Envoy proxy attempted TCP or mTLS connection to upstream IP/Port")
			steps = append(steps, "Target port connection refused or dropped by NetworkPolicy")
			steps = append(steps, "Envoy recorded 503 UF (Upstream Connection Failure)")
		case "EnvoyNoRouteConfigured":
			steps = append(steps, "HTTP request Host header and Request URI received")
			steps = append(steps, "No matching route found in VirtualService or RouteConfiguration")
			steps = append(steps, "Envoy returned 404 NR (No Route Configured)")
		case "EnvoyTLSHandshakeFailed":
			steps = append(steps, "Envoy initiated TLS handshake with upstream service")
			steps = append(steps, "Certificate verification failed or mTLS mode mismatch")
			steps = append(steps, "Envoy closed connection with 503 UC (Upstream Connection Terminated)")
		case "EnvoyUpstreamTimeout":
			steps = append(steps, "Envoy forwarded request to upstream backend pod")
			steps = append(steps, "Backend application delayed in producing response")
			steps = append(steps, "VirtualService timeout timer expired, returning 504 UT (Upstream Timeout)")
		case "NginxConfigSyntaxError":
			steps = append(steps, "Nginx master process attempted configuration load or reload")
			steps = append(steps, "Syntax error encountered in nginx.conf or Ingress configuration-snippet")
			steps = append(steps, fmt.Sprintf("Nginx logged 'nginx: [emerg]' and exited (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet detected abnormal termination and restarted container")
		case "NginxClientBodySizeExceeded":
			steps = append(steps, "Client attempted large payload or file upload")
			steps = append(steps, "Payload exceeded Nginx client_max_body_size threshold")
			steps = append(steps, "Nginx returned 413 Request Entity Too Large without forwarding to upstream")
		case "IstioProxyNotReady":
			steps = append(steps, "istio-proxy sidecar started during pod initialization")
			steps = append(steps, "xDS synchronization delay with istiod or CPU throttling")
			steps = append(steps, "Failed readiness probe on port 15021; pod prevented from serving traffic")
		case "IstioStartupRaceCondition":
			steps = append(steps, "Main container and istio-proxy started concurrently")
			steps = append(steps, "Main container attempted outbound DB or DNS call before proxy 15021 became Ready")
			steps = append(steps, "Local connection refused by iptables redirect, causing crash")
			steps = append(steps, fmt.Sprintf("Application exited with code %s and entered restart loop", exitCodeStr))
		case "IstioStrictMTLSMismatch":
			steps = append(steps, "Client attempted plaintext HTTP request to service")
			steps = append(steps, "Destination namespace enforced STRICT mTLS PeerAuthentication")
			steps = append(steps, "Envoy rejected non-mTLS plaintext connection and terminated stream")
		case "EnvoyGatewayTranslationFailed":
			steps = append(steps, "Gateway API HTTPRoute resource declared")
			steps = append(steps, "Backend service not found or cross-namespace ReferenceGrant missing")
			steps = append(steps, "Envoy Gateway xDS translation NACKed route configuration")
		case "VaultSealedFailure":
			steps = append(steps, "HashiCorp Vault pod restarted or redeployed")
			steps = append(steps, "Unseal keys not present in memory; Vault entered Sealed mode")
			steps = append(steps, "Secret access requests failed with HTTP 503")
			steps = append(steps, "Dependent application crashed due to missing credentials")
		case "VaultTokenExpired":
			steps = append(steps, "Application requested secret refresh or renewed token")
			steps = append(steps, "Vault token TTL expired or Kubernetes Auth role binding failed")
			steps = append(steps, "Vault returned 403 Forbidden")
		case "CoreDNSLoopDetected":
			steps = append(steps, "Node /etc/resolv.conf contained local loopback address (127.0.0.53/127.0.0.1)")
			steps = append(steps, "CoreDNS forward plugin looped queries indefinitely")
			steps = append(steps, "CoreDNS loop plugin detected loop and halted pod to avoid cluster storm")
			steps = append(steps, "Cluster-wide DNS resolution temporarily interrupted")
		case "CertManagerWebhookFailure":
			steps = append(steps, "K8s API server initiated validation for Certificate or Issuer resource")
			steps = append(steps, "cert-manager-webhook call timed out or blocked by network/firewall")
			steps = append(steps, "Resource creation blocked by ValidatingWebhookConfiguration failure")
		case "ACMERateLimitExceeded":
			steps = append(steps, "High volume of certificate requests sent to Let's Encrypt")
			steps = append(steps, "ACME API rate limit exceeded for account or domain")
			steps = append(steps, "ACME server returned HTTP 429 Too Many Requests")
		case "PrometheusWALCorruption":
			steps = append(steps, "Abrupt node termination or ungraceful SIGKILL interrupted disk flush")
			steps = append(steps, "Prometheus TSDB Write-Ahead Log (WAL) segment corrupted")
			steps = append(steps, fmt.Sprintf("Prometheus failed WAL replay on startup and exited (Exit code %s)", exitCodeStr))
			steps = append(steps, "Metrics collection halted")
		case "PrometheusCardinalityOOM":
			steps = append(steps, "Metrics exported with high-cardinality labels (userId, guid, timestamp)")
			steps = append(steps, "TSDB memory surged beyond cgroup limit")
			steps = append(steps, fmt.Sprintf("Linux kernel OOM Killer terminated Prometheus (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet recorded OOMKilled and restarted pod")
		case "FluentBitBufferExhaustion":
			steps = append(steps, "Log generation spiked or destination storage experienced backpressure")
			steps = append(steps, "Fluent Bit in-memory ring buffer filled, pausing ingestion")
			steps = append(steps, "Log collection delayed with potential log drop risk")
		case "ElasticsearchDiskFloodStage":
			steps = append(steps, "Elasticsearch data node disk usage passed 95% flood stage watermark")
			steps = append(steps, "Cluster forcibly applied read_only_allow_delete block on all indices")
			steps = append(steps, "All index write operations rejected")
		case "ElasticsearchCircuitBreaker":
			steps = append(steps, "Large aggregation or heavy wildcard query executed")
			steps = append(steps, "Memory demand exceeded circuit breaker threshold ([parent]/[fielddata])")
			steps = append(steps, "Elasticsearch tripped CircuitBreakingException to prevent JVM crash")
		case "PatroniLeaderLeaseLost":
			steps = append(steps, "DCS (etcd or k8s API) network latency or partition occurred")
			steps = append(steps, "Patroni primary failed to renew leader heartbeat lease")
			steps = append(steps, "Primary self-demoted to replica to prevent split-brain")
			steps = append(steps, "Cluster entered read-only failover phase")
		case "PostgresWALDiskFull":
			steps = append(steps, "Lagging replication slot or failed archiving accumulated pg_wal segments")
			steps = append(steps, "Storage volume filled to 100%, preventing write-ahead logging")
			steps = append(steps, fmt.Sprintf("PostgreSQL PANIC (could not write to log file) forced shutdown (Exit code %s)", exitCodeStr))
		case "ArgoCDRepoServerOOM":
			steps = append(steps, "Rendering massive Helm chart with many subcharts or large Kustomize overlays")
			steps = append(steps, "argocd-repo-server memory exceeded container limit")
			steps = append(steps, fmt.Sprintf("Kernel OOM Killer killed process (Exit code %s)", exitCodeStr))
			steps = append(steps, "GitOps sync operation aborted")
		case "GitRateLimitExceeded":
			steps = append(steps, "Argo CD polled multiple repositories frequently")
			steps = append(steps, "Remote Git host (GitHub/GitLab) API rate limit quota exhausted")
			steps = append(steps, "Remote repo access blocked by HTTP 403/429")
		case "GCPAuthDefaultCredentialsMissing":
			steps = append(steps, "Google Cloud client SDK initialized and attempted ADC lookup")
			steps = append(steps, "GOOGLE_APPLICATION_CREDENTIALS not set and metadata server lookup failed")
			steps = append(steps, fmt.Sprintf("DefaultCredentialsError aborted application startup (Exit code %s)", exitCodeStr))
		case "GCPGeminiQuotaExceeded":
			steps = append(steps, "Application dispatched generateContent request to Google Gemini API")
			steps = append(steps, "Project rate limit (TPM/RPM) exceeded, returning HTTP 429 ResourceExhausted")
			steps = append(steps, "Process terminated due to unhandled APIError or retry limit reached")
		case "GCPGeminiSafetyBlocked":
			steps = append(steps, "Google Gemini model evaluated prompt and response candidates")
			steps = append(steps, "Safety ratings exceeded safetySettings policy threshold")
			steps = append(steps, "Candidate blocked with finish_reason: SAFETY")
		case "GCPBigQueryQuotaExceeded":
			steps = append(steps, "Application submitted large BigQuery analytical query")
			steps = append(steps, "Query bytes scanned exceeded maximum_bytes_billed limit")
			steps = append(steps, "BigQuery API returned 400 Query exceeded limit error")
		case "GCPStorageAccessDenied":
			steps = append(steps, "Storage API request issued against Google Cloud Storage bucket/object")
			steps = append(steps, "Service account lacked storage.objects.get/create IAM permissions")
			steps = append(steps, "GCS API returned 403 Forbidden")
		case "ClickHouseTooManyParts":
			steps = append(steps, "High frequency small INSERT batches executed against ClickHouse table")
			steps = append(steps, "Background partition merges lagged behind write rate; parts exceeded threshold (300+)")
			steps = append(steps, "ClickHouse threw 'Too many parts' exception to prevent server degradation")
		case "ClickHouseMemoryLimit":
			steps = append(steps, "Large aggregation or complex JOIN query consumed excessive memory")
			steps = append(steps, "Configured max_server_memory_usage or query memory limit reached")
			steps = append(steps, "Memory tracker aborted query execution to safeguard node")
		case "ClickHouseZooKeeperSessionLost":
			steps = append(steps, "Replicated ClickHouse table lost heartbeat with ZooKeeper ensemble")
			steps = append(steps, "Session expired due to network latency or ZooKeeper pause")
			steps = append(steps, "Table isolated in read-only mode to prevent split-brain")
		case "ZooKeeperDiskFull":
			steps = append(steps, "ZooKeeper transaction commit logs and snapshot files accumulated")
			steps = append(steps, "dataDir or dataLogDir storage volume reached 100% capacity (ENOSPC)")
			steps = append(steps, fmt.Sprintf("ZooKeeper server halted with IOException: No space left on device (Exit code %s)", exitCodeStr))
		case "ZooKeeperQuorumLost":
			steps = append(steps, "ZooKeeper nodes failed or network partition isolated instances")
			steps = append(steps, "Ensemble lost majority quorum (N/2 + 1) for leader election")
			steps = append(steps, "ZooKeeper halted client request processing")
		case "ValkeyOOM":
			steps = append(steps, "Valkey in-memory storage consumption reached maxmemory limit")
			steps = append(steps, "Eviction policy failed to reclaim sufficient memory")
			steps = append(steps, "Write commands rejected with 'OOM command not allowed'")
		case "PostgresTxidExhaustion":
			steps = append(steps, "PostgreSQL transaction ID generation exceeded 2 billion without freeze")
			steps = append(steps, "Wraparound data loss prevention safety triggered")
			steps = append(steps, "PostgreSQL refused all write transactions and entered emergency read-only mode")
		case "JenkinsDiskSpaceExhausted":
			steps = append(steps, "Build artifacts and Docker layer caches accumulated on Jenkins node")
			steps = append(steps, "Available disk space fell below threshold (1.0 GiB)")
			steps = append(steps, "Jenkins controller disabled executor to avoid catastrophic disk full")
		case "ArgoWorkflowDeadlineExceeded":
			steps = append(steps, "Argo Workflow task encountered slow processing or blocking I/O")
			steps = append(steps, "activeDeadlineSeconds threshold elapsed")
			steps = append(steps, "workflow-controller terminated pod with WorkflowDeadlineExceeded")
		case "ArgoRolloutAnalysisFailed":
			steps = append(steps, "Argo Rollouts measured AnalysisRun metrics during canary step")
			steps = append(steps, "Prometheus metric failure threshold reached")
			steps = append(steps, "Rollout controller aborted rollout and initiated automated rollback")
		case "KyvernoAdmissionPolicyViolation":
			steps = append(steps, "Kubernetes API server received pod creation/mutation request")
			steps = append(steps, "Kyverno admission webhook evaluated ClusterPolicy rules")
			steps = append(steps, "Validation check failed, denying resource admission")
		case "KyvernoWebhookTimeout":
			steps = append(steps, "API server dispatched webhook call to Kyverno controller on port 9443")
			steps = append(steps, "Controller overloaded or TLS cert expired, resulting in context deadline exceeded")
			steps = append(steps, "Webhook failure policy blocked pod deployment")
		case "GatekeeperConstraintViolation":
			steps = append(steps, "OPA Gatekeeper admission webhook evaluated resource spec against Rego constraints")
			steps = append(steps, "Constraint violation triggered deny rule")
			steps = append(steps, "API server rejected operation with 403 Forbidden")
		case "SecretProviderClassNotFound":
			steps = append(steps, "Kubelet initiated Secrets Store CSI volume setup")
			steps = append(steps, "SecretProviderClass resource not found in pod namespace")
			steps = append(steps, "MountVolume.SetUp failed, placing pod in ContainerCreating / CrashLoopBackOff")
		case "NFSMountAccessDenied":
			steps = append(steps, "Node attempted NFS remote directory mount (mount.nfs)")
			steps = append(steps, "NFS server rejected client IP or root UID mapping")
			steps = append(steps, "Mount failure blocked container startup")
		case "NFSConnectionTimeout":
			steps = append(steps, "Node attempted TCP handshake to NFS server on port 2049/111")
			steps = append(steps, "Connection timed out due to firewall or server outage")
			steps = append(steps, "Volume mount timeout stalled pod initialization")
		case "MetricsServerKubeletScrapeFailed":
			steps = append(steps, "metrics-server attempted metric collection from Kubelet port 10250")
			steps = append(steps, "Connection timed out or rejected due to self-signed certificate SAN mismatch")
			steps = append(steps, "HPA autoscaling stalled due to missing metrics")
		case "LiteLLMRateLimitExceeded":
			steps = append(steps, "Client request forwarded through LiteLLM proxy to upstream LLM")
			steps = append(steps, "Upstream provider rate limit reached (HTTP 429 TPM/RPM)")
			steps = append(steps, "LiteLLM raised RateLimitError to client")
		case "LiteLLMBudgetExceeded":
			steps = append(steps, "LiteLLM proxy validated virtual key cumulative spend")
			steps = append(steps, "max_budget ceiling reached; further queries rejected with BudgetExceededError")
		case "LiteLLMContextWindowExceeded":
			steps = append(steps, "Input prompt and requested generation tokens exceeded model capacity")
			steps = append(steps, "LiteLLM rejected request with ContextWindowExceededError")
		case "TCPConnectionReset":
			steps = append(steps, "Client attempted communication with remote service via TCP")
			steps = append(steps, "Peer process terminated unexpectedly or intermediate firewall closed idle connection")
			steps = append(steps, "TCP RST packet delivered, causing connection reset by peer (ECONNRESET)")
		case "TCPConnectionRefused":
			steps = append(steps, "Client transmitted TCP SYN packet to target IP/port")
			steps = append(steps, "No active listener process on port or NetworkPolicy blocked ingress")
			steps = append(steps, "Kernel returned TCP RST/ACK, immediately refusing connection (ECONNREFUSED)")
		case "TCPConnectionTimeout":
			steps = append(steps, "Client initiated TCP 3-way handshake and awaited SYN-ACK")
			steps = append(steps, "Firewall dropped SYN silently or route discarded packets without response")
			steps = append(steps, fmt.Sprintf("TCP SYN retransmission limit reached, terminating connection with timeout (Exit code %s)", exitCodeStr))
		case "NetworkUnreachable":
			steps = append(steps, "Application dispatched network packet to destination host")
			steps = append(steps, "Host or CNI routing table lacked valid gateway route (No route to host)")
			steps = append(steps, "IP layer halted socket communication with EHOSTUNREACH / ENETUNREACH")
		case "EphemeralPortExhaustion":
			steps = append(steps, "Surge of outbound short-lived HTTP/TCP connections created")
			steps = append(steps, "Accumulated TIME_WAIT sockets exhausted local port allocation range")
			steps = append(steps, "Kernel failed to bind socket with EADDRNOTAVAIL (Cannot assign requested address)")
		case "TLSUntrustedCA":
			steps = append(steps, "Client established TLS handshake and retrieved server certificate")
			steps = append(steps, "Certificate issuer CA not found in system trust store")
			steps = append(steps, "X.509 validation aborted with 'certificate signed by unknown authority' or PKIX failure")
		case "TLSCertificateExpired":
			steps = append(steps, "Client evaluated server certificate validity dates (NotAfter)")
			steps = append(steps, "Certificate expiration date elapsed or system clock is out of sync")
			steps = append(steps, "TLS handshake aborted with CERT_HAS_EXPIRED")
		case "TLSHostnameMismatch":
			steps = append(steps, "Client verified certificate Subject Alternative Names (SAN)")
			steps = append(steps, "Target destination hostname or IP missing from certificate SAN extensions")
			steps = append(steps, "TLS handshake rejected connection to prevent man-in-the-middle impersonation")
		case "TLSClientCertRequired":
			steps = append(steps, "mTLS server issued CertificateRequest during handshake negotiation")
			steps = append(steps, "Client failed to present valid client certificate or private key")
			steps = append(steps, "Server issued bad_certificate / certificate_required alert, closing stream")
		case "ProxyAuthenticationRequired":
			steps = append(steps, "Application routed outbound traffic through Squid forward proxy")
			steps = append(steps, "Proxy-Authorization header missing or proxy credentials invalid")
			steps = append(steps, "Squid rejected request with HTTP 407 Proxy Authentication Required")
		case "ProxyAccessDeniedACL":
			steps = append(steps, "Squid proxy received client HTTP/HTTPS request")
			steps = append(steps, "Client IP or destination domain matched denial ACL in squid.conf")
			steps = append(steps, "Squid responded with HTTP 403 Forbidden (ERR_ACCESS_DENIED)")
		case "ProxyConnectTunnelFailed":
			steps = append(steps, "Client attempted HTTPS CONNECT tunnel to non-standard destination port")
			steps = append(steps, "Port violated Squid Safe_ports or SSL_ports whitelist policy")
			steps = append(steps, "Squid closed connection with CONNECT method denied")
		case "ProxyDNSResolutionFailed":
			steps = append(steps, "Squid forward proxy attempted DNS lookup for destination FQDN")
			steps = append(steps, "Upstream DNS resolution failed or domain does not exist")
			steps = append(steps, "Squid returned HTTP 502 Bad Gateway (ERR_DNS_FAIL)")
		case "ProxyGatewayTimeout":
			steps = append(steps, "Squid proxy forwarded request to upstream destination and waited for response")
			steps = append(steps, "Upstream server delayed response beyond Squid read_timeout limit")
			steps = append(steps, "Squid returned HTTP 504 Gateway Timeout (ERR_READ_TIMEOUT)")
		case "MySQLTooManyConnections":
			steps = append(steps, "Application pod attempted to establish a new connection to MySQL server")
			steps = append(steps, "MySQL active connection count reached server 'max_connections' limit")
			steps = append(steps, "MySQL server rejected connection with Error 1040 (ER_CON_COUNT_ERROR)")
		case "MySQLDeadlock":
			steps = append(steps, "Concurrent transactions acquired mutually conflicting locks on same database rows")
			steps = append(steps, "InnoDB deadlock detection engine identified cyclic wait-for dependency")
			steps = append(steps, "InnoDB selected transaction as deadlock victim and forced rollback with Error 1213")
		case "MySQLCommunicationsLinkFailure":
			steps = append(steps, "Connection pool attempted to reuse an idle TCP socket")
			steps = append(steps, "MySQL server or intermediary load balancer closed socket due to wait_timeout expiration")
			steps = append(steps, "Driver threw Communications link failure exception on query dispatch")
		case "PostgresTooManyConnections":
			steps = append(steps, "Multiple application pods requested new connections to PostgreSQL")
			steps = append(steps, "PostgreSQL available connection slots (max_connections) completely exhausted")
			steps = append(steps, "PostgreSQL rejected connection with FATAL 53300 (sorry, too many clients already)")
		case "PostgresDeadlock":
			steps = append(steps, "Concurrent transactions waited for mutual locks across different tables/rows")
			steps = append(steps, "PostgreSQL lock manager detected cycle after deadlock_timeout elapsed")
			steps = append(steps, "PostgreSQL aborted current transaction with 40P01 deadlock_detected")
		case "PostgresInFailedSQLTransaction":
			steps = append(steps, "Prior statement inside transaction block encountered an error or constraint violation")
			steps = append(steps, "Application failed to issue ROLLBACK and attempted next query in same transaction")
			steps = append(steps, "PostgreSQL blocked all subsequent commands with 25P02 in_failed_sql_transaction")
		case "ClickHouseSimultaneousQueries":
			steps = append(steps, "High volume of analytics queries submitted simultaneously to ClickHouse")
			steps = append(steps, "Server reached configured max_concurrent_queries limit")
			steps = append(steps, "ClickHouse rejected query with Code 202 (TOO_MANY_SIMULTANEOUS_QUERIES)")
		case "BigQueryPartitionFilterRequired":
			steps = append(steps, "SQL query dispatched against partitioned BigQuery table")
			steps = append(steps, "Table enforce requirePartitionFilter=true but query omitted partition filter")
			steps = append(steps, "BigQuery optimizer rejected query execution to prevent costly full table scans")
		case "BigQueryBytesBilledLimitExceeded":
			steps = append(steps, "Query job submitted with maximum_bytes_billed cost ceiling")
			steps = append(steps, "Estimated query data scan bytes exceeded the configured limit")
			steps = append(steps, "BigQuery aborted execution with 400 Query exceeded limit for bytes billed")
		default:
			steps = append(steps, fmt.Sprintf("Container termination observed (RootCause: %s, ExitCode: %s)", inc.RootCause, exitCodeStr))
			if len(inc.MatchedEvents) > 0 {
				steps = append(steps, fmt.Sprintf("Correlated K8s Event: %s", inc.MatchedEvents[0]))
			}
			steps = append(steps, "Container exited and was restarted by Kubelet")
		}
	}

	var res []observerv1alpha1.ChainStep
	for i, s := range steps {
		res = append(res, observerv1alpha1.ChainStep{
			Step:        i + 1,
			Description: s,
		})
	}
	return res
}

func buildInferredContext(inc IncidentContext, lang string) string {
	culpritStr := ""
	if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
		if inc.CulpritCode.Line > 0 {
			culpritStr = fmt.Sprintf(" [%s:%d]", inc.CulpritCode.File, inc.CulpritCode.Line)
		} else {
			culpritStr = fmt.Sprintf(" [%s]", inc.CulpritCode.File)
		}
	}

	if lang == "ko" {
		switch inc.RootCause {
		case "GracefulShutdownTimeout":
			return "배포 롤아웃 또는 노드 유지보수 중 SIGTERM 수신 후 종료 유예시간(terminationGracePeriodSeconds) 내에 연결 드레인을 완료하지 못해 Kubelet에 의해 SIGKILL(137)로 강제 사살되었습니다."
		case "ReadOnlyRootFilesystem", "ReadOnlyFilesystemError":
			return "파드 SecurityContext의 readOnlyRootFilesystem 제약 상태에서 임시 디렉토리 쓰기를 시도하다 EROFS 오류로 중단되었습니다."
		case "HeapCorruption":
			return fmt.Sprintf("C/C++ 네이티브 또는 JNI/CGO 라이브러리에서 Double Free 또는 메모리 오염(Heap Corruption)으로 인해 프로세스가 중단되었습니다%s.", culpritStr)
		case "NodeV8FatalError":
			return "Node.js V8 런타임의 힙 메모리가 max-old-space-size 한도를 초과하여 치명적 OOM 오류로 프로세스가 중단되었습니다."
		case "SidecarCascadeFailure":
			return "동일 파드 내 사이드카(Istio/Envoy, Vault, Cloud SQL Proxy 등)의 중단으로 인해 로컬호스트 통신이 단절되어 메인 컨테이너가 연쇄 실패했습니다."
		case "InitContainerFailed":
			return "파드 기동 전제조건인 initContainer 작업이 실패하여 메인 애플리케이션이 실행되지 못했습니다."
		case "OOMKilled", "ProbableOOMKilled", "SystemOOMKilled":
			return "컨테이너의 실제 메모리 사용량이 cgroup에 설정된 한도(Limit)를 초과하여 리눅스 커널 OOM Killer에 의해 프로세스가 강제 사살되었습니다."
		case "LivenessProbeFailure":
			return "애플리케이션이 Liveness Probe 검사에 제한 시간 내에 응답하지 못하여 Kubelet에 의해 비정상으로 판정되고 재기동되었습니다."
		case "StartupProbeFailure":
			return "애플리케이션의 초기 부팅 및 초기화가 설정된 startupProbe 시간 내에 완료되지 못했습니다."
		case "SpringHikariPoolExhaustion":
			return "트래픽 폭주 또는 트랜잭션 지연으로 HikariCP 데이터베이스 커넥션 풀이 고갈되었습니다."
		case "SpringPortInUse", "GoPortInUse", "NodePortInUse", "DotNetPortInUse", "PortConflict":
			return "지정된 네트워크 포트가 이미 다른 프로세스에 의해 점유되어 서버 리스너 바인딩에 실패했습니다."
		case "SpringBootStartupFailure":
			return fmt.Sprintf("스프링 부트 애플리케이션 컨텍스트 초기화 중 BeanCreationException 또는 설정 오류가 발생했습니다%s.", culpritStr)
		case "JVMHeapOOM":
			return "Java 가상 머신(JVM)의 힙 메모리가 소진되어 java.lang.OutOfMemoryError가 발생했습니다."
		case "JVMMetaspaceOOM":
			return "JVM 메타스페이스 메모리가 초과되어 클래스 메타데이터를 추가 로드할 수 없습니다."
		case "JVMDirectMemoryOOM":
			return "NIO 다이렉트 버퍼 메모리가 -XX:MaxDirectMemorySize 한도를 초과했습니다."
		case "JVMThreadExhaustion":
			return "OS 네이티브 스레드 수 또는 cgroup pids 한도에 도달하여 신규 JVM 스레드 생성이 불가능합니다."
		case "JVMNullPointer":
			return fmt.Sprintf("JVM 실행 중 NullPointerException 예외가 발생하여 비정상 종료되었습니다%s.", culpritStr)
		case "GoPanic", "GoNilPointerDereference", "GoIndexOutOfRange", "GoSliceBoundsOutOfRange":
			return fmt.Sprintf("Go 소스코드에서 미처리 런타임 패닉(Panic)이 발생하여 프로세스가 충돌했습니다%s.", culpritStr)
		case "GoDeadlock":
			return "Go 런타임에서 모든 고루틴이 대기 상태에 빠진 교착 상태(Deadlock)가 발생하여 프로세스가 강제 중단되었습니다."
		case "GoConcurrentMapAccess":
			return "동기화 락 없는 Go map 동시 읽기/쓰기 데이터 레이스로 인해 프로세스가 강제 중단되었습니다."
		case "PythonModuleNotFound", "NodeModuleNotFound", "JVMClassNotFound", "DotNetAssemblyNotFound":
			return fmt.Sprintf("실행에 필요한 핵심 모듈 또는 어셈블리 파일을 환경 내에서 찾을 수 없습니다%s.", culpritStr)
		case "PythonWorkerTimeout":
			return "Gunicorn/Uvicorn 워커가 동기 블로킹 작업으로 인해 지정된 타임아웃 내에 하트비트를 보내지 못했습니다."
		case "PythonMemoryError", "NodeHeapOOM", "DotNetOOM", "RubyNoMemoryError", "RustAllocFailed", "PHPMemoryExhausted":
			return fmt.Sprintf("언어 런타임의 메모리 할당 한도가 초과되었습니다%s.", culpritStr)
		case "DotNetNullReference":
			return fmt.Sprintf(".NET 애플리케이션에서 초기화되지 않은 객체 참조(NullReferenceException)가 발생했습니다%s.", culpritStr)
		case "PostgresMaxConnections":
			return "데이터베이스 서버의 최대 동시 연결 수(max_connections)가 초과되어 신규 커넥션이 거절되었습니다."
		case "RedisOOM":
			return "Redis 인메모리 사용량이 maxmemory 한도에 도달하여 신규 쓰기 작업이 거절되었습니다."
		case "NginxWorkerConnections":
			return "Nginx 워커당 동시 커넥션 한도(worker_connections)를 초과하여 신규 요청 연결이 실패했습니다."
		case "DiskNoSpaceLeft":
			return "컨테이너 로컬 파일시스템의 남은 저장 공간이 부족(ENOSPC)하여 디스크 쓰기 오류가 발생했습니다."
		case "FileDescriptorExhaustion":
			return "프로세스 열린 파일/소켓 디스크립터 한도(ulimit nofile)에 도달하여 통신이 마비되었습니다."
		case "ArchitectureMismatch":
			return "컨테이너 바이너리의 CPU 아키텍처와 노드 아키텍처가 일치하지 않아(Exec format error) 기동에 실패했습니다."
		case "PythonUnhandledException", "AppUnhandledException":
			errName := inc.ErrorClass
			if errName == "" || errName == "PythonException" {
				errName = "미처리 예외(Unhandled Exception)"
			}
			fnStr := ""
			if inc.CulpritCode != nil && inc.CulpritCode.Function != "" {
				fnStr = fmt.Sprintf(" %s() 함수", inc.CulpritCode.Function)
			}
			return fmt.Sprintf("Python 런타임에서 %s 예외가 처리되지 않아 프로세스가 비정상 종료되었습니다%s%s. 입력값 검증 실패 또는 에러 방어 로직 부재가 원인입니다.", errName, culpritStr, fnStr)
		case "CircularImportError":
			return fmt.Sprintf("Python 모듈 상호 순환 참조(Circular Import)로 인해 모듈 심볼 로드에 실패했습니다%s.", culpritStr)
		case "SpringCircularDependency":
			return fmt.Sprintf("Spring Boot 빈들 간의 상호 순환 참조(Circular Dependency)로 인해 ApplicationContext 초기화에 실패했습니다%s.", culpritStr)
		case "LazyInitializationException":
			return fmt.Sprintf("JPA/Hibernate 영속성 컨텍스트(Session) 종료 후 트랜잭션 외부에서 지연 로딩 필드에 접근하여 실패했습니다%s.", culpritStr)
		case "TransientPropertyValueException":
			return fmt.Sprintf("JPA 저장 시 영속화되지 않은 자식 엔티티를 참조(TransientPropertyValueException)하여 실패했습니다%s.", culpritStr)
		case "NodeTypeError":
			return fmt.Sprintf("Node.js V8 런타임에서 undefined 또는 null 객체의 속성을 읽으려다 TypeError가 발생했습니다%s.", culpritStr)
		case "NodeUnhandledPromiseRejection":
			return fmt.Sprintf("Node.js 비동기 Promise 실행 중 거부(Rejection)가 발생했으나 에러 핸들러가 누락되어 충돌했습니다%s.", culpritStr)
		case "NodeESMMismatch":
			return fmt.Sprintf("Node.js 모듈 로드 중 ESM(import)과 CommonJS(require) 구문 불일치로 인해 기동에 실패했습니다%s.", culpritStr)
		case "NodePrismaError", "NodePrismaInitFailed":
			return fmt.Sprintf("Prisma ORM 데이터베이스 오류(%s)로 인해 서비스 프로세스가 비정상 종료되었습니다%s.", inc.ErrorClass, culpritStr)
		case "EnvoyNoHealthyUpstream":
			return "Envoy/Istio 프록시가 가용한 정상 업스트림 엔드포인트를 찾지 못해 요청이 503 UH(No Healthy Upstream)로 차단되었습니다."
		case "EnvoyCircuitBreakerOverflow":
			return "Envoy 서킷 브레이커의 maxConnections 또는 maxPendingRequests 임계치를 초과하여 503 UO(Upstream Overflow)로 요청이 차단되었습니다."
		case "EnvoyUpstreamConnectionFailure":
			return "Envoy가 업스트림 서비스에 대한 TCP 커넥션 또는 mTLS 연결 수립에 실패하여 503 UF(Upstream Connection Failure) 오류가 발생했습니다."
		case "EnvoyNoRouteConfigured":
			return "요청된 Host 헤더 또는 경로(URI)와 일치하는 Envoy 라우팅 규칙이 없어 404 NR(No Route) 에러가 발생했습니다."
		case "EnvoyTLSHandshakeFailed":
			return "업스트림 서비스와의 TLS/mTLS 핸드셰이크 협상 중 연결이 종료(503 UC)되었습니다."
		case "EnvoyUpstreamTimeout":
			return "업스트림 서비스가 지정된 타임아웃 내에 응답을 반환하지 않아 504 UT(Upstream Timeout)가 발생했습니다."
		case "NginxConfigSyntaxError":
			return fmt.Sprintf("Nginx 설정 파일 문법 오류([emerg])로 인해 웹 서버 프로세스가 비정상 종료되었습니다%s.", culpritStr)
		case "NginxClientBodySizeExceeded":
			return "클라이언트 요청 본문 크기가 Nginx의 client_max_body_size(기본 1MB)를 초과하여 413 에러로 차단되었습니다."
		case "IstioProxyNotReady":
			return "istio-proxy 사이드카가 준비 상태(Readiness 15021)에 도달하지 못해 서비스 트래픽 수신이 차단되었습니다."
		case "IstioStartupRaceCondition":
			return "istio-proxy 사이드카가 준비 상태에 도달하기 전 메인 애플리케이션이 외부 통신을 시도하여 연결 거부로 크래시되었습니다 (기동 순서 역전 현상)."
		case "IstioStrictMTLSMismatch":
			return "Istio PeerAuthentication 정책이 STRICT 모드로 설정되어 있어 평문(Plaintext) 트래픽 연결이 거절되었습니다."
		case "EnvoyGatewayTranslationFailed":
			return "Envoy Gateway가 Gateway API HTTPRoute 설정을 변환하지 못했거나 백엔드 참조(ResolvedRefs: False) 검증에 실패했습니다."
		case "VaultSealedFailure":
			return "HashiCorp Vault가 봉인(Sealed) 상태로 진입하여 시크릿 조회 API가 HTTP 503을 반환했습니다."
		case "VaultTokenExpired":
			return "Vault 인증 토큰이 만료되었거나 서비스어카운트의 Kubernetes Auth 역할(Role) 바인딩 권한이 거부되었습니다."
		case "CoreDNSLoopDetected":
			return "CoreDNS loop 플러그인이 호스트와 CoreDNS 간의 무한 순환 DNS 포워딩 루프를 감지하고 프로세스를 중단했습니다."
		case "CertManagerWebhookFailure":
			return "cert-manager-webhook 검증 웹훅 서비스 호출이 타임아웃되거나 연결이 거부되어 인증서 리소스 생성이 차단되었습니다."
		case "ACMERateLimitExceeded":
			return "Let's Encrypt ACME API의 도메인당 주간 인증서 발급 속도 제한(Rate Limit)을 초과했습니다."
		case "PrometheusWALCorruption":
			return "비정상 종료 또는 파일시스템 손상으로 Prometheus TSDB의 WAL(Write-Ahead Log) 파일이 손상되었습니다."
		case "PrometheusCardinalityOOM":
			return "고카디널리티(High-Cardinality) 라벨 폭증으로 인해 Prometheus TSDB 메모리가 고갈되어 OOMKilled되었습니다."
		case "FluentBitBufferExhaustion":
			return "로그 수집량 급증 또는 출력 대상 장애로 인해 Fluent Bit 버퍼가 고갈되어 로그 수집이 일시 중단되었습니다."
		case "ElasticsearchDiskFloodStage":
			return "Elasticsearch 노드 디스크 사용량이 95%를 초과하여 모든 인덱스가 읽기 전용(read_only_allow_delete)으로 잠겼습니다."
		case "ElasticsearchCircuitBreaker":
			return "대규모 집계 쿼리로 인해 Elasticsearch 힙 메모리 서킷 브레이커가 발동하여 쿼리가 차단되었습니다."
		case "PatroniLeaderLeaseLost":
			return "Patroni가 분산 합의 저장소(etcd/DCS) 리더 임차권을 상실하여 Primary 인스턴스에서 강등(Demote)되었습니다."
		case "PostgresWALDiskFull":
			return "PostgreSQL pg_wal 볼륨이 고갈되어 쓰기 트랜잭션 처리가 불가능해 데이터베이스가 크래시되었습니다."
		case "ArgoCDRepoServerOOM":
			return "Argo CD repo-server가 대규모 Helm/Kustomize 매니페스트 렌더링 중 메모리 한도를 초과하여 OOMKilled되었습니다."
		case "GitRateLimitExceeded":
			return "GitHub/GitLab API 호출 속도 제한(Rate Limit)을 초과하여 Git 원격 저장소 동기화가 실패했습니다."
		case "GCPAuthDefaultCredentialsMissing":
			return "Google Cloud SDK의 애플리케이션 기본 자격 증명(ADC) 부재로 클라이언트 초기화에 실패했습니다."
		case "GCPGeminiQuotaExceeded":
			return "Google Gemini API 호출 속도 제한(TPM/RPM) 또는 일일 할당량(Quota) 초과로 요청이 거부되었습니다."
		case "GCPGeminiSafetyBlocked":
			return "Google Gemini 모델 안전성 필터(Safety Ratings) 정책에 의해 생성 콘텐츠가 차단되었습니다."
		case "GCPBigQueryQuotaExceeded":
			return "BigQuery 쿼리 바이트 청구 한도(maximum_bytes_billed) 초과로 분석 쿼리가 중단되었습니다."
		case "GCPStorageAccessDenied":
			return "Google Cloud Storage 버킷 또는 객체 접근 IAM 권한이 없어(403 Forbidden) 파일 I/O에 실패했습니다."
		case "ClickHouseTooManyParts":
			return "소규모 INSERT 빈발로 ClickHouse 테이블 파트 수가 한도를 초과하여 데이터 보호를 위해 쓰기가 차단되었습니다."
		case "ClickHouseMemoryLimit":
			return "ClickHouse 서버 또는 쿼리 메모리 한도(max_server_memory_usage) 초과로 작업이 강제 종료되었습니다."
		case "ClickHouseZooKeeperSessionLost":
			return "ClickHouse가 ZooKeeper 분산 코디네이션 세션을 상실하여 테이블이 읽기 전용으로 격리되었습니다."
		case "ZooKeeperDiskFull":
			return "ZooKeeper 트랜잭션 로그/스냅샷 디스크 볼륨이 고갈되어 서버 데몬이 비정상 종료되었습니다."
		case "ZooKeeperQuorumLost":
			return "ZooKeeper 클러스터가 과반수 쿼럼(Quorum)을 상실하여 리더 선출 및 요청 처리가 마비되었습니다."
		case "ValkeyOOM":
			return "Valkey 메모리가 maxmemory 제한에 도달하여 신규 쓰기 명령이 거절되었습니다."
		case "PostgresTxidExhaustion":
			return "PostgreSQL 트랜잭션 ID 래핑(TXID Wraparound) 방지 비상 잠금으로 인해 데이터베이스가 읽기 전용화되었습니다."
		case "JenkinsDiskSpaceExhausted":
			return "Jenkins 노드의 워크스페이스 저장 공간이 임계치 미만으로 고갈되어 빌드가 중단되었습니다."
		case "ArgoWorkflowDeadlineExceeded":
			return "Argo Workflow 파이프라인 태스크가 지정된 activeDeadlineSeconds 실행 시간을 초과했습니다."
		case "ArgoRolloutAnalysisFailed":
			return "Argo Rollouts 카나리 배포 분석(AnalysisRun) 지표 측정 실패로 자동 롤백되었습니다."
		case "KyvernoAdmissionPolicyViolation":
			return "Kyverno 보안 어드미션 정책(ClusterPolicy) 위반으로 인해 파드 생성이 거절되었습니다."
		case "KyvernoWebhookTimeout":
			return "Kyverno 웹훅 컨트롤러 호출 타임아웃 또는 인증서 만료로 리소스 배포가 차단되었습니다."
		case "GatekeeperConstraintViolation":
			return "OPA Gatekeeper 제약 조건(Constraint) 위반으로 인해 쿠버네티스 리소스 생성이 거부되었습니다."
		case "SecretProviderClassNotFound":
			return "Secrets Store CSI Driver가 참조하는 SecretProviderClass 리소스를 찾을 수 없어 볼륨 마운트에 실패했습니다."
		case "NFSMountAccessDenied":
			return "NFS 스토리지 서버의 Export 디렉토리 마운트 권한이 거부(Access denied)되었습니다."
		case "NFSConnectionTimeout":
			return "NFS 스토리지 서버(2049 포트) 연결 타임아웃으로 볼륨 마운트가 실패했습니다."
		case "MetricsServerKubeletScrapeFailed":
			return "metrics-server가 노드 Kubelet(10250) 메트릭을 스크랩하지 못해 HPA 메트릭 조회가 불가능합니다."
		case "LiteLLMRateLimitExceeded":
			return "LiteLLM 프록시 연결 업스트림 LLM 프로바이더의 속도 제한(Rate Limit 429)을 초과했습니다."
		case "LiteLLMBudgetExceeded":
			return "LiteLLM 가상 키에 할당된 최대 비용 예산(max_budget) 한도에 도달하여 요청이 차단되었습니다."
		case "LiteLLMContextWindowExceeded":
			return "요청 토큰 수가 LLM 모델의 최대 컨텍스트 윈도우 길이를 초과했습니다."
		case "TCPConnectionReset":
			return "피어 서버의 비정상 종료 또는 방화벽 세션 만료로 TCP 연결이 강제 리셋(RST)되었습니다."
		case "TCPConnectionRefused":
			return "대상 목적지 포트가 열려있지 않거나 프로세스가 실행되지 않아 TCP 연결이 거절되었습니다."
		case "TCPConnectionTimeout":
			return "방화벽 패킷 드롭 또는 라우팅 장애로 TCP SYN 응답을 받지 못해 연결이 타임아웃되었습니다."
		case "NetworkUnreachable":
			return "로컬 라우팅 경로 부재 또는 서브넷 게이트웨이 단절로 네트워크 목적지에 도달할 수 없습니다."
		case "EphemeralPortExhaustion":
			return "아웃바운드 단기 소켓 과다로 인해 로컬 임시 포트(Ephemeral Port)가 고갈되었습니다."
		case "TLSUntrustedCA":
			return "대상 서버의 TLS 인증서가 신뢰할 수 없는 CA에 의해 서명되어 인증서 검증에 실패했습니다."
		case "TLSCertificateExpired":
			return "대상 서버의 TLS 인증서 유효기간이 만료되었거나 시스템 시계가 동기화되지 않았습니다."
		case "TLSHostnameMismatch":
			return "TLS 인증서의 주체 대체 이름(SAN)과 접속 대상 호스트명이 일치하지 않아 연결이 차단되었습니다."
		case "TLSClientCertRequired":
			return "상호 TLS(mTLS) 서버가 클라이언트 인증서를 요구하였으나 인증서가 누락되었거나 거부되었습니다."
		case "ProxyAuthenticationRequired":
			return "Squid HTTP 프록시의 인증 자격 증명(Proxy-Authorization)이 누락되었거나 올바르지 않습니다."
		case "ProxyAccessDeniedACL":
			return "Squid 프록시의 접근 제어 목록(ACL) 정책에 의해 요청이 차단(403 Forbidden)되었습니다."
		case "ProxyConnectTunnelFailed":
			return "비표준 포트 접속으로 인해 Squid 프록시의 HTTPS CONNECT 터널링이 거부되었습니다."
		case "ProxyDNSResolutionFailed":
			return "Squid 프록시 서버에서 목적지 도메인의 DNS 해석에 실패하여 502 Bad Gateway가 발생했습니다."
		case "ProxyGatewayTimeout":
			return "Squid 프록시가 업스트림 서버로부터 시간 내에 응답을 받지 못해 504 Gateway Timeout이 발생했습니다."
		case "MySQLTooManyConnections":
			return "MySQL 서버 동시 연결 한도(max_connections) 초과로 신규 커넥션이 거부되었습니다 (Error 1040)."
		case "MySQLDeadlock":
			return "MySQL InnoDB 트랜잭션 상호 잠금(Deadlock)이 감지되어 트랜잭션이 강제 롤백되었습니다 (Error 1213)."
		case "MySQLCommunicationsLinkFailure":
			return "MySQL 유휴 연결 시간(wait_timeout) 초과 또는 소켓 비정상 종료로 통신 링크가 단절되었습니다."
		case "PostgresTooManyConnections":
			return "PostgreSQL 연결 슬롯 고갈(max_connections)로 인해 신규 접속이 거부되었습니다 (SQLState 53300)."
		case "PostgresDeadlock":
			return "PostgreSQL 트랜잭션 교착 상태(Deadlock)가 감지되어 트랜잭션이 중단되었습니다 (SQLState 40P01)."
		case "PostgresInFailedSQLTransaction":
			return "PostgreSQL 트랜잭션 내 이전 오류 발생 후 ROLLBACK 없이 후속 쿼리가 실행되어 명령이 거부되었습니다 (SQLState 25P02)."
		case "ClickHouseSimultaneousQueries":
			return "ClickHouse 동시 실행 쿼리 한도(max_concurrent_queries) 초과로 쿼리가 거부되었습니다 (Code 202)."
		case "BigQueryPartitionFilterRequired":
			return "BigQuery 파티션 테이블 쿼리 시 필수 파티션 필터가 누락되어 쿼리가 거부되었습니다."
		case "BigQueryBytesBilledLimitExceeded":
			return "BigQuery 쿼리 바이트 청구 한도(maximum_bytes_billed)를 초과하여 쿼리 실행이 차단되었습니다."
		default:
			return fmt.Sprintf("컨테이너가 %s 원인으로 비정상 종료되었습니다%s.", inc.RootCause, culpritStr)
		}
	}

	// English default
	switch inc.RootCause {
	case "GracefulShutdownTimeout":
		return "Process exceeded terminationGracePeriodSeconds after SIGTERM and was forcefully killed with SIGKILL (137)."
	case "ReadOnlyRootFilesystem", "ReadOnlyFilesystemError":
		return "Process crashed attempting write operations under readOnlyRootFilesystem securityContext policy."
	case "HeapCorruption":
		return fmt.Sprintf("Fatal glibc heap corruption (Double free or pointer error) encountered in native library%s.", culpritStr)
	case "NodeV8FatalError":
		return "Node.js V8 JavaScript engine heap limit exceeded resulting in fatal OOM crash."
	case "SidecarCascadeFailure":
		return "A peer sidecar container (Istio, Vault, Proxy) crashed or was unready, breaking localhost communication."
	case "InitContainerFailed":
		return "Pod initContainer failed, preventing the main application container from starting."
	case "OOMKilled", "ProbableOOMKilled", "SystemOOMKilled":
		return "Container memory consumption exceeded the configured cgroup limit and was terminated by the Linux kernel OOM Killer."
	case "LivenessProbeFailure":
		return "The application failed to respond to configured liveness probes in time and was restarted by Kubelet."
	case "GoPanic", "GoNilPointerDereference":
		return fmt.Sprintf("Unhandled Go runtime panic caused application crash%s.", culpritStr)
	case "GoDeadlock":
		return "All active goroutines entered a waiting state (Deadlock), halting the Go runtime."
	case "JVMHeapOOM":
		return "JVM exhausted allocated heap memory (-Xmx), resulting in OutOfMemoryError."
	case "DotNetNullReference":
		return fmt.Sprintf("Uninitialized object reference (NullReferenceException) encountered in .NET runtime%s.", culpritStr)
	case "PythonUnhandledException", "AppUnhandledException":
		errName := inc.ErrorClass
		if errName == "" || errName == "PythonException" {
			errName = "Unhandled Exception"
		}
		fnStr := ""
		if inc.CulpritCode != nil && inc.CulpritCode.Function != "" {
			fnStr = fmt.Sprintf(" function %s()", inc.CulpritCode.Function)
		}
		return fmt.Sprintf("Unhandled Python %s encountered causing process crash%s%s.", errName, culpritStr, fnStr)
	case "CircularImportError":
		return fmt.Sprintf("Python circular module dependency prevented import resolution%s.", culpritStr)
	case "SpringCircularDependency":
		return fmt.Sprintf("Spring Boot circular bean dependency cycle prevented context initialization%s.", culpritStr)
	case "LazyInitializationException":
		return fmt.Sprintf("JPA/Hibernate LazyInitializationException: lazy association accessed without active session%s.", culpritStr)
	case "TransientPropertyValueException":
		return fmt.Sprintf("JPA TransientPropertyValueException: referenced unsaved transient child entity%s.", culpritStr)
	case "NodeTypeError":
		return fmt.Sprintf("Node.js TypeError: cannot read property of undefined or null%s.", culpritStr)
	case "NodeUnhandledPromiseRejection":
		return fmt.Sprintf("Node.js UnhandledPromiseRejection: rejected promise terminated process%s.", culpritStr)
	case "NodeESMMismatch":
		return fmt.Sprintf("Node.js module system mismatch between ESM and CommonJS%s.", culpritStr)
	case "NodePrismaError", "NodePrismaInitFailed":
		return fmt.Sprintf("Prisma ORM database error (%s) halted service%s.", inc.ErrorClass, culpritStr)
	case "EnvoyNoHealthyUpstream":
		return "Envoy/Istio proxy could not find any healthy upstream endpoints (503 UH flag)."
	case "EnvoyCircuitBreakerOverflow":
		return "Envoy circuit breaker threshold exceeded for connections or pending requests (503 UO flag)."
	case "EnvoyUpstreamConnectionFailure":
		return "Envoy failed to connect to upstream service (503 UF flag, Connection Refused or timeout)."
	case "EnvoyNoRouteConfigured":
		return "Envoy failed to match route configuration for request host or path (404 NR flag)."
	case "EnvoyTLSHandshakeFailed":
		return "Envoy upstream TLS handshake failed or connection reset prematurely (503 UC flag)."
	case "EnvoyUpstreamTimeout":
		return "Envoy upstream service did not respond within configured timeout (504 UT flag)."
	case "NginxConfigSyntaxError":
		return fmt.Sprintf("Nginx configuration syntax error ([emerg]) prevented startup%s.", culpritStr)
	case "NginxClientBodySizeExceeded":
		return "Client request body exceeded Nginx client_max_body_size limit (413 Request Entity Too Large)."
	case "IstioProxyNotReady":
		return "istio-proxy sidecar failed readiness probe on port 15021, preventing traffic routing."
	case "IstioStartupRaceCondition":
		return "Application crashed attempting network egress before istio-proxy sidecar reached Ready state."
	case "IstioStrictMTLSMismatch":
		return "Plaintext traffic rejected by destination namespace STRICT mTLS PeerAuthentication policy."
	case "EnvoyGatewayTranslationFailed":
		return "Envoy Gateway failed xDS translation or Gateway API backendRefs resolution."
	case "VaultSealedFailure":
		return "HashiCorp Vault instance is sealed (HTTP 503); secrets cannot be fetched."
	case "VaultTokenExpired":
		return "Vault token expired or Kubernetes Auth role binding failed (403 Forbidden)."
	case "CoreDNSLoopDetected":
		return "CoreDNS loop plugin detected forwarding loop and stopped to prevent cluster-wide outage."
	case "CertManagerWebhookFailure":
		return "cert-manager-webhook call timed out or connection refused during resource validation."
	case "ACMERateLimitExceeded":
		return "Let's Encrypt ACME API rate limit exceeded for domain or account."
	case "PrometheusWALCorruption":
		return "Prometheus TSDB Write-Ahead Log (WAL) corruption prevented database recovery."
	case "PrometheusCardinalityOOM":
		return "High-cardinality label explosion caused Prometheus TSDB memory exhaustion (OOMKilled)."
	case "FluentBitBufferExhaustion":
		return "Fluent Bit ring buffer filled up; log ingestion paused due to downstream backpressure."
	case "ElasticsearchDiskFloodStage":
		return "Elasticsearch disk usage exceeded 95% flood stage watermark; indices set to read-only."
	case "ElasticsearchCircuitBreaker":
		return "Elasticsearch memory circuit breaker tripped ([parent]/[fielddata]) to prevent JVM OOM."
	case "PatroniLeaderLeaseLost":
		return "Patroni lost DCS leader lease and demoted PostgreSQL primary to replica."
	case "PostgresWALDiskFull":
		return "PostgreSQL pg_wal volume full (PANIC: could not write to log file); server shut down."
	case "ArgoCDRepoServerOOM":
		return "Argo CD repo-server exceeded memory limit while rendering large Helm/Kustomize manifests."
	case "GitRateLimitExceeded":
		return "Remote Git host (GitHub/GitLab) API rate limit exceeded, halting GitOps synchronization."
	case "GCPAuthDefaultCredentialsMissing":
		return "Google Cloud SDK Application Default Credentials (ADC) lookup failed."
	case "GCPGeminiQuotaExceeded":
		return "Google Gemini API rate limit or project quota exceeded (HTTP 429 ResourceExhausted)."
	case "GCPGeminiSafetyBlocked":
		return "Google Gemini response candidate or prompt blocked by safety filters."
	case "GCPBigQueryQuotaExceeded":
		return "BigQuery query exceeded bytes billed limit (maximum_bytes_billed)."
	case "GCPStorageAccessDenied":
		return "Google Cloud Storage bucket or object access denied (HTTP 403 Forbidden)."
	case "ClickHouseTooManyParts":
		return "ClickHouse table partition parts exceeded threshold due to small frequent inserts."
	case "ClickHouseMemoryLimit":
		return "ClickHouse memory limit exceeded for query or server total."
	case "ClickHouseZooKeeperSessionLost":
		return "ClickHouse lost ZooKeeper coordination session, halting replicated engine tables."
	case "ZooKeeperDiskFull":
		return "ZooKeeper transaction log or snapshot disk space exhausted."
	case "ZooKeeperQuorumLost":
		return "ZooKeeper ensemble lost majority quorum (N/2 + 1) for leader election."
	case "ValkeyOOM":
		return "Valkey in-memory storage consumption reached maxmemory limit."
	case "PostgresTxidExhaustion":
		return "PostgreSQL entered emergency read-only mode to prevent catastrophic TXID wraparound data loss."
	case "JenkinsDiskSpaceExhausted":
		return "Jenkins node workspace disk space fell below safety threshold."
	case "ArgoWorkflowDeadlineExceeded":
		return "Argo Workflow task exceeded configured activeDeadlineSeconds."
	case "ArgoRolloutAnalysisFailed":
		return "Argo Rollouts canary AnalysisRun metrics evaluation failed, triggering automated abort."
	case "KyvernoAdmissionPolicyViolation":
		return "Pod admission rejected due to Kyverno ClusterPolicy rule violation."
	case "KyvernoWebhookTimeout":
		return "Kyverno admission webhook call timed out or TLS certificate expired."
	case "GatekeeperConstraintViolation":
		return "Resource creation rejected by OPA Gatekeeper constraint violation."
	case "SecretProviderClassNotFound":
		return "Secrets Store CSI Driver referenced SecretProviderClass resource not found."
	case "NFSMountAccessDenied":
		return "NFS server rejected remote directory mount access."
	case "NFSConnectionTimeout":
		return "NFS storage server connection timed out on port 2049/111."
	case "MetricsServerKubeletScrapeFailed":
		return "metrics-server failed to scrape Kubelet metrics on port 10250."
	case "LiteLLMRateLimitExceeded":
		return "LiteLLM upstream LLM provider rate limit exceeded (HTTP 429 TPM/RPM)."
	case "LiteLLMBudgetExceeded":
		return "LiteLLM user/key budget limit exceeded; further requests rejected."
	case "LiteLLMContextWindowExceeded":
		return "Prompt and generation tokens exceeded LLM model maximum context window length."
	case "TCPConnectionReset":
		return "TCP connection forcibly reset by peer or intermediate firewall/LB (ECONNRESET)."
	case "TCPConnectionRefused":
		return "TCP connection refused: target port is not listening or process is down (ECONNREFUSED)."
	case "TCPConnectionTimeout":
		return "TCP connection timed out waiting for SYN-ACK response (ETIMEDOUT / i/o timeout)."
	case "NetworkUnreachable":
		return "No routing path to target host or subnet gateway down (EHOSTUNREACH / ENETUNREACH)."
	case "EphemeralPortExhaustion":
		return "Outbound ephemeral ports exhausted, preventing new TCP socket allocation (EADDRNOTAVAIL)."
	case "TLSUntrustedCA":
		return "TLS certificate signed by unknown authority (self-signed or untrusted private CA)."
	case "TLSCertificateExpired":
		return "TLS certificate expired or system clock out of sync (CERT_HAS_EXPIRED)."
	case "TLSHostnameMismatch":
		return "TLS certificate Subject Alternative Name (SAN) does not match target hostname."
	case "TLSClientCertRequired":
		return "Mutual TLS (mTLS) handshake failed: client certificate required by server."
	case "ProxyAuthenticationRequired":
		return "Squid forward proxy authentication required (HTTP 407 Proxy Authentication Required)."
	case "ProxyAccessDeniedACL":
		return "Squid forward proxy access denied by ACL policy (HTTP 403 Forbidden)."
	case "ProxyConnectTunnelFailed":
		return "Squid HTTPS CONNECT tunnel rejected due to non-standard or restricted port."
	case "ProxyDNSResolutionFailed":
		return "Squid forward proxy failed upstream domain DNS resolution (HTTP 502 Bad Gateway)."
	case "ProxyGatewayTimeout":
		return "Squid forward proxy upstream read timed out (HTTP 504 Gateway Timeout)."
	case "MySQLTooManyConnections":
		return "MySQL server max_connections limit exceeded, rejecting new client connections (Error 1040)."
	case "MySQLDeadlock":
		return "MySQL InnoDB transaction deadlock detected and rolled back automatically (Error 1213)."
	case "MySQLCommunicationsLinkFailure":
		return "MySQL communications link failure due to server wait_timeout expiration or closed socket."
	case "PostgresTooManyConnections":
		return "PostgreSQL connection slots exhausted (SQLState 53300: sorry, too many clients already)."
	case "PostgresDeadlock":
		return "PostgreSQL transaction deadlock detected and aborted (SQLState 40P01)."
	case "PostgresInFailedSQLTransaction":
		return "PostgreSQL transaction aborted due to earlier failure, subsequent commands ignored (SQLState 25P02)."
	case "ClickHouseSimultaneousQueries":
		return "ClickHouse max concurrent queries limit reached (Code 202: Too many simultaneous queries)."
	case "BigQueryPartitionFilterRequired":
		return "BigQuery partitioned table requires a partition filter over partition columns (requirePartitionFilter=true)."
	case "BigQueryBytesBilledLimitExceeded":
		return "BigQuery query exceeded configured limit for bytes billed (maximum_bytes_billed)."
	default:
		return fmt.Sprintf("Container terminated due to %s%s.", inc.RootCause, culpritStr)
	}
}

func buildSuggestedFix(inc IncidentContext, lang string) string {
	if lang == "ko" {
		switch inc.RootCause {
		case "GracefulShutdownTimeout":
			return "1) SIGTERM 신호 수신 시 활성 커넥션 및 큐 작업을 신속히 정리하도록 타임아웃을 설정하세요. 2) 파드 spec.terminationGracePeriodSeconds(기본 30초)를 늘려 안전한 드레인 시간을 확보하세요."
		case "ReadOnlyRootFilesystem", "ReadOnlyFilesystemError":
			return "1) 파드 securityContext.readOnlyRootFilesystem 설정을 확인하세요. 2) 애플리케이션이 임시 파일이나 캐시를 작성하는 디렉토리(/tmp, /var/log 등)에 emptyDir 볼륨을 마운트하세요."
		case "HeapCorruption":
			return "1) C/C++ 네이티브 라이브러리 및 JNI/CGO 코드의 메모리 할당/해제 로직을 점검하세요. 2) AddressSanitizer(ASan) 또는 Valgrind로 힙 손상 지점을 추적하세요."
		case "NodeV8FatalError":
			return "1) 컨테이너 환경변수에 NODE_OPTIONS=\"--max-old-space-size=4096\"을 설정하여 V8 힙을 확장하세요. 2) 전역 캐시 배열 누수를 점검하세요."
		case "SidecarCascadeFailure":
			return "1) 파드 내 사이드카 컨테이너(istio-proxy, cloud-sql-proxy, vault-agent 등)의 로그 및 종료 상태를 확인하세요. 2) 쿠버네티스 1.28+ 네이티브 사이드카(restartPolicy: Always)를 적용하여 초기화 순서를 보장하세요."
		case "InitContainerFailed":
			return "1) 실패한 initContainer의 로그(kubectl logs <pod> -c <init-container>)를 확인하세요. 2) 데이터베이스 마이그레이션 또는 사전 권한 설정을 점검하세요."
		case "OOMKilled", "ProbableOOMKilled", "SystemOOMKilled":
			return "1) 파드 스펙의 메모리 한도(resources.limits.memory)를 증설하세요. 2) JVM의 경우 -XX:MaxRAMPercentage 또는 -Xmx가 컨테이너 한도보다 최소 200MB 이상 작게 설정되었는지 확인하세요."
		case "LivenessProbeFailure":
			return "1) livenessProbe의 timeoutSeconds 및 failureThreshold를 증설하세요. 2) 헬스체크 엔드포인트(/healthz)가 느린 외부 DB/캐시 쿼리에 종속되지 않도록 분리하세요."
		case "StartupProbeFailure":
			return "1) startupProbe의 initialDelaySeconds 또는 failureThreshold를 늘려 앱의 느린 초기화 시간을 확보하세요."
		case "SpringHikariPoolExhaustion":
			return "1) spring.datasource.hikari.maximum-pool-size를 늘리세요. 2) 트랜잭션(@Transactional) 범위를 최소화하고 커넥션 누수(leakDetectionThreshold)를 활성화하세요."
		case "SpringPortInUse", "GoPortInUse", "NodePortInUse", "DotNetPortInUse", "PortConflict":
			return "1) 서버 설정의 수신 포트 번호를 변경하세요. 2) 동일 호스트 네트워크(hostNetwork: true)를 사용하는 다른 파드와의 포트 충돌 여부를 확인하세요."
		case "SpringBootStartupFailure":
			return "1) application.yml 프로퍼티 설정값 오탈자를 검토하세요. 2) 누락된 의존성(@Autowired, @Bean) 주입 대상을 확인하세요."
		case "JVMHeapOOM":
			return "1) JVM -Xmx 힙 한도를 증설하거나 파드 메모리 제한을 늘리세요. 2) -XX:+HeapDumpOnOutOfMemoryError 옵션으로 힙 덤프를 추출하여 메모리 점유 객체를 프로파일링하세요."
		case "JVMMetaspaceOOM":
			return "1) -XX:MaxMetaspaceSize를 늘리세요. 2) CGLIB/Spring 동적 프록시 클래스 생성 누수 여부를 점검하세요."
		case "JVMDirectMemoryOOM":
			return "1) -XX:MaxDirectMemorySize를 확장하세요. 2) Netty ByteBuf의 ReferenceCountUtil.release() 누락을 점검하세요."
		case "JVMThreadExhaustion":
			return "1) 스레드 풀(ExecutorService)의 과도한 스레드 생성을 제한하세요. 2) 노드 cgroup pids.max 한도를 확장하세요."
		case "JVMNullPointer":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				return fmt.Sprintf("%s:%d의 참조 대상 객체에 Null 검증(Objects.requireNonNull 또는 if != null)을 보강하세요.", inc.CulpritCode.File, inc.CulpritCode.Line)
			}
			return "객체 초기화 여부와 Optional을 활용한 Null 안전성을 보강하세요."
		case "GoPanic", "GoNilPointerDereference", "GoIndexOutOfRange", "GoSliceBoundsOutOfRange":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				return fmt.Sprintf("해당 소스코드(%s:%d)에서 Nil 포인터 또는 슬라이스 범위 체크를 보강하고 defer recover()를 적용하세요.", inc.CulpritCode.File, inc.CulpritCode.Line)
			}
			return "최상위 고루틴에 defer recover() 블록을 구현하여 패닉 발생 시 프로세스 크래시를 방지하세요."
		case "GoDeadlock":
			return "1) 뮤텍스 Lock()과 Unlock()의 짝이 맞는지 확인하세요. 2) 버퍼 없는 채널 송수신 고루틴의 대기 조건을 점검하세요."
		case "GoConcurrentMapAccess":
			return "표준 Go map 대신 sync.RWMutex로 보호하거나 동시성 전용 sync.Map을 사용하세요."
		case "PythonWorkerTimeout":
			return "1) Gunicorn의 --timeout 설정을 늘리세요. 2) 워커가 블로킹되는 긴 I/O 작업을 Celery 비동기 큐로 위임하세요."
		case "PythonModuleNotFound", "NodeModuleNotFound", "JVMClassNotFound", "DotNetAssemblyNotFound":
			return "Dockerfile 빌드 단계에서 의존성 설치 파일(requirements.txt / package.json / pom.xml)에 누락된 패키지가 있는지 확인하세요."
		case "NodeHeapOOM":
			return "1) 컨테이너 환경변수에 NODE_OPTIONS=\"--max-old-space-size=4096\"을 설정하여 V8 힙을 확장하세요. 2) 전역 캐시 배열 누수를 점검하세요."
		case "DotNetNullReference":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				return fmt.Sprintf("%s:%d의 참조 대상 객체에 null 조건 연산자(?.) 또는 null 병합 연산자(??)를 적용하세요.", inc.CulpritCode.File, inc.CulpritCode.Line)
			}
			return "의존성 주입(DI) 등록 누락 여부를 확인하고 Nullable 참조 형식을 활성화하세요."
		case "PostgresMaxConnections":
			return "1) PgBouncer 또는 ProxySQL 커넥션 풀러를 도입하세요. 2) DB 서버의 max_connections 파라미터를 증설하세요."
		case "RedisOOM":
			return "1) Redis maxmemory 용량을 확장하세요. 2) maxmemory-policy allkeys-lru로 만료 키 제거 정책을 설정하세요."
		case "NginxWorkerConnections":
			return "nginx.conf의 worker_connections(기본 1024) 및 worker_processes를 시스템 코어 수에 맞추어 증설하세요."
		case "DiskNoSpaceLeft":
			return "1) 로그 로테이션(logrotate) 설정을 점검하세요. 2) 파드 스펙의 ephemeral-storage limit을 늘리거나 임시 볼륨(emptyDir)을 분리하세요."
		case "FileDescriptorExhaustion":
			return "1) 컨테이너의 ulimit -n(nofile) 설정을 확인하세요. 2) HTTP 클라이언트 또는 DB 커넥션 종료 후 소켓 close() 누락을 점검하세요."
		case "ArchitectureMismatch":
			return "노드 CPU 아키텍처에 맞게 docker buildx --platform linux/amd64,linux/arm64 옵션으로 멀티 아키텍처 이미지를 다시 빌드하세요."
		case "PythonUnhandledException", "AppUnhandledException":
			errName := inc.ErrorClass
			if errName == "" || errName == "PythonException" {
				errName = "예외"
			}
			locStr := ""
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				locStr = fmt.Sprintf("[%s:%d] ", inc.CulpritCode.File, inc.CulpritCode.Line)
			}
			return fmt.Sprintf("1) %s해당 코드 위치에 try-except %s 블록을 추가하여 예외 발생 시 안전하게 복구하거나 로깅 후 정상 종료하도록 처리하세요. 2) 입력값 유효성 검증(Data Validation)을 사전에 수행하여 비정상 데이터 처리를 방어하세요.", locStr, errName)
		case "CircularImportError":
			return "1) 상호 순환 참조되는 import 구문을 함수 내부(로컬 스코프)로 이동하세요. 2) 타입 힌팅 전용인 경우 'if typing.TYPE_CHECKING:' 블록을 사용하세요. 3) 공통 데이터 모델을 별도 모듈로 분리하세요."
		case "SpringCircularDependency":
			return "1) 상호 주입되는 빈 필드나 생성자 매개변수에 '@Lazy' 어노테이션을 추가하세요. 2) 공통 비즈니스 로직을 제3의 서비스 빈으로 분리하세요. 3) 임시로 application.yml에 'spring.main.allow-circular-references: true'를 활성화하세요."
		case "LazyInitializationException":
			return "1) Repository JPQL 쿼리에 'JOIN FETCH'를 추가하여 연관 엔티티를 한 번에 조회하세요. 2) '@EntityGraph' 어노테이션을 적용하세요. 3) 조회 메서드에 '@Transactional(readOnly = true)'를 선언하여 영속성 세션을 유지하세요."
		case "TransientPropertyValueException":
			return "1) 부모 엔티티의 연관관계 어노테이션(@OneToMany, @ManyToOne 등)에 'cascade = CascadeType.ALL' 또는 'CascadeType.PERSIST'를 추가하세요. 2) 자식 엔티티를 부모보다 먼저 repository.save() 하세요."
		case "NodeTypeError":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				return fmt.Sprintf("1) [%s:%d] 프로퍼티 접근 전 옵셔널 체이닝(obj?.field)을 적용하세요. 2) 객체가 undefined/null인지 유효성 검증(if (!obj) ...) 로직을 보강하세요.", inc.CulpritCode.File, inc.CulpritCode.Line)
			}
			return "1) 프로퍼티 접근 전 옵셔널 체이닝(obj?.field)을 적용하세요. 2) 객체가 undefined/null인지 유효성 검증(if (!obj) ...) 로직을 보강하세요."
		case "NodeUnhandledPromiseRejection":
			return "1) 모든 async 함수 호출에 'await'를 누락하지 않았는지 확인하세요. 2) 비동기 호출을 try/catch 블록으로 감싸거나 Promise 뒤에 '.catch(err => ...)' 에러 핸들러를 반드시 연결하세요."
		case "NodeESMMismatch":
			return "1) package.json에 '\"type\": \"module\"'을 선언하세요. 2) CommonJS 전용 파일은 확장자를 '.cjs'로 변경하세요. 3) TypeScript의 경우 tsconfig.json에서 'moduleResolution'을 'NodeNext'로 설정하세요."
		case "NodePrismaError", "NodePrismaInitFailed":
			return "1) 중복 키 위반인 경우 삽입 전 findUnique 검증 또는 upsert() 구문을 사용하세요. 2) DATABASE_URL 환경변수 및 K8s Service DNS 연결성을 점검하세요."
		case "EnvoyNoHealthyUpstream":
			return "1) 대상 파드가 Ready 상태인지 확인하세요 ('kubectl get endpoints <service>'). 2) DestinationRule의 outlierDetection 또는 헬스체크 설정을 점검하세요."
		case "EnvoyCircuitBreakerOverflow":
			return "1) DestinationRule의 connectionPool 설정을 확장하세요:\n```yaml\ntrafficPolicy:\n  connectionPool:\n    tcp:\n      maxConnections: 1024\n    http:\n      maxPendingRequests: 1024\n      maxRequestsPerConnection: 100\n```\n2) 백엔드 파드를 수평 확장(HPA)하여 부하를 분산하세요."
		case "EnvoyUpstreamConnectionFailure":
			return "1) 백엔드 파드의 리슨 포트가 Service spec의 targetPort와 일치하는지 확인하세요. 2) NetworkPolicy가 인입 트래픽을 차단하지 않는지 점검하세요 ('kubectl describe networkpolicy')."
		case "EnvoyNoRouteConfigured":
			return "1) VirtualService 또는 Ingress의 'hosts' 및 'http.match' URI 경로가 클라이언트 요청과 일치하는지 확인하세요. 2) Istio Ingress Gateway와 VirtualService 간 게이트웨이 바인딩을 점검하세요."
		case "EnvoyTLSHandshakeFailed":
			return "1) DestinationRule의 tls.mode(ISTIO_MUTUAL vs SIMPLE vs DISABLE) 설정이 대상 서비스의 TLS 지원 여부와 일치하는지 확인하세요. 2) 대상 파드에 istio-proxy가 주입되지 않은 경우 'tls.mode: DISABLE'을 지정하세요."
		case "EnvoyUpstreamTimeout":
			return "1) VirtualService의 timeout 설정을 늘리세요 (예: 'timeout: 30s'). 2) 백엔드 애플리케이션의 데이터베이스 쿼리 락 또는 블로킹 I/O를 최적화하세요."
		case "NginxConfigSyntaxError":
			return "1) Ingress의 'nginx.ingress.kubernetes.io/configuration-snippet' 또는 'server-snippet' 어노테이션의 세미콜론(;) 누락 및 오탈자를 수정하세요. 2) 'kubectl logs -n ingress-nginx <ingress-controller-pod>'로 구체적인 에러 라인을 확인하세요."
		case "NginxClientBodySizeExceeded":
			return "1) Ingress에 아래 어노테이션을 추가하여 요청 본문 크기 한도를 확장하세요:\n```yaml\nmetadata:\n  annotations:\n    nginx.ingress.kubernetes.io/proxy-body-size: \"50m\"\n```"
		case "IstioProxyNotReady":
			return "1) istiod 컨트롤 플레인의 상태를 점검하세요 ('istioctl proxy-status'). 2) istio-proxy 컨테이너의 CPU/메모리 Limit을 증설하여 리소스 스로틀링을 방지하세요."
		case "IstioStartupRaceCondition":
			return "1) 파드 metadata.annotations에 아래 설정을 추가하여 프록시 기동 완료 후 앱이 실행되도록 제어하세요:\n```yaml\nmetadata:\n  annotations:\n    proxy.istio.io/config: \"holdApplicationUntilProxyStarts: true\"\n```\n2) 쿠버네티스 1.28+ 네이티브 사이드카 컨테이너('restartPolicy: Always' in initContainers)를 도입하세요."
		case "IstioStrictMTLSMismatch":
			return "1) 클라이언트 파드 네임스페이스에 'istio-injection=enabled' 라벨을 적용하여 사이드카를 주입하세요. 2) 평문 클라이언트와의 호환을 위해 PeerAuthentication을 PERMISSIVE 모드로 변경하세요:\n```yaml\nspec:\n  mtls:\n    mode: PERMISSIVE\n```"
		case "EnvoyGatewayTranslationFailed":
			return "1) Gateway API HTTPRoute의 backendRefs에 지정된 Service 이름 및 포트를 확인하세요. 2) 다른 네임스페이스의 백엔드인 경우 해당 네임스페이스에 ReferenceGrant 리소스를 생성하세요."
		case "VaultSealedFailure":
			return "1) Vault 파드에 접속하여 키 샤드로 언실(Unseal)을 수행하세요:\n```bash\nvault operator unseal <unseal-key-1>\nvault operator unseal <unseal-key-2>\nvault operator unseal <unseal-key-3>\n```\n2) 프로덕션 환경에서는 AWS KMS, GCP KMS 또는 Azure Key Vault를 연동하여 자동 언실(Auto-unseal)을 구성하세요."
		case "VaultTokenExpired":
			return "1) Vault 역할(Role)의 token_ttl 및 token_max_ttl 설정을 점검하세요. 2) Vault Agent의 auto-auth 갱신 설정(vault.hashicorp.com/agent-inject: 'true')을 확인하세요."
		case "CoreDNSLoopDetected":
			return "1) 워커 노드의 '/etc/resolv.conf'에서 로컬 루프백 주소(127.0.0.53/127.0.0.1)를 제거하고 외부 네임서버(8.8.8.8, 1.1.1.1)를 설정하세요. 2) Kubelet 설정에 '--resolv-conf=/etc/systemd/resolved/resolv.conf'를 지정하세요."
		case "CertManagerWebhookFailure":
			return "1) cert-manager-webhook 파드 상태를 점검하세요 ('kubectl get pods -n cert-manager'). 2) API 서버와 워커 노드 간 10250, 6443, 9443 포트 네트워크 정책 및 클러스터 방화벽을 확인하세요."
		case "ACMERateLimitExceeded":
			return "1) 개발/스테이징 환경에서는 Let's Encrypt Staging API('https://acme-staging-v02.api.letsencrypt.org/directory') Issuer를 사용하세요. 2) 불필요하게 파드를 재배포하며 매번 새 인증서를 요청하지 않도록 Secret을 재사용하세요."
		case "PrometheusWALCorruption":
			return "1) Prometheus에 '--storage.tsdb.wal-compression'을 활성화하세요. 2) 손상된 WAL 세그먼트를 제거하거나 PV 볼륨 백업에서 WAL을 복원하세요:\n```bash\nkubectl exec -it <prometheus-pod> -- rm -rf /prometheus/wal/000000*\n```"
		case "PrometheusCardinalityOOM":
			return "1) Prometheus scrape 설정의 metric_relabel_configs에서 고유 ID 라벨을 제거하세요:\n```yaml\nmetricRelabelings:\n  - action: labeldrop\n    regex: (userId|user_id|sessionId|traceId|guid)\n```\n2) 파드의 memory limit을 증설하세요."
		case "FluentBitBufferExhaustion":
			return "1) Fluent Bit 설정에 파일시스템 기반 버퍼링(배압 디스크 버퍼링)을 활성화하세요:\n```ini\n[SERVICE]\n    storage.path /var/log/fluentbit/buffer\n[INPUT]\n    storage.type filesystem\n    storage.buffering on\n```\n2) Elasticsearch/Loki 등 수신 엔드포인트의 병목 현상을 해결하세요."
		case "ElasticsearchDiskFloodStage":
			return "1) PV 스토리지 볼륨 용량을 증설하고 오래된 인덱스를 삭제하세요. 2) 인덱스 읽기 전용 잠금을 해제하세요:\n```bash\ncurl -X PUT \"localhost:9200/*/_settings\" -H 'Content-Type: application/json' -d'{\"index.blocks.read_only_allow_delete\": null}'\n```"
		case "ElasticsearchCircuitBreaker":
			return "1) Elasticsearch JVM 힙 크기를 확장하세요 ('ES_JAVA_OPTS=-Xms16g -Xmx16g', 최대 31GB). 2) 필드데이터 캐시 크기 및 indices.breaker.total.use_real_memory 설정을 최적화하세요."
		case "PatroniLeaderLeaseLost":
			return "1) etcd 클러스터의 디스크 fsync 지연 시간(WAL sync) 및 네트워크 안정성을 점검하세요. 2) Patroni 설정의 'ttl'(기본 30초) 및 'loop_wait'(기본 10초)를 네트워크 환경에 맞게 늘리세요."
		case "PostgresWALDiskFull":
			return "1) 사용되지 않거나 지연된 복제 슬롯을 삭제하세요:\n```sql\nSELECT slot_name, active FROM pg_replication_slots;\nSELECT pg_drop_replication_slot('inactive_slot_name');\n```\n2) archive_command 실패 여부를 확인하고 pg_wal 마운트 볼륨을 확장하세요."
		case "ArgoCDRepoServerOOM":
			return "1) argocd-repo-server 디플로이먼트의 memory limit을 최소 2GiB 이상으로 증설하세요:\n```yaml\nresources:\n  limits:\n    memory: 4Gi\n  requests:\n    memory: 1Gi\n```\n2) 환경변수 'ARGOCD_EXEC_TIMEOUT'을 180s로 설정하고 Helm 매니페스트를 분할하세요."
		case "GitRateLimitExceeded":
			return "1) Argo CD repo 자격 증명에 GitHub App 또는 충분한 쿼터의 Personal Access Token(PAT)을 등록하세요. 2) 주기적 폴링 대신 Git Webhook 알림 방식으로 전환하세요."
		case "GCPAuthDefaultCredentialsMissing":
			return "1) 파드에 서비스 어카운트 키 Secret을 볼륨으로 마운트하고 'GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/key.json'을 설정하세요. 2) GKE Workload Identity 환경인 경우 Kubernetes ServiceAccount에 'iam.gke.io/gcp-service-account' 어노테이션이 올바른지 점검하세요."
		case "GCPGeminiQuotaExceeded":
			return "1) Google Cloud Console의 Vertex AI / Gemini API 할당량(TPM, RPM) 상향을 요청하세요. 2) 애플리케이션에 지수 백오프(Exponential Backoff) 재시도 로직을 적용하거나 LiteLLM 프록시로 트래픽을 분산하세요."
		case "GCPGeminiSafetyBlocked":
			return "1) Gemini generationConfig의 safetySettings(HARM_CATEGORY_HARASSMENT 등) 임계값을 BLOCK_ONLY_HIGH로 완화하세요. 2) 사용자 입력 프롬프트 사전 필터링 로직을 보강하세요."
		case "GCPBigQueryQuotaExceeded":
			return "1) 쿼리 잡 설정의 'maximum_bytes_billed' 한도를 늘리거나 날짜 파티션/클러스터링 필터를 적용해 스캔 용량을 줄이세요. 2) GCP BigQuery 슬롯 예약(Slot Reservations)을 검토하세요."
		case "GCPStorageAccessDenied":
			return "1) 서비스 어카운트에 'roles/storage.objectViewer' 또는 'roles/storage.objectAdmin' IAM 역할을 부여하세요. 2) 버킷의 Uniform Bucket-Level Access 정책을 확인하세요."
		case "ClickHouseTooManyParts":
			return "1) 클라이언트에서 10,000건 이상 단위로 벌크(배치) INSERT를 수행하거나 Buffer 엔진 테이블을 도입하세요. 2) clickhouse-server 설정에서 'parts_to_delay_insert'(기본 150) 및 'parts_to_throw_insert'(기본 300) 임계값을 환경에 맞게 조정하세요."
		case "ClickHouseMemoryLimit":
			return "1) clickhouse users.xml에서 'max_server_memory_usage' 및 'max_memory_usage' 설정을 확장하세요. 2) 대규모 JOIN/GROUP BY 쿼리에 'max_bytes_before_external_group_by' 디스크 오프로딩을 활성화하세요."
		case "ClickHouseZooKeeperSessionLost":
			return "1) ZooKeeper 파드의 가동 상태와 네트워크 레이턴시를 점검하세요. 2) clickhouse-server의 'session_timeout_ms'(기본 30초) 및 'operation_timeout_ms'를 상향 조정하세요."
		case "ZooKeeperDiskFull":
			return "1) ZooKeeper PVC 스토리지 용량을 즉시 증설하세요. 2) zoo.cfg에 'autopurge.purgeInterval=1' 및 'autopurge.snapRetainCount=3' 설정을 활성화하여 오래된 스냅샷을 자동 삭제하세요."
		case "ZooKeeperQuorumLost":
			return "1) 과반수(N/2 + 1)의 ZooKeeper 노드가 정상 실행 중인지 확인하세요. 2) 노드 간 2888(피어 통신) 및 3888(리더 선출) 포트 방화벽을 점검하세요."
		case "ValkeyOOM":
			return "1) valkey.conf에서 'maxmemory' 한도를 증설하거나 파드 메모리 제한을 확장하세요. 2) 'maxmemory-policy allkeys-lru' 등 만료 키 축출 정책을 설정하세요."
		case "PostgresTxidExhaustion":
			return "1) 즉시 단일 사용자 모드('postgres --single -D /var/lib/postgresql/data')로 진입하여 'VACUUM FREEZE ANALYZE'를 긴급 수행하세요. 2) 'autovacuum_freeze_max_age' 및 'autovacuum_vacuum_cost_limit'을 튜닝하세요."
		case "JenkinsDiskSpaceExhausted":
			return "1) Jenkins 홈/워크스페이스 볼륨 PVC 용량을 확장하세요. 2) 파이프라인 post 블록에 'cleanWs()'를 추가하고 'Discard old builds' 보존 정책을 적용하세요."
		case "ArgoWorkflowDeadlineExceeded":
			return "1) Workflow 템플릿의 'activeDeadlineSeconds' 값을 늘려 충분한 실행 시간을 부여하세요. 2) 파이프라인 외부 호출 I/O 병목 및 데이터베이스 락 지연을 점검하세요."
		case "ArgoRolloutAnalysisFailed":
			return "1) AnalysisTemplate의 Prometheus 쿼리 성공률(success-rate) 또는 레이턴시 지표 임계값을 점검하세요. 2) 카나리 파드의 로그를 확인하여 신규 버전 결함을 수정하세요."
		case "KyvernoAdmissionPolicyViolation":
			return "1) 에러 로그에 명시된 Kyverno 정책 요구사항(보안 컨텍스트, 라벨, 이미지 태그 등)을 파드 스펙에 보강하세요. 2) 'kubectl get cpol -A'로 활성화된 정책을 확인하세요."
		case "KyvernoWebhookTimeout":
			return "1) kyverno 파드의 CPU/메모리 부하 및 가동 상태를 점검하세요. 2) API 서버와 kyverno 서비스 간 9443 포트 방화벽 및 Webhook TLS Secret 갱신 상태를 확인하세요."
		case "GatekeeperConstraintViolation":
			return "1) Gatekeeper 제약 조건 위반 항목(privileged 컨테이너, CPU/메모리 제한 누락 등)을 매니페스트에 보강하세요. 2) 'kubectl get constraints'로 위반 상태를 조회하세요."
		case "SecretProviderClassNotFound":
			return "1) 파드와 동일한 네임스페이스에 SecretProviderClass 리소스가 생성되어 있는지 확인하세요 ('kubectl get secretproviderclass -n <ns>'). 2) 볼륨 spec의 secretProviderClass 이름 오탈자를 수정하세요."
		case "NFSMountAccessDenied":
			return "1) NFS 서버의 '/etc/exports' 설정에서 클러스터 워커 노드 CIDR 대역 허용 및 'no_root_squash' 옵션을 확인하세요. 2) NFS 서버에서 'exportfs -rav'를 실행하여 설정을 갱신하세요."
		case "NFSConnectionTimeout":
			return "1) NFS 서버 호스트의 가동 상태를 점검하세요. 2) 워커 노드와 NFS 서버 간 방화벽에서 TCP/UDP 2049(NFS) 및 111(rpcbind) 포트가 허용되었는지 확인하세요."
		case "MetricsServerKubeletScrapeFailed":
			return "1) Kubelet 자체 서명 인증서 사용 환경인 경우 metrics-server 디플로이먼트 인수에 '--kubelet-insecure-tls'를 추가하세요. 2) 제어 평면과 워커 노드 간 10250 포트 방화벽을 허용하세요."
		case "LiteLLMRateLimitExceeded":
			return "1) LiteLLM config.yaml에 모델 폴백(fallback) 라우팅을 구성하세요. 2) 클라이언트에 지수 백오프(Exponential Backoff) 재시도를 적용하거나 Redis/Valkey 캐싱을 활성화하세요."
		case "LiteLLMBudgetExceeded":
			return "1) LiteLLM 관리자 UI 또는 API에서 해당 사용자/키의 'max_budget' 한도를 증설하거나 리셋하세요. 2) 월간 예산 리셋 주기를 확인하세요."
		case "LiteLLMContextWindowExceeded":
			return "1) 대화 히스토리 슬라이딩 윈도우 또는 텍스트 요약을 적용하여 프롬프트를 압축하세요. 2) 더 큰 컨텍스트 윈도우를 지원하는 모델(Gemini 1.5, Claude 3.5 등)로 전환하세요."
		case "TCPConnectionReset":
			return "1) 대상 서비스 파드의 비정상 종료(SIGSEGV/OOM) 여부를 확인하세요. 2) L4/클라우드 로드밸런서의 Idle Timeout 설정을 클라이언트 keep-alive 주기보다 길게 늘리세요."
		case "TCPConnectionRefused":
			return "1) 대상 파드가 기동되어 지정된 포트로 리슨 중인지 점검하세요 ('kubectl get endpoints <svc>'). 2) Kubernetes Service의 port와 targetPort가 일치하는지 확인하세요."
		case "TCPConnectionTimeout":
			return "1) 목적지 IP/포트에 대한 NetworkPolicy 인입(Ingress) 규칙 및 보안 그룹(Security Group)을 점검하세요. 2) VPC 서브넷 라우팅 테이블이 패킷을 정상 포워딩하는지 확인하세요."
		case "NetworkUnreachable":
			return "1) 노드의 CNI 플러그인(Calico, Cilium) 상태와 Pod CIDR 라우팅을 점검하세요. 2) 외부 통신 시 NAT 게이트웨이 또는 Egress Gateway 라우팅 상태를 확인하세요."
		case "EphemeralPortExhaustion":
			return "1) HTTP 커넥션 풀(Keep-Alive)을 적용하여 소켓 재사용률을 높이세요. 2) 노드 sysctl 설정을 확장하세요:\n```bash\nsysctl -w net.ipv4.ip_local_port_range=\"1024 65535\"\nsysctl -w net.ipv4.tcp_tw_reuse=1\n```"
		case "TLSUntrustedCA":
			return "1) 사설 루트 CA 인증서를 ConfigMap으로 생성하고 컨테이너의 '/etc/ssl/certs' 또는 Java 'cacerts'에 마운트하세요. 2) Dockerfile에서 'update-ca-certificates'를 실행하도록 설정하세요."
		case "TLSCertificateExpired":
			return "1) 대상 서버의 만료된 TLS 인증서를 즉시 갱신하세요 ('cert-manager renew' 등). 2) 노드의 NTP 데몬(chrony, systemd-timesyncd)을 점검하여 시스템 시계를 동기화하세요."
		case "TLSHostnameMismatch":
			return "1) 'openssl s_client -connect <host>:<port> -servername <host>' 명령으로 서버 인증서의 SAN 목록을 점검하세요. 2) IP 주소 대신 인증서에 등록된 올바른 FQDN 도메인명으로 접속하세요."
		case "TLSClientCertRequired":
			return "1) 클라이언트 설정에 유효한 mTLS 클라이언트 인증서(cert.pem)와 개인키(key.pem)를 등록하세요. 2) Istio PeerAuthentication 모드를 점검하세요."
		case "ProxyAuthenticationRequired":
			return "1) HTTP_PROXY 또는 HTTPS_PROXY 환경변수에 프록시 인증 계정 정보를 포함하세요 (예: 'http://username:password@proxy.internal:3128'). 2) Squid 프록시의 'auth_param basic' 설정을 확인하세요."
		case "ProxyAccessDeniedACL":
			return "1) Squid의 'squid.conf'에서 클라이언트 소스 IP 대역 또는 대상 도메인에 대한 허용 규칙을 추가하세요:\n```ini\nacl my_k8s_cluster src 10.244.0.0/16\nhttp_access allow my_k8s_cluster\n```\n2) 'squid -k reconfigure'를 실행하여 설정을 갱신하세요."
		case "ProxyConnectTunnelFailed":
			return "1) Squid 설정에 대상 서비스의 포트를 허용 목록으로 추가하세요:\n```ini\nacl SSL_ports port 8443 9443 6443\nacl Safe_ports port 8443 9443 6443\n```\n2) 'http_access deny !Safe_ports' 거부 규칙 순서를 확인하세요."
		case "ProxyDNSResolutionFailed":
			return "1) Squid 프록시 서버의 '/etc/resolv.conf' 네임서버 및 외부 인터넷 DNS 질의 연결성을 점검하세요. 2) 요청 URL의 호스트명 오탈자를 확인하세요."
		case "ProxyGatewayTimeout":
			return "1) Squid 설정의 'read_timeout'(기본 15분) 및 'connect_timeout'을 환경에 맞게 늘리세요. 2) 목적지 서버의 데이터베이스 쿼리 및 애플리케이션 지연을 최적화하세요."
		case "MySQLTooManyConnections":
			return "1) MySQL 'max_connections' 설정을 상향하거나 클라우드 파라미터 그룹을 증설하세요:\n```sql\nSET GLOBAL max_connections = 500;\n```\n2) 각 파드의 커넥션 풀 크기(HikariCP maximum-pool-size, SQLAlchemy pool_size)를 파드 복제본 수에 맞게 제한하고 커넥션 누수를 점검하세요."
		case "MySQLDeadlock":
			return "1) 복수 테이블/행 갱신 시 접근 순서를 일관되게 정렬(ORDER BY ID)하여 순환 락 대기를 방지하세요. 2) 트랜잭션 범위를 최소화하고 적절한 인덱스를 추가하세요. 3) 데드락 발생 시 Spring @Retryable(CannotAcquireLockException.class) 또는 retry 데코레이터를 적용하세요."
		case "MySQLCommunicationsLinkFailure":
			return "1) 커넥션 풀의 maxLifetime 및 idleTimeout을 MySQL의 'wait_timeout'(기본 28800초, 클라우드 권장 300~600초)보다 최소 30초 짧게 설정하세요. 2) connection-test-query('SELECT 1') 또는 keep-alive 유효성 검증을 활성화하세요."
		case "PostgresTooManyConnections":
			return "1) PgBouncer 또는 Odyssey 커넥션 풀러를 도입하여 연결을 멀티플렉싱하세요. 2) 'postgresql.conf'의 'max_connections'를 상향 조정하고 파드별 max_connections 할당량을 축소하세요."
		case "PostgresDeadlock":
			return "1) 여러 레코드를 수정할 때 항상 기본키(PK) 순으로 정렬하여 락을 획득하도록 쿼리를 수정하세요. 2) 'SELECT FOR UPDATE' 대상 레코드 범위를 축소하고 트랜잭션 보유 시간을 최소화하세요."
		case "PostgresInFailedSQLTransaction":
			return "1) 트랜잭션 블록 내에서 쿼리 오류 발생 시 즉시 명시적 ROLLBACK을 수행하거나 세이브포인트(SAVEPOINT)를 활용하세요. 2) ORM 트랜잭션 컨텍스트 매니저 바운더리 및 예외 처리 로직을 점검하세요."
		case "ClickHouseSimultaneousQueries":
			return "1) ClickHouse 서버 config.xml의 'max_concurrent_queries'(기본 100)를 상향하세요. 2) 클라이언트 측에서 쿼리를 배치로 묶거나 작업 큐를 도입하여 동시 요청 수를 조절하세요."
		case "BigQueryPartitionFilterRequired":
			return "1) 쿼리의 WHERE 절에 대상 테이블의 파티션 컬럼(예: _PARTITIONDATE, _PARTITIONTIME 또는 일자/타임스탬프 필드) 조건을 반드시 포함하세요."
		case "BigQueryBytesBilledLimitExceeded":
			return "1) 쿼리 작업 옵션의 'maximum_bytes_billed' 한도를 상향하거나 쿼리에 파티션/클러스터링 필터를 추가하여 스캔 용량을 줄이세요. 2) 'SELECT *' 대신 필요한 컬럼만 명시하세요."
		default:
			return "직전 컨테이너 로그 및 종료 코드를 확인하여 애플리케이션 설정 및 파드 리소스 사양을 점검하세요."
		}
	}

	// English default
	switch inc.RootCause {
	case "GracefulShutdownTimeout":
		return "1) Optimize SIGTERM handler to drain connections faster. 2) Increase terminationGracePeriodSeconds in pod spec (default 30s) to allow adequate drain time."
	case "ReadOnlyRootFilesystem", "ReadOnlyFilesystemError":
		return "1) Inspect readOnlyRootFilesystem in pod securityContext. 2) Mount emptyDir volumes for writable locations such as /tmp."
	case "HeapCorruption":
		return "1) Inspect native C/C++ extensions or JNI/CGO memory management. 2) Debug double free / memory overwrites using AddressSanitizer (ASan)."
	case "NodeV8FatalError":
		return "1) Increase '--max-old-space-size' in NODE_OPTIONS. 2) Profile heap snapshots for unbounded object caching leaks."
	case "SidecarCascadeFailure":
		return "1) Check logs of peer sidecars (istio-proxy, proxy). 2) Adopt K8s 1.28+ native sidecar containers to guarantee startup ordering."
	case "InitContainerFailed":
		return "1) Inspect logs of the failed initContainer (kubectl logs <pod> -c <init-name>). 2) Verify migration prerequisites."
	case "OOMKilled", "ProbableOOMKilled", "SystemOOMKilled":
		return "1) Increase pod memory limit (resources.limits.memory). 2) Tune JVM -Xmx to remain at least 250MB below the container limit."
	case "LivenessProbeFailure":
		return "1) Adjust probe timeoutSeconds and failureThreshold. 2) Ensure health check endpoint does not block on slow downstream dependencies."
	case "GoPanic", "GoNilPointerDereference":
		if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
			return fmt.Sprintf("Inspect %s:%d for nil pointer or slice index out-of-range, and guard with nil checks or defer recover().", inc.CulpritCode.File, inc.CulpritCode.Line)
		}
		return "Implement top-level defer recover() to prevent unexpected panics from terminating the process."
	case "JVMHeapOOM":
		return "1) Increase -Xmx heap limit or pod memory limit. 2) Enable -XX:+HeapDumpOnOutOfMemoryError to inspect memory leak candidates."
	case "PythonUnhandledException", "AppUnhandledException":
		errName := inc.ErrorClass
		if errName == "" || errName == "PythonException" {
			errName = "Exception"
		}
		locStr := ""
		if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
			locStr = fmt.Sprintf("[%s:%d] ", inc.CulpritCode.File, inc.CulpritCode.Line)
		}
		return fmt.Sprintf("1) Wrap %scritical logic in try-except %s block with fallback or retry logic. 2) Implement strict input schema validation to prevent invalid payloads from triggering unhandled crashes.", locStr, errName)
	case "CircularImportError":
		return "1) Move circular import inside function scope, 2) use 'if typing.TYPE_CHECKING:' for type annotations, or 3) refactor shared models into a separate module."
	case "SpringCircularDependency":
		return "1) Add '@Lazy' on the injected dependency, 2) extract shared logic into a third service bean, or 3) set 'spring.main.allow-circular-references: true' in application.yml."
	case "LazyInitializationException":
		return "1) Use 'JOIN FETCH' in JPQL queries, 2) apply '@EntityGraph', or 3) keep persistence session open with '@Transactional(readOnly = true)'."
	case "TransientPropertyValueException":
		return "1) Add 'cascade = CascadeType.ALL' or 'CascadeType.PERSIST' to relation mapping, or 2) persist child entity before saving parent."
	case "NodeTypeError":
		return "1) Use optional chaining (obj?.prop) before property access, 2) add null/undefined checks before calling methods."
	case "NodeUnhandledPromiseRejection":
		return "1) Ensure all async functions are awaited inside try/catch blocks, 2) attach '.catch()' handlers to all Promises."
	case "NodeESMMismatch":
		return "1) Set '\"type\": \"module\"' in package.json, 2) rename CommonJS files to '.cjs', or 3) set 'moduleResolution: NodeNext' in tsconfig.json."
	case "NodePrismaError", "NodePrismaInitFailed":
		return "1) Use prisma.model.upsert() for unique constraint violations, 2) verify DATABASE_URL and Kubernetes cluster DNS."
	case "EnvoyNoHealthyUpstream":
		return "1) Verify target pods are in Ready state ('kubectl get endpoints <service>'). 2) Check DestinationRule outlierDetection settings."
	case "EnvoyCircuitBreakerOverflow":
		return "1) Enlarge DestinationRule connectionPool maxConnections and maxPendingRequests. 2) Scale out backend replicas via HPA."
	case "EnvoyUpstreamConnectionFailure":
		return "1) Verify backend pod listening port matches Service targetPort. 2) Inspect NetworkPolicy ingress rules."
	case "EnvoyNoRouteConfigured":
		return "1) Check VirtualService hosts and HTTP route match rules against request Host and URI. 2) Verify gateway bindings."
	case "EnvoyTLSHandshakeFailed":
		return "1) Verify DestinationRule tls.mode (ISTIO_MUTUAL vs DISABLE) matches upstream capabilities. 2) Check upstream TLS certificates."
	case "EnvoyUpstreamTimeout":
		return "1) Increase timeout in VirtualService (e.g. 'timeout: 30s'). 2) Profile and optimize upstream database queries and processing latency."
	case "NginxConfigSyntaxError":
		return "1) Check Ingress configuration-snippet annotations for missing semicolons or syntax typos. 2) Review Ingress controller logs for error line numbers."
	case "NginxClientBodySizeExceeded":
		return "1) Add annotation 'nginx.ingress.kubernetes.io/proxy-body-size: \"50m\"' to your Ingress definition."
	case "IstioProxyNotReady":
		return "1) Check istiod control plane health ('istioctl proxy-status'). 2) Increase CPU and memory limits on istio-proxy container."
	case "IstioStartupRaceCondition":
		return "1) Add annotation 'proxy.istio.io/config: holdApplicationUntilProxyStarts: true' to the pod. 2) Migrate to K8s 1.28+ native sidecar containers."
	case "IstioStrictMTLSMismatch":
		return "1) Label client namespace with 'istio-injection=enabled'. 2) Or change PeerAuthentication mode to PERMISSIVE for backward compatibility."
	case "EnvoyGatewayTranslationFailed":
		return "1) Check Gateway API HTTPRoute backendRefs service and port. 2) For cross-namespace backends, create a ReferenceGrant."
	case "VaultSealedFailure":
		return "1) Unseal Vault instance using 'vault operator unseal' with key shares. 2) Enable auto-unseal via cloud KMS for production."
	case "VaultTokenExpired":
		return "1) Inspect Vault role token_ttl and token_max_ttl. 2) Verify Kubernetes ServiceAccount token auto-renewal in Vault Agent."
	case "CoreDNSLoopDetected":
		return "1) Remove local loopback (127.0.0.53/127.0.0.1) from worker node /etc/resolv.conf and specify upstream DNS (8.8.8.8). 2) Pass --resolv-conf to kubelet."
	case "CertManagerWebhookFailure":
		return "1) Check cert-manager-webhook pod status and logs. 2) Ensure ports 10250, 6443, 9443 are allowed between API server and worker nodes."
	case "ACMERateLimitExceeded":
		return "1) Switch to Let's Encrypt Staging API issuer (acme-staging-v02) for non-production environments. 2) Reuse existing certificate secrets across deployments."
	case "PrometheusWALCorruption":
		return "1) Enable '--storage.tsdb.wal-compression'. 2) Remove corrupted WAL segments or restore from volume snapshot."
	case "PrometheusCardinalityOOM":
		return "1) Drop high-cardinality labels (userId, guid) using metric_relabel_configs with 'action: labeldrop'. 2) Increase Prometheus pod memory limit."
	case "FluentBitBufferExhaustion":
		return "1) Enable persistent disk buffering with 'storage.type filesystem' and 'storage.buffering on'. 2) Resolve downstream destination ingestion bottlenecks."
	case "ElasticsearchDiskFloodStage":
		return "1) Expand disk storage volume and clean up old indices. 2) Reset index read-only block with 'curl -X PUT \"localhost:9200/*/_settings\" -d '{\"index.blocks.read_only_allow_delete\": null}''."
	case "ElasticsearchCircuitBreaker":
		return "1) Increase ES_JAVA_OPTS heap size (up to 31GB). 2) Tune indices.breaker.total.use_real_memory and limit heavy aggregations."
	case "PatroniLeaderLeaseLost":
		return "1) Verify etcd fsync latency and DCS network connectivity. 2) Tune Patroni 'ttl' and 'loop_wait' parameters."
	case "PostgresWALDiskFull":
		return "1) Drop inactive replication slots using 'SELECT pg_drop_replication_slot()'. 2) Check archive_command status and expand disk storage."
	case "ArgoCDRepoServerOOM":
		return "1) Increase memory limit on argocd-repo-server (recommend >= 2GiB-4GiB). 2) Set ARGOCD_EXEC_TIMEOUT and decompose large charts."
	case "GitRateLimitExceeded":
		return "1) Configure GitHub App or Personal Access Token (PAT) with higher API quotas in Argo CD repository credentials. 2) Switch to webhook notifications instead of polling."
	case "GCPAuthDefaultCredentialsMissing":
		return "1) Mount a GCP service account JSON key and set GOOGLE_APPLICATION_CREDENTIALS. 2) For GKE Workload Identity, verify the ServiceAccount annotation 'iam.gke.io/gcp-service-account'."
	case "GCPGeminiQuotaExceeded":
		return "1) Request a quota increase for Gemini API (TPM, RPM) in Google Cloud Console. 2) Implement exponential backoff retry logic or route requests through LiteLLM."
	case "GCPGeminiSafetyBlocked":
		return "1) Adjust Gemini safetySettings thresholds (e.g. BLOCK_ONLY_HIGH). 2) Sanitize and filter prompt inputs."
	case "GCPBigQueryQuotaExceeded":
		return "1) Increase 'maximum_bytes_billed' in query configuration or optimize query with partition/cluster filters. 2) Inspect BigQuery slot reservations."
	case "GCPStorageAccessDenied":
		return "1) Grant 'roles/storage.objectViewer' or 'roles/storage.objectAdmin' to the service account. 2) Verify bucket Uniform Bucket-Level Access."
	case "ClickHouseTooManyParts":
		return "1) Batch inserts into larger chunks (10,000+ rows) or adopt the Buffer table engine. 2) Tune parts_to_throw_insert in ClickHouse merge tree settings."
	case "ClickHouseMemoryLimit":
		return "1) Increase max_server_memory_usage in ClickHouse users.xml and increase pod memory. 2) Enable 'max_bytes_before_external_group_by' for spill-to-disk queries."
	case "ClickHouseZooKeeperSessionLost":
		return "1) Check ZooKeeper cluster status and network latency. 2) Increase session_timeout_ms in ClickHouse zookeeper configuration."
	case "ZooKeeperDiskFull":
		return "1) Expand ZooKeeper storage volume PVC. 2) Enable automatic purge with autopurge.purgeInterval=1 and autopurge.snapRetainCount=3 in zoo.cfg."
	case "ZooKeeperQuorumLost":
		return "1) Ensure a majority (N/2 + 1) of ZooKeeper nodes are healthy. 2) Verify ports 2888 (peer) and 3888 (leader election) are reachable."
	case "ValkeyOOM":
		return "1) Increase 'maxmemory' in valkey.conf or increase pod memory limit. 2) Configure eviction policy (e.g. maxmemory-policy allkeys-lru)."
	case "PostgresTxidExhaustion":
		return "1) Enter single-user mode immediately ('postgres --single') and run 'VACUUM FREEZE ANALYZE'. 2) Tune autovacuum_freeze_max_age."
	case "JenkinsDiskSpaceExhausted":
		return "1) Expand Jenkins home/workspace PVC volume. 2) Add 'cleanWs()' in pipeline post-actions or prune old build histories."
	case "ArgoWorkflowDeadlineExceeded":
		return "1) Increase 'activeDeadlineSeconds' in the workflow template. 2) Profile task execution for slow I/O or deadlocks."
	case "ArgoRolloutAnalysisFailed":
		return "1) Inspect Prometheus queries in the AnalysisTemplate. 2) Review recent application error logs from canary pods to fix bugs."
	case "KyvernoAdmissionPolicyViolation":
		return "1) Update pod spec to satisfy the violated Kyverno ClusterPolicy (e.g. securityContext, image tags). 2) Run 'kubectl get cpol' to inspect active policies."
	case "KyvernoWebhookTimeout":
		return "1) Check kyverno controller pod resource usage and health. 2) Verify port 9443 connectivity and webhook TLS secret validity."
	case "GatekeeperConstraintViolation":
		return "1) Update resource manifest to comply with the Gatekeeper constraint rules. 2) Run 'kubectl get constraints' to view violations."
	case "SecretProviderClassNotFound":
		return "1) Ensure SecretProviderClass exists in the same namespace as the pod. 2) Check secretProviderClass name spelling in volume spec."
	case "NFSMountAccessDenied":
		return "1) Check '/etc/exports' on NFS server for worker node CIDR and 'no_root_squash'. 2) Reload exports with 'exportfs -rav'."
	case "NFSConnectionTimeout":
		return "1) Verify NFS server host is running. 2) Ensure firewall permits TCP/UDP ports 2049 (NFS) and 111 (rpcbind)."
	case "MetricsServerKubeletScrapeFailed":
		return "1) Add '--kubelet-insecure-tls' to metrics-server container args for self-signed Kubelet certificates. 2) Open port 10250 between control plane and worker nodes."
	case "LiteLLMRateLimitExceeded":
		return "1) Configure model fallbacks in LiteLLM config.yaml. 2) Enable Redis/Valkey response caching in LiteLLM to reduce upstream load."
	case "LiteLLMBudgetExceeded":
		return "1) Increase or reset 'max_budget' for the user/key via LiteLLM Admin API or UI. 2) Verify budget reset duration settings."
	case "LiteLLMContextWindowExceeded":
		return "1) Truncate or summarize prompt history to fit within the context window. 2) Switch to a larger context window model."
	case "TCPConnectionReset":
		return "1) Check if remote service pod crashed unexpectedly (OOM/segfault). 2) Ensure load balancer idle timeout exceeds client keep-alive duration."
	case "TCPConnectionRefused":
		return "1) Verify destination pod is running and listening on the target port ('kubectl get endpoints <svc>'). 2) Check Service targetPort mapping."
	case "TCPConnectionTimeout":
		return "1) Inspect NetworkPolicy ingress rules and cloud security groups for dropped SYN packets. 2) Check VPC route table health."
	case "NetworkUnreachable":
		return "1) Check node CNI plugin health (Calico, Cilium) and pod CIDR routes. 2) Verify NAT Gateway status for outbound internet traffic."
	case "EphemeralPortExhaustion":
		return "1) Implement HTTP connection pooling with keep-alive. 2) Expand sysctl: 'sysctl -w net.ipv4.ip_local_port_range=\"1024 65535\"' and 'net.ipv4.tcp_tw_reuse=1'."
	case "TLSUntrustedCA":
		return "1) Mount private root CA certificate into container trust store (/etc/ssl/certs or Java cacerts). 2) Run 'update-ca-certificates' in Dockerfile."
	case "TLSCertificateExpired":
		return "1) Renew the expired TLS certificate on the target server ('cert-manager renew'). 2) Verify node clock synchronization via NTP."
	case "TLSHostnameMismatch":
		return "1) Verify certificate SAN with 'openssl s_client -connect <host>:<port>'. 2) Connect via valid FQDN domain name rather than raw IP."
	case "TLSClientCertRequired":
		return "1) Supply valid mTLS client certificate and private key in client request options. 2) Check Istio PeerAuthentication mode."
	case "ProxyAuthenticationRequired":
		return "1) Add proxy credentials to HTTP_PROXY/HTTPS_PROXY environment variables (http://user:pass@proxy:3128). 2) Check Squid auth_param configuration."
	case "ProxyAccessDeniedACL":
		return "1) Add 'http_access allow' rule for client IP or destination domain in squid.conf. 2) Run 'squid -k reconfigure' to apply changes."
	case "ProxyConnectTunnelFailed":
		return "1) Add target port to 'SSL_ports' and 'Safe_ports' in squid.conf. 2) Review the '!Safe_ports' denial rule ordering."
	case "ProxyDNSResolutionFailed":
		return "1) Inspect /etc/resolv.conf and upstream DNS connectivity on the Squid proxy host. 2) Check destination hostname spelling."
	case "ProxyGatewayTimeout":
		return "1) Increase 'read_timeout' and 'connect_timeout' in squid.conf. 2) Optimize upstream server processing latency."
	case "MySQLTooManyConnections":
		return "1) Increase max_connections in MySQL / RDS parameter group. 2) Limit client connection pool maximum sizes per pod."
	case "MySQLDeadlock":
		return "1) Access rows in consistent order across transactions to prevent lock cycles. 2) Shorten transaction scope and implement automatic retries."
	case "MySQLCommunicationsLinkFailure":
		return "1) Set connection pool maxLifetime shorter than MySQL wait_timeout. 2) Enable validation query ('SELECT 1') before socket reuse."
	case "PostgresTooManyConnections":
		return "1) Deploy PgBouncer or Odyssey connection pooler. 2) Increase max_connections in postgresql.conf and reduce pool sizes."
	case "PostgresDeadlock":
		return "1) Sort rows by primary key before updating to acquire locks in consistent order. 2) Reduce SELECT FOR UPDATE lock scope."
	case "PostgresInFailedSQLTransaction":
		return "1) Issue explicit ROLLBACK or use SAVEPOINT upon catching errors within a transaction block. 2) Fix transaction manager boundary."
	case "ClickHouseSimultaneousQueries":
		return "1) Increase 'max_concurrent_queries' in ClickHouse config.xml. 2) Batch client queries or queue them to throttle concurrency."
	case "BigQueryPartitionFilterRequired":
		return "1) Include partition column (_PARTITIONDATE or timestamp column) conditions in the WHERE clause."
	case "BigQueryBytesBilledLimitExceeded":
		return "1) Increase maximum_bytes_billed in job configuration or filter on partitioned and clustered columns. 2) Avoid SELECT *."
	default:
		return "Inspect previous container logs and verify pod resource limits and application configurations."
	}
}
