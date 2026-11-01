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
		case "PostgresMaxConnections", "MySQLTooManyConnections":
			steps = append(steps, "클라이언트 연결 수가 데이터베이스 서버의 max_connections 한도에 도달함")
			steps = append(steps, "신규 연결 요청이 거부됨 (FATAL / ERROR 1040)")
			steps = append(steps, "애플리케이션이 DB 연결 실패로 인해 크래시되거나 헬스체크에 실패함")
		case "PostgresDeadlock", "MySQLDeadlock":
			steps = append(steps, "동시 실행 중인 트랜잭션들이 서로 다른 순서로 데이터 락을 획득함")
			steps = append(steps, "데이터베이스 엔진의 데드락 탐지기가 교착 상태를 감지함")
			steps = append(steps, "트랜잭션이 롤백되고 애플리케이션 예외로 전파됨")
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
		case "PostgresMaxConnections", "MySQLTooManyConnections":
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
		case "PostgresMaxConnections", "MySQLTooManyConnections":
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
	default:
		return "Inspect previous container logs and verify pod resource limits and application configurations."
	}
}
