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
	default:
		return "Inspect previous container logs and verify pod resource limits and application configurations."
	}
}
