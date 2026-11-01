package knowledge

import (
	"fmt"
)

// SignalInfo provides comprehensive details regarding POSIX signals and their container termination semantics.
type SignalInfo struct {
	SignalNumber int
	SignalName   string
	ExitCode     int
	Description  string
	KernelReason string
	DescriptionKo string
	ActionKo      string
	DescriptionEn string
	ActionEn      string
}

// PosixSignals maps signal numbers (1..31) to their respective diagnostic metadata.
var PosixSignals = map[int]SignalInfo{
	1: {
		SignalNumber: 1,
		SignalName:   "SIGHUP",
		ExitCode:     129,
		Description:  "Hangup detected on controlling terminal or death of controlling process",
		KernelReason: "Controlling terminal disconnected or parent process terminated without forwarding signals.",
		DescriptionKo: "제어 터미널이 분리되었거나 상위 프로세스가 종료되어 SIGHUP(129) 신호를 수신했습니다.",
		ActionKo:      "컨테이너 진입점 프로세스가 데몬 모드로 전환되지 않도록 foreground 실행 설정을 확인하십시오.",
		DescriptionEn: "Process received SIGHUP (Exit code 129) due to terminal disconnect or parent process termination.",
		ActionEn:      "Ensure container entrypoint runs in the foreground without detaching from PID 1.",
	},
	2: {
		SignalNumber: 2,
		SignalName:   "SIGINT",
		ExitCode:     130,
		Description:  "Terminal interrupt signal (Ctrl+C)",
		KernelReason: "Interactive terminal interrupt requested.",
		DescriptionKo: "인터럽트 신호 SIGINT(130)에 의해 프로세스가 중단되었습니다.",
		ActionKo:      "수동 인터럽트 또는 테스트 러너의 강제 중단 신호 여부를 확인하십시오.",
		DescriptionEn: "Process interrupted by SIGINT (Exit code 130).",
		ActionEn:      "Check if an interactive interrupt or automated test harness sent a break command.",
	},
	3: {
		SignalNumber: 3,
		SignalName:   "SIGQUIT",
		ExitCode:     131,
		Description:  "Terminal quit signal with core dump request",
		KernelReason: "Quit signal issued, typically with core dump generation.",
		DescriptionKo: "SIGQUIT(131) 신호로 인해 프로세스가 종료되었습니다 (코어 덤프 요청).",
		ActionKo:      "디버거 또는 스택 덤프 분석을 위한 종료 요청 여부를 확인하십시오.",
		DescriptionEn: "Process terminated with SIGQUIT (Exit code 131) requesting core dump.",
		ActionEn:      "Inspect debug traces or core dumps generated during shutdown.",
	},
	4: {
		SignalNumber: 4,
		SignalName:   "SIGILL",
		ExitCode:     132,
		Description:  "Illegal Instruction",
		KernelReason: "CPU executed an invalid machine instruction (e.g. unsupported AVX/SSE on host CPU).",
		DescriptionKo: "CPU가 유효하지 않은 기계어 명령어를 실행하여 SIGILL(132) 오류로 종료되었습니다 (AVX/SSE 지원 불일치 등).",
		ActionKo:      "컨테이너 이미지 컴파일 시 호스트 노드 CPU 아키텍처(AVX2/AVX-512)와 호환되도록 빌드 옵션을 조정하십시오.",
		DescriptionEn: "Illegal instruction executed (SIGILL, Exit code 132), often caused by CPU microarchitecture mismatch (e.g. AVX/AVX2).",
		ActionEn:      "Compile the binary with target CPU architecture flags compatible with all cluster worker nodes.",
	},
	6: {
		SignalNumber: 6,
		SignalName:   "SIGABRT",
		ExitCode:     134,
		Description:  "Process aborted by abort() or assertion failure",
		KernelReason: "Application or native glibc called abort() due to an unrecoverable assertion failure.",
		DescriptionKo: "프로세스가 abort() 함수를 호출하거나 네이티브 라이브러리(glibc) 어설션 실패로 강제 중단되었습니다 (SIGABRT, 134).",
		ActionKo:      "로그 내 C/C++ 네이티브 스택 트레이스나 힙 손상(double free, corruption) 메시지를 점검하십시오.",
		DescriptionEn: "Process aborted via SIGABRT (Exit code 134) typically from native assertions or memory corruption.",
		ActionEn:      "Inspect logs for glibc assertion failures, double-free errors, or native library panics.",
	},
	7: {
		SignalNumber: 7,
		SignalName:   "SIGBUS",
		ExitCode:     135,
		Description:  "Bus error (bad memory access)",
		KernelReason: "Hardware bus error, misaligned memory access, or truncated mmap shared file.",
		DescriptionKo: "물리적 버스 오류 또는 파일 mmap 영역 절삭(Truncate)으로 인해 유효하지 않은 메모리 접근(SIGBUS, 135)이 발생했습니다.",
		ActionKo:      "볼륨 마운트된 공유 메모리(/dev/shm) 크기 부족 또는 실행 중 바이너리 파일 덮어쓰기 여부를 확인하십시오.",
		DescriptionEn: "Process terminated by SIGBUS (Exit code 135) due to invalid memory alignment or truncated mmap backing file.",
		ActionEn:      "Check shared memory size (/dev/shm) or verify files mmapped into memory were not truncated.",
	},
	8: {
		SignalNumber: 8,
		SignalName:   "SIGFPE",
		ExitCode:     136,
		Description:  "Floating point exception (division by zero or overflow)",
		KernelReason: "Arithmetic error in CPU execution unit.",
		DescriptionKo: "0으로 나누기(Division by zero) 또는 부동소수점 오버플로우로 인해 SIGFPE(136) 예외가 발생했습니다.",
		ActionKo:      "수학 연산 코드의 0 나눗셈 예외 처리 및 정수/부동소수점 오버플로우 방어 로직을 추가하십시오.",
		DescriptionEn: "Floating point exception (SIGFPE, Exit code 136) caused by zero division or numeric overflow.",
		ActionEn:      "Add defensive guards against division by zero in application arithmetic routines.",
	},
	9: {
		SignalNumber: 9,
		SignalName:   "SIGKILL",
		ExitCode:     137,
		Description:  "Forced termination by kernel or orchestration",
		KernelReason: "Process killed immediately by Linux kernel (OOM Killer, cgroup limit, probe timeout, or forced eviction).",
		DescriptionKo: "Linux 커널 또는 오케스트레이터에 의해 프로세스가 즉시 강제 사살되었습니다 (SIGKILL, 137).",
		ActionKo:      "cgroup OOMKilled 이벤트, Liveness Probe 실패 여부, 또는 terminationGracePeriod 초과 여부를 확인하십시오.",
		DescriptionEn: "Process forcibly killed by SIGKILL (Exit code 137) via cgroup OOM, probe failure, or deadline exceed.",
		ActionEn:      "Check cgroup OOM status, liveness probe timeouts, or terminationGracePeriodSeconds expiration.",
	},
	11: {
		SignalNumber: 11,
		SignalName:   "SIGSEGV",
		ExitCode:     139,
		Description:  "Segmentation fault (invalid memory reference)",
		KernelReason: "Attempted to access memory that was not allocated, read-only, or beyond process bounds.",
		DescriptionKo: "할당되지 않았거나 보호된 메모리 주소를 역참조하여 세그멘테이션 오류(SIGSEGV, 139)가 발생했습니다.",
		ActionKo:      "C/C++ 네이티브 라이브러리, JNI, CGO, 또는 잘못된 포인터 역참조 코드를 디버깅하십시오.",
		DescriptionEn: "Segmentation fault (SIGSEGV, Exit code 139) due to invalid pointer dereference or out-of-bounds memory access.",
		ActionEn:      "Debug native libraries (C/C++, JNI, CGO) for dangling pointers or buffer overruns.",
	},
	13: {
		SignalNumber: 13,
		SignalName:   "SIGPIPE",
		ExitCode:     141,
		Description:  "Broken pipe (write to pipe with no readers)",
		KernelReason: "Process attempted to write data to a closed socket, pipe, or FIFO.",
		DescriptionKo: "수신자가 닫힌 네트워크 소켓 또는 파이프에 데이터를 쓰려다 SIGPIPE(141) 신호로 중단되었습니다.",
		ActionKo:      "클라이언트 연결 조기 종료 시 소켓 write 에러(EPIPE)를 핸들링하도록 SIGPIPE 무시(SIG_IGN) 설정을 적용하십시오.",
		DescriptionEn: "Broken pipe (SIGPIPE, Exit code 141) caused by writing to a closed socket or pipe.",
		ActionEn:      "Handle EPIPE gracefully and ignore SIGPIPE on network sockets.",
	},
	15: {
		SignalNumber: 15,
		SignalName:   "SIGTERM",
		ExitCode:     143,
		Description:  "Polite termination request",
		KernelReason: "Kubernetes sent SIGTERM during pod scale down, deployment rollout, or node drain.",
		DescriptionKo: "배포 롤아웃, 오토스케일링 인하, 또는 노드 드레인 과정에서 쿠버네티스의 정상 종료 요청(SIGTERM, 143)을 수신했습니다.",
		ActionKo:      "예상치 못한 재시작인 경우 디플로이먼트 개정 내역 및 노드 유지보수 일정을 점검하십시오.",
		DescriptionEn: "Process gracefully terminated following SIGTERM (Exit code 143) from Kubernetes during pod lifecycle events.",
		ActionEn:      "Normal during rolling updates or pod deletion. Check deployment history if unexpected.",
	},
}

// LookupSignalByExitCode retrieves signal information if the exit code corresponds to 128 + N.
func LookupSignalByExitCode(exitCode int) (SignalInfo, bool) {
	if exitCode > 128 && exitCode < 165 {
		sigNum := exitCode - 128
		info, ok := PosixSignals[sigNum]
		if ok {
			return info, true
		}
		return SignalInfo{
			SignalNumber:  sigNum,
			SignalName:    fmt.Sprintf("SIG#%d", sigNum),
			ExitCode:      exitCode,
			Description:   fmt.Sprintf("Killed by signal %d", sigNum),
			KernelReason:  "Process terminated by external OS signal.",
			DescriptionKo: fmt.Sprintf("OS 시그널 %d(종료 코드 %d)에 의해 프로세스가 강제 종료되었습니다.", sigNum, exitCode),
			ActionKo:      "프로세스에 신호를 전송한 상위 데몬 또는 쿠버네티스 수명주기 이벤트를 확인하십시오.",
			DescriptionEn: fmt.Sprintf("Process terminated by OS signal %d (Exit code %d).", sigNum, exitCode),
			ActionEn:      "Check external monitors or orchestration hooks that sent this signal.",
		}, true
	}
	return SignalInfo{}, false
}
