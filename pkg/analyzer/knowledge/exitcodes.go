package knowledge

import "fmt"

// ExitCodeInfo provides diagnostic metadata for known exit codes.
type ExitCodeInfo struct {
	ExitCode      int
	Name          string
	Category      string
	DescriptionKo string
	ActionKo      string
	DescriptionEn string
	ActionEn      string
}

var CommonExitCodes = map[int]ExitCodeInfo{
	0: {
		ExitCode:      0,
		Name:          "Success / Completed",
		Category:      "Application",
		DescriptionKo: "프로세스가 에러 없이 정상 종료(0)되었습니다. 데몬이나 백엔드 서버가 백그라운드로 분기되어 포그라운드 프로세스가 끝났을 수 있습니다.",
		ActionKo:      "컨테이너 메인 엔트리포인트가 포그라운드에서 유지되도록 실행 플래그를 확인하십시오 (예: daemon off; 설정).",
		DescriptionEn: "Process completed successfully with exit code 0. Container may have terminated because the command completed or detached.",
		ActionEn:      "Ensure entrypoint command runs in foreground without exiting immediately (e.g. daemon off;).",
	},
	1: {
		ExitCode:      1,
		Name:          "General Application Error",
		Category:      "Application",
		DescriptionKo: "애플리케이션 런타임에서 일반적인 처리되지 않은 예외(Unhandled Exception) 또는 fatal 오류가 발생했습니다.",
		ActionKo:      "컨테이너 표준 에러(stderr) 로그에서 언어별 스택 트레이스를 점검하십시오.",
		DescriptionEn: "Application exited with generic error status 1 due to unhandled exceptions or fatal logic errors.",
		ActionEn:      "Check container stderr logs for stack traces and unhandled exception details.",
	},
	2: {
		ExitCode:      2,
		Name:          "Misuse of Shell Builtins / Fatal Panic",
		Category:      "Application",
		DescriptionKo: "셸 내장 명령어 오용 또는 Go 런타임 패닉(Go Panic) 등의 치명적인 런타임 중단이 발생했습니다.",
		ActionKo:      "Go 런타임 패닉 또는 셸 스크립트 문법 오류 여부를 컨테이너 로그에서 확인하십시오.",
		DescriptionEn: "Shell builtin syntax error or fatal runtime panic (e.g., Golang unhandled panic).",
		ActionEn:      "Check logs for Golang panic stack traces or script syntax errors.",
	},
	125: {
		ExitCode:      125,
		Name:          "Container Runtime Failure",
		Category:      "Infrastructure",
		DescriptionKo: "컨테이너 런타임(containerd / CRI-O)이 컨테이너를 구동하지 못했습니다 (docker run 실패 등).",
		ActionKo:      "노드 Kubelet 로그 및 containerd 데몬 상태를 점검하십시오.",
		DescriptionEn: "Container runtime failed to launch the container command.",
		ActionEn:      "Inspect node kubelet and containerd daemon logs for runtime errors.",
	},
	126: {
		ExitCode:      126,
		Name:          "Command Invoked Cannot Execute (Permission Denied)",
		Category:      "Configuration",
		DescriptionKo: "컨테이너 진입점(Entrypoint) 바이너리 또는 스크립트에 실행 권한(chmod +x)이 없습니다.",
		ActionKo:      "Dockerfile에서 실행 파일에 'chmod +x' 권한을 부여하거나 SecurityContext 설정을 점검하십시오.",
		DescriptionEn: "Container entrypoint binary or script lacks execution permissions (chmod +x).",
		ActionEn:      "Add execute permissions to the entrypoint script in Dockerfile or verify securityContext.",
	},
	127: {
		ExitCode:      127,
		Name:          "Command Not Found",
		Category:      "Configuration",
		DescriptionKo: "지정된 진입점 명령어 또는 실행 파일이 컨테이너 이미지 $PATH 내에 존재하지 않습니다.",
		ActionKo:      "Dockerfile의 CMD/ENTRYPOINT 경로를 확인하고, Alpine 등의 경량 이미지에서 필요한 셸(/bin/bash, /bin/sh)이 설치되어 있는지 확인하십시오.",
		DescriptionEn: "Specified command or executable was not found in container filesystem $PATH.",
		ActionEn:      "Verify entrypoint path in Dockerfile and ensure required shell or glibc/musl binaries exist in image.",
	},
	128: {
		ExitCode:      128,
		Name:          "Invalid Exit Argument",
		Category:      "Configuration",
		DescriptionKo: "프로세스가 0~255 범위를 벗어난 유효하지 않은 종료 코드로 exit()를 호출했습니다.",
		ActionKo:      "애플리케이션 종료 처리 코드에서 exit() 인자값을 확인하십시오.",
		DescriptionEn: "Process called exit() with an invalid argument outside the 0-255 range.",
		ActionEn:      "Check application termination code for invalid exit arguments.",
	},
	255: {
		ExitCode:      255,
		Name:          "Fatal Exit Code Out Of Range",
		Category:      "Application",
		DescriptionKo: "치명적인 예외로 인해 프로세스가 255 상태로 비정상 종료되었습니다 (SSH/bash 종료 코드 등).",
		ActionKo:      "컨테이너 표준 오류 로그에서 원인 예외를 확인하십시오.",
		DescriptionEn: "Process exited with status 255, commonly triggered by fatal script or SSH command errors.",
		ActionEn:      "Inspect container stderr logs for root cause exceptions.",
	},
}

// LookupExitCode retrieves diagnostic details for known exit codes.
func LookupExitCode(code int) (ExitCodeInfo, bool) {
	info, ok := CommonExitCodes[code]
	if ok {
		return info, true
	}
	if sigInfo, isSig := LookupSignalByExitCode(code); isSig {
		return ExitCodeInfo{
			ExitCode:      code,
			Name:          sigInfo.SignalName,
			Category:      "Infrastructure",
			DescriptionKo: sigInfo.DescriptionKo,
			ActionKo:      sigInfo.ActionKo,
			DescriptionEn: sigInfo.DescriptionEn,
			ActionEn:      sigInfo.ActionEn,
		}, true
	}
	return ExitCodeInfo{
		ExitCode:      code,
		Name:          fmt.Sprintf("ExitCode_%d", code),
		Category:      "Unknown",
		DescriptionKo: fmt.Sprintf("분류되지 않은 종료 코드 %d로 프로세스가 종료되었습니다.", code),
		ActionKo:      fmt.Sprintf("해당 애플리케이션의 문서에서 종료 코드 %d의 의미를 확인하십시오.", code),
		DescriptionEn: fmt.Sprintf("Process exited with unclassified exit code %d.", code),
		ActionEn:      fmt.Sprintf("Consult application documentation for exit code %d definition.", code),
	}, false
}
