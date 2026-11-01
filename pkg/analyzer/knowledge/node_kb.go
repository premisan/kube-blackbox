package knowledge

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
)

// NodeFrame represents a single stack frame from a Node.js V8 stack trace.
type NodeFrame struct {
	Function string
	File     string
	Line     int
	Column   int
	IsUser   bool
}

// NodeDeepAnalysis holds deep diagnostic findings extracted from Node.js / TypeScript logs.
type NodeDeepAnalysis struct {
	ErrorClass     string
	ErrorMessage   string
	IsUnhandledRejection bool
	InnerErrorClass string
	InnerErrorMsg   string
	Framework      string
	CulpritCode    *observerv1alpha1.CulpritCode
	CodeSnippet    string
	PrismaCode     string
	SuggestedFix   string
	SuggestedFixKo string
	SummaryKo      string
	SummaryEn      string
}

var (
	nodeFrameRegex = regexp.MustCompile(`^\s*at\s+(?:async\s+)?(?:([^\s(]+)\s+\((?:file:\/\/)?([^:]+):(\d+):(\d+)\)|(?:file:\/\/)?([^:]+):(\d+):(\d+))`)
	nodeExcRegex   = regexp.MustCompile(`(?m)^([a-zA-Z0-9_\.]*(?:Error|Exception|TypeError|ReferenceError|SyntaxError|RangeError|URIError|EvalError))(?::\s*(.*))?$`)
	nodePrismaCode = regexp.MustCompile(`(?s)(?:PrismaClientKnownRequestError|PrismaClientInitializationError).*?(P\d{4})`)
	nodeNestDep    = regexp.MustCompile(`Nest can't resolve dependencies of the ([^\s\.]+).*?argument ([^\s]+) at index \[(\d+)\]`)
)

// AnalyzeNodeDeepCrash performs deep diagnostic inspection of Node.js / V8 engine crash logs.
func AnalyzeNodeDeepCrash(logs string) *NodeDeepAnalysis {
	if !strings.Contains(logs, "Error") &&
		!strings.Contains(logs, "at ") &&
		!strings.Contains(logs, "FATAL ERROR:") &&
		!strings.Contains(logs, "unhandledRejection") &&
		!strings.Contains(logs, "UnhandledPromiseRejection") {
		return nil
	}

	analysis := &NodeDeepAnalysis{}
	lowerLogs := strings.ToLower(logs)

	// 1. Detect UnhandledPromiseRejection
	if strings.Contains(logs, "UnhandledPromiseRejection") || strings.Contains(logs, "unhandledRejection") {
		analysis.IsUnhandledRejection = true
	}

	// 2. Parse Stack Frames and identify User Code
	lines := strings.Split(logs, "\n")
	var frames []NodeFrame
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if m := nodeFrameRegex.FindStringSubmatch(trimmed); len(m) >= 5 {
			fn := m[1]
			file := m[2]
			lineStr := m[3]
			colStr := m[4]
			if file == "" && len(m) >= 8 {
				file = m[5]
				lineStr = m[6]
				colStr = m[7]
			}
			lineNum, _ := strconv.Atoi(lineStr)
			colNum, _ := strconv.Atoi(colStr)

			isUser := !strings.Contains(file, "node_modules") &&
				!strings.Contains(file, "node:internal") &&
				!strings.Contains(file, "internal/process") &&
				!strings.Contains(file, "internal/modules")

			frames = append(frames, NodeFrame{
				Function: fn,
				File:     file,
				Line:     lineNum,
				Column:   colNum,
				IsUser:   isUser,
			})
		}
	}

	for _, f := range frames {
		if f.IsUser && f.Line > 0 {
			parts := strings.Split(f.File, "/")
			analysis.CulpritCode = &observerv1alpha1.CulpritCode{
				Language: "JavaScript/TypeScript",
				File:     parts[len(parts)-1],
				Line:     f.Line,
				Function: f.Function,
			}
			break
		}
	}

	// 3. Extract Error Class & Message
	excMatches := nodeExcRegex.FindAllStringSubmatch(logs, -1)
	if len(excMatches) > 0 {
		analysis.ErrorClass = excMatches[0][1]
		if len(excMatches[0]) > 2 {
			analysis.ErrorMessage = strings.TrimSpace(excMatches[0][2])
		}
	}

	// 4. Framework Tagging
	if strings.Contains(lowerLogs, "@nestjs") || strings.Contains(logs, "Nest can't resolve dependencies") {
		analysis.Framework = "NestJS"
	} else if strings.Contains(lowerLogs, "prisma") {
		analysis.Framework = "Prisma"
	} else if strings.Contains(lowerLogs, "typeorm") {
		analysis.Framework = "TypeORM"
	} else if strings.Contains(lowerLogs, "mongoose") {
		analysis.Framework = "Mongoose"
	} else if strings.Contains(lowerLogs, "express") {
		analysis.Framework = "Express"
	} else if strings.Contains(lowerLogs, "fastify") {
		analysis.Framework = "Fastify"
	}

	// 5. Domain Rules
	detectNodeDomainRules(logs, analysis)

	return analysis
}

func detectNodeDomainRules(logs string, analysis *NodeDeepAnalysis) {
	// 1. ESM vs CommonJS Mismatch
	if strings.Contains(logs, "exports is not defined in ES module scope") ||
		strings.Contains(logs, "require is not defined in ES module scope") ||
		strings.Contains(logs, "Cannot use import statement outside a module") ||
		strings.Contains(logs, "ERR_REQUIRE_ESM") {
		analysis.SummaryKo = "Node.js 모듈 시스템(ESM vs CommonJS) 불일치 오류"
		analysis.SuggestedFixKo = "1) package.json에 '\"type\": \"module\"'을 설정하거나, 2) CommonJS 파일 확장자를 .cjs로 변경하거나, 3) tsconfig.json의 'moduleResolution'을 'NodeNext'로 일치시키십시오."
		analysis.SummaryEn = "Node.js module system mismatch (ESM vs CommonJS)"
		analysis.SuggestedFix = "1) Set '\"type\": \"module\"' in package.json, 2) rename CommonJS files to '.cjs', or 3) set 'moduleResolution: NodeNext' in tsconfig.json."
		return
	}

	// 2. Express ERR_HTTP_HEADERS_SENT
	if strings.Contains(logs, "ERR_HTTP_HEADERS_SENT") || strings.Contains(logs, "Cannot set headers after they are sent to the client") {
		analysis.SummaryKo = "Express 이중 응답 전송 오류 (Cannot set headers after they are sent to the client)"
		analysis.SuggestedFixKo = "라우터/미들웨어 핸들러에서 res.send() 또는 res.json() 호출 시 'return res.json(...)'과 같이 return 문을 명시하여 이후 코드의 중복 응답 전송을 방지하십시오."
		analysis.SummaryEn = "Express ERR_HTTP_HEADERS_SENT: headers already sent to client"
		analysis.SuggestedFix = "Ensure all response calls use 'return res.json(...)' or 'return res.send(...)' to prevent duplicate response transmission."
		return
	}

	// 3. Prisma Error Codes
	if pMatch := nodePrismaCode.FindStringSubmatch(logs); len(pMatch) >= 2 {
		code := pMatch[1]
		analysis.PrismaCode = code
		switch code {
		case "P2002":
			analysis.SummaryKo = fmt.Sprintf("Prisma 유니크 제약 조건(Unique constraint) 위반 (%s)", code)
			analysis.SuggestedFixKo = "데이터베이스에 이미 존재하는 고유 필드(이메일, 아이디 등) 중복 저장을 방지하기 위해 유효성 검사 또는 upsert() 구문을 적용하십시오."
			analysis.SummaryEn = fmt.Sprintf("Prisma unique constraint violation (%s)", code)
			analysis.SuggestedFix = "Validate uniqueness before insert or use prisma.model.upsert() to handle duplicates gracefully."
		case "P1001":
			analysis.SummaryKo = fmt.Sprintf("Prisma 데이터베이스 서버 접속 실패 (%s)", code)
			analysis.SuggestedFixKo = "DATABASE_URL 환경변수 및 K8s Service DNS, 포트, 방화벽(네트워크 정책) 연결 상태를 확인하십시오."
			analysis.SummaryEn = fmt.Sprintf("Prisma unable to reach database server (%s)", code)
			analysis.SuggestedFix = "Verify DATABASE_URL connection string, Kubernetes cluster DNS, and database port accessibility."
		default:
			analysis.SummaryKo = fmt.Sprintf("Prisma ORM 데이터베이스 오류 (%s): %s", code, analysis.ErrorMessage)
			analysis.SuggestedFixKo = "Prisma 스키마 정의 및 쿼리 파라미터를 점검하십시오."
			analysis.SummaryEn = fmt.Sprintf("Prisma error (%s): %s", code, analysis.ErrorMessage)
			analysis.SuggestedFix = "Check Prisma schema mappings and database query parameters."
		}
		return
	}

	// 4. NestJS Dependency Injection Failure
	if nMatch := nodeNestDep.FindStringSubmatch(logs); len(nMatch) >= 3 {
		targetClass := nMatch[1]
		missingDep := nMatch[2]
		analysis.SummaryKo = fmt.Sprintf("NestJS 의존성 주입(DI) 실패: '%s'에 주입할 '%s' 공급자(Provider) 누락", targetClass, missingDep)
		analysis.SuggestedFixKo = fmt.Sprintf("해당 모듈(@Module)의 'providers: [%s]' 목록에 추가하거나 해당 공급자를 export하는 모듈을 'imports: [...]'에 등록하십시오.", missingDep)
		analysis.SummaryEn = fmt.Sprintf("NestJS dependency injection failure for '%s' (missing '%s')", targetClass, missingDep)
		analysis.SuggestedFix = fmt.Sprintf("Add '%s' to providers array in @Module({ providers: [...] }) or import the exporting module.", missingDep)
		return
	}

	// 5. Unhandled Promise Rejection generic handling
	if analysis.IsUnhandledRejection {
		analysis.SummaryKo = fmt.Sprintf("Node.js 비동기 Promise 예외 미처리 (UnhandledPromiseRejection): %s", analysis.ErrorMessage)
		analysis.SuggestedFixKo = "비동기 함수 호출에 'await'를 누락했거나 '.catch(err => ...)' 또는 try/catch 블록이 누락되었습니다. 비동기 호출 지점에 예외 핸들러를 추가하십시오."
		analysis.SummaryEn = fmt.Sprintf("Node.js UnhandledPromiseRejection: %s", analysis.ErrorMessage)
		analysis.SuggestedFix = "Ensure all async functions are awaited inside try/catch blocks or have '.catch()' error handlers attached."
		return
	}
}
