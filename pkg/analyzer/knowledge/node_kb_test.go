package knowledge

import (
	"testing"
)

func TestAnalyzeNodeDeepCrash_ESMMismatch(t *testing.T) {
	logs := `
ReferenceError: exports is not defined in ES module scope
This file is being treated as an ES module because it has a '.js' file extension and 'package.json' contains "type": "module".
    at file:///app/dist/index.js:8:23
    at ModuleJob.run (node:internal/modules/esm/module_job:194:25)
`
	analysis := AnalyzeNodeDeepCrash(logs)
	if analysis == nil {
		t.Fatalf("expected non-nil analysis")
	}
	if analysis.SummaryKo == "" || analysis.SuggestedFixKo == "" {
		t.Errorf("expected localized summary and fix for ESM mismatch")
	}
	if analysis.CulpritCode == nil || analysis.CulpritCode.File != "index.js" || analysis.CulpritCode.Line != 8 {
		t.Errorf("expected culprit index.js:8, got %+v", analysis.CulpritCode)
	}
}

func TestAnalyzeNodeDeepCrash_PrismaP2002(t *testing.T) {
	logs := `
PrismaClientKnownRequestError: 
Invalid 'prisma.user.create()' invocation:
Unique constraint failed on the constraint: 'users_email_key' (P2002)
    at RequestHandler.handleRequestError (/app/node_modules/@prisma/client/runtime/library.js:122:7147)
    at async createUser (/app/src/services/userService.ts:45:18)
    at async handleSignUp (/app/src/controllers/authController.ts:24:12)
`
	analysis := AnalyzeNodeDeepCrash(logs)
	if analysis == nil {
		t.Fatalf("expected non-nil analysis")
	}
	if analysis.PrismaCode != "P2002" {
		t.Errorf("expected Prisma code P2002, got %q", analysis.PrismaCode)
	}
	if analysis.CulpritCode == nil || analysis.CulpritCode.File != "userService.ts" || analysis.CulpritCode.Line != 45 {
		t.Errorf("expected culprit userService.ts:45, got %+v", analysis.CulpritCode)
	}
}

func TestAnalyzeNodeDeepCrash_NestJSDependency(t *testing.T) {
	logs := `
[Nest] 1  - 11/02/2026, 1:00:00 AM   ERROR [ExceptionHandler] Nest can't resolve dependencies of the OrderService (?). Please make sure that the argument PaymentGateway at index [0] is available in the current context.
`
	analysis := AnalyzeNodeDeepCrash(logs)
	if analysis == nil {
		t.Fatalf("expected non-nil analysis")
	}
	if analysis.Framework != "NestJS" {
		t.Errorf("expected NestJS framework, got %q", analysis.Framework)
	}
	if analysis.SummaryKo == "" {
		t.Errorf("expected non-empty localized summary")
	}
}

func TestAnalyzeNodeDeepCrash_FalsePositivePrevention(t *testing.T) {
	// Case 1: ClickHouse server logs containing "Error" and words with "at "
	clickhouseLogs := `
16. ? @ 0x00007acd2f5d81c4
17. ? @ 0x00007acd2f657ac0
 (version 25.2.1.3085 (official build))
2026.10.29 17:10:33.131931 [ 43 ] {} <Information> Application: Closed all listening sockets.
2026.10.29 17:10:33.132186 [ 43 ] {} <Information> Application: Closed connections.
2026.10.29 17:10:33.132861 [ 43 ] {} <Information> Application: Stopping AsyncLoader.
2026.10.29 17:10:33.133135 [ 43 ] {} <Information> CgroupsMemoryUsageObserver: Stopped cgroup current memory usage observer thread
2026.10.29 17:10:33.144490 [ 43 ] {} <Information> Application: Shutting down storages.
2026.10.29 17:10:33.298563 [ 214 ] {} <Information> system.latency_log (027618c1-67e1-4506-86e3-f7305b726925) (MergerMutator): Selected 2 parts from 202610_2646230_2650088_3086 to 202610_2650089_2650089_0. Merge selecting phase took: 0ms
2026.10.29 17:10:33.354306 [ 211 ] {} <Error> system.text_log: Merge failed at line 100
`
	if analysis := AnalyzeNodeDeepCrash(clickhouseLogs); analysis != nil {
		t.Errorf("expected nil for ClickHouse non-Node.js logs, got %+v", analysis)
	}

	// Case 2: Python / Gunicorn / Flask webserver shutdown logs
	flaskLogs := `
connected to AWS IoT
[2026-10-30 02:28:36 +0900] [9] [INFO] Worker exiting (pid: 9)
connecting to IoT FLASK_ENV production AWS a2xjzp4d3ro6zs-ats.iot.ap-northeast-2.amazonaws.com
connect iot aws
connected to AWS IoT
[2026-10-30 02:28:36 +0900] [8] [INFO] Worker exiting (pid: 8)
connecting to IoT FLASK_ENV production AWS a2xjzp4d3ro6zs-ats.iot.ap-northeast-2.amazonaws.com
connect iot aws
connected to AWS IoT
[2026-10-30 02:28:37 +0900] [7] [INFO] Worker exiting (pid: 7)
connecting to IoT FLASK_ENV production AWS a2xjzp4d3ro6zs-ats.iot.ap-northeast-2.amazonaws.com
connect iot aws
connected to AWS IoT
[2026-10-30 02:28:46 +0900] [1] [INFO] Shutting down: Master
Error occurred at shutdown: None
`
	if analysis := AnalyzeNodeDeepCrash(flaskLogs); analysis != nil {
		t.Errorf("expected nil for Python/Flask webserver logs, got %+v", analysis)
	}
}
