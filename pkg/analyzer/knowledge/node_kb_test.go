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
