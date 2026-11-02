package knowledge

import (
	"testing"
)

func TestSemanticCatalog_EnterpriseScale(t *testing.T) {
	if len(SemanticCatalog) < 100 {
		t.Fatalf("expected at least 100 indexed entries in SemanticCatalog, got: %d", len(SemanticCatalog))
	}

	testCases := []struct {
		lang       string
		key        string
		expectRoot string
	}{
		// Database & Drivers
		{"Database", "MySQL_1213_Deadlock", "MySQLDeadlock"},
		{"Database", "MySQL_1040_TooManyConnections", "MySQLTooManyConnections"},
		{"Database", "PostgreSQL_40P01_Deadlock", "PostgresDeadlock"},
		{"Database", "PostgreSQL_25P02_InFailedTx", "PostgresInFailedSQLTransaction"},
		{"Database", "Redis_OOM_CommandNotAllowed", "RedisOOM"},
		{"Database", "Kafka_NotEnoughReplicas", "KafkaNotEnoughReplicas"},
		{"Database", "ClickHouse_202_SimultaneousQueries", "ClickHouseSimultaneousQueries"},
		{"Database", "Mongo_DuplicateKey_E11000", "MongoDuplicateKey"},

		// Java & Spring
		{"Java", "NullPointerException", "JVMNullPointer"},
		{"Java", "OutOfMemoryError: Java heap space", "JVMHeapOOM"},
		{"Java", "BeanCreationException", "SpringBootStartupFailure"},
		{"Java", "LazyInitializationException", "LazyInitializationException"},
		{"Java", "HikariPoolExhaustion", "SpringHikariPoolExhaustion"},
		{"Java", "CallNotPermittedException", "CircuitBreakerOpen"},
		{"Java", "FeignException", "SpringCloudFeignFailure"},

		// Python & Web
		{"Python", "KeyError", "PythonKeyError"},
		{"Python", "AttributeError", "PythonAttributeError"},
		{"Python", "RequestValidationError", "FastAPIValidationError"},
		{"Python", "DetachedInstanceError", "SQLAlchemyDetachedInstanceError"},
		{"Python", "WorkerLostError", "CeleryWorkerLostError"},
		{"Python", "CUDA out of memory", "PyTorchCUDAOutOfMemory"},

		// Node.js & TypeScript
		{"Node.js", "TypeError", "NodeTypeError"},
		{"Node.js", "UnhandledPromiseRejection", "NodeUnhandledPromiseRejection"},
		{"Node.js", "JavaScript heap out of memory", "NodeV8FatalError"},
		{"Node.js", "PrismaClientKnownRequestError", "NodePrismaError"},
		{"Node.js", "NestCanNotResolveDependenciesException", "NestJSDependencyResolutionFailed"},

		// Go
		{"Go", "GoDeadlock", "GoDeadlock"},
		{"Go", "GoConcurrentMapAccess", "GoConcurrentMapAccess"},
		{"Go", "GoNilPointerDereference", "GoNilPointerDereference"},
		{"Go", "sql: no rows in result set", "GoSQLNoRows"},
		{"Go", "rpc error: code = Unavailable", "GRPCServerUnavailable"},

		// .NET
		{"DotNet", "NullReferenceException", "DotNetNullReference"},
		{"DotNet", "DbUpdateException", "DotNetEFDbUpdateException"},
		{"DotNet", "OutOfMemoryException", "DotNetOOM"},

		// Infra & Signals
		{"System", "SegmentationFault", "SegmentationFault"},
		{"System", "OOMKilled", "OOMKilled"},
		{"Infrastructure", "Envoy_NoHealthyUpstream_503UH", "EnvoyNoHealthyUpstream"},
		{"Infrastructure", "CoreDNSLoopDetected", "CoreDNSLoopDetected"},
		{"Configuration", "VaultSealedFailure", "VaultSealedFailure"},
	}

	for _, tc := range testCases {
		entry, found := LookupSemanticCatalog(tc.lang, tc.key)
		if !found {
			t.Errorf("expected to find catalog entry for lang=%s, key=%s", tc.lang, tc.key)
			continue
		}
		if entry.RootCause != tc.expectRoot {
			t.Errorf("expected root cause %s, got %s for key=%s", tc.expectRoot, entry.RootCause, tc.key)
		}
		if entry.SummaryKo == "" {
			t.Errorf("missing SummaryKo for key=%s", tc.key)
		}
		if entry.ActionKo == "" {
			t.Errorf("missing ActionKo for key=%s", tc.key)
		}
		if len(entry.RootCauseChainKo) == 0 {
			t.Errorf("missing RootCauseChainKo for key=%s", tc.key)
		}
	}
}
