package knowledge

import (
	"fmt"
	"regexp"
	"strings"
)

// DBDriverAnalysis represents detailed findings from database driver and client SDK crashes across languages.
type DBDriverAnalysis struct {
	Database       string // mysql, postgresql, clickhouse, bigquery
	DriverLang     string // java, python, nodejs, go, generic
	RootCause      string
	ErrorClass     string
	SummaryKo      string
	SummaryEn      string
	SuggestedFixKo string
	SuggestedFixEn string
}

var (
	// --- Language / Driver Detectors ---
	javaDriverRegex   = regexp.MustCompile(`(?i)(?:com\.mysql\.cj\.jdbc|org\.postgresql\.|com\.clickhouse\.client|com\.google\.cloud\.bigquery|java\.sql\.|HikariPool|org\.hibernate\.|org\.springframework\.jdbc|r2dbc)`)
	pythonDriverRegex = regexp.MustCompile(`(?i)(?:pymysql|psycopg2|asyncpg|clickhouse_driver|clickhouse_connect|google\.cloud\.bigquery|sqlalchemy|aiomysql|mysqlclient|Traceback \(most recent call last\):)`)
	nodeDriverRegex   = regexp.MustCompile(`(?i)(?:node_modules[/\\](?:mysql2|pg|@clickhouse|@google-cloud[/\\]bigquery|typeorm|prisma|knex)|PrismaClient|ER_[A-Z_]+|ClickHouseClient)`)
	goDriverRegex     = regexp.MustCompile(`(?i)(?:go-sql-driver/mysql|jackc/pgx|lib/pq|ClickHouse/clickhouse-go|cloud\.google\.com/go/bigquery)`)

	// --- MySQL Driver Patterns ---
	mySQLTooManyConnectionsRegex = regexp.MustCompile(`(?i)(?:error\s*1040\b|ER_CON_COUNT_ERROR|\(?1040\)?\s*[,:]?\s*['"]?Too many connections|Too many connections.*?mysql|Data source rejected establishment of connection.*?Too many connections)`)
	mySQLDeadlockRegex           = regexp.MustCompile(`(?i)(?:error\s*1213\b|ER_LOCK_DEADLOCK|Deadlock found when trying to get lock;\s*try restarting transaction|MySQLTransactionRollbackException:\s*Deadlock|LockAcquisitionException.*?deadlock)`)
	mySQLLockWaitTimeoutRegex    = regexp.MustCompile(`(?i)(?:error\s*1205\b|ER_LOCK_WAIT_TIMEOUT|Lock wait timeout exceeded;\s*try restarting transaction|MySQLTimeoutException:\s*Lock wait timeout)`)
	mySQLPacketTooLargeRegex     = regexp.MustCompile(`(?i)(?:error\s*1153\b|ER_NET_PACKET_TOO_LARGE|Got a packet bigger than 'max_allowed_packet' bytes|PacketTooBigException)`)
	mySQLCommLinkFailureRegex    = regexp.MustCompile(`(?i)(?:Communications link failure|Lost connection to MySQL server during query|MySQL server has gone away|\bPROTOCOL_CONNECTION_LOST\b)`)
	mySQLReadOnlyRegex           = regexp.MustCompile(`(?i)(?:ER_OPTION_PREVENTS_STATEMENT|The MySQL server is running with the --(?:super-)?read-only option)`)

	// --- PostgreSQL Driver Patterns ---
	pgTooManyConnectionsRegex = regexp.MustCompile(`(?i)(?:53300.*?too_many_connections|remaining connection slots are reserved for non-replication superuser connections|sorry,\s*too many clients already|TooManyConnectionsError|\b53300\b)`)
	pgDeadlockRegex           = regexp.MustCompile(`(?i)(?:40P01.*?deadlock_detected|ERROR:\s*deadlock detected.*?Process \d+ waits for|DeadlockDetected:\s*deadlock detected)`)
	pgInFailedTxRegex         = regexp.MustCompile(`(?i)(?:25P02.*?in_failed_sql_transaction|current transaction is aborted,\s*commands ignored until end of transaction block|InFailedSqlTransaction)`)
	pgStatementTimeoutRegex   = regexp.MustCompile(`(?i)(?:57014.*?query_canceled|canceling statement due to statement timeout|QueryCanceled:\s*canceling statement due to statement timeout)`)
	pgCannotConnectNowRegex   = regexp.MustCompile(`(?i)(?:57P03.*?cannot_connect_now|FATAL:\s*the database system is in recovery mode|FATAL:\s*the database system is starting up|FATAL:\s*the database system is shutting down)`)
	pgDiskFullRegex           = regexp.MustCompile(`(?i)(?:53100.*?disk_full|could not extend file.*?: No space left on device|PANIC:\s*could not write to log file)`)

	// --- ClickHouse Driver Patterns ---
	chSimultaneousQueriesRegex = regexp.MustCompile(`(?i)(?:Code:\s*202\b.*?Too many simultaneous queries|DB::Exception:\s*Too many simultaneous queries\. Maximum:\s*\d+)`)
	chMemoryLimitDriverRegex   = regexp.MustCompile(`(?i)(?:Code:\s*241\b.*?Memory limit \([^)]+\) exceeded|DB::Exception:\s*Memory limit \(for query\) exceeded|CANNOT_ALLOCATE_MEMORY.*?ClickHouse)`)
	chTimeoutExceededRegex     = regexp.MustCompile(`(?i)(?:Code:\s*159\b.*?Timeout exceeded|DB::Exception:\s*Timeout exceeded:\s*elapsed \d+|Estimated query execution time.*?exceeded)`)
	chConnPoolExhaustedRegex   = regexp.MustCompile(`(?i)(?:No free connection in pool.*?clickhouse|ClickHouse.*?connection pool exhausted|ClickHouseClient.*?pool size exceeded|Timeout waiting for connection from ClickHouse pool)`)

	// --- BigQuery SDK Patterns ---
	bqBytesBilledLimitRegex    = regexp.MustCompile(`(?i)(?:Query exceeded limit for bytes billed:\s*\d+\.\s*Limit was\s*\d+|bytesBilledLimitExceeded|maximum_bytes_billed.*?(?:exceeded|reached))`)
	bqPartitionFilterReqRegex  = regexp.MustCompile(`(?i)(?:Cannot query over table '.*?' without a filter over column\(s\) '.*?' that can be used for partition elimination|requirePartitionFilter|query has no filter over the partition column)`)
	bqResponseTooLargeRegex    = regexp.MustCompile(`(?i)(?:Response too large to return with inline results|responseTooLarge|Set allowLargeResults or specify destination table)`)
	bqStreamingQuotaRegex      = regexp.MustCompile(`(?i)(?:quotaExceeded.*?streaming inserts|Exceeded rate limits.*?streaming insert|streamingBuffer.*?quota)`)
	bqTableNotFoundLocRegex    = regexp.MustCompile(`(?i)(?:Not found:\s*Table .*? was not found in location \w+|Dataset .*? was not found in location \w+|Cross-region queries are not allowed)`)
)

// DetectDriverLanguage identifies which programming language driver threw the database exception.
func DetectDriverLanguage(logs string) string {
	if javaDriverRegex.MatchString(logs) {
		return "java"
	}
	if pythonDriverRegex.MatchString(logs) {
		return "python"
	}
	if nodeDriverRegex.MatchString(logs) {
		return "nodejs"
	}
	if goDriverRegex.MatchString(logs) {
		return "go"
	}
	return "generic"
}

// AnalyzeDBDriverLogs analyzes logs for MySQL, PostgreSQL, ClickHouse, and BigQuery errors across language drivers.
func AnalyzeDBDriverLogs(logs string) *DBDriverAnalysis {
	if strings.TrimSpace(logs) == "" {
		return nil
	}

	driverLang := DetectDriverLanguage(logs)

	// =========================================================================
	// 1. MySQL Driver Errors
	// =========================================================================
	if mySQLTooManyConnectionsRegex.MatchString(logs) {
		fixKo := "1) MySQL 서버의 'max_connections'(기본 151) 설정을 상향하거나 RDS/Aurora 파라미터 그룹을 증설하세요."
		fixEn := "1) Increase 'max_connections' in MySQL / RDS parameter group."
		switch driverLang {
		case "java":
			fixKo += " 2) HikariCP의 'maximum-pool-size'를 인스턴스/파드 수에 맞게 분할 조정하고 커넥션 누수를 점검하세요."
			fixEn += " 2) Reduce HikariCP maximum-pool-size per pod and check for connection leaks."
		case "python":
			fixKo += " 2) SQLAlchemy create_engine 'pool_size' 및 'max_overflow'를 축소하고 세션 닫기(with Session():)를 점검하세요."
			fixEn += " 2) Tune SQLAlchemy pool_size and ensure sessions are cleanly closed with context managers."
		case "nodejs":
			fixKo += " 2) mysql2/TypeORM/Prisma의 connectionLimit을 낮추어 파드 전체의 동시 풀 크기가 max_connections를 초과하지 않도록 하세요."
			fixEn += " 2) Lower connectionLimit in mysql2/Prisma to prevent pod pool sprawl."
		}
		return &DBDriverAnalysis{
			Database:       "mysql",
			DriverLang:     driverLang,
			RootCause:      "MySQLTooManyConnections",
			ErrorClass:     "MySQL_1040_TooManyConnections",
			SummaryKo:      fmt.Sprintf("[%s] MySQL 서버 동시 연결 한도(max_connections) 초과로 신규 커넥션 거부 (Error 1040)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] MySQL server max_connections limit exceeded, rejecting new connection (Error 1040)", strings.ToUpper(driverLang)),
			SuggestedFixKo: fixKo,
			SuggestedFixEn: fixEn,
		}
	}

	if mySQLDeadlockRegex.MatchString(logs) {
		fixKo := "1) 복수 테이블/행 갱신 시 접근 순서를 일관되게 정렬(ORDER BY ID)하여 락 순환을 차단하세요. 2) 트랜잭션 범위를 최소화하고 인덱스를 추가하여 락 점유 범위를 축소하세요."
		fixEn := "1) Access and update rows in a consistent order across transactions to break lock cycle. 2) Keep transactions short and add indexes."
		switch driverLang {
		case "java":
			fixKo += " 3) Spring @Retryable(value = {CannotAcquireLockException.class}, maxAttempts = 3, backoff = @Backoff(delay = 100))을 적용하세요."
			fixEn += " 3) Apply Spring @Retryable on transactional services with exponential backoff."
		case "python":
			fixKo += " 3) 데드락 발생 시 tenacity 라이브러리 등을 활용해 자동 트랜잭션 재시도 로직을 구성하세요."
			fixEn += " 3) Use tenacity or custom retry decorator to automatically retry on OperationalError 1213."
		case "nodejs":
			fixKo += " 3) Prisma/TypeORM 트랜잭션 실패 시 지수 백오프 기반 재시도 헬퍼를 적용하세요."
			fixEn += " 3) Wrap Prisma/TypeORM interactive transactions in a retry loop on ER_LOCK_DEADLOCK."
		}
		return &DBDriverAnalysis{
			Database:       "mysql",
			DriverLang:     driverLang,
			RootCause:      "MySQLDeadlock",
			ErrorClass:     "MySQL_1213_Deadlock",
			SummaryKo:      fmt.Sprintf("[%s] MySQL InnoDB 트랜잭션 상호 잠금(Deadlock) 감지 및 자동 롤백 (Error 1213)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] MySQL InnoDB transaction deadlock detected and rolled back (Error 1213)", strings.ToUpper(driverLang)),
			SuggestedFixKo: fixKo,
			SuggestedFixEn: fixEn,
		}
	}

	if mySQLLockWaitTimeoutRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "mysql",
			DriverLang:     driverLang,
			RootCause:      "MySQLLockWaitTimeout",
			ErrorClass:     "MySQL_1205_LockWaitTimeout",
			SummaryKo:      fmt.Sprintf("[%s] MySQL InnoDB 락 대기 시간 한도(innodb_lock_wait_timeout) 초과 (Error 1205)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] MySQL InnoDB lock wait timeout exceeded (Error 1205)", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) 장기 실행 트랜잭션(Long-running transaction) 또는 미커밋 세션을 'SHOW FULL PROCESSLIST' 및 'information_schema.innodb_trx'로 확인하세요. 2) 'innodb_lock_wait_timeout'(기본 50초)을 워크로드에 맞게 조정하세요.",
			SuggestedFixEn: "1) Inspect uncommitted or long-running transactions via 'information_schema.innodb_trx'. 2) Tune innodb_lock_wait_timeout.",
		}
	}

	if mySQLPacketTooLargeRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "mysql",
			DriverLang:     driverLang,
			RootCause:      "MySQLPacketTooLarge",
			ErrorClass:     "MySQL_1153_PacketTooLarge",
			SummaryKo:      fmt.Sprintf("[%s] MySQL 네트워크 패킷 크기가 서버의 'max_allowed_packet' 한도를 초과 (Error 1153)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] MySQL packet bigger than 'max_allowed_packet' bytes (Error 1153)", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) MySQL 서버 my.cnf의 'max_allowed_packet'(예: 64M, 128M)을 상향하세요. 2) JDBC/클라이언트 측에도 대용량 패킷 허용 옵션(maxAllowedPacket)을 일치시키세요.",
			SuggestedFixEn: "1) Increase 'max_allowed_packet' in MySQL server my.cnf. 2) Match driver client maxAllowedPacket setting.",
		}
	}

	if mySQLCommLinkFailureRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "mysql",
			DriverLang:     driverLang,
			RootCause:      "MySQLCommunicationsLinkFailure",
			ErrorClass:     "MySQL_CommunicationsLinkFailure",
			SummaryKo:      fmt.Sprintf("[%s] MySQL 커넥션 유휴 시간(wait_timeout) 초과 또는 원격 소켓 강제 종료로 인한 통신 링크 단절", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] MySQL communications link failure due to server wait_timeout or abruptly dropped socket", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) 커넥션 풀의 max-lifetime 및 idle-timeout을 MySQL 'wait_timeout'(통상 300~600초)보다 최소 30초 짧게 설정하세요. 2) 'test-while-idle' 유효성 검사 쿼리('SELECT 1')를 활성화하세요.",
			SuggestedFixEn: "1) Set connection pool maxLifetime and idleTimeout shorter than MySQL wait_timeout. 2) Enable connection validation query ('SELECT 1').",
		}
	}

	if mySQLReadOnlyRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "mysql",
			DriverLang:     driverLang,
			RootCause:      "MySQLReadOnlyMode",
			ErrorClass:     "MySQL_1290_ReadOnlyMode",
			SummaryKo:      fmt.Sprintf("[%s] MySQL 인스턴스가 읽기 전용(--read-only/super-read-only) 상태에서 쓰기 쿼리 거절 (클러스터 페일오버 미반영)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] MySQL server is in read-only mode, rejecting write queries (cluster failover desync)", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) DB 클러스터 페일오버 후 쓰기 엔드포인트(Primary/Writer) DNS가 새 프라이머리를 가리키는지 확인하세요. 2) 클라이언트 측 DNS 캐싱 TTL을 1~5초로 낮추세요.",
			SuggestedFixEn: "1) Verify application connection string points to cluster Writer endpoint. 2) Reduce JVM/DNS caching TTL.",
		}
	}

	// =========================================================================
	// 2. PostgreSQL Driver Errors
	// =========================================================================
	if pgTooManyConnectionsRegex.MatchString(logs) {
		fixKo := "1) PgBouncer 또는 Odyssey 커넥션 풀러를 도입하여 클라이언트 연결을 멀티플렉싱하세요. 2) postgresql.conf의 'max_connections'를 상향 조정하세요."
		fixEn := "1) Introduce PgBouncer or Odyssey connection pooler. 2) Increase max_connections in postgresql.conf."
		switch driverLang {
		case "java":
			fixKo += " 3) HikariCP의 maximum-pool-size를 파드 복제본 수에 맞게 분할 축소하세요."
			fixEn += " 3) Lower HikariCP maximum-pool-size according to pod replica count."
		case "python":
			fixKo += " 3) Celery / Gunicorn 워커 프로세스당 커넥션 풀 크기(max_overflow)를 제한하세요."
			fixEn += " 3) Restrict connection pool per Celery/Gunicorn worker process."
		case "nodejs":
			fixKo += " 3) pg.Pool의 'max' 옵션을 낮추고 unhandled query rejection 시 풀 반환을 점검하세요."
			fixEn += " 3) Lower pg.Pool max option and ensure client.release() in finally blocks."
		}
		return &DBDriverAnalysis{
			Database:       "postgresql",
			DriverLang:     driverLang,
			RootCause:      "PostgresTooManyConnections",
			ErrorClass:     "PostgreSQL_53300_TooManyConnections",
			SummaryKo:      fmt.Sprintf("[%s] PostgreSQL 연결 슬롯 고갈 (SQLState 53300: sorry, too many clients already)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] PostgreSQL connection slots exhausted (SQLState 53300: too many clients)", strings.ToUpper(driverLang)),
			SuggestedFixKo: fixKo,
			SuggestedFixEn: fixEn,
		}
	}

	if pgDeadlockRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "postgresql",
			DriverLang:     driverLang,
			RootCause:      "PostgresDeadlock",
			ErrorClass:     "PostgreSQL_40P01_Deadlock",
			SummaryKo:      fmt.Sprintf("[%s] PostgreSQL 트랜잭션 상호 잠금(Deadlock) 감지 및 자동 취소 (SQLState 40P01)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] PostgreSQL transaction deadlock detected and aborted (SQLState 40P01)", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) 여러 행을 갱신할 때 항상 기본키(PK) 순으로 정렬하여 일관된 순서로 락을 획득하도록 쿼리를 수정하세요. 2) 'SELECT ... FOR UPDATE' 대상 범위를 최소화하세요.",
			SuggestedFixEn: "1) Acquire locks in a consistent order by sorting updated rows by primary key. 2) Minimize SELECT FOR UPDATE locking scope.",
		}
	}

	if pgInFailedTxRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "postgresql",
			DriverLang:     driverLang,
			RootCause:      "PostgresInFailedSQLTransaction",
			ErrorClass:     "PostgreSQL_25P02_InFailedTx",
			SummaryKo:      fmt.Sprintf("[%s] PostgreSQL 트랜잭션 내 이전 에러 발생 후 ROLLBACK 없이 후속 쿼리 실행 시도 (SQLState 25P02)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] PostgreSQL transaction aborted due to earlier failure, subsequent commands ignored (SQLState 25P02)", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) 트랜잭션 블록 내에서 쿼리 오류 발생 시 즉시 명시적 ROLLBACK을 수행하거나 SAVEPOINT를 사용하세요. 2) ORM 트랜잭션 롤백 핸들러 누락 여부를 확인하세요.",
			SuggestedFixEn: "1) Execute an explicit ROLLBACK or use SAVEPOINT when an error occurs within a transaction. 2) Check ORM rollback exception handlers.",
		}
	}

	if pgStatementTimeoutRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "postgresql",
			DriverLang:     driverLang,
			RootCause:      "PostgresStatementTimeout",
			ErrorClass:     "PostgreSQL_57014_StatementTimeout",
			SummaryKo:      fmt.Sprintf("[%s] PostgreSQL 쿼리 실행 시간 제한(statement_timeout) 초과로 강제 취소 (SQLState 57014)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] PostgreSQL statement canceled due to statement_timeout (SQLState 57014)", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) 'EXPLAIN (ANALYZE, BUFFERS)'로 느린 쿼리의 인덱스 부재 및 순차 스캔(Seq Scan)을 점검하세요. 2) 대량 배치 작업의 경우 세션 단위로 'SET statement_timeout = ...'을 상향하세요.",
			SuggestedFixEn: "1) Run 'EXPLAIN ANALYZE' to optimize slow queries with proper indexes. 2) Adjust 'SET statement_timeout' per session for heavy batch jobs.",
		}
	}

	if pgCannotConnectNowRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "postgresql",
			DriverLang:     driverLang,
			RootCause:      "PostgresCannotConnectNow",
			ErrorClass:     "PostgreSQL_57P03_CannotConnectNow",
			SummaryKo:      fmt.Sprintf("[%s] PostgreSQL 인스턴스가 복구 모드(Recovery) 또는 기동 중으로 접속 불가 (SQLState 57P03)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] PostgreSQL database is in recovery mode or starting up, rejecting connections (SQLState 57P03)", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) PostgreSQL 파드의 WAL 리플레이 상태 및 컨테이너 로그를 점검하세요. 2) 클러스터 페일오버 시 승격 완료(pg_isready -h ...) 전까지 파드 기동을 대기시키세요.",
			SuggestedFixEn: "1) Check WAL replay progress and container logs. 2) Ensure pod waits until pg_isready confirms primary promotion.",
		}
	}

	if pgDiskFullRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "postgresql",
			DriverLang:     driverLang,
			RootCause:      "PostgresDiskFull",
			ErrorClass:     "PostgreSQL_53100_DiskFull",
			SummaryKo:      fmt.Sprintf("[%s] PostgreSQL 데이터 디렉토리 또는 WAL 볼륨 디스크 용량 고갈 (SQLState 53100)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] PostgreSQL disk full, unable to extend table or WAL logs (SQLState 53100)", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) PostgreSQL PVC 스토리지 용량을 즉시 확장하세요. 2) 미사용 복제 슬롯(pg_replication_slots) 또는 아카이브 정체로 인한 pg_wal 누적을 정리하세요.",
			SuggestedFixEn: "1) Expand PostgreSQL PVC volume size immediately. 2) Clean up orphan replication slots causing pg_wal accumulation.",
		}
	}

	// =========================================================================
	// 3. ClickHouse Driver Errors
	// =========================================================================
	if chSimultaneousQueriesRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "clickhouse",
			DriverLang:     driverLang,
			RootCause:      "ClickHouseSimultaneousQueries",
			ErrorClass:     "ClickHouse_202_SimultaneousQueries",
			SummaryKo:      fmt.Sprintf("[%s] ClickHouse 동시 실행 쿼리 한도(max_concurrent_queries) 초과 (Code 202)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] ClickHouse max concurrent queries limit reached (Code 202)", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) ClickHouse 서버 config.xml의 'max_concurrent_queries'(기본 100)를 상향하세요. 2) 클라이언트 측에서 쿼리를 배치로 통합하거나 작업 큐(Queue)를 통해 동시 유입량을 제어하세요.",
			SuggestedFixEn: "1) Increase 'max_concurrent_queries' in ClickHouse config.xml. 2) Batch queries or implement concurrency throttling on the client side.",
		}
	}

	if chMemoryLimitDriverRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "clickhouse",
			DriverLang:     driverLang,
			RootCause:      "ClickHouseMemoryLimit",
			ErrorClass:     "ClickHouse_241_MemoryLimitExceeded",
			SummaryKo:      fmt.Sprintf("[%s] ClickHouse 단일 쿼리 메모리 한도(max_memory_usage) 초과 (Code 241)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] ClickHouse query memory limit exceeded (Code 241)", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) 세션 또는 사용자 프로필에서 'max_memory_usage'(기본 10GB)를 상향하세요. 2) 'max_bytes_before_external_group_by' 및 'max_bytes_before_external_sort'를 설정하여 디스크 오프로딩(Spill-to-disk)을 허용하세요.",
			SuggestedFixEn: "1) Increase max_memory_usage in user profile or session settings. 2) Enable 'max_bytes_before_external_group_by' for spill-to-disk execution.",
		}
	}

	if chTimeoutExceededRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "clickhouse",
			DriverLang:     driverLang,
			RootCause:      "ClickHouseTimeoutExceeded",
			ErrorClass:     "ClickHouse_159_TimeoutExceeded",
			SummaryKo:      fmt.Sprintf("[%s] ClickHouse 쿼리 실행 타임아웃(max_execution_time) 초과 (Code 159)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] ClickHouse query execution timeout exceeded (Code 159)", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) 쿼리 프로필의 'max_execution_time' 설정을 점검하세요. 2) WHERE 절에 파티션 키 및 기본 인덱스(ORDER BY)를 조건으로 지정하여 스캔 데이터 블록을 줄이세요.",
			SuggestedFixEn: "1) Check and increase max_execution_time in profile settings. 2) Add partition key and primary order by keys in the WHERE clause.",
		}
	}

	if chConnPoolExhaustedRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "clickhouse",
			DriverLang:     driverLang,
			RootCause:      "ClickHouseConnectionPoolExhausted",
			ErrorClass:     "ClickHouse_ConnectionPoolExhausted",
			SummaryKo:      fmt.Sprintf("[%s] ClickHouse 클라이언트 드라이버 연결 풀(Connection Pool) 고갈", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] ClickHouse client driver connection pool exhausted", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) 클라이언트 드라이버 설정의 최대 풀 크기(max_open_connections / pool_size)를 상향하세요. 2) 쿼리 완료 후 응답 스트림 닫기(Close/Release)가 누락되지 않았는지 확인하세요.",
			SuggestedFixEn: "1) Increase client connection pool size (max_open_connections / pool_size). 2) Ensure response streams and connections are closed properly.",
		}
	}

	// =========================================================================
	// 4. BigQuery SDK Errors
	// =========================================================================
	if bqBytesBilledLimitRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "bigquery",
			DriverLang:     driverLang,
			RootCause:      "BigQueryBytesBilledLimitExceeded",
			ErrorClass:     "BigQuery_BytesBilledLimitExceeded",
			SummaryKo:      fmt.Sprintf("[%s] BigQuery 쿼리 스캔 바이트 청구 한도(maximum_bytes_billed) 초과", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] BigQuery query exceeded limit for bytes billed (maximum_bytes_billed)", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) 쿼리 작업 옵션의 'maximum_bytes_billed'를 상향하거나 쿼리에 파티션 및 클러스터링 필터를 추가하여 스캔 데이터 용량을 줄이세요. 2) 불필요한 'SELECT *'를 지양하고 필요한 컬럼만 프로젝션하세요.",
			SuggestedFixEn: "1) Increase 'maximum_bytes_billed' in query job options or add partition/clustering filters. 2) Avoid 'SELECT *' and project only required columns.",
		}
	}

	if bqPartitionFilterReqRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "bigquery",
			DriverLang:     driverLang,
			RootCause:      "BigQueryPartitionFilterRequired",
			ErrorClass:     "BigQuery_PartitionFilterRequired",
			SummaryKo:      fmt.Sprintf("[%s] BigQuery 파티션 테이블 쿼리 시 필수 파티션 필터 누락 (requirePartitionFilter=true)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] BigQuery partition filter required over partitioned table", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) 쿼리의 WHERE 절에 파티션 컬럼(예: _PARTITIONDATE, _PARTITIONTIME 또는 일자/타임스탬프 필드) 조건을 반드시 포함하세요.",
			SuggestedFixEn: "1) Include a filter condition over the partition column in the WHERE clause (e.g. _PARTITIONDATE or timestamp column).",
		}
	}

	if bqResponseTooLargeRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "bigquery",
			DriverLang:     driverLang,
			RootCause:      "BigQueryResponseTooLarge",
			ErrorClass:     "BigQuery_ResponseTooLarge",
			SummaryKo:      fmt.Sprintf("[%s] BigQuery 인라인 반환 응답 크기 제한 초과 (대용량 결과 집합)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] BigQuery response too large to return with inline results", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) 쿼리 작업 시 대상 테이블(destinationTable)을 지정하거나 BigQuery Storage Read API(고성능 대용량 읽기)를 사용하세요.",
			SuggestedFixEn: "1) Set a destinationTable for large results or utilize the BigQuery Storage Read API.",
		}
	}

	if bqStreamingQuotaRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "bigquery",
			DriverLang:     driverLang,
			RootCause:      "BigQueryStreamingInsertQuota",
			ErrorClass:     "BigQuery_StreamingInsertQuota",
			SummaryKo:      fmt.Sprintf("[%s] BigQuery 스트리밍 인서트(insertAll) API 속도 제한 및 프로젝트 할당량 초과", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] BigQuery streaming insert quota or rate limit exceeded", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) BigQuery Storage Write API(권장)로 마이그레이션하거나 Cloud Storage 경유 일괄 적재(Load Job)로 전환하세요.",
			SuggestedFixEn: "1) Migrate to BigQuery Storage Write API or batch load via Cloud Storage Load Jobs.",
		}
	}

	if bqTableNotFoundLocRegex.MatchString(logs) {
		return &DBDriverAnalysis{
			Database:       "bigquery",
			DriverLang:     driverLang,
			RootCause:      "BigQueryTableNotFoundInLocation",
			ErrorClass:     "BigQuery_TableNotFoundInLocation",
			SummaryKo:      fmt.Sprintf("[%s] BigQuery 데이터셋/테이블 위치(리전) 불일치 (교차 리전 쿼리 불가)", strings.ToUpper(driverLang)),
			SummaryEn:      fmt.Sprintf("[%s] BigQuery table not found in requested location (cross-region query not allowed)", strings.ToUpper(driverLang)),
			SuggestedFixKo: "1) 클라이언트 설정의 'location'(예: 'asia-northeast3', 'US')이 대상 데이터셋의 생성 리전과 일치하는지 확인하세요.",
			SuggestedFixEn: "1) Ensure client query job location matches the BigQuery dataset location.",
		}
	}

	return nil
}
