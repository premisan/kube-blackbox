package knowledge

import (
	"regexp"
	"strings"
)

// DataInfraAnalysis stores findings from ClickHouse, ZooKeeper, Valkey, and deep PostgreSQL crashes.
type DataInfraAnalysis struct {
	Component      string // clickhouse, zookeeper, valkey, postgresql
	RootCause      string
	ErrorClass     string
	SummaryKo      string
	SummaryEn      string
	SuggestedFixKo string
	SuggestedFixEn string
}

var (
	// ClickHouse
	chMemoryLimitRegex     = regexp.MustCompile(`(?i)(?:DB::Exception:\s*Memory limit \(total\) exceeded|DB::Exception:\s*Memory limit \([^)]+\) exceeded|Memory limit .*? would exceed maximum)`)
	chTooManyPartsRegex    = regexp.MustCompile(`(?i)(?:DB::Exception:\s*Too many parts \(\d+\) in all data parts in table|Too many unmerged parts in table)`)
	chZkSessionLostRegex   = regexp.MustCompile(`(?i)(?:Coordination::Exception:\s*Connection lost|Coordination::Exception:\s*ZooKeeper session has expired|ZooKeeper session expired.*?: clickhouse)`)
	chReadOnlyReplicaRegex = regexp.MustCompile(`(?i)(?:DB::Exception:\s*Table is in readonly mode|Replica is in readonly mode because)`)

	// ZooKeeper
	zkSessionExpiredRegex = regexp.MustCompile(`(?i)(?:KeeperException\$SessionExpiredException|Session expired for client|SessionMovedException)`)
	zkDiskFullRegex       = regexp.MustCompile(`(?i)(?:java\.io\.IOException:\s*No space left on device.*?: zookeeper|Failed to write snap.*?: No space left on device|commit log .*?: No space left on device)`)
	zkQuorumLostRegex     = regexp.MustCompile(`(?i)(?:Leader election failed|Cannot open channel to \d+ in election|QuorumPeer.*?: Could not establish connection to server|Notification reconfig failed)`)

	// Valkey
	valkeyOOMRegex         = regexp.MustCompile(`(?i)(?:OOM command not allowed when used memory > 'maxmemory'.*?: valkey|valkey.*?: Out of memory allocating|OOM command not allowed when used memory > 'maxmemory')`)
	valkeyReadOnlyRegex    = regexp.MustCompile(`(?i)(?:READONLY You can't write against a read only replica|valkey.*?: Server is read-only)`)
	valkeyClusterDownRegex = regexp.MustCompile(`(?i)(?:CLUSTERDOWN The cluster is down|CLUSTERDOWN Hash slot not served)`)

	// PostgreSQL Deep
	pgTxidWraparoundRegex = regexp.MustCompile(`(?i)(?:database is not accepting commands to avoid wraparound data loss in database|database ".*?" must be vacuumed|HINT:\s*Stop the postmaster and vacuum that database in single-user mode)`)
	pgLockTimeoutRegex    = regexp.MustCompile(`(?i)(?:canceling statement due to lock timeout|ERROR:\s*55P03:\s*lock_not_available)`)
	pgStmtTimeoutRegex    = regexp.MustCompile(`(?i)(?:canceling statement due to statement timeout|ERROR:\s*57014:\s*query_canceled)`)
)

// AnalyzeDataInfraLogs inspects logs for ClickHouse, ZooKeeper, Valkey, and PostgreSQL crashes.
func AnalyzeDataInfraLogs(logs string) *DataInfraAnalysis {
	if strings.TrimSpace(logs) == "" {
		return nil
	}

	// 1. ClickHouse
	if chTooManyPartsRegex.MatchString(logs) {
		return &DataInfraAnalysis{
			Component:      "clickhouse",
			RootCause:      "ClickHouseTooManyParts",
			ErrorClass:     "ClickHouse_TooManyParts",
			SummaryKo:      "ClickHouse 테이블 데이터 파트(parts) 수 한도 초과 (소규모 INSERT 과다로 인한 머지 지연)",
			SummaryEn:      "ClickHouse too many unmerged data parts in table due to high-frequency small inserts",
			SuggestedFixKo: "1) 클라이언트에서 10,000건 이상 단위로 벌크(배치) INSERT를 수행하거나 Buffer 엔진 테이블을 사용하세요. 2) 'parts_to_delay_insert' 및 'parts_to_throw_insert' 설정을 점검하세요.",
			SuggestedFixEn: "1) Batch inserts into larger chunks (10,000+ rows) or use the Buffer table engine. 2) Tune parts_to_throw_insert in ClickHouse merge tree settings.",
		}
	}
	if chMemoryLimitRegex.MatchString(logs) {
		return &DataInfraAnalysis{
			Component:      "clickhouse",
			RootCause:      "ClickHouseMemoryLimit",
			ErrorClass:     "ClickHouse_MemoryLimitExceeded",
			SummaryKo:      "ClickHouse 서버 또는 쿼리 메모리 한도(max_server_memory_usage / max_memory_usage) 초과",
			SummaryEn:      "ClickHouse memory limit exceeded for query or server total",
			SuggestedFixKo: "1) 'max_server_memory_usage' 및 파드 메모리 제한을 증설하세요. 2) 대규모 JOIN/GROUP BY 쿼리에 'max_bytes_before_external_group_by' 디스크 오프로딩 설정을 활성화하세요.",
			SuggestedFixEn: "1) Increase max_server_memory_usage and pod memory limit. 2) Enable 'max_bytes_before_external_group_by' for spill-to-disk query execution.",
		}
	}
	if chZkSessionLostRegex.MatchString(logs) {
		return &DataInfraAnalysis{
			Component:      "clickhouse",
			RootCause:      "ClickHouseZooKeeperSessionLost",
			ErrorClass:     "ClickHouse_ZKSessionLost",
			SummaryKo:      "ClickHouse가 ZooKeeper/Keeper 클러스터와의 세션 하트비트를 상실하여 복제본이 중단됨",
			SummaryEn:      "ClickHouse lost ZooKeeper coordination session, halting replicated engine tables",
			SuggestedFixKo: "1) ZooKeeper 파드의 가동 상태와 네트워크 레이턴시를 점검하세요. 2) clickhouse 설정의 'operation_timeout_ms' 및 'session_timeout_ms'를 상향 조정하세요.",
			SuggestedFixEn: "1) Check ZooKeeper cluster status and network latency. 2) Increase session_timeout_ms in ClickHouse zookeeper configuration.",
		}
	}
	if chReadOnlyReplicaRegex.MatchString(logs) {
		return &DataInfraAnalysis{
			Component:      "clickhouse",
			RootCause:      "ClickHouseReadOnlyReplica",
			ErrorClass:     "ClickHouse_ReadOnlyReplica",
			SummaryKo:      "ClickHouse 복제본 메타데이터 동기화 실패로 테이블이 읽기 전용(Readonly) 모드로 전환됨",
			SummaryEn:      "ClickHouse table switched to read-only mode due to replica synchronization failure",
			SuggestedFixKo: "1) 'SYSTEM RESTART REPLICA <table_name>'을 실행하여 복제 세션을 재초기화하세요. 2) ZooKeeper 메타데이터 불일치 여부를 점검하세요.",
			SuggestedFixEn: "1) Run 'SYSTEM RESTART REPLICA <table_name>'. 2) Verify ZooKeeper replica metadata consistency.",
		}
	}

	// 2. ZooKeeper
	if zkDiskFullRegex.MatchString(logs) {
		return &DataInfraAnalysis{
			Component:      "zookeeper",
			RootCause:      "ZooKeeperDiskFull",
			ErrorClass:     "ZooKeeper_DiskSpaceExhausted",
			SummaryKo:      "ZooKeeper 트랜잭션 로그(dataLogDir) 또는 스냅샷(dataDir) 디스크 공간 고갈",
			SummaryEn:      "ZooKeeper transaction log (dataLogDir) or snapshot disk space exhausted",
			SuggestedFixKo: "1) 스토리지 PVC 볼륨 용량을 즉시 증설하세요. 2) 'autopurge.purgeInterval=1' 및 'autopurge.snapRetainCount=3'으로 오래된 스냅샷 자동 정리를 활성화하세요.",
			SuggestedFixEn: "1) Expand ZooKeeper storage volume PVC. 2) Enable automatic purge with autopurge.purgeInterval=1 and autopurge.snapRetainCount=3.",
		}
	}
	if zkQuorumLostRegex.MatchString(logs) {
		return &DataInfraAnalysis{
			Component:      "zookeeper",
			RootCause:      "ZooKeeperQuorumLost",
			ErrorClass:     "ZooKeeper_QuorumLost",
			SummaryKo:      "ZooKeeper 앙상블 리더 선출 실패 또는 쿼럼(과반수 노드) 상실",
			SummaryEn:      "ZooKeeper ensemble quorum lost or leader election failure",
			SuggestedFixKo: "1) 과반수(N/2 + 1)의 ZooKeeper 노드가 정상 실행 중인지 확인하세요. 2) 앙상블 간 2888/3888 포트 통신 및 NetworkPolicy를 점검하세요.",
			SuggestedFixEn: "1) Ensure a majority (N/2 + 1) of ZooKeeper nodes are healthy. 2) Verify ports 2888/3888 are reachable across all nodes.",
		}
	}
	if zkSessionExpiredRegex.MatchString(logs) {
		return &DataInfraAnalysis{
			Component:      "zookeeper",
			RootCause:      "ZooKeeperSessionExpired",
			ErrorClass:     "ZooKeeper_SessionExpired",
			SummaryKo:      "ZooKeeper 클라이언트 세션 만료 (네트워크 파티션 또는 GC 일시정지로 인한 하트비트 누락)",
			SummaryEn:      "ZooKeeper client session expired due to network partition or long JVM GC pauses",
			SuggestedFixKo: "1) 클라이언트 JVM 힙 GC 튜닝(G1GC)을 적용하여 긴 STW(Stop-The-World)를 방지하세요. 2) tickTime 및 maxSessionTimeout 설정을 상향 조정하세요.",
			SuggestedFixEn: "1) Tune client JVM GC to eliminate long Stop-The-World pauses. 2) Increase tickTime and maxSessionTimeout.",
		}
	}

	// 3. Valkey
	if valkeyOOMRegex.MatchString(logs) {
		return &DataInfraAnalysis{
			Component:      "valkey",
			RootCause:      "ValkeyOOM",
			ErrorClass:     "Valkey_OOM_MaxMemory",
			SummaryKo:      "Valkey 인메모리 사용량이 maxmemory 한도에 도달하여 신규 쓰기 거부",
			SummaryEn:      "Valkey maxmemory limit reached; write commands rejected with OOM",
			SuggestedFixKo: "1) valkey.conf에서 'maxmemory' 한도를 증설하거나 파드 메모리를 확장하세요. 2) 'maxmemory-policy allkeys-lru' 등 만료 키 축출 정책을 적용하세요.",
			SuggestedFixEn: "1) Increase 'maxmemory' in valkey.conf or increase pod memory. 2) Configure eviction policy (e.g. maxmemory-policy allkeys-lru).",
		}
	}
	if valkeyReadOnlyRegex.MatchString(logs) {
		return &DataInfraAnalysis{
			Component:      "valkey",
			RootCause:      "ValkeyReadOnlyReplica",
			ErrorClass:     "Valkey_ReadOnlyReplica",
			SummaryKo:      "Valkey 읽기 전용 복제본(ReadOnly Replica)에 쓰기 명령 실행 시도",
			SummaryEn:      "Attempted write command against a read-only Valkey replica",
			SuggestedFixKo: "1) 클라이언트 연결 엔드포인트를 마스터(Primary) 서비스로 변경하세요. 2) 센티널(Sentinel) 또는 클러스터 페일오버 상태를 확인하세요.",
			SuggestedFixEn: "1) Direct write traffic to the Valkey Primary endpoint. 2) Check Sentinel or Cluster failover state.",
		}
	}
	if valkeyClusterDownRegex.MatchString(logs) {
		return &DataInfraAnalysis{
			Component:      "valkey",
			RootCause:      "ValkeyClusterDown",
			ErrorClass:     "Valkey_ClusterDown",
			SummaryKo:      "Valkey 클러스터 슬롯 미할당 또는 마스터 노드 과반수 다운 (CLUSTERDOWN)",
			SummaryEn:      "Valkey cluster is down; hash slots not fully covered or quorum lost",
			SuggestedFixKo: "1) 'valkey-cli cluster check <node-ip>:6379'로 슬롯 커버리지를 진단하세요. 2) 다운된 마스터 노드를 재시작하거나 슬롯 재분배(reshard)를 수행하세요.",
			SuggestedFixEn: "1) Run 'valkey-cli cluster check' to inspect slot allocation. 2) Restart failed masters or reshard unassigned slots.",
		}
	}

	// 4. PostgreSQL Deep
	if pgTxidWraparoundRegex.MatchString(logs) {
		return &DataInfraAnalysis{
			Component:      "postgresql",
			RootCause:      "PostgresTxidExhaustion",
			ErrorClass:     "Postgres_TxidWraparoundEmergency",
			SummaryKo:      "PostgreSQL 트랜잭션 ID 래핑(TXID Wraparound) 방지를 위해 데이터베이스가 비상 잠금(읽기 전용)됨",
			SummaryEn:      "PostgreSQL stopped accepting writes to prevent catastrophic TXID wraparound data loss",
			SuggestedFixKo: "1) 즉시 단일 사용자 모드(postgres --single) 또는 비상 유지보수로 진입하여 'VACUUM FREEZE ANALYZE'를 수행하세요. 2) autovacuum_freeze_max_age 설정을 점검하세요.",
			SuggestedFixEn: "1) Run 'VACUUM FREEZE ANALYZE' in single-user mode immediately. 2) Tune autovacuum settings to ensure aggressive freezing.",
		}
	}
	if pgLockTimeoutRegex.MatchString(logs) {
		return &DataInfraAnalysis{
			Component:      "postgresql",
			RootCause:      "PostgresLockTimeout",
			ErrorClass:     "Postgres_LockTimeout",
			SummaryKo:      "PostgreSQL 테이블/행 락(Lock) 획득 대기 시간 초과로 쿼리가 취소됨",
			SummaryEn:      "PostgreSQL query canceled due to lock_timeout waiting for table or row lock",
			SuggestedFixKo: "1) 장시간 실행 중인 트랜잭션('pg_stat_activity')의 배타적 DDL/DML 락 경합을 점검하세요. 2) 'lock_timeout' 값을 최적화하세요.",
			SuggestedFixEn: "1) Check 'pg_stat_activity' for blocking transactions holding conflicting locks. 2) Optimize lock_timeout.",
		}
	}
	if pgStmtTimeoutRegex.MatchString(logs) {
		return &DataInfraAnalysis{
			Component:      "postgresql",
			RootCause:      "PostgresStatementTimeout",
			ErrorClass:     "Postgres_StatementTimeout",
			SummaryKo:      "PostgreSQL 개별 쿼리 실행 시간 한도(statement_timeout) 초과로 쿼리가 취소됨",
			SummaryEn:      "PostgreSQL statement canceled due to statement_timeout",
			SuggestedFixKo: "1) 느린 쿼리에 인덱스를 추가하거나 EXPLAIN ANALYZE로 실행 계획을 튜닝하세요. 2) 긴 배치의 경우 세션 레벨에서 statement_timeout을 조정하세요.",
			SuggestedFixEn: "1) Add indexes or optimize query plan with EXPLAIN ANALYZE. 2) Adjust statement_timeout for long-running batch jobs.",
		}
	}

	return nil
}
