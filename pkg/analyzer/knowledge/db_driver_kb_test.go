package knowledge

import (
	"testing"
)

func TestAnalyzeDBDriverLogs_MySQLTooManyConnections(t *testing.T) {
	// Java HikariCP / MySQL Connector/J
	javaLogs := `
2026-11-02 02:00:00.123 [main] ERROR com.zaxxer.hikari.pool.HikariPool - HikariPool-1 - Exception during pool initialization.
java.sql.SQLException: Data source rejected establishment of connection,  message from server: "Too many connections"
	at com.mysql.cj.jdbc.exceptions.SQLError.createSQLException(SQLError.java:129)
	at com.mysql.cj.jdbc.exceptions.SQLError.createCommunicationException(SQLError.java:115)
`
	res := AnalyzeDBDriverLogs(javaLogs)
	if res == nil {
		t.Fatal("expected non-nil result for MySQL too many connections (Java)")
	}
	if res.RootCause != "MySQLTooManyConnections" {
		t.Fatalf("expected MySQLTooManyConnections, got %s", res.RootCause)
	}
	if res.DriverLang != "java" {
		t.Fatalf("expected java, got %s", res.DriverLang)
	}
	if res.Database != "mysql" {
		t.Fatalf("expected mysql, got %s", res.Database)
	}

	// Python PyMySQL
	pyLogs := `
Traceback (most recent call last):
  File "app.py", line 15, in <module>
    conn = pymysql.connect(host='mysql', user='app', password='pwd', db='shop')
  File "/usr/local/lib/python3.11/site-packages/pymysql/__init__.py", line 94, in Connect
    return Connection(*args, **kwargs)
pymysql.err.OperationalError: (1040, 'Too many connections')
`
	resPy := AnalyzeDBDriverLogs(pyLogs)
	if resPy == nil || resPy.RootCause != "MySQLTooManyConnections" || resPy.DriverLang != "python" {
		t.Fatalf("unexpected result for Python PyMySQL: %+v", resPy)
	}
}

func TestAnalyzeDBDriverLogs_MySQLDeadlock(t *testing.T) {
	// Node.js mysql2
	nodeLogs := `
Error: ER_LOCK_DEADLOCK: Deadlock found when trying to get lock; try restarting transaction
    at PromisePool.query (/app/node_modules/mysql2/promise.js:356:22)
    at Object.transferFunds (/app/src/services/account.ts:88:14)
    code: 'ER_LOCK_DEADLOCK',
    errno: 1213,
    sqlState: '40001'
`
	res := AnalyzeDBDriverLogs(nodeLogs)
	if res == nil {
		t.Fatal("expected non-nil result for MySQL Deadlock (Node.js)")
	}
	if res.RootCause != "MySQLDeadlock" {
		t.Fatalf("expected MySQLDeadlock, got %s", res.RootCause)
	}
	if res.DriverLang != "nodejs" {
		t.Fatalf("expected nodejs, got %s", res.DriverLang)
	}
}

func TestAnalyzeDBDriverLogs_PostgresTooManyConnections(t *testing.T) {
	// Node pg / PostgreSQL 53300
	nodePgLogs := `
error: sorry, too many clients already
    at Parser.parseErrorMessage (/app/node_modules/pg-protocol/dist/parser.js:287:98)
    at Parser.handlePacket (/app/node_modules/pg-protocol/dist/parser.js:126:29)
  length: 88,
  severity: 'FATAL',
  code: '53300',
  file: 'proc.c',
  routine: 'InitProcess'
`
	res := AnalyzeDBDriverLogs(nodePgLogs)
	if res == nil {
		t.Fatal("expected non-nil result for PostgreSQL too many connections")
	}
	if res.RootCause != "PostgresTooManyConnections" {
		t.Fatalf("expected PostgresTooManyConnections, got %s", res.RootCause)
	}
	if res.DriverLang != "nodejs" {
		t.Fatalf("expected nodejs, got %s", res.DriverLang)
	}
}

func TestAnalyzeDBDriverLogs_PostgresInFailedTx(t *testing.T) {
	// Python psycopg2
	pyLogs := `
Traceback (most recent call last):
  File "repo.py", line 42, in fetch_user
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
psycopg2.errors.InFailedSqlTransaction: current transaction is aborted, commands ignored until end of transaction block
`
	res := AnalyzeDBDriverLogs(pyLogs)
	if res == nil {
		t.Fatal("expected non-nil result for PostgresInFailedSQLTransaction")
	}
	if res.RootCause != "PostgresInFailedSQLTransaction" {
		t.Fatalf("expected PostgresInFailedSQLTransaction, got %s", res.RootCause)
	}
	if res.DriverLang != "python" {
		t.Fatalf("expected python, got %s", res.DriverLang)
	}
}

func TestAnalyzeDBDriverLogs_ClickHouseSimultaneousQueries(t *testing.T) {
	// ClickHouse Code 202
	chLogs := `
2026-11-02 02:10:00 [ClickHouseClient] Query execution error:
Code: 202. DB::Exception: Too many simultaneous queries. Maximum: 100. (TOO_MANY_SIMULTANEOUS_QUERIES) (version 24.3.1.2672)
    at ClickHouseClient.query (/app/node_modules/@clickhouse/client/dist/index.js:145:12)
`
	res := AnalyzeDBDriverLogs(chLogs)
	if res == nil {
		t.Fatal("expected non-nil result for ClickHouse simultaneous queries")
	}
	if res.RootCause != "ClickHouseSimultaneousQueries" {
		t.Fatalf("expected ClickHouseSimultaneousQueries, got %s", res.RootCause)
	}
	if res.DriverLang != "nodejs" {
		t.Fatalf("expected nodejs, got %s", res.DriverLang)
	}
}

func TestAnalyzeDBDriverLogs_BigQueryPartitionFilterRequired(t *testing.T) {
	// BigQuery Python SDK
	pyLogs := `
Traceback (most recent call last):
  File "analytics.py", line 55, in run_aggregation
    query_job.result()
google.cloud.exceptions.BadRequest: 400 Cannot query over table 'project.dataset.events' without a filter over column(s) 'event_timestamp' that can be used for partition elimination
`
	res := AnalyzeDBDriverLogs(pyLogs)
	if res == nil {
		t.Fatal("expected non-nil result for BigQuery partition filter required")
	}
	if res.RootCause != "BigQueryPartitionFilterRequired" {
		t.Fatalf("expected BigQueryPartitionFilterRequired, got %s", res.RootCause)
	}
	if res.DriverLang != "python" {
		t.Fatalf("expected python, got %s", res.DriverLang)
	}
	if res.Database != "bigquery" {
		t.Fatalf("expected bigquery, got %s", res.Database)
	}
}

func TestAnalyzeDBDriverLogs_BigQueryBytesBilled(t *testing.T) {
	// BigQuery Java SDK
	javaLogs := `
com.google.cloud.bigquery.BigQueryException: Query exceeded limit for bytes billed: 107374182400. Limit was 10737418240.
	at com.google.cloud.bigquery.spi.v2.HttpBigQueryRpc.translate(HttpBigQueryRpc.java:112)
	at com.google.cloud.bigquery.BigQueryImpl.query(BigQueryImpl.java:345)
`
	res := AnalyzeDBDriverLogs(javaLogs)
	if res == nil {
		t.Fatal("expected non-nil result for BigQuery bytes billed limit")
	}
	if res.RootCause != "BigQueryBytesBilledLimitExceeded" {
		t.Fatalf("expected BigQueryBytesBilledLimitExceeded, got %s", res.RootCause)
	}
	if res.DriverLang != "java" {
		t.Fatalf("expected java, got %s", res.DriverLang)
	}
}

func TestAnalyzeDBDriverLogs_AdditionalCases(t *testing.T) {
	// MySQL CommunicationsLinkFailure (Java)
	javaCommLogs := `
com.mysql.cj.jdbc.exceptions.CommunicationsException: Communications link failure
The last packet successfully received from the server was 300,120 milliseconds ago. The last packet sent successfully to the server was 300,121 milliseconds ago.
	at com.mysql.cj.jdbc.exceptions.SQLError.createCommunicationsException(SQLError.java:174)
`
	resComm := AnalyzeDBDriverLogs(javaCommLogs)
	if resComm == nil || resComm.RootCause != "MySQLCommunicationsLinkFailure" || resComm.DriverLang != "java" {
		t.Fatalf("unexpected result for MySQLCommunicationsLinkFailure: %+v", resComm)
	}

	// PostgreSQL Deadlock (Python psycopg2)
	pyDeadlockLogs := `
Traceback (most recent call last):
  File "transfer.py", line 82, in do_transfer
    cursor.execute("UPDATE accounts SET balance = balance - 100 WHERE id = 1")
psycopg2.errors.DeadlockDetected: deadlock detected
DETAIL:  Process 12345 waits for ExclusiveLock on tuple (0, 1) of relation 16384 of database 16385; blocked by process 12346.
`
	resPgDeadlock := AnalyzeDBDriverLogs(pyDeadlockLogs)
	if resPgDeadlock == nil || resPgDeadlock.RootCause != "PostgresDeadlock" || resPgDeadlock.DriverLang != "python" {
		t.Fatalf("unexpected result for PostgresDeadlock: %+v", resPgDeadlock)
	}

	// ClickHouse Timeout Exceeded (Python clickhouse_driver)
	chTimeoutLogs := `
clickhouse_driver.errors.ServerException: Code: 159, DB::Exception: Timeout exceeded: elapsed 30.000123 seconds, maximum: 30. (TIMEOUT_EXCEEDED) (version 23.8.4.1)
`
	resChTimeout := AnalyzeDBDriverLogs(chTimeoutLogs)
	if resChTimeout == nil || resChTimeout.RootCause != "ClickHouseTimeoutExceeded" {
		t.Fatalf("unexpected result for ClickHouseTimeoutExceeded: %+v", resChTimeout)
	}

	// BigQuery ResponseTooLarge (Node.js)
	bqLargeLogs := `
Error: 400 Response too large to return with inline results. Set allowLargeResults or specify destination table.
    at /app/node_modules/@google-cloud/bigquery/build/src/bigquery.js:560:23
`
	resBqLarge := AnalyzeDBDriverLogs(bqLargeLogs)
	if resBqLarge == nil || resBqLarge.RootCause != "BigQueryResponseTooLarge" || resBqLarge.DriverLang != "nodejs" {
		t.Fatalf("unexpected result for BigQueryResponseTooLarge: %+v", resBqLarge)
	}

	// BigQuery TableNotFoundInLocation (Node.js)
	bqLocLogs := `
Error: Not found: Table my-gcp-project:analytics_kr.daily_metrics was not found in location US
    at /app/node_modules/@google-cloud/bigquery/build/src/table.js:312:15
`
	resBqLoc := AnalyzeDBDriverLogs(bqLocLogs)
	if resBqLoc == nil || resBqLoc.RootCause != "BigQueryTableNotFoundInLocation" || resBqLoc.DriverLang != "nodejs" {
		t.Fatalf("unexpected result for BigQueryTableNotFoundInLocation: %+v", resBqLoc)
	}
}
