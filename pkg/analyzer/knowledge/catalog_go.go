package knowledge

func init() {
	loadGoSemanticCatalog()
}

func loadGoSemanticCatalog() {
	entries := []SemanticCatalogEntry{
		// ==================== Go Runtime ====================
		{
			ErrorClass: "GoDeadlock",
			Language:   "Go",
			Category:   "Application",
			RootCause:  "GoDeadlock",
			SummaryKo:  "모든 활성 고루틴(Goroutine)이 채널 수신 또는 뮤텍스(Mutex) 락 대기 상태에 빠져 Go 런타임에 의해 프로세스가 즉시 강제 종료되었습니다 (all goroutines are asleep - deadlock!).",
			ActionKo:   "1) unbuffered 채널에서 읽기 고루틴 없이 쓰기를 시도하거나 그 반대인 상황을 점검하세요. 2) sync.Mutex 또는 RWMutex의 Lock() 후 Unlock() 누락(defer mu.Unlock() 필수)을 확인하세요. 3) sync.WaitGroup의 Add()와 Done() 카운터 불일치를 점검하세요.",
			SummaryEn:  "Go runtime fatal error: all goroutines are asleep - deadlock! (all goroutines blocked on channels or mutexes).",
			ActionEn:   "1) Inspect channel send/receive operations without active receivers. 2) Ensure defer mu.Unlock() is called. 3) Verify sync.WaitGroup Add/Done counts.",
			RootCauseChainKo: []string{
				"실행 중인 모든 고루틴이 상호 채널 I/O 또는 동기화 락(sync.Mutex) 대기에 진입함",
				"Go 런타임 스케줄러의 실행 큐(Runqueue)에 실행 가능한(runnable) 고루틴이 0개가 됨",
				"런타임이 데드락 상태를 감지하고 'fatal error: all goroutines are asleep - deadlock!'를 출력하며 즉시 강제 종료(abort)함",
			},
			RootCauseChainEn: []string{
				"All active goroutines entered blocking channel operations or mutex lock acquisition",
				"Go runtime scheduler observed zero runnable goroutines across all processor contexts (P)",
				"Runtime panic detector triggered immediate crash with 'all goroutines are asleep - deadlock!'",
			},
			InferredContextKo: "채널 버퍼 크기 부족, 고루틴 조기 종료로 인한 채널 수신자 소멸 또는 뮤텍스 잠금 해제 누락으로 시스템이 멈춘 상태입니다.",
			SuggestedFixKo:    "1) 뮤텍스 잠금 직후 'defer mu.Unlock()'을 반드시 선언하세요. 2) 채널 통신 시 'select { case ch <- val: case <-ctx.Done(): return }' 패턴을 사용하여 타임아웃/취소 탈출구를 마련하세요.",
		},
		{
			ErrorClass: "GoConcurrentMapAccess",
			Language:   "Go",
			Category:   "Application",
			RootCause:  "GoConcurrentMapAccess",
			SummaryKo:  "여러 고루틴이 락 동기화 없이 표준 Go map에 동시 쓰기를 시도하여 런타임이 프로세스를 즉시 사살했습니다 (fatal error: concurrent map writes).",
			ActionKo:   "1) 표준 map 대신 'sync.RWMutex'로 맵 읽기/쓰기를 보호하세요. 2) 동시성이 높은 캐시에는 'sync.Map'을 사용하세요. 3) 'go test -race' 또는 빌드 시 '-race' 플래그를 사용하여 데이터 레이스를 사전 탐지하세요.",
			SummaryEn:  "Go runtime fatal error: concurrent map writes / concurrent map read and map write.",
			ActionEn:   "1) Protect maps with sync.RWMutex. 2) Use sync.Map for read-heavy concurrent caches. 3) Compile with 'go build -race' to detect race conditions.",
			RootCauseChainKo: []string{
				"복수의 고루틴이 락 보호 없이 동일한 Go 내장 map 객체에 동시 접근함",
				"최소 하나 이상의 고루틴이 map 버킷(Bucket)에 쓰기(Write/Delete) 작업을 수행함",
				"Go 런타임의 동시성 감지 비트 검사기가 메모리 오염 방지를 위해 recover 불가능한 'fatal error: concurrent map writes'로 프로세스를 즉시 강제 종료함",
			},
			RootCauseChainEn: []string{
				"Multiple goroutines concurrently accessed a standard Go map without synchronization",
				"At least one goroutine attempted write mutation while another read or wrote",
				"Go runtime race detector aborted the process immediately with 'fatal error: concurrent map writes'",
			},
			InferredContextKo: "웹 요청 핸들러마다 고루틴이 생성되는 환경에서 공통 세션/캐시 맵에 락 없이 쓰기를 시도하여 발생한 동시성 결함입니다.",
			SuggestedFixKo:    "1) 구조체에 'sync.RWMutex'를 임베딩하고 읽기는 'mu.RLock()', 쓰기는 'mu.Lock()'을 적용하세요. 2) 읽기가 압도적인 경우 'sync.Map'을 사용하세요.",
		},
		{
			ErrorClass: "GoNilPointerDereference",
			Language:   "Go",
			Category:   "Application",
			RootCause:  "GoNilPointerDereference",
			SummaryKo:  "초기화되지 않은 nil 포인터 또는 nil 인터페이스의 구조체 필드나 메서드를 역참조하여 런타임 패닉이 발생했습니다 (panic: runtime error: invalid memory address or nil pointer dereference).",
			ActionKo:   "1) 함수 반환 에러 검사('if err != nil')를 누락하지 마세요. 2) 포인터 참조 전 'if ptr != nil' 검증을 추가하세요. 3) 웹 핸들러 최상단에 'defer func() { if r := recover(); r != nil { ... } }()' 미들웨어를 적용하세요.",
			SummaryEn:  "Go runtime panic: invalid memory address or nil pointer dereference.",
			ActionEn:   "1) Always check returned errors before using pointers ('if err != nil { return err }'). 2) Add nil guards. 3) Apply recovery middleware in HTTP handlers.",
			RootCauseChainKo: []string{
				"함수가 실패하여 nil 포인터와 error를 반환했으나 호출자가 error 검사를 생략함",
				"nil 상태인 포인터 변수의 필드 또는 메서드를 직접 참조함",
				"Go 런타임이 무효 메모리 접근을 감지하고 nil pointer dereference 패닉을 발생시킴",
				"상위 호출자에 recover() 핸들러가 없어 스택트레이스를 stderr에 출력하고 비정상 종료됨",
			},
			RootCauseChainEn: []string{
				"Function returned nil pointer along with an error that went unchecked",
				"Caller attempted dereference on the zero-valued nil pointer",
				"Runtime panic triggered; unwound goroutine stack without recover()",
			},
			InferredContextKo: "DB 조회나 HTTP 클라이언트 호출에서 반환된 error를 무시하고 결과 포인터의 필드를 바로 읽으려다 발생했습니다.",
			SuggestedFixKo:    "1) 'res, err := client.Do(req); if err != nil { return err }; defer res.Body.Close()'와 같이 항상 error를 먼저 검사하세요.",
		},
		{
			ErrorClass: "GoIndexOutOfRange",
			Language:   "Go",
			Category:   "Application",
			RootCause:  "GoIndexOutOfRange",
			SummaryKo:  "슬라이스(Slice) 또는 배열의 실제 길이(len)를 벗어난 인덱스에 접근하여 런타임 패닉이 발생했습니다 (panic: runtime error: index out of range).",
			ActionKo:   "1) 슬라이스 인덱스 접근 전 'if index < len(slice)' 경계 검사를 수행하세요. 2) 슬라이스 슬라이싱([low:high]) 시 high가 cap(slice)을 초과하지 않는지 확인하세요.",
			SummaryEn:  "Go runtime panic: runtime error: index out of range [x] with length y.",
			ActionEn:   "1) Check slice length before direct indexing ('if i < len(slice)'). 2) Ensure slicing bounds do not exceed capacity.",
			RootCauseChainKo: []string{
				"애플리케이션이 빈 슬라이스 또는 크기 n인 슬라이스의 n 이상 위치를 인덱싱함",
				"Go 런타임 바운드 체커(Bounds Check)가 슬라이스 길이 초과 감지",
				"panic: runtime error: index out of range 발생 및 미처리로 프로세스 크래시",
			},
			InferredContextKo: "문자열 split 결과나 정규식 매칭 결과의 배열 길이를 확인하지 않고 [0] 또는 [1] 요소를 접근하여 발생했습니다.",
			SuggestedFixKo:    "1) 'if len(parts) >= 2 { val = parts[1] }' 패턴으로 반드시 길이를 사전에 확인하세요.",
		},
		{
			ErrorClass: "GoContextDeadlineExceeded",
			Language:   "Go",
			Category:   "Dependency",
			RootCause:  "GoContextDeadlineExceeded",
			SummaryKo:  "데이터베이스 쿼리, 외부 HTTP 호출 또는 gRPC RPC 처리가 context.WithTimeout에 지정된 마감 시간을 초과했습니다 (context deadline exceeded).",
			ActionKo:   "1) context 타임아웃 시간(예: 3초 -> 10초)을 늘리거나 호출 대상 서비스의 지연 시간을 최적화하세요. 2) 외부 I/O 슬로우 쿼리 및 네트워크 레이턴시를 점검하세요.",
			SummaryEn:  "Go context.DeadlineExceeded: operation canceled after reaching context timeout ceiling.",
			ActionEn:   "1) Increase context timeout duration. 2) Optimize downstream database queries or API latency. 3) Audit network bottlenecks.",
			RootCauseChainKo: []string{
				"호출자가 context.WithTimeout(ctx, duration)으로 시간 제한을 설정함",
				"다운스트림 DB 또는 원격 서비스의 응답 지연으로 타이머가 먼저 만료됨",
				"Go 런타임 context 채널(ctx.Done())이 닫히며 'context deadline exceeded' 에러 반환",
			},
			InferredContextKo: "DB 커넥션 풀 경합 또는 외부 결제 API 무응답으로 클라이언트 요청의 허용 타임아웃이 초과되었습니다.",
			SuggestedFixKo:    "1) 호출 지점에 적절한 타임아웃(최소 5~10초)을 부여하고, circuit breaker(Hystrix-Go 또는 go-resilience)를 적용하세요.",
		},
		{
			ErrorClass: "GoBrokenPipe",
			Language:   "Go",
			Category:   "Infrastructure",
			RootCause:  "GoBrokenPipe",
			SummaryKo:  "클라이언트가 응답을 받기 전에 브라우저를 닫거나 연결을 끊어 소켓 쓰기 중 'broken pipe' 또는 'connection reset by peer' 오류가 발생했습니다.",
			ActionKo:   "1) 대용량 응답 전송 시 클라이언트 조기 이탈 여부를 점검하세요. 2) HTTP 미들웨어에서 'broken pipe' 에러를 무시하거나 경고(Warn) 수준으로 로깅하세요.",
			SummaryEn:  "Go network I/O error: write: broken pipe or connection reset by peer.",
			ActionEn:   "1) Handle client disconnections gracefully in streaming endpoints. 2) Downgrade broken pipe logs to Warning level.",
			RootCauseChainKo: []string{
				"서버가 클라이언트 TCP 소켓으로 대용량 HTTP 응답 데이터를 스트리밍 중",
				"클라이언트(브라우저/앱)가 페이지를 새로고침하거나 타임아웃으로 TCP 소켓을 먼저 닫음",
				"서버의 net.Conn.Write()가 커널로부터 EPIPE(Broken pipe) 신호를 수신함",
			},
			InferredContextKo: "대용량 파일 다운로드 또는 SSE 스트리밍 중 사용자가 브라우저 탭을 닫아 발생한 일반적인 네트워크 단절 현상입니다.",
			SuggestedFixKo:    "1) 'if errors.Is(err, syscall.EPIPE) { return }'로 처리하여 불필요한 패닉/치명적 로깅을 억제하세요.",
		},

		// ==================== Additional Enterprise Go & GORM ====================
		{
			ErrorClass: "sql: no rows in result set",
			Language:   "Go",
			Category:   "Application",
			RootCause:  "GoSQLNoRows",
			SummaryKo:  "데이터베이스 단일 행 조회(QueryRow) 결과 일치하는 레코드가 존재하지 않습니다 (sql.ErrNoRows / gorm.ErrRecordNotFound).",
			ActionKo:   "1) 'errors.Is(err, sql.ErrNoRows)' 검사를 통해 에러를 캐치하고 404 Not Found 또는 빈 객체로 안전하게 처리하세요. 2) WHERE 조건에 전달된 파라미터가 유효한지 점검하세요.",
			SummaryEn:  "Go database/sql: sql.ErrNoRows / gorm.ErrRecordNotFound: query expected rows but none were returned.",
			ActionEn:   "1) Catch with errors.Is(err, sql.ErrNoRows) and return clean 404 responses. 2) Validate query filter parameters.",
			RootCauseChainKo: []string{
				"애플리케이션이 db.QueryRow() 또는 gorm.First()로 특정 키의 레코드를 조회함",
				"데이터베이스 인덱스 스캔 결과 일치하는 조건의 튜플이 0개 반환됨",
				"드라이버가 sql.ErrNoRows를 반환하고 미처리 시 상위 로직에서 500 내부 서버 오류를 발생시킴",
			},
			InferredContextKo: "존재하지 않는 회원 번호나 삭제된 게시글 ID를 조회할 때 에러 분기 처리가 누락되어 발생했습니다.",
			SuggestedFixKo:    "1) 'if errors.Is(err, gorm.ErrRecordNotFound) { return c.Status(404).JSON(fiber.Map{\"error\": \"not found\"}) }' 방어 코드를 작성하세요.",
		},
		{
			ErrorClass: "redis: nil",
			Language:   "Go",
			Category:   "Application",
			RootCause:  "GoRedisNil",
			SummaryKo:  "Go-Redis(go-redis/v9) 클라이언트가 키를 조회했으나 캐시 키가 존재하지 않거나 만료되었습니다 (redis.Nil).",
			ActionKo:   "1) 'errors.Is(err, redis.Nil)'로 캐시 미스(Cache Miss)를 정상적인 비즈니스 흐름으로 분기하고 DB에서 데이터를 재조회하세요. 2) 불필요하게 패닉(Panic)을 일으키지 않도록 점검하세요.",
			SummaryEn:  "Go-Redis redis.Nil: requested key does not exist in Redis cache (cache miss).",
			ActionEn:   "1) Treat errors.Is(err, redis.Nil) as a normal cache miss; fetch from DB and populate cache. 2) Avoid panicking on nil keys.",
			RootCauseChainKo: []string{
				"애플리케이션이 redisClient.Get(ctx, key).Result() 호출",
				"Redis 서버가 해당 키를 찾지 못하고 (nil) 벌크 문자열 응답 반환",
				"go-redis 라이브러리가 redis.Nil 에러를 생성함",
			},
			InferredContextKo: "캐시 만료(TTL)로 인한 자연스러운 캐시 미스 상황에서 nil 에러 검사를 생략하고 패닉을 발생시켜 서버가 크래시되었습니다.",
			SuggestedFixKo:    "1) 'if errors.Is(err, redis.Nil) { val = fetchFromDB(); redisClient.Set(ctx, key, val, ttl) }' 캐시 어사이드(Cache-Aside) 패턴을 적용하세요.",
		},
		{
			ErrorClass: "gorm.ErrDuplicatedKey",
			Language:   "Go",
			Category:   "Application",
			RootCause:  "GoGormDuplicateKey",
			SummaryKo:  "GORM 실행 중 유니크 제약 조건(Unique Key) 위반이 발생했습니다 (duplicated key not allowed).",
			ActionKo:   "1) GORM 'clause.OnConflict{DoNothing: true}' 또는 DoUpdates를 활용하여 Upsert를 수행하세요. 2) 중복 에러 발생 시 HTTP 409 Conflict로 안전하게 변환하세요.",
			SummaryEn:  "gorm.ErrDuplicatedKey: unique constraint violation during GORM Create() operation.",
			ActionEn:   "1) Use clause.OnConflict for Upsert logic. 2) Map duplicate key errors to HTTP 409 Conflict.",
			RootCauseChainKo: []string{
				"GORM db.Create(&model) 실행 시 SQL INSERT 발행",
				"데이터베이스 고유 인덱스에서 키 중복 발생",
				"GORM이 gorm.ErrDuplicatedKey 오류를 반환함",
			},
			InferredContextKo: "동일한 식별자로 동시 트랜잭션이 생성 작업을 수행하다 발생한 유니크 제약 충돌입니다.",
			SuggestedFixKo:    "1) 'db.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: \"email\"}}, DoNothing: true}).Create(&user)'를 적용하세요.",
		},
	}

	RegisterCatalogEntries(entries)
}
