package knowledge

func init() {
	loadDotNetSemanticCatalog()
}

func loadDotNetSemanticCatalog() {
	entries := []SemanticCatalogEntry{
		// ==================== .NET CLR Core Exceptions ====================
		{
			ErrorClass: "NullReferenceException",
			Language:   "DotNet",
			Category:   "Application",
			RootCause:  "DotNetNullReference",
			SummaryKo:  "초기화되지 않은 null 객체 레퍼런스의 속성(Property) 또는 메서드에 접근하여 System.NullReferenceException이 발생했습니다.",
			ActionKo:   "1) C# 널 조건부 연산자('obj?.Property') 또는 널 병합 연산자('obj ?? defaultValue')를 적용하세요. 2) C# 8.0+ Nullable Reference Types('#nullable enable')을 활성화하여 컴파일 타임에 null 가능성을 검증하세요. 3) 메서드 인자에 'ArgumentNullException.ThrowIfNull(param)' 가드를 추가하세요.",
			SummaryEn:  "System.NullReferenceException: attempted to dereference a null object reference.",
			ActionEn:   "1) Apply C# null-conditional ('?.') or null-coalescing ('??') operators. 2) Enable C# Nullable Reference Types (#nullable enable). 3) Add ArgumentNullException.ThrowIfNull guards.",
			RootCauseChainKo: []string{
				"애플리케이션 소스코드에서 아직 인스턴스화되지 않았거나 null을 반환한 객체 참조",
				".NET CLR(Common Language Runtime) 실행 엔진이 유효하지 않은 메모리 주소(0x0) 역참조 감지",
				"System.NullReferenceException 예외가 발생하고 catch되지 않아 최상위 스레드가 중단되고 프로세스 종료",
			},
			RootCauseChainEn: []string{
				"Application code accessed a member of an uninstantiated or null-valued reference type",
				".NET CLR execution engine intercepted invalid memory address dereference",
				"System.NullReferenceException propagated unhandled, aborting the managed thread and process",
			},
			InferredContextKo: "의존성 주입(DI) 서비스 등록 누락, LINQ FirstOrDefault() 조회 결과 미존재 또는 역직렬화 시 필수 필드 누락으로 발생했습니다.",
			SuggestedFixKo:    "1) 'var name = user?.Profile?.Name ?? \"Unknown\";' 형태로 방어 코드를 작성하세요. 2) csproj 파일에 '<Nullable>enable</Nullable>'을 추가하여 빌드 시점에 경고를 잡으세요.",
		},
		{
			ErrorClass: "OutOfMemoryException",
			Language:   "DotNet",
			Category:   "Application",
			RootCause:  "DotNetOOM",
			SummaryKo:  ".NET CLR 가비지 컬렉터(GC)가 추가 메모리를 할당할 수 없어 System.OutOfMemoryException이 발생했습니다 (LOH 파편화 또는 cgroup 한도 도달).",
			ActionKo:   "1) 파드 spec.resources.limits.memory를 증설하세요. 2) 85KB 이상 대형 객체 힙(LOH, Large Object Heap) 할당을 줄이기 위해 'ArrayPool<T>.Shared'를 사용하세요. 3) 'DOTNET_GCHeapHardLimit' 환경변수를 컨테이너 Limit에 맞추어 설정하세요.",
			SummaryEn:  "System.OutOfMemoryException: .NET CLR was unable to allocate contiguous memory (LOH fragmentation or cgroup limit).",
			ActionEn:   "1) Increase container memory limit. 2) Use ArrayPool<T>.Shared to mitigate LOH allocations. 3) Set DOTNET_GCHeapHardLimit in container environment.",
			RootCauseChainKo: []string{
				"대용량 바이트 배열 할당, 문자열 결합 또는 캐시 누적으로 .NET 가상 메모리 급증",
				".NET GC가 Generation 2 수집을 시도했으나 LOH(Large Object Heap) 파편화로 연속 메모리 블록 확보 실패",
				"System.OutOfMemoryException이 발생하며 CLR 런타임이 즉시 강제 종료됨",
			},
			InferredContextKo: "대용량 파일 업로드/다운로드 버퍼를 byte[]로 직접 할당하여 LOH 메모리가 고갈된 전형적인 .NET 메모리 장애입니다.",
			SuggestedFixKo:    "1) 'byte[] buffer = ArrayPool<byte>.Shared.Rent(size); try { ... } finally { ArrayPool<byte>.Shared.Return(buffer); }' 패턴을 적용하세요. 2) 파드 환경변수에 'DOTNET_gcServer=1' 및 'DOTNET_GCHeapHardLimitPercent=75'를 지정하세요.",
		},
		{
			ErrorClass: "StackOverflowException",
			Language:   "DotNet",
			Category:   "Application",
			RootCause:  "DotNetStackOverflow",
			SummaryKo:  "재귀 호출 종료 조건 누락 또는 C# 프로퍼티 getter/setter 순환 참조로 호출 스택이 고갈되었습니다 (System.StackOverflowException).",
			ActionKo:   "1) C# 자동 구현 프로퍼티('public int Age { get => Age; }' -> 무한 재귀)의 오탈자를 점검하세요. 2) 재귀 함수의 종료 조건을 확인하세요. (참고: .NET에서 StackOverflowException은 catch 블록으로 잡을 수 없습니다).",
			SummaryEn:  "System.StackOverflowException: execution stack exhausted due to unbounded recursion or property getter loop.",
			ActionEn:   "1) Check for property getter recursive loops ('get => Age'). 2) Verify recursion termination conditions. (StackOverflowException cannot be caught).",
			RootCauseChainKo: []string{
				"C# 프로퍼티 접근자 또는 재귀 알고리즘이 자기 자신을 끝없이 호출함",
				".NET CLR 스레드의 스택 공간(기본 1MB)이 프레임 누적으로 완전히 소진됨",
				"System.StackOverflowException이 발생하며 프로세스가 안전을 위해 즉시 강제 중단됨",
			},
			InferredContextKo: "C# 프로퍼티 선언 시 백킹 필드(_age) 대신 프로퍼티 자체(Age)를 반환하도록 작성하여 발생한 런타임 무한 루프입니다.",
			SuggestedFixKo:    "1) 프로퍼티 선언부를 점검하세요: 'public int Age { get => _age; set => _age = value; }'. 2) 재귀 호출을 Queue/Stack 기반 루프로 전환하세요.",
		},

		// ==================== ASP.NET Core & Entity Framework Core ====================
		{
			ErrorClass: "DbUpdateException",
			Language:   "DotNet",
			Category:   "Application",
			RootCause:  "DotNetEFDbUpdateException",
			SummaryKo:  "Entity Framework Core가 데이터베이스에 변경 사항(SaveChanges)을 커밋하는 중 제약 조건(외래키, 유니크, NOT NULL) 위반으로 실패했습니다.",
			ActionKo:   "1) 'ex.InnerException'의 실제 SQL 에러(Unique constraint violation 등)를 확인하세요. 2) 엔티티 모델의 필수 프로퍼티와 DB 스키마 간 일치 여부를 점검하세요. 3) 중복 데이터 삽입 방지 검증을 추가하세요.",
			SummaryEn:  "Microsoft.EntityFrameworkCore.DbUpdateException: database constraint violation during SaveChanges().",
			ActionEn:   "1) Inspect ex.InnerException for the underlying SQL error. 2) Verify entity model constraints match database schema. 3) Add validation before calling SaveChanges.",
			RootCauseChainKo: []string{
				"DbContext.SaveChanges() 또는 SaveChangesAsync()가 SQL INSERT/UPDATE/DELETE 문을 일괄 발행함",
				"데이터베이스 엔진에서 유니크 제약 위반, 외래키 참조 무결성 위반 또는 NOT NULL 위반 반환",
				"EF Core가 DbUpdateException을 던지고 트랜잭션을 롤백함",
			},
			InferredContextKo: "동일한 고유 키(이메일, 주문번호)로 동시 생성 요청이 유입되어 발생한 EF Core 트랜잭션 오류입니다.",
			SuggestedFixKo:    "1) 'try { await context.SaveChangesAsync(); } catch (DbUpdateException ex) when (ex.InnerException is PostgresException or MySqlException) { ... }'로 세부 예외를 핸들링하세요.",
		},
		{
			ErrorClass: "DbUpdateConcurrencyException",
			Language:   "DotNet",
			Category:   "Application",
			RootCause:  "DotNetEFConcurrencyException",
			SummaryKo:  "낙관적 동시성 제어(Optimistic Concurrency) 충돌로 인해 다른 트랜잭션이 이미 수정한 레코드를 덮어쓰려다 실패했습니다 (DbUpdateConcurrencyException).",
			ActionKo:   "1) 엔티티의 동시성 토큰(RowVersion / [Timestamp])을 확인하세요. 2) 충돌 발생 시 최신 데이터를 재조회(ReloadAsync)하여 비즈니스 로직을 재시도하세요.",
			SummaryEn:  "Microsoft.EntityFrameworkCore.DbUpdateConcurrencyException: optimistic concurrency conflict during SaveChanges().",
			ActionEn:   "1) Audit concurrency tokens/RowVersion timestamps. 2) Catch exception, reload latest entity from DB, and retry.",
			RootCauseChainKo: []string{
				"두 개 이상의 요청이 동일한 엔티티를 동시에 조회하여 메모리에 로드함",
				"첫 번째 요청이 먼저 변경 사항을 DB에 커밋하고 RowVersion 타임스탬프를 갱신함",
				"두 번째 요청이 이전 RowVersion 값으로 UPDATE를 시도하다 0개 행이 갱신되어 DbUpdateConcurrencyException 발생",
			},
			InferredContextKo: "재고 차감이나 상태 변경 시 동시 요청 간의 경합으로 발생한 낙관적 락 충돌입니다.",
			SuggestedFixKo:    "1) 'foreach (var entry in ex.Entries) { await entry.ReloadAsync(); }'로 최신 상태를 반영 후 재시도 루프를 구성하세요.",
		},
		{
			ErrorClass: "InvalidOperationException: No service for type",
			Language:   "DotNet",
			Category:   "Configuration",
			RootCause:  "DotNetDIMissingService",
			SummaryKo:  "ASP.NET Core 의존성 주입(DI) 컨테이너에 등록되지 않은 인터페이스나 서비스를 생성자에서 주입받으려다 기동에 실패했습니다.",
			ActionKo:   "1) Program.cs에서 'builder.Services.AddScoped<IService, Service>()' 또는 'AddSingleton / AddTransient' 등록을 누락했는지 확인하세요. 2) 인터페이스와 구현 클래스 간의 생명주기(Scoped vs Singleton) 불일치를 점검하세요.",
			SummaryEn:  "System.InvalidOperationException: Unable to resolve service for type 'IService' while attempting to activate 'Controller'.",
			ActionEn:   "1) Register missing service in Program.cs (builder.Services.AddScoped/AddTransient/AddSingleton). 2) Audit DI lifetime scope mismatches.",
			RootCauseChainKo: []string{
				"ASP.NET Core Kestrel 호스트가 컨트롤러 또는 서비스 인스턴스화를 시작함",
				"내장 DI 컨테이너(IServiceProvider)가 생성자 매개변수에 선언된 인터페이스의 등록 구현체를 검색함",
				"서비스 디스크립터가 누락되어 'Unable to resolve service' InvalidOperationException 발생 및 호스트 기동 중단",
			},
			InferredContextKo: "신규 인터페이스 구현 후 Program.cs에 DI 서비스 등록을 누락하여 컨테이너가 배포 즉시 크래시된 상황입니다.",
			SuggestedFixKo:    "1) Program.cs에 'builder.Services.AddScoped<ITargetService, TargetService>();'를 추가하세요. 2) Singleton 서비스 안에서 Scoped 서비스를 주입하지 않도록 IServiceScopeFactory를 활용하세요.",
		},
		{
			ErrorClass: "HttpRequestException",
			Language:   "DotNet",
			Category:   "Dependency",
			RootCause:  "DotNetHttpRequestException",
			SummaryKo:  "HttpClient를 통한 외부 HTTP 호출 중 연결 실패, DNS 해석 불가 또는 SSL 핸드셰이크 오류가 발생했습니다 (System.Net.Http.HttpRequestException).",
			ActionKo:   "1) IHttpClientFactory를 사용하여 소켓 고갈(Socket Exhaustion)을 방지하세요. 2) Polly 라이브러리를 결합하여 재시도(Retry with backoff) 및 서킷 브레이커를 적용하세요. 3) 대상 서비스 주소와 포트 접근성을 점검하세요.",
			SummaryEn:  "System.Net.Http.HttpRequestException: outbound HTTP request failed (connection refused, DNS error, or timeout).",
			ActionEn:   "1) Use IHttpClientFactory to prevent socket exhaustion. 2) Integrate Polly for retry and circuit breaker policies. 3) Verify remote endpoint reachability.",
			RootCauseChainKo: []string{
				"애플리케이션이 HttpClient.SendAsync() 또는 GetAsync()로 원격 API 호출",
				"네트워크 단절, 방화벽 차단 또는 업스트림 서버 응답 없음으로 TCP 커넥션 수립 실패",
				"HttpRequestException이 발생하고 핸들링되지 않아 요청 처리가 실패함",
			},
			InferredContextKo: "new HttpClient()를 수시로 생성하여 TIME_WAIT 소켓이 고갈되었거나 외부 의존 서비스 장애로 통신이 단절되었습니다.",
			SuggestedFixKo:    "1) 'builder.Services.AddHttpClient(\"ClientName\").AddTransientHttpErrorPolicy(policy => policy.WaitAndRetryAsync(3, _ => TimeSpan.FromMilliseconds(500)));'를 적용하세요.",
		},
	}

	RegisterCatalogEntries(entries)
}
