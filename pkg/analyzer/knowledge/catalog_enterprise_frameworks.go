package knowledge

func init() {
	loadEnterpriseFrameworksCatalog()
}

func loadEnterpriseFrameworksCatalog() {
	entries := []SemanticCatalogEntry{
		// ==================== Resilience4j / Circuit Breakers ====================
		{
			ErrorClass: "CallNotPermittedException",
			Language:   "Java",
			Category:   "Dependency",
			RootCause:  "CircuitBreakerOpen",
			SummaryKo:  "원격 서비스 연속 실패로 서킷 브레이커가 열려(OPEN 상태) 신규 요청이 전면 차단되었습니다 (Resilience4j CallNotPermittedException).",
			ActionKo:   "1) 다운스트림 외부 의존 서비스의 장애 및 지연 상태를 확인하세요. 2) Fallback 메서드(@CircuitBreaker(fallbackMethod = \"...\"))를 구현하여 안전한 기본값을 반환하세요. 3) 서킷 브레이커 설정(failureRateThreshold, waitDurationInOpenState)을 점검하세요.",
			SummaryEn:  "io.github.resilience4j.circuitbreaker.CallNotPermittedException: CircuitBreaker is OPEN, rejecting execution.",
			ActionEn:   "1) Verify downstream dependent service health. 2) Implement fallback methods in @CircuitBreaker. 3) Review failureRateThreshold and waitDurationInOpenState.",
			RootCauseChainKo: []string{
				"호출 대상 다운스트림 서비스가 연속 타임아웃 또는 5xx 서버 오류를 반환함",
				"Resilience4j 서킷 브레이커가 최근 슬라이딩 윈도우 실패율(failureRateThreshold: 50%) 초과를 감지함",
				"서킷 상태가 OPEN으로 전이되어 후속 모든 클라이언트 요청을 CallNotPermittedException으로 즉시 차단함",
			},
			RootCauseChainEn: []string{
				"Downstream microservice returned repeated 5xx responses or timed out",
				"Resilience4j circuit breaker observed failure rate exceeding threshold",
				"Circuit transitioned to OPEN state, fast-failing subsequent calls with CallNotPermittedException",
			},
			InferredContextKo: "연쇄 장애(Cascading Failure)를 방지하기 위해 서킷 브레이커가 보호 모드로 진입하여 신규 외부 호출을 거부하고 있습니다.",
			SuggestedFixKo:    "1) application.yml에서 'resilience4j.circuitbreaker.instances.<name>.waitDurationInOpenState=10s' 및 'slidingWindowSize=100'을 조정하세요. 2) 클라이언트 서비스에 대체 캐시 데이터 반환 등 Fallback 로직을 적용하세요.",
		},
		{
			ErrorClass: "RequestNotPermittedException",
			Language:   "Java",
			Category:   "Infrastructure",
			RootCause:  "RateLimiterExceeded",
			SummaryKo:  "인입 요청량이 허용된 초당 호출 쿼터(limitForPeriod)를 초과하여 Resilience4j RateLimiter에 의해 차단되었습니다.",
			ActionKo:   "1) Resilience4j RateLimiter의 'limitForPeriod' 및 'limitRefreshPeriod'를 증설하세요. 2) 클라이언트에 지수 백오프 재시도 또는 429 Too Many Requests 응답을 전달하세요.",
			SummaryEn:  "io.github.resilience4j.ratelimiter.RequestNotPermittedException: RateLimiter does not permit further calls.",
			ActionEn:   "1) Increase limitForPeriod in RateLimiter config. 2) Implement client-side throttling or return HTTP 429 responses.",
			RootCauseChainKo: []string{
				"순간적인 트래픽 폭주로 초당 허용 요청량(Rate Limit)을 초과함",
				"RateLimiter 토큰 버킷이 소진되고 timeoutDuration 동안 토큰을 획득하지 못함",
				"RequestNotPermittedException이 발생하며 요청이 즉시 차단됨",
			},
			InferredContextKo: "외부 크롤러 인입 또는 배치 작업의 대량 요청으로 API 보호를 위한 Rate Limiting 임계치에 도달했습니다.",
			SuggestedFixKo:    "1) 'resilience4j.ratelimiter.instances.<name>.limitForPeriod=500'으로 상향하고 'timeoutDuration=100ms'로 버퍼링 시간을 부여하세요.",
		},

		// ==================== Spring Cloud & Feign & WebClient ====================
		{
			ErrorClass: "FeignException",
			Language:   "Java",
			Category:   "Dependency",
			RootCause:  "SpringCloudFeignFailure",
			SummaryKo:  "Spring Cloud OpenFeign을 통한 마이크로서비스 간 HTTP 통신 중 원격 서비스로부터 오류 응답(4xx 또는 5xx)을 수신했습니다.",
			ActionKo:   "1) 원격 마이크로서비스의 가동 상태와 응답 본문 에러 메시지를 확인하세요. 2) Feign 클라이언트에 'ErrorDecoder'를 등록하여 원격 예외를 비즈니스 예외로 변환하세요. 3) Feign 타임아웃(connectTimeout, readTimeout)을 점검하세요.",
			SummaryEn:  "feign.FeignException: HTTP error status received from remote microservice invocation.",
			ActionEn:   "1) Inspect downstream service logs for upstream errors. 2) Implement a custom Feign ErrorDecoder. 3) Adjust connectTimeout and readTimeout.",
			RootCauseChainKo: []string{
				"FeignClient 인터페이스 선언을 통해 원격 서비스 URL로 HTTP 요청 전송",
				"원격 서버가 400/404/500/502 등의 HTTP 오류 상태 코드와 에러 페이로드를 반환함",
				"기본 ErrorDecoder가 FeignException을 발생시키며 호출 스택으로 전파됨",
			},
			InferredContextKo: "MSA 내부 통신 중 결제 또는 유저 서비스가 비정상 응답을 반환하여 주문 서비스가 함께 실패한 연쇄 오류입니다.",
			SuggestedFixKo:    "1) application.yml에 'feign.client.config.default.connectTimeout=3000' 및 'readTimeout=5000'을 설정하세요. 2) Feign 전용 FallbackFactory를 등록하세요.",
		},
		{
			ErrorClass: "WebClientRequestException",
			Language:   "Java",
			Category:   "Dependency",
			RootCause:  "SpringWebClientConnectionFailed",
			SummaryKo:  "Spring WebFlux WebClient 비동기 요청 중 TCP 연결 거절(Connection Refused) 또는 DNS 해석 실패로 원격 서버에 접속하지 못했습니다.",
			ActionKo:   "1) 대상 서비스의 도메인/IP 및 포트 수신 대기 여부를 점검하세요. 2) k8s 클러스터 CoreDNS 상태 및 NetworkPolicy 인입 차단 여부를 확인하세요. 3) WebClient 타임아웃 설정을 점검하세요.",
			SummaryEn:  "org.springframework.web.reactive.function.client.WebClientRequestException: failed to connect to remote server.",
			ActionEn:   "1) Verify target hostname and port reachability. 2) Inspect cluster CoreDNS resolution and NetworkPolicies. 3) Audit HttpClient timeout configs.",
			RootCauseChainKo: []string{
				"WebClient가 비동기 논블로킹 Netty 채널을 통해 원격 엔드포인트로 소켓 연결을 시도함",
				"원격 서버가 다운되었거나 네트워크 정책에 의해 패킷이 드롭되어 연결 수립 실패",
				"WebClientRequestException(nested: ConnectException)이 발생하며 리액티브 스트림이 에러 종료됨",
			},
			InferredContextKo: "호출 대상 파드가 기동 전이거나 배포 교체 중 엔드포인트가 일시 소멸하여 연결이 거절되었습니다.",
			SuggestedFixKo:    "1) 'webClient.get().retrieve().bodyToMono(...).retryWhen(Retry.backoff(3, Duration.ofMillis(200)))'로 일시적 연결 실패에 재시도를 적용하세요.",
		},

		// ==================== MyBatis / QueryDSL ====================
		{
			ErrorClass: "TooManyResultsException",
			Language:   "Java",
			Category:   "Application",
			RootCause:  "MyBatisTooManyResults",
			SummaryKo:  "MyBatis 단일 행 조회(selectOne) 쿼리가 2개 이상의 결과 행을 반환하여 org.apache.ibatis.exceptions.TooManyResultsException이 발생했습니다.",
			ActionKo:   "1) 쿼리 WHERE 절에 고유 식별자(PK/Unique 키) 조건이 누락되었는지 확인하세요. 2) 매퍼 메서드 반환 타입을 단일 객체에서 'List<T>'로 변경하거나 쿼리에 'LIMIT 1'을 추가하세요.",
			SummaryEn:  "org.apache.ibatis.exceptions.TooManyResultsException: Expected one result (or null) to be returned by selectOne(), but found multiple.",
			ActionEn:   "1) Verify unique constraint in WHERE clause. 2) Change method return type to List<T> or append 'LIMIT 1' to SQL.",
			RootCauseChainKo: []string{
				"애플리케이션 매퍼가 단일 객체 반환 메서드를 호출함 (내부적으로 SqlSession.selectOne 실행)",
				"데이터베이스에서 해당 조건으로 복수(2건 이상)의 데이터 행이 반환됨",
				"MyBatis 엔진이 데이터 모호성 방지를 위해 TooManyResultsException을 발생시킴",
			},
			InferredContextKo: "테이블에 중복 데이터가 존재하거나, 쿼리 조건에 사용자 ID나 주문 번호 등 필수 식별 조건이 누락되어 발생했습니다.",
			SuggestedFixKo:    "1) SQL 쿼리 끝에 'LIMIT 1'을 명시하거나, 2) DB 컬럼에 UNIQUE 제약 조건을 걸어 중복 데이터 생성을 원천 차단하세요.",
		},
		{
			ErrorClass: "BindingException",
			Language:   "Java",
			Category:   "Configuration",
			RootCause:  "MyBatisBindingException",
			SummaryKo:  "MyBatis 매퍼 인터페이스 메서드명과 XML 매퍼 파일의 SQL ID가 불일치하거나 매개변수 바인딩에 실패했습니다 (BindingException).",
			ActionKo:   "1) 매퍼 인터페이스의 메서드명과 XML의 '<select id=\"...\">'이 정확히 일치하는지 대소문자를 확인하세요. 2) 매개변수가 2개 이상일 때 '@Param(\"paramName\")' 어노테이션을 명시하세요.",
			SummaryEn:  "org.apache.ibatis.binding.BindingException: Invalid bound statement (not found) or parameter mapping error.",
			ActionEn:   "1) Ensure mapper interface method name matches XML statement ID. 2) Add @Param annotations when passing multiple arguments.",
			RootCauseChainKo: []string{
				"Spring 컴포넌트가 MyBatis 매퍼 인터페이스의 메서드를 호출함",
				"MyBatis Configuration 매핑 테이블에서 해당 FQCN + 메서드명에 일치하는 MappedStatement 검색 실패",
				"BindingException: Invalid bound statement (not found)가 발생하며 실행 실패",
			},
			InferredContextKo: "XML 파일이 빌드 아티팩트(JAR)의 리소스 디렉토리에 누락되었거나 네임스페이스 오탈자로 인해 발생했습니다.",
			SuggestedFixKo:    "1) application.yml에서 'mybatis.mapper-locations=classpath*:mapper/**/*.xml' 경로가 정확한지 확인하세요.",
		},

		// ==================== Apache Kafka Enterprise ====================
		{
			ErrorClass: "RecordTooLargeException",
			Language:   "Java",
			Category:   "Configuration",
			RootCause:  "KafkaRecordTooLarge",
			SummaryKo:  "Kafka로 발행하려는 메시지 크기가 브로커의 'message.max.bytes' 또는 프로듀서의 'max.request.size'를 초과했습니다.",
			ActionKo:   "1) 대용량 페이로드는 S3/GCS에 업로드하고 객체 URL만 Kafka 메시지로 전달하는 'Claim Check' 패턴을 적용하세요. 2) 브로커의 'message.max.bytes'와 프로듀서의 'max.request.size' 설정을 상향하세요.",
			SummaryEn:  "org.apache.kafka.common.errors.RecordTooLargeException: message size exceeded broker message.max.bytes.",
			ActionEn:   "1) Adopt Claim Check pattern (store large payload in S3 and pass URI). 2) Increase max.request.size on producer and message.max.bytes on broker.",
			RootCauseChainKo: []string{
				"프로듀서가 대용량 JSON, 이미지 또는 배치 레코드 데이터를 Kafka 토픽으로 전송함",
				"직렬화된 바이트 크기가 프로듀서 max.request.size(기본 1MB) 또는 브로커 한도를 초과함",
				"Kafka 클러스터가 데이터 거절과 함께 RecordTooLargeException을 던짐",
			},
			InferredContextKo: "메시지 큐에 수십 메가바이트의 원본 파일이나 방대한 통계 데이터를 직접 전송하려다 발생한 브로커 제약 위반입니다.",
			SuggestedFixKo:    "1) 대용량 파일은 오브젝트 스토리지(S3)에 먼저 적재 후 키값만 전송하세요. 2) 프로듀서 압축 옵션 'compression.type=snappy' 또는 'zstd'를 활성화하세요.",
		},

		// ==================== Python AI & Deep Learning (PyTorch / CUDA) ====================
		{
			ErrorClass: "CUDA out of memory",
			Language:   "Python",
			Category:   "Application",
			RootCause:  "PyTorchCUDAOutOfMemory",
			SummaryKo:  "PyTorch 딥러닝 모델 훈련 또는 추론 중 GPU VRAM 메모리가 완전히 고갈되었습니다 (torch.cuda.OutOfMemoryError).",
			ActionKo:   "1) 배치 사이즈(batch_size)를 줄이세요 (예: 32 -> 16). 2) 추론 시 'torch.no_grad()' 컨텍스트를 적용하여 연산 그래프 메모리를 절약하세요. 3) 주기적으로 'torch.cuda.empty_cache()'를 호출하여 조각난 캐시를 정리하세요.",
			SummaryEn:  "torch.cuda.OutOfMemoryError: CUDA out of memory. Tried to allocate more VRAM than available on GPU device.",
			ActionEn:   "1) Reduce training/inference batch size. 2) Wrap inference in 'with torch.no_grad():'. 3) Call torch.cuda.empty_cache() periodically.",
			RootCauseChainKo: []string{
				"대규모 언어 모델(LLM) 또는 컴퓨터 비전 모델 가중치 및 활성화 텐서 할당",
				"NVIDIA GPU 장치의 실제 VRAM 메모리가 한계에 도달하여 추가 텐서 메모리 할당 실패",
				"PyTorch CUDA 메모리 할당자가 OutOfMemoryError를 발생시키고 학습/추론 프로세스를 강제 종료함",
			},
			InferredContextKo: "배치 사이즈가 너무 크거나 모델 추론 시 그레디언트(Gradient) 그래프가 누적되어 GPU 전용 비디오 메모리가 고갈된 상황입니다.",
			SuggestedFixKo:    "1) 추론 파이프라인에 'with torch.inference_mode():'를 명시하세요. 2) Mixed Precision 훈련('torch.cuda.amp.autocast()')을 적용하여 FP16/BF16으로 메모리를 절반으로 줄이세요.",
		},

		// ==================== Node.js NestJS Dependency Resolution ====================
		{
			ErrorClass: "NestCanNotResolveDependenciesException",
			Language:   "Node.js",
			Category:   "Configuration",
			RootCause:  "NestJSDependencyResolutionFailed",
			SummaryKo:  "NestJS가 의존성 주입(DI) 그래프 구성 중 필수 Provider나 모듈(Module)을 찾지 못해 부팅에 실패했습니다 (Nest can't resolve dependencies).",
			ActionKo:   "1) 해당 서비스를 사용하는 모듈의 'providers' 배열에 서비스가 등록되어 있는지 확인하세요. 2) 다른 모듈의 서비스라면 해당 모듈의 'exports'에 추가하고 현재 모듈의 'imports'에 모듈을 등록하세요. 3) 순환 참조 시 'forwardRef(() => TargetService)'를 적용하세요.",
			SummaryEn:  "NestCanNotResolveDependenciesException: Nest cannot resolve dependencies of the provider/controller during bootstrap.",
			ActionEn:   "1) Ensure provider is in the 'providers' array of the module. 2) Export provider from its module and import that module. 3) Use forwardRef(() => ...) for circular dependencies.",
			RootCauseChainKo: []string{
				"NestJS IoC 컨테이너가 애플리케이션 모듈 트리 부트스트랩을 시작함",
				"특정 컨트롤러/서비스의 생성자 인자 타입 토큰을 해결(Resolve)하지 못함",
				"NestCanNotResolveDependenciesException 오류를 출력하고 Node.js 프로세스가 기동 실패로 즉시 종료됨",
			},
			InferredContextKo: "새로운 서비스를 컨트롤러에 주입했으나 상위 모듈의 providers 목록에 선언하지 않아 발생한 NestJS 설정 결함입니다.",
			SuggestedFixKo:    "1) 에러 로그에서 누락된 파라미터 인덱스(예: argument [0])를 확인하고, 모듈 데코레이터 '@Module({ providers: [MissingService], imports: [RequiredModule] })'를 보완하세요.",
		},

		// ==================== gRPC Distributed Systems ====================
		{
			ErrorClass: "rpc error: code = Unavailable",
			Language:   "Go",
			Category:   "Dependency",
			RootCause:  "GRPCServerUnavailable",
			SummaryKo:  "원격 gRPC 서버 프로세스가 다운되었거나 네트워크 연결이 거절되어 통신이 불가합니다 (rpc error: code = Unavailable desc = connection refused).",
			ActionKo:   "1) 호출 대상 gRPC 서버 파드의 상태 및 서비스 수신 포트를 점검하세요. 2) 클라이언트에 지수 백오프 재시도(gRPC retry policy)를 구성하세요. 3) 로드밸런서 엔드포인트 해석 상태를 점검하세요.",
			SummaryEn:  "rpc error: code = Unavailable: remote gRPC server is down, unreachable, or refused TCP connection.",
			ActionEn:   "1) Check downstream gRPC server pod availability. 2) Configure gRPC exponential backoff retry interceptor. 3) Audit load balancer endpoint health.",
			RootCauseChainKo: []string{
				"gRPC 클라이언트 스텁이 HTTP/2 기반 원격 RPC 메서드를 호출함",
				"원격 서버가 수신 포트를 열지 않았거나 파드가 재기동되어 TCP 소켓 연결 수립 실패",
				"gRPC 전송 계층이 상태 코드 14 (Unavailable)을 반환하고 클라이언트 호출이 실패함",
			},
			InferredContextKo: "MSA 환경에서 백엔드 인증/결제 gRPC 서비스가 배포 중이거나 다운되어 프론트 게이트웨이 호출이 차단되었습니다.",
			SuggestedFixKo:    "1) gRPC 클라이언트 다이얼 옵션에 'grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.DefaultConfig})'를 적용하세요.",
		},
		{
			ErrorClass: "rpc error: code = ResourceExhausted",
			Language:   "Go",
			Category:   "Application",
			RootCause:  "GRPCResourceExhausted",
			SummaryKo:  "수신된 gRPC 메시지 크기가 기본 버퍼 한도(4MB)를 초과하여 거절되었습니다 (received message larger than max).",
			ActionKo:   "1) gRPC 클라이언트/서버 다이얼 옵션에서 'MaxCallRecvMsgSize' 및 'MaxCallSendMsgSize'를 상향하세요 (예: 50MB). 2) 대용량 데이터는 gRPC 스트리밍(Client/Server Streaming)으로 분할 전송하세요.",
			SummaryEn:  "rpc error: code = ResourceExhausted desc = received message larger than max (4MB ceiling exceeded).",
			ActionEn:   "1) Increase MaxCallRecvMsgSize and MaxCallSendMsgSize in gRPC dial options. 2) Chunk large payloads using gRPC streaming.",
			RootCauseChainKo: []string{
				"원격 서버가 4MB 이상의 대용량 protobuf 페이로드를 단일 응답으로 반환함",
				"클라이언트 gRPC 디코더가 기본 버퍼 한도(DefaultMaxReceiveMessageSize: 4MB) 초과를 감지함",
				"메모리 보호를 위해 ResourceExhausted (code 8) 오류를 반환하고 즉시 연결을 중단함",
			},
			InferredContextKo: "대량 데이터 전수 조회를 단일 gRPC RPC로 받으려다 4MB 기본 보호 제한에 걸려 실패한 상황입니다.",
			SuggestedFixKo:    "1) 'grpc.Dial(target, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(50 * 1024 * 1024)))'로 수신 버퍼 한도를 50MB로 증설하세요.",
		},
	}

	RegisterCatalogEntries(entries)
}
