package knowledge

import (
	"regexp"
	"strings"
)

// NetTLSProxyAnalysis stores findings from low-level network, TLS/PKI, and HTTP proxy (Squid) failures.
type NetTLSProxyAnalysis struct {
	Component      string // network, tls, squid-proxy
	RootCause      string
	ErrorClass     string
	SummaryKo      string
	SummaryEn      string
	SuggestedFixKo string
	SuggestedFixEn string
}

var (
	// Network Layer Regex
	tcpConnResetRegex = regexp.MustCompile(`(?i)(?:read:\s*connection reset by peer|connection reset by peer|ECONNRESET|WSAECONNRESET|java\.net\.SocketException:\s*Connection reset|ClientException:\s*Connection reset|tcp\.connection_reset)`)
	tcpConnRefusedRegex = regexp.MustCompile(`(?i)(?:connect:\s*connection refused|ECONNREFUSED|java\.net\.ConnectException:\s*Connection refused|dial tcp .*?:\s*connect:\s*connection refused|failed to connect to .*?:\s*Connection refused)`)
	tcpConnTimeoutRegex = regexp.MustCompile(`(?i)(?:connect:\s*connection timed out|ETIMEDOUT|java\.net\.SocketTimeoutException:\s*connect timed out|dial tcp .*?:\s*i/o timeout|connect timed out|operation timed out.*?: dial tcp)`)
	netUnreachableRegex = regexp.MustCompile(`(?i)(?:no route to host|network is unreachable|EHOSTUNREACH|ENETUNREACH|java\.net\.NoRouteToHostException|dial tcp .*?:\s*no route to host)`)
	ephemeralPortRegex  = regexp.MustCompile(`(?i)(?:cannot assign requested address|EADDRNOTAVAIL|java\.net\.BindException:\s*Address already in use: connect|bind:\s*cannot assign requested address|socket: All ports in use)`)
	dnsTimeoutRegex     = regexp.MustCompile(`(?i)(?:temporary failure in name resolution|EAI_AGAIN|java\.net\.UnknownHostException|lookup .*? on .*?:\s*read udp .*?:\s*i/o timeout|dns resolution timed out)`)
	brokenPipeRegex     = regexp.MustCompile(`(?i)(?:broken pipe|EPIPE|java\.net\.SocketException:\s*Broken pipe|write:\s*broken pipe)`)

	// TLS / PKI Layer Regex
	tlsUntrustedCARegex = regexp.MustCompile(`(?i)(?:x509:\s*certificate signed by unknown authority|PKIX path building failed.*?: unable to find valid certification path to requested target|CERTIFICATE_VERIFY_FAILED.*?: self signed certificate|CERTIFICATE_VERIFY_FAILED.*?: certificate verify failed: unable to get local issuer certificate|DEPTH_ZERO_SELF_SIGNED_CERT|SSLHandshakeException.*?: sun\.security\.validator\.ValidatorException)`)
	tlsExpiredRegex     = regexp.MustCompile(`(?i)(?:x509:\s*certificate has expired or is not yet valid|CERT_HAS_EXPIRED|CertificateExpiredException|certificate has expired|NotAfter: )`)
	tlsHostMismatchRegex = regexp.MustCompile(`(?i)(?:x509:\s*certificate is valid for .*?,\s*not|ERR_TLS_CERT_ALTNAME_INVALID|HostnameVerifier failed|certificate verify failed: IP address mismatch|certificate verify failed: Hostname mismatch)`)
	tlsProtocolMismatchRegex = regexp.MustCompile(`(?i)(?:tls:\s*protocol version not supported|SSLV3_ALERT_HANDSHAKE_FAILURE|no shared cipher|sslv3 alert handshake failure|tlsv1 alert protocol version|SSLHandshakeException.*?: Received fatal alert:\s*handshake_failure)`)
	tlsClientCertReqRegex   = regexp.MustCompile(`(?i)(?:tls:\s*client certificate required|ssl alert certificate required|bad certificate.*?: tls|SSLHandshakeException.*?: Received fatal alert:\s*bad_certificate)`)
	tlsIncompleteChainRegex = regexp.MustCompile(`(?i)(?:UNABLE_TO_VERIFY_LEAF_SIGNATURE|unable to get local issuer certificate|x509:\s*cannot verify signature: algorithm unimplemented|incomplete certificate chain)`)

	// Squid & Forward Proxy Layer Regex
	squidAuthRequiredRegex = regexp.MustCompile(`(?i)(?:407 Proxy Authentication Required|ERR_CACHE_ACCESS_DENIED.*?: squid|Proxy-Authenticate:\s*Basic|Squid:.*?407 Proxy Authentication Required)`)
	squidConnRefusedRegex  = regexp.MustCompile(`(?i)(?:ERR_CONNECT_FAIL|503 Service Unavailable.*?: Connection to .*? failed \(111\) Connection refused|Connection to .*? failed \(111\) Connection refused|Squid:.*?ERR_CONNECT_FAIL)`)
	squidDNSFailRegex      = regexp.MustCompile(`(?i)(?:ERR_DNS_FAIL|502 Bad Gateway.*?: DNS name lookup failure|DNS name lookup failure.*?: squid|Name service error for name=)`)
	squidTimeoutRegex      = regexp.MustCompile(`(?i)(?:ERR_READ_TIMEOUT|ERR_LIFETIME_EXP|504 Gateway Timeout.*?: squid|The read operation timed out.*?: squid|Connection to .*? timed out)`)
	squidAccessDeniedRegex = regexp.MustCompile(`(?i)(?:ERR_ACCESS_DENIED|Access Denied by Squid ACL|The following error was encountered while trying to retrieve the URL.*?: Access Denied|acl localnet block|Squid:.*?403 Forbidden)`)
	squidConnectRejectRegex = regexp.MustCompile(`(?i)(?:CONNECT method denied|ERR_UNSUP_REQ.*?: CONNECT|The requested URL could not be retrieved.*?: Safe_ports|SSL_ports.*?: denied|CONNECT tunnel failed)`)
	squidSSLBumpRegex      = regexp.MustCompile(`(?i)(?:ERR_SECURE_ACCEPT_FAIL|SslBump.*?: certificate error|Failed to generate fake certificate.*?: squid|ssl_crtd.*?: helper failed)`)
)

// AnalyzeNetTLSProxyLogs inspects logs for network, SSL/TLS, and Squid HTTP proxy failures.
func AnalyzeNetTLSProxyLogs(logs string) *NetTLSProxyAnalysis {
	if strings.TrimSpace(logs) == "" {
		return nil
	}

	// 1. Squid HTTP Forward Proxy Layer (가장 구체적인 에러 우선)
	if squidAuthRequiredRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "squid-proxy",
			RootCause:      "ProxyAuthenticationRequired",
			ErrorClass:     "Squid_407_AuthRequired",
			SummaryKo:      "Squid HTTP 프록시 인증 필요 (HTTP 407 Proxy Authentication Required)",
			SummaryEn:      "Squid forward proxy authentication required (HTTP 407 Proxy Authentication Required)",
			SuggestedFixKo: "1) HTTP_PROXY 또는 HTTPS_PROXY 환경변수에 프록시 인증 자격 증명(http://user:password@proxy:3128)을 포함하세요. 2) Squid 프록시 서버의 auth_param 기본 인증 설정을 점검하세요.",
			SuggestedFixEn: "1) Include proxy credentials in HTTP_PROXY/HTTPS_PROXY environment variables (http://user:pass@proxy:3128). 2) Check Squid auth_param configuration.",
		}
	}
	if squidAccessDeniedRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "squid-proxy",
			RootCause:      "ProxyAccessDeniedACL",
			ErrorClass:     "Squid_403_AccessDenied",
			SummaryKo:      "Squid 프록시 접근 제어 목록(ACL) 차단 (HTTP 403 Forbidden - ERR_ACCESS_DENIED)",
			SummaryEn:      "Squid forward proxy access denied by ACL (HTTP 403 Forbidden - ERR_ACCESS_DENIED)",
			SuggestedFixKo: "1) Squid의 squid.conf에서 클러스터 소스 IP(src acl) 또는 대상 도메인(dstdomain acl)에 대한 'http_access allow' 규칙을 추가하세요. 2) 허용 포트 목록(Safe_ports)을 점검하세요.",
			SuggestedFixEn: "1) Add 'http_access allow' rule for client IP or destination domain in squid.conf. 2) Verify Safe_ports and SSL_ports ACL lists.",
		}
	}
	if squidConnectRejectRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "squid-proxy",
			RootCause:      "ProxyConnectTunnelFailed",
			ErrorClass:     "Squid_Connect_Rejected",
			SummaryKo:      "Squid HTTPS CONNECT 터널링 거절 (비표준 SSL 포트 또는 Safe_ports 차단)",
			SummaryEn:      "Squid HTTPS CONNECT tunnel rejected (non-standard SSL port or Safe_ports violation)",
			SuggestedFixKo: "1) squid.conf의 'acl SSL_ports port <port>' 및 'acl Safe_ports port <port>'에 접속하려는 포트를 추가하세요. 2) 'http_access deny !Safe_ports' 정책을 점검하세요.",
			SuggestedFixEn: "1) Add the target destination port to SSL_ports and Safe_ports in squid.conf. 2) Review the '!Safe_ports' denial rule.",
		}
	}
	if squidDNSFailRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "squid-proxy",
			RootCause:      "ProxyDNSResolutionFailed",
			ErrorClass:     "Squid_502_DNSFail",
			SummaryKo:      "Squid 프록시의 업스트림 목적지 도메인 DNS 해석 실패 (HTTP 502 Bad Gateway - ERR_DNS_FAIL)",
			SummaryEn:      "Squid proxy failed to resolve upstream target domain DNS (HTTP 502 - ERR_DNS_FAIL)",
			SuggestedFixKo: "1) Squid 프록시 서버의 /etc/resolv.conf 네임서버 설정 및 외부 DNS 연결성을 점검하세요. 2) 요청 URL의 목적지 호스트명 오탈자를 확인하세요.",
			SuggestedFixEn: "1) Inspect /etc/resolv.conf and upstream DNS connectivity on the Squid proxy host. 2) Check destination hostname spelling.",
		}
	}
	if squidTimeoutRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "squid-proxy",
			RootCause:      "ProxyGatewayTimeout",
			ErrorClass:     "Squid_504_Timeout",
			SummaryKo:      "Squid 프록시의 업스트림 서버 응답 대기 시간 초과 (HTTP 504 Gateway Timeout - ERR_READ_TIMEOUT)",
			SummaryEn:      "Squid proxy upstream read timeout (HTTP 504 Gateway Timeout - ERR_READ_TIMEOUT)",
			SuggestedFixKo: "1) Squid의 'read_timeout' 및 'connect_timeout' 설정을 늘리세요. 2) 업스트림 백엔드 서버의 처리 지연 또는 네트워크 병목을 점검하세요.",
			SuggestedFixEn: "1) Increase 'read_timeout' and 'connect_timeout' in squid.conf. 2) Optimize upstream server processing latency.",
		}
	}
	if squidConnRefusedRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "squid-proxy",
			RootCause:      "ProxyConnectionRefused",
			ErrorClass:     "Squid_503_ConnectFail",
			SummaryKo:      "Squid 프록시가 업스트림 대상 서버 TCP 연결에 실패함 (HTTP 503 - ERR_CONNECT_FAIL)",
			SummaryEn:      "Squid proxy failed to establish TCP connection to upstream server (HTTP 503 - ERR_CONNECT_FAIL)",
			SuggestedFixKo: "1) 대상 서버가 정상 구동 중인지, 포트가 열려 있는지 확인하세요. 2) 프록시 서버와 대상 서버 사이의 네트워크 방화벽을 점검하세요.",
			SuggestedFixEn: "1) Verify destination server is running and listening on the target port. 2) Inspect firewalls between proxy and destination.",
		}
	}
	if squidSSLBumpRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "squid-proxy",
			RootCause:      "ProxySSLBumpFailure",
			ErrorClass:     "Squid_SSLBump_Failed",
			SummaryKo:      "Squid SslBump(SSL 가로채기/검사) 동적 인증서 생성 실패 (ERR_SECURE_ACCEPT_FAIL)",
			SummaryEn:      "Squid SslBump dynamic certificate generation or verification failed (ERR_SECURE_ACCEPT_FAIL)",
			SuggestedFixKo: "1) Squid의 ssl_crtd 헬퍼 데몬 디렉토리 권한과 캐시 크기를 확인하세요. 2) Squid 사설 루트 CA 인증서의 유효기간 및 클라이언트 신뢰 등록 여부를 점검하세요.",
			SuggestedFixEn: "1) Check permissions of squid ssl_crtd helper and certificate cache. 2) Verify validity of Squid private CA cert and client trust store.",
		}
	}

	// 2. TLS / PKI Layer
	if tlsUntrustedCARegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "tls",
			RootCause:      "TLSUntrustedCA",
			ErrorClass:     "TLS_Certificate_UnknownCA",
			SummaryKo:      "TLS/HTTPS 인증서가 신뢰할 수 없는 CA에 의해 서명됨 (자체 서명 인증서 또는 사설 CA 미등록)",
			SummaryEn:      "TLS certificate signed by unknown authority (self-signed or missing private root CA in trust store)",
			SuggestedFixKo: "1) 컨테이너 시스템 신뢰 인증서 저장소(/etc/ssl/certs, Java cacerts)에 사설 CA 인증서를 마운트하고 갱신하세요 ('update-ca-certificates'). 2) 사내 프록시(Zscaler, Squid) 인증서를 추가하세요.",
			SuggestedFixEn: "1) Mount private root CA into container trust store (/etc/ssl/certs or Java cacerts) and run update-ca-certificates. 2) Add corporate egress proxy root CA.",
		}
	}
	if tlsExpiredRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "tls",
			RootCause:      "TLSCertificateExpired",
			ErrorClass:     "TLS_Certificate_Expired",
			SummaryKo:      "TLS 인증서가 만료되었거나 시스템 시계(Clock skew)가 맞지 않음 (CERT_HAS_EXPIRED)",
			SummaryEn:      "TLS certificate has expired or system clock skew invalidates certificate validity",
			SuggestedFixKo: "1) 대상 서버의 TLS 인증서를 즉시 갱신하세요 ('cert-manager renew' 등). 2) 노드의 NTP/시간 동기화 상태를 점검하세요.",
			SuggestedFixEn: "1) Renew the expired TLS certificate on the target server. 2) Verify node clock synchronization via NTP.",
		}
	}
	if tlsHostMismatchRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "tls",
			RootCause:      "TLSHostnameMismatch",
			ErrorClass:     "TLS_Hostname_Mismatch",
			SummaryKo:      "TLS 인증서의 주체 대체 이름(SAN/CommonName)과 접속 호스트명/IP 불일치",
			SummaryEn:      "TLS certificate Subject Alternative Name (SAN) does not match target hostname or IP address",
			SuggestedFixKo: "1) 접속하려는 도메인 또는 IP가 인증서의 SAN 목록에 포함되어 있는지 확인하세요 ('openssl x509 -noout -text'). 2) IP 대신 올바른 FQDN으로 접속하세요.",
			SuggestedFixEn: "1) Inspect certificate SAN with 'openssl x509 -noout -text' and ensure the hostname is included. 2) Connect via FQDN instead of raw IP.",
		}
	}
	if tlsIncompleteChainRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "tls",
			RootCause:      "TLSIncompleteChain",
			ErrorClass:     "TLS_Incomplete_Chain",
			SummaryKo:      "서버가 중간 CA(Intermediate CA) 인증서를 누락하고 리프 인증서만 반환하여 검증 실패",
			SummaryEn:      "Server returned incomplete certificate chain missing intermediate CA certificate",
			SuggestedFixKo: "1) 웹서버 또는 Ingress의 인증서 설정에 중간 인증서가 포함된 전체 체인(fullchain.pem)을 번들링하세요.",
			SuggestedFixEn: "1) Bundle the full certificate chain (fullchain.pem) including intermediate CAs in the server configuration.",
		}
	}
	if tlsClientCertReqRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "tls",
			RootCause:      "TLSClientCertRequired",
			ErrorClass:     "TLS_ClientCert_Required_mTLS",
			SummaryKo:      "서버가 상호 TLS(mTLS) 클라이언트 인증서를 요구하였으나 인증서가 제공되지 않거나 유효하지 않음",
			SummaryEn:      "Mutual TLS (mTLS) handshake failed: client certificate required by server but not provided or rejected",
			SuggestedFixKo: "1) 클라이언트 요청 설정에 유효한 mTLS 클라이언트 인증서와 개인키를 등록하세요. 2) Istio의 경우 PeerAuthentication mTLS 모드를 확인하세요.",
			SuggestedFixEn: "1) Provide valid client certificate and private key in client request configuration. 2) Verify Istio PeerAuthentication mode.",
		}
	}
	if tlsProtocolMismatchRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "tls",
			RootCause:      "TLSHandshakeProtocolMismatch",
			ErrorClass:     "TLS_Protocol_Cipher_Mismatch",
			SummaryKo:      "클라이언트와 서버 간 지원하는 TLS 프로토콜 버전(TLS 1.2 vs 1.3) 또는 암호화 스위트(Cipher Suite) 불일치",
			SummaryEn:      "TLS protocol version or cipher suite mismatch between client and server (HANDSHAKE_FAILURE)",
			SuggestedFixKo: "1) 클라이언트와 서버가 최소 TLS 1.2 이상을 활성화했는지 확인하세요. 2) 상호 호환되는 공통 암호화 알고리즘(Cipher Suite) 목록을 구성하세요.",
			SuggestedFixEn: "1) Ensure both client and server enable at least TLS 1.2. 2) Configure overlapping cipher suites.",
		}
	}

	// 3. Network Layer
	if tcpConnResetRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "network",
			RootCause:      "TCPConnectionReset",
			ErrorClass:     "Network_TCP_ConnectionReset",
			SummaryKo:      "피어 서버 또는 중간 방화벽/로드밸런서에 의해 TCP 커넥션이 강제 초기화(RST)됨 (ECONNRESET)",
			SummaryEn:      "TCP connection forcibly reset by peer or intermediate firewall/load balancer (ECONNRESET)",
			SuggestedFixKo: "1) 원격 서비스가 비정상 크래시되었거나 백로그 큐가 가득 찼는지 점검하세요. 2) 방화벽 또는 NAT 게이트웨이의 유휴 세션 타임아웃(Idle timeout)을 확인하세요.",
			SuggestedFixEn: "1) Check if remote service crashed or reached TCP backlog limits. 2) Inspect firewall/NAT gateway idle session timeout.",
		}
	}
	if tcpConnRefusedRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "network",
			RootCause:      "TCPConnectionRefused",
			ErrorClass:     "Network_TCP_ConnectionRefused",
			SummaryKo:      "대상 목적지 포트가 열려있지 않거나 프로세스가 기동되지 않아 TCP 연결이 즉시 거부됨 (ECONNREFUSED)",
			SummaryEn:      "TCP connection refused: target port is not listening or process is down (ECONNREFUSED)",
			SuggestedFixKo: "1) 대상 파드/서비스가 정상 구동 중이고 지정된 포트(targetPort)로 리스닝하는지 확인하세요. 2) Kubernetes Service 셀렉터가 올바른 파드를 가리키는지 점검하세요.",
			SuggestedFixEn: "1) Verify the target pod is running and listening on the designated port. 2) Check Kubernetes Service targetPort and selector.",
		}
	}
	if tcpConnTimeoutRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "network",
			RootCause:      "TCPConnectionTimeout",
			ErrorClass:     "Network_TCP_ConnectTimeout",
			SummaryKo:      "TCP 3-Way Handshake SYN 패킷에 대한 응답이 없어 연결 시도가 타임아웃됨 (ETIMEDOUT)",
			SummaryEn:      "TCP 3-way handshake timed out waiting for SYN-ACK response (ETIMEDOUT)",
			SuggestedFixKo: "1) 목적지 IP/포트에 대한 쿠버네티스 NetworkPolicy, 보안 그룹(Security Group) 또는 라우팅 테이블을 점검하세요. 2) 대상 호스트의 방화벽 드롭 여부를 확인하세요.",
			SuggestedFixEn: "1) Inspect NetworkPolicy, security groups, and routing tables for dropped SYN packets. 2) Verify firewall ingress rules.",
		}
	}
	if netUnreachableRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "network",
			RootCause:      "NetworkUnreachable",
			ErrorClass:     "Network_Route_Unreachable",
			SummaryKo:      "네트워크 라우팅 경로 부재 또는 서브넷 게이트웨이 연결 불가 (No route to host / ENETUNREACH)",
			SummaryEn:      "No routing path to target host or subnet gateway down (EHOSTUNREACH / ENETUNREACH)",
			SuggestedFixKo: "1) 노드 CNI 플러그인(Calico, Cilium, Flannel)의 IP 풀 및 라우팅 테이블 상태를 확인하세요. 2) VPC 서브넷 라우팅 테이블 및 NAT 게이트웨이 상태를 점검하세요.",
			SuggestedFixEn: "1) Verify CNI IP pool allocation and node routing table health. 2) Check VPC subnet route tables and NAT gateways.",
		}
	}
	if ephemeralPortRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "network",
			RootCause:      "EphemeralPortExhaustion",
			ErrorClass:     "Network_EphemeralPort_Exhaustion",
			SummaryKo:      "로컬 아웃바운드 임시 포트(Ephemeral Port) 고갈로 신규 소켓 바인딩 실패 (EADDRNOTAVAIL)",
			SummaryEn:      "Outbound ephemeral ports exhausted, preventing new TCP socket allocation (EADDRNOTAVAIL)",
			SuggestedFixKo: "1) 커넥션 풀(Keep-Alive)을 재사용하여 TIME_WAIT 소켓 적체를 줄이세요. 2) 노드 sysctl 'net.ipv4.ip_local_port_range' 확장 및 'net.ipv4.tcp_tw_reuse=1'을 활성화하세요.",
			SuggestedFixEn: "1) Reuse connections with HTTP Keep-Alive connection pooling. 2) Expand sysctl 'net.ipv4.ip_local_port_range' and enable 'net.ipv4.tcp_tw_reuse=1'.",
		}
	}
	if dnsTimeoutRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "network",
			RootCause:      "DNSResolutionTimeout",
			ErrorClass:     "Network_DNS_ResolutionFailed",
			SummaryKo:      "DNS 쿼리 타임아웃 또는 도메인 해석 실패 (EAI_AGAIN / UnknownHostException)",
			SummaryEn:      "DNS resolution timed out or temporary failure in name resolution (EAI_AGAIN)",
			SuggestedFixKo: "1) CoreDNS 파드의 가동 상태와 CPU/메모리 스로틀링 여부를 확인하세요. 2) 파드 dnsConfig의 'ndots' 옵션을 2 이하로 줄여 불필요한 DNS 검색 루프를 방지하세요.",
			SuggestedFixEn: "1) Check CoreDNS pod status and resource limits. 2) Reduce ndots in pod dnsConfig to prevent redundant search loops.",
		}
	}
	if brokenPipeRegex.MatchString(logs) {
		return &NetTLSProxyAnalysis{
			Component:      "network",
			RootCause:      "BrokenPipe",
			ErrorClass:     "Network_BrokenPipe_EPIPE",
			SummaryKo:      "이미 원격에서 닫힌 TCP 소켓에 데이터 쓰기를 시도하여 파이프가 단절됨 (EPIPE / Broken pipe)",
			SummaryEn:      "Attempted write to a closed TCP socket stream (EPIPE / Broken pipe)",
			SuggestedFixKo: "1) 클라이언트 타임아웃이 서버 응답 시간보다 짧아 조기 연결을 닫았는지 확인하세요. 2) 대용량 응답 스트리밍 중 클라이언트 중단 예외 처리를 보강하세요.",
			SuggestedFixEn: "1) Check if client prematurely closed connection due to short timeout. 2) Handle client disconnect gracefully during streaming writes.",
		}
	}

	return nil
}
