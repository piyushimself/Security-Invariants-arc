import { SecurityInvariant } from '../../types/invariants';

export const httpRules: SecurityInvariant[] = [
  {
    ruleNumber: 1,
    id: 'SEC-HTTP-001',
    title: 'Dual Framing Conflict Rejection (CL + TE)',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'Request Smuggling & Framing',
    difficulty: 'Intermediate',
    standardType: 'Mandatory Standard',
    standards: ['RFC 9112 §6.3', 'OWASP A05:2021', 'CWE-444'],
    formalInvariant: '∀ r ∈ Requests, (HasHeader(r, "Content-Length") ∧ HasHeader(r, "Transfer-Encoding")) ⇒ Action(r) = REJECT_400',
    symbolBreakdown: [
      { symbol: '∀ r ∈ Requests', meaning: 'For every incoming HTTP request r' },
      { symbol: 'HasHeader(r, h)', meaning: 'Predicate true if header h exists in r' },
      { symbol: '∧', meaning: 'Logical AND (both conditions must hold)' },
      { symbol: '⇒', meaning: 'Material implication (then the following action is mandatory)' },
      { symbol: 'Action(r) = REJECT_400', meaning: 'The proxy/server must terminate the request and return HTTP 400 Bad Request immediately' }
    ],
    plainEnglish: 'Whenever an HTTP/1.1 message contains both Content-Length and Transfer-Encoding headers, the server or intermediary must reject the message with a 400 Bad Request. Mixing both framing headers is an ambiguous condition that enables HTTP Request Smuggling.',
    whyItMatters: 'If a front-end proxy prioritizes Content-Length while a back-end server prioritizes Transfer-Encoding (or vice-versa), an attacker can embed an arbitrary hidden request inside the payload of the first. This leads to cache poisoning, credential hijacking, and complete bypass of web application firewalls.',
    vulnerableExample: {
      language: 'nginx/python',
      code: `# Vulnerable reverse proxy configuration / logic:
# Silently stripping Transfer-Encoding or ignoring Content-Length without failing
if 'Transfer-Encoding' in request.headers and 'Content-Length' in request.headers:
    # INCORRECT: Picking one arbitrarily allows smuggling downstream
    del request.headers['Content-Length']
    forward_to_backend(request)`,
      explanation: 'Arbitrarily stripping one header rather than rejecting the malformed request leaves the downstream parser vulnerable to discrepancies in whitespace or chunk framing.'
    },
    secureExample: {
      language: 'python/go',
      code: `func validateFraming(req *http.Request) error {
    hasCL := req.Header.Get("Content-Length") != ""
    hasTE := len(req.Header.Values("Transfer-Encoding")) > 0
    if hasCL && hasTE {
        // MANDATORY per RFC 9112 Section 6.3:
        return &HTTPError{StatusCode: 400, Message: "Conflicting framing headers (CL + TE)"}
    }
    return nil
}`,
      explanation: 'Fails closed immediately at the earliest boundary with HTTP 400, preventing any ambiguous byte stream from reaching backend workers.'
    },
    howToTest: {
      tools: ['curl', 'netcat', 'Burp Suite HTTP Smuggler'],
      steps: [
        'Send raw HTTP/1.1 request containing both Content-Length: 4 and Transfer-Encoding: chunked.',
        'Verify proxy returns 400 Bad Request without forwarding bytes to backend.',
        'Inspect upstream logs to confirm connection was reset or closed.'
      ],
      commandExample: 'printf "POST / HTTP/1.1\\r\\nHost: target.com\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\n" | nc target.com 80'
    },
    interviewChallenge: {
      scenario: 'You are reviewing a cloud migration where Cloudflare proxies to an internal Go service. Burp Suite reports a potential CL.TE smuggling warning on an API gateway.',
      question: 'Why does removing the Content-Length header at the edge reverse-proxy fail to solve the problem for HTTP/2 downgrades?',
      hint: 'Think about how HTTP/2 pseudo-headers like :path and binary frames are translated into HTTP/1.1 text pipelines.',
      sampleAnswer: 'When an HTTP/2 connection is downgraded to HTTP/1.1 downstream, binary DATA frame lengths are often translated into a newly synthesized Content-Length header. If the attacker also injected a Transfer-Encoding header inside an H2 pseudo-header or header list, the synthesized request arrives at the backend with both headers, triggering CL.TE or H2.CL desynchronization.',
      keyTakeaway: 'Always reject ambiguous framing at the gateway; never try to "repair" or normalize conflicting headers across protocol downgrade boundaries.'
    },
    simulation: {
      type: 'http_headers',
      label: 'Framing Discrepancy Detector',
      defaultInput: 'POST /api/checkout HTTP/1.1\nHost: example.com\nContent-Length: 13\nTransfer-Encoding: chunked\n\n0\n\nGPOST /admin',
      testFunctionDescription: 'Checks if request presents simultaneous Content-Length and Transfer-Encoding framing headers.'
    }
  },
  {
    ruleNumber: 2,
    id: 'SEC-HTTP-002',
    title: 'Absolute Host Header Single-Occurrence Invariant',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'Host Header Attacks & Routing',
    difficulty: 'Beginner',
    standardType: 'Mandatory Standard',
    standards: ['RFC 9112 §7.1', 'OWASP ASVS 4.0 §13.1.1', 'CWE-20'],
    formalInvariant: '∀ r ∈ Requests_{HTTP/1.1}, Count(Headers(r, "Host")) = 1 ∧ Host(r) ∈ AllowedHostnames',
    symbolBreakdown: [
      { symbol: 'Count(Headers(r, "Host")) = 1', meaning: 'The request must contain exactly one Host header field (no duplicates)' },
      { symbol: 'AllowedHostnames', meaning: 'Strict explicit whitelist of acceptable domain names and ports' },
      { symbol: '∈', meaning: 'Element of (must match predefined set)' }
    ],
    plainEnglish: 'Every HTTP/1.1 request must supply exactly one Host header. If zero or multiple Host headers appear, or if the value does not match an approved whitelist, reject with 400 Bad Request or 421 Misdirected Request.',
    whyItMatters: 'Multiple Host headers confuse proxies and virtual host dispatchers, leading to password reset poisoning, cache poisoning, and Server-Side Request Forgery (SSRF) when frameworks blindly trust the Host header to generate absolute URLs.',
    vulnerableExample: {
      language: 'javascript/node',
      code: `// Express / Node.js vulnerable host usage
app.post('/auth/reset-password', (req, res) => {
    // VULNERABLE: req.headers.host is attacker-controlled!
    const resetUrl = "https://" + req.headers.host + "/reset?token=" + user.token;
    emailService.send(user.email, resetUrl);
});`,
      explanation: 'An attacker submits Host: evil-attacker.com, causing the generated password reset link to redirect the victim to an attacker-controlled server.'
    },
    secureExample: {
      language: 'typescript/node',
      code: `const ALLOWED_HOSTS = new Set(['app.example.com', 'api.example.com']);

function enforceHostHeader(req: Request, res: Response, next: NextFunction) {
    const rawHost = req.headers['host'];
    if (!rawHost || Array.isArray(rawHost) || !ALLOWED_HOSTS.has(rawHost.toLowerCase())) {
        return res.status(400).send("Invalid or untrusted Host header");
    }
    next();
}`,
      explanation: 'Rejects array instances (duplicate headers) and strictly matches against a canonical allowlist.'
    },
    howToTest: {
      tools: ['curl', 'OWASP ZAP'],
      steps: [
        'Send request with two Host headers: Host: good.com and Host: evil.com.',
        'Send request with an unlisted Host: spoofed.com.',
        'Verify server responds with 400 Bad Request.'
      ],
      commandExample: 'curl -H "Host: legitimate.com" -H "Host: attacker.com" https://target.internal/api'
    },
    interviewChallenge: {
      scenario: 'A developer argues that using X-Forwarded-Host from the reverse proxy is safer than using the Host header directly.',
      question: 'Is X-Forwarded-Host inherently trustworthy when received by an internal application?',
      hint: 'Where did the reverse proxy get the value, and does it sanitize client-supplied headers?',
      sampleAnswer: 'No. Unless the edge reverse proxy explicitly strips or overwrites any incoming X-Forwarded-Host from external clients, an attacker can directly inject an arbitrary X-Forwarded-Host header. Always configure the edge proxy to overwrite forwarding headers with its own verified upstream value.',
      keyTakeaway: 'Never generate security-critical URLs (password resets, OAuth redirects) from untrusted client-supplied headers.'
    }
  },
  {
    ruleNumber: 3,
    id: 'SEC-HTTP-003',
    title: 'HSTS Max-Age and Preload Invariant',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'Transport Layer & Encryption',
    difficulty: 'Beginner',
    standardType: 'Mandatory Standard',
    standards: ['RFC 6797 §6.1', 'NIST SP 800-52r2', 'CWE-319'],
    formalInvariant: '∀ resp ∈ Responses, Scheme(resp) = HTTPS ⇒ (HasHeader(resp, "Strict-Transport-Security") ∧ MaxAge(resp) ≥ 31536000 ∧ IncludesSubDomains(resp))',
    symbolBreakdown: [
      { symbol: 'Scheme(resp) = HTTPS', meaning: 'When the response is delivered over a secure TLS channel' },
      { symbol: 'MaxAge(resp) ≥ 31536000', meaning: 'The max-age parameter must be at least one full year (31,536,000 seconds)' },
      { symbol: 'IncludesSubDomains(resp)', meaning: 'The includeSubDomains directive must be present to protect all subsidiary namespaces' }
    ],
    plainEnglish: 'Every HTTPS response must declare Strict-Transport-Security with a max-age of at least one year and the includeSubDomains directive. HSTS instructs browsers to refuse plain HTTP connections and prohibit user click-through on certificate warnings.',
    whyItMatters: 'Without HSTS, the very first connection made to a domain (or any link followed via http://) is vulnerable to SSL stripping attacks (e.g., moxie sslstrip), downgrade attacks, and active adversary wiretapping.',
    vulnerableExample: {
      language: 'http',
      code: `HTTP/1.1 200 OK
Content-Type: text/html
# VULNERABLE: Missing Strict-Transport-Security header entirely
# Or dangerously low max-age:
# Strict-Transport-Security: max-age=300`,
      explanation: 'Short max-age values fail to protect returning visitors across extended intervals, and lack of includeSubDomains leaves subdomains vulnerable to MITM.'
    },
    secureExample: {
      language: 'http',
      code: `HTTP/1.1 200 OK
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Type: text/html`,
      explanation: 'Provides 2-year enforcement, covers all subdomains, and qualifies for submission into Chrome/Firefox hardcoded preload lists.'
    },
    howToTest: {
      tools: ['curl', 'hstspreload.org', 'testssl.sh'],
      steps: [
        'Query the domain via curl -sI https://example.com | grep -i strict.',
        'Verify max-age is >= 31536000, includeSubDomains is present, and preload is added.',
        'Verify HTTP to HTTPS 301 redirect is emitted.'
      ],
      commandExample: 'curl -sI https://example.com | grep -i "strict-transport-security"'
    },
    interviewChallenge: {
      scenario: 'You deploy HSTS with includeSubDomains; preload on an enterprise root domain, but the marketing department hosts an unencrypted legacy site at blog.company.com.',
      question: 'What happens to users attempting to visit blog.company.com once preload is active, and how can this be rolled back?',
      hint: 'Preload lists are hardcoded into compiled browser binaries.',
      sampleAnswer: 'All modern browsers will strictly enforce HTTPS on blog.company.com. Because the legacy blog lacks TLS, browsers will display a hard fatal error that users cannot bypass. Removing a domain from browser preload lists takes months to propagate across browser release cycles.',
      keyTakeaway: 'Audit all subdomains for TLS readiness before setting includeSubDomains and submitting to the HSTS preload list.'
    }
  },
  {
    ruleNumber: 4,
    id: 'SEC-HTTP-004',
    title: 'Hop-by-Hop Header Stripping Invariant',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'Intermediary & Proxy Smuggling',
    difficulty: 'Advanced',
    standardType: 'Mandatory Standard',
    standards: ['RFC 9110 §7.6.1', 'CWE-444'],
    formalInvariant: '∀ h ∈ HopByHopHeaders, Forward(Proxy, h) = ∅ ∧ (h ∈ ConnectionValue ⇒ Strip(h))',
    symbolBreakdown: [
      { symbol: 'HopByHopHeaders', meaning: 'Headers specific to a single transport link (Connection, Keep-Alive, Proxy-Authenticate, etc.)' },
      { symbol: 'Forward(Proxy, h) = ∅', meaning: 'The proxy must NEVER forward hop-by-hop headers to the downstream connection' },
      { symbol: 'ConnectionValue', meaning: 'Tokens listed in the value of the Connection header itself' }
    ],
    plainEnglish: 'Intermediaries must remove all hop-by-hop headers as well as any header listed inside the Connection header before forwarding the request to downstream backends.',
    whyItMatters: 'Attackers can exploit hop-by-hop header injection (e.g. Connection: close, X-Forwarded-For) to trick front-end reverse proxies into stripping critical headers (like client authentication certs or authorization tokens) before the request reaches the backend.',
    vulnerableExample: {
      language: 'python',
      code: `# Vulnerable proxy forwarder
def forward_request(req):
    # VULNERABLE: Blindly copying all headers, including Connection-listed headers
    headers = dict(req.headers)
    return requests.get(BACKEND_URL, headers=headers)`,
      explanation: 'Allows attacker to specify Connection: X-Real-IP, causing upstream middleware to strip real client attribution.'
    },
    secureExample: {
      language: 'go',
      code: `var hopHeaders = []string{
    "Connection", "Keep-Alive", "Proxy-Authenticate", 
    "Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade",
}

func sanitizeHopByHop(h http.Header) {
    if c := h.Get("Connection"); c != "" {
        for _, f := range strings.Split(c, ",") {
            h.Del(strings.TrimSpace(f))
        }
    }
    for _, k := range hopHeaders {
        h.Del(k)
    }
}`,
      explanation: 'Parses the Connection header tokens and removes each identified header along with standard RFC 9110 hop-by-hop headers.'
    },
    howToTest: {
      tools: ['curl', 'mitmproxy'],
      steps: [
        'Send request with header: Connection: close, X-Authenticated-User.',
        'Observe whether the backend service receives X-Authenticated-User or if it was removed by proxy.'
      ],
      commandExample: 'curl -H "Connection: close, X-Client-Cert" -H "X-Client-Cert: fake" https://gateway.internal/'
    },
    interviewChallenge: {
      scenario: 'An attacker uses Connection: close, X-Forwarded-For to bypass an IP-based rate limiter located at the API gateway.',
      question: 'Explain the mechanism of this attack and how to remediate it.',
      hint: 'How does an intermediate proxy handle tokens declared in the Connection header?',
      sampleAnswer: 'The attacker declares X-Forwarded-For as a hop-by-hop token via the Connection header. When a compliant edge proxy processes the Connection header, it dutifully strips X-Forwarded-For before forwarding to downstream microservices, nullifying downstream rate-limiting or auditing that relies on that header.',
      keyTakeaway: 'The gateway must strictly enforce which headers can be stripped and overwrite security-critical forwarding headers using internal values.'
    }
  },
  {
    ruleNumber: 5,
    id: 'SEC-HTTP-005',
    title: 'CRLF Injection Header Delimiter Invariant',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'Response Splitting & Injection',
    difficulty: 'Intermediate',
    standardType: 'Mandatory Standard',
    standards: ['RFC 9112 §2.2', 'OWASP Top 10 A03', 'CWE-113'],
    formalInvariant: '∀ h ∈ HeaderFields, (\\r ∈ Value(h) ∨ \\n ∈ Value(h) ∨ \\0 ∈ Value(h)) ⇒ REJECT(r)',
    symbolBreakdown: [
      { symbol: 'h ∈ HeaderFields', meaning: 'Any HTTP request or response header line' },
      { symbol: '\\r, \\n, \\0', meaning: 'Carriage Return (0x0D), Line Feed (0x0A), and Null byte (0x00)' },
      { symbol: 'REJECT(r)', meaning: 'Abort processing immediately with 400 Bad Request / 500 Internal Error' }
    ],
    plainEnglish: 'Header names and header values must never contain raw carriage return (CR) or line feed (LF) characters. If unencoded CRLF is detected in input used to construct headers, reject the transaction immediately.',
    whyItMatters: 'CRLF injection in responses allows attackers to terminate the header section and inject arbitrary HTTP headers (Set-Cookie) or inject an entirely fake second HTTP response body (HTTP Response Splitting), corrupting shared caches.',
    vulnerableExample: {
      language: 'python/flask',
      code: `@app.route('/redirect')
def redirect_user():
    target = request.args.get('next')
    # VULNERABLE: Direct concatenation of user input into header without CRLF validation
    response = make_response(redirect(target))
    response.headers['X-Redirect-Target'] = target
    return response`,
      explanation: 'Attacker passes /redirect?next=%0d%0aSet-Cookie:+admin=1%0d%0a%0d%0a<html>Hacked</html> to achieve response splitting.'
    },
    secureExample: {
      language: 'python',
      code: `import re

def sanitize_header_value(val: str) -> str:
    if re.search(r'[\\r\\n\\x00]', val):
        raise ValueError("CRLF or Null character detected in header parameter")
    return val`,
      explanation: 'Explicitly validates against control characters before writing to the HTTP stream.'
    },
    howToTest: {
      tools: ['curl', 'Burp Suite'],
      steps: [
        'Send URL-encoded %0d%0a into user-controllable query parameters reflected into response headers.',
        'Inspect raw response wire format to ensure no new header or body boundary was formed.'
      ],
      commandExample: 'curl -i "https://target.com/track?lang=en%0d%0aSet-Cookie:%20pwned=true"'
    },
    interviewChallenge: {
      scenario: 'A legacy application reflects the user language parameter into a Set-Cookie header. An attacker sends ?lang=en\\r\\nContent-Length:%200\\r\\n\\r\\nHTTP/1.1%20200%20OK...',
      question: 'What is this attack called, and what is its effect on downstream cache proxies (e.g. Varnish)?',
      hint: 'The cache sees two responses for one request.',
      sampleAnswer: 'This is HTTP Response Splitting. The downstream proxy parser parses the second injected header boundary as a separate, subsequent HTTP response. It then associates this malicious response with the next pending user request in the queue, poisoning the cache for legitimate users.',
      keyTakeaway: 'Always use modern HTTP frameworks with built-in CRLF rejection, and strip control characters from user data.'
    }
  },
  {
    ruleNumber: 6,
    id: 'SEC-HTTP-006',
    title: 'HTTP/2 Flow Control and Stream Multiplexing Resource Bound',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'Protocol DoS & Rapid Reset',
    difficulty: 'Advanced',
    standardType: 'Mandatory Standard',
    standards: ['RFC 9113 §5.1.2', 'CVE-2023-44487', 'CWE-400'],
    formalInvariant: '∀ conn ∈ H2_Connections, Rate(RST_STREAM) ≤ MaxResetRate ∧ ActiveStreams(conn) ≤ SETTINGS_MAX_CONCURRENT_STREAMS',
    symbolBreakdown: [
      { symbol: 'Rate(RST_STREAM)', meaning: 'Number of RST_STREAM cancel frames received per second on a single connection' },
      { symbol: 'MaxResetRate', meaning: 'Strict upper threshold for client-initiated stream resets' },
      { symbol: 'ActiveStreams(conn)', meaning: 'Current count of open or half-closed streams' }
    ],
    plainEnglish: 'HTTP/2 servers must cap the maximum concurrent streams and throttle the rate of incoming RST_STREAM frames. Any connection that rapidly initiates and cancels streams must be terminated with GOAWAY (ENHANCE_YOUR_CALM).',
    whyItMatters: 'CVE-2023-44487 ("Rapid Reset") allowed attackers to generate millions of requests per second by opening streams and immediately canceling them with RST_STREAM, causing massive asymmetric CPU exhaustion on proxy servers without reaching concurrent stream limits.',
    vulnerableExample: {
      language: 'c/go',
      code: `// Flawed H2 handling: resets stream without penalizing connection credit
func onRstStream(stream *Stream) {
    // VULNERABLE: Instantly frees stream slot without rate-limiting reset velocity
    delete(conn.streams, stream.id)
}`,
      explanation: 'Allows attacker to churn through hundreds of thousands of streams within a single TCP connection, bypassing SETTINGS_MAX_CONCURRENT_STREAMS.'
    },
    secureExample: {
      language: 'go',
      code: `func (c *H2Conn) handleRstStream(streamID uint32) error {
    c.resetRateLimiter.Take() // Token bucket check
    if c.resetRateLimiter.Exceeded() {
        // RFC 9113: Terminate connection on abusive reset pattern
        return c.sendGoAway(http2.ErrCodeEnhanceYourCalm)
    }
    return c.closeStream(streamID)
}`,
      explanation: 'Applies rate limiting to RST_STREAM frames and terminates abusive connections with GOAWAY.'
    },
    howToTest: {
      tools: ['h2load', 'custom Python h2 script'],
      steps: [
        'Establish single TLS HTTP/2 connection.',
        'Send bursts of HEADERS followed immediately by RST_STREAM frames (>1000/sec).',
        'Verify server emits GOAWAY with error code 0xb (ENHANCE_YOUR_CALM).'
      ],
      commandExample: 'h2load -n 100000 -c 1 -m 100 https://target.internal/'
    },
    interviewChallenge: {
      scenario: 'During an outage, your reverse proxy cluster exhibits 100% CPU utilization while network bandwidth is barely 2% of capacity on HTTP/2 ports.',
      question: 'What metric should you inspect to determine if this is an HTTP/2 Rapid Reset attack?',
      hint: 'Look for the ratio between HEADERS frames and RST_STREAM frames.',
      sampleAnswer: 'Inspect the incoming H2 frame distribution: specifically the ratio of HEADERS frames to RST_STREAM frames and the frequency of stream cancellations per connection. In Rapid Reset, the reset rate closely tracks the request rate while active stream counts remain artificially low.',
      keyTakeaway: 'Resource bounds in multiplexed protocols must govern both concurrency and state-transition velocity.'
    }
  },
  {
    ruleNumber: 7,
    id: 'SEC-HTTP-007',
    title: 'Content-Type and Nosniff Boundary Enforcement',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'MIME Sniffing & XSS Mitigation',
    difficulty: 'Beginner',
    standardType: 'Mandatory Standard',
    standards: ['RFC 9110 §8.3', 'OWASP Secure Headers Project', 'CWE-430'],
    formalInvariant: '∀ resp ∈ Responses, HasBody(resp) ⇒ (HasHeader(resp, "Content-Type") ∧ HasHeader(resp, "X-Content-Type-Options: nosniff"))',
    symbolBreakdown: [
      { symbol: 'HasBody(resp)', meaning: 'HTTP response contains a non-empty entity body' },
      { symbol: 'Content-Type', meaning: 'Explicit MIME type including character set (e.g., text/html; charset=utf-8)' },
      { symbol: 'nosniff', meaning: 'Directs the browser not to inspect file bytes to guess an executable MIME type' }
    ],
    plainEnglish: 'Every response with a payload body must declare an explicit Content-Type header with character set and include X-Content-Type-Options: nosniff to stop browsers from executing disguised HTML or scripts.',
    whyItMatters: 'Without nosniff, browsers inspect the first few bytes of downloaded files. If a user uploads an image containing `<script>` tags, the browser may interpret the image as HTML/JavaScript and execute it in the domain origin, causing Stored XSS.',
    vulnerableExample: {
      language: 'http',
      code: `HTTP/1.1 200 OK
Content-Type: image/jpeg
# VULNERABLE: Missing X-Content-Type-Options: nosniff
# Browser sniffs body bytes, finds <html> tag, and executes embedded JS`,
      explanation: 'Allows user-uploaded files to be rendered as executable scripts by browsers executing MIME sniffing algorithms.'
    },
    secureExample: {
      language: 'http',
      code: `HTTP/1.1 200 OK
Content-Type: image/jpeg
X-Content-Type-Options: nosniff
Content-Disposition: attachment; filename="avatar.jpg"`,
      explanation: 'Disables MIME sniffing and forces user-uploaded content to be treated strictly according to declared type.'
    },
    howToTest: {
      tools: ['curl', 'browser DevTools'],
      steps: [
        'Serve an avatar upload with Content-Type: text/plain containing <html><script>alert(1)</script></html>.',
        'Request via browser and ensure browser displays plain text instead of executing script.'
      ],
      commandExample: 'curl -sI https://example.com/uploads/sample.png | grep -i x-content-type-options'
    },
    interviewChallenge: {
      scenario: 'A developer stores user avatars in S3 and serves them directly through CloudFront with Content-Type: text/plain.',
      question: 'Can an attacker achieve XSS on the main domain if nosniff is missing?',
      hint: 'Think about how Internet Explorer and older Chromium engines handle HTML tags inside text/plain.',
      sampleAnswer: 'Yes. Without nosniff, older browsers will inspect the body content, identify HTML tags, and switch the execution context from text to text/html, executing embedded JavaScript in the origin of the S3 bucket or CloudFront domain.',
      keyTakeaway: 'Always supply X-Content-Type-Options: nosniff and serve untrusted uploads from a dedicated, isolated sandbox origin.'
    }
  },
  {
    ruleNumber: 8,
    id: 'SEC-HTTP-008',
    title: 'HTTP Method Whitelisting and Idempotency Guard',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'Method Tampering & Safe Verbs',
    difficulty: 'Beginner',
    standardType: 'Mandatory Standard',
    standards: ['RFC 9110 §9.2', 'OWASP ASVS 4.0 §13.1.4', 'CWE-650'],
    formalInvariant: '∀ r ∈ Requests, Method(r) ∈ {GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD} ∧ (Method(r) ∈ {GET, HEAD, OPTIONS} ⇒ StateChange(r) = False)',
    symbolBreakdown: [
      { symbol: 'Method(r)', meaning: 'HTTP verb declared in request line' },
      { symbol: 'StateChange(r) = False', meaning: 'Safe methods (RFC 9110 §9.2.1) must never mutate server state, database rows, or financial balances' }
    ],
    plainEnglish: 'Applications must reject unknown or obsolete HTTP methods (such as TRACE or DEBUG) and guarantee that safe methods (GET, HEAD, OPTIONS) never mutate persistent server state.',
    whyItMatters: 'Using GET requests to trigger actions (e.g. `/api/transfer?amount=1000&to=bob`) makes state changes trivially exploitable via Cross-Site Request Forgery (CSRF) or browser prefetching. Enabling TRACE allows Cross-Site Tracing (XST) to steal HttpOnly cookies.',
    vulnerableExample: {
      language: 'javascript/express',
      code: `// VULNERABLE: State mutation via GET request
app.get('/users/:id/delete', async (req, res) => {
    await db.user.delete(req.params.id);
    res.send("Deleted");
});`,
      explanation: 'An attacker embeds `<img src="https://bank.com/users/42/delete">` on a forum, causing victims browsers to unknowingly trigger deletion.'
    },
    secureExample: {
      language: 'javascript/express',
      code: `// SECURE: Strict verb whitelisting + POST/DELETE for mutation
app.delete('/users/:id', authenticate, verifyCSRFToken, async (req, res) => {
    await db.user.delete(req.params.id);
    res.status(204).end();
});`,
      explanation: 'Requires non-safe method with CSRF tokens or origin checks, protecting against passive image triggers.'
    },
    howToTest: {
      tools: ['curl', 'nmap http-methods'],
      steps: [
        'Send TRACE / HTTP/1.1 to verify TRACE is disabled (405 Method Not Allowed).',
        'Verify search crawlers or image prefetchers do not inadvertently delete records via GET.'
      ],
      commandExample: 'curl -X TRACE -i https://example.com/'
    },
    interviewChallenge: {
      scenario: 'A penetration tester uses HTTP verb tampering: replacing POST with HEAD or arbitrary verbs like FOO to bypass an authentication filter.',
      question: 'Why did the authentication filter fail to block FOO /admin, and how should authorization filters be constructed?',
      hint: 'Did the security filter whitelist methods or blacklist specific methods?',
      sampleAnswer: 'The filter was written with an insecure blacklist (e.g., checking only if method is POST or GET). Unrecognized verbs fell through to the application handler, which used an overarching fallback dispatcher. Authorization filters must be fail-closed: authenticate and authorize the request regardless of verb, or strictly whitelist allowed methods.',
      keyTakeaway: 'Never use method blacklists in security middleware; adopt fail-closed default deny.'
    }
  },
  {
    ruleNumber: 9,
    id: 'SEC-HTTP-009',
    title: 'Strict Request Header Size and Count Caps',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'DoS & Buffer Exhaustion',
    difficulty: 'Intermediate',
    standardType: 'Mandatory Standard',
    standards: ['RFC 9112 §2.1', 'CWE-400'],
    formalInvariant: '∀ r ∈ Requests, Size(Headers(r)) ≤ MaxHeaderBytes ∧ Count(Headers(r)) ≤ MaxHeaderCount',
    symbolBreakdown: [
      { symbol: 'Size(Headers(r))', meaning: 'Total byte length of all header fields combined' },
      { symbol: 'MaxHeaderBytes', meaning: 'Hard limit typically set to 8KB–16KB' },
      { symbol: 'MaxHeaderCount', meaning: 'Maximum allowable distinct headers (typically 50–100)' }
    ],
    plainEnglish: 'Web servers and proxies must enforce an immutable upper bound on the combined size and count of incoming HTTP headers (typically 8KB–16KB), terminating over-sized headers with 431 Request Header Fields Too Large.',
    whyItMatters: 'Without strict limits, attackers can launch Slowloris attacks or consume gigabytes of heap memory on reverse proxies by sending endless unique headers, causing Out-Of-Memory (OOM) crashes across worker processes.',
    vulnerableExample: {
      language: 'node/http',
      code: `// Flawed custom parser without maxHeaderSize limits
const server = http.createServer({
    maxHeaderSize: 1024 * 1024 * 100 // 100MB headers allowed!
}, handler);`,
      explanation: 'Allows concurrent connections to allocate hundreds of megabytes of buffer space for header storage.'
    },
    secureExample: {
      language: 'nginx',
      code: `# Nginx strict header size configuration
large_client_header_buffers 4 8k;
client_header_buffer_size 1k;
client_header_timeout 10s;`,
      explanation: 'Enforces an 8KB ceiling per buffer with strict 10s read timeouts, preventing Slowloris and OOM exhaustion.'
    },
    howToTest: {
      tools: ['curl', 'Slowloris script'],
      steps: [
        'Send request with 100KB of arbitrary headers.',
        'Verify server returns 431 Request Header Fields Too Large or 400 Bad Request within milliseconds.'
      ],
      commandExample: 'curl -H "$(python3 -c \'print("X-Spam: " + "A"*20000)\')" https://target.com/'
    },
    interviewChallenge: {
      scenario: 'Users report random 431 errors when using an enterprise application integrated with multiple SAML/OAuth SSO identity providers.',
      question: 'What is the root cause, and how do you resolve it safely without creating a DoS vulnerability?',
      hint: 'Check cookie sizes and authorization bearer headers.',
      sampleAnswer: 'Multiple large JWT tokens or session cookies accumulate on the domain, exceeding the 8KB header buffer. To resolve safely, split session state, store tokens in backend Redis sessions rather than fat cookies, or moderately raise the limit to 16KB while maintaining strict timeout controls.',
      keyTakeaway: 'Keep headers lean; excessive cookie bloat harms both latency and DoS resilience.'
    }
  },
  {
    ruleNumber: 10,
    id: 'SEC-HTTP-010',
    title: 'WebSocket Handshake Origin and Subprotocol Validation',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'Cross-Site WebSocket Hijacking (CSWSH)',
    difficulty: 'Advanced',
    standardType: 'Mandatory Standard',
    standards: ['RFC 6455 §4.2.2', 'OWASP ASVS 4.0 §13.4.1', 'CWE-346'],
    formalInvariant: '∀ w ∈ WS_UpgradeRequests, Origin(w) ∈ TrustedOrigins ∧ ValidateCSRFToken(w) = True',
    symbolBreakdown: [
      { symbol: 'w ∈ WS_UpgradeRequests', meaning: 'HTTP GET request with Upgrade: websocket and Connection: Upgrade' },
      { symbol: 'Origin(w) ∈ TrustedOrigins', meaning: 'The browser Origin header must be verified against an approved whitelist' },
      { symbol: 'ValidateCSRFToken(w)', meaning: 'Handshake must require a cryptographically random, one-time anti-CSRF token' }
    ],
    plainEnglish: 'During WebSocket upgrade handshakes, the server must strictly validate the Origin header against a trusted whitelist and require an anti-CSRF token. Browsers do not enforce Same-Origin Policy on WebSocket connections.',
    whyItMatters: 'Because browsers attach ambient cookies during cross-site WebSocket handshakes, an attacker hosting malicious JavaScript on evil.com can open a WebSocket to `wss://bank.com/stream`, hijack the authenticated session, and exfiltrate real-time messages (Cross-Site WebSocket Hijacking).',
    vulnerableExample: {
      language: 'javascript/ws',
      code: `const wss = new WebSocketServer({ port: 8080 });
wss.on('connection', (ws, req) => {
    // VULNERABLE: No Origin check! Accepts connection from any origin
    const user = getSessionUserFromCookie(req.headers.cookie);
    ws.send(JSON.stringify({ secretFeed: user.accountData }));
});`,
      explanation: 'Any website visited by an authenticated user can open a connection and read private user streams.'
    },
    secureExample: {
      language: 'javascript/ws',
      code: `const ALLOWED_ORIGIN = 'https://app.example.com';

wss.on('connection', (ws, req) => {
    const origin = req.headers['origin'];
    if (origin !== ALLOWED_ORIGIN) {
        ws.close(1008, "Policy Violation: Untrusted Origin");
        return;
    }
    // Verify one-time handshake ticket
    const ticket = parseTicket(req.url);
    if (!verifyAndBurnTicket(ticket)) {
        ws.close(1008, "Invalid Handshake Token");
        return;
    }
});`,
      explanation: 'Verifies the origin header and consumes a single-use token issued during authenticated page load.'
    },
    howToTest: {
      tools: ['wscat', 'curl', 'browser console'],
      steps: [
        'Attempt WebSocket connection from browser on a different origin or using wscat with Origin: https://evil.com.',
        'Verify server returns 403 Forbidden or drops handshake.'
      ],
      commandExample: 'wscat -c wss://target.com/ws -H "Origin: https://attacker.com"'
    },
    interviewChallenge: {
      scenario: 'A developer assumes that because WebSockets use TLS (wss://), they are immune to CSRF.',
      question: 'Why is this assumption false?',
      hint: 'Does the browser send cookies with cross-origin WebSocket connections?',
      sampleAnswer: 'TLS encrypts the transport between client and server, but the browser automatically attaches cookies to cross-origin WebSocket upgrade requests just like regular requests. Without explicit Origin validation or CSRF tokens, any third-party script can initiate an authenticated session over TLS.',
      keyTakeaway: 'Same-Origin Policy does NOT automatically restrict WebSocket connections; origin checks are mandatory.'
    }
  },
  {
    ruleNumber: 11,
    id: 'SEC-HTTP-011',
    title: 'Early Hints (103) Information Leakage Invariant',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'Information Disclosure & 1xx Responses',
    difficulty: 'Intermediate',
    standardType: 'Mandatory Standard',
    standards: ['RFC 8297 §2', 'RFC 9110 §15.2.4', 'CWE-200'],
    formalInvariant: '∀ resp ∈ 103_EarlyHints, HasHeader(resp, "Set-Cookie") = False ∧ (∀ link ∈ PreloadLinks(resp), Origin(link) ∈ TrustedPreloadDomains)',
    symbolBreakdown: [
      { symbol: 'resp ∈ 103_EarlyHints', meaning: 'Any informational 103 Early Hints response emitted before the final 200/300 status' },
      { symbol: 'HasHeader(resp, "Set-Cookie") = False', meaning: 'Early Hints must NEVER attempt to alter cookie or session state' },
      { symbol: 'Origin(link) ∈ TrustedPreloadDomains', meaning: 'Preloaded Link headers must point only to verified, trustworthy asset domains' }
    ],
    plainEnglish: 'An HTTP 103 Early Hints response must never include Set-Cookie headers, authorization credentials, or unvetted external asset links. Intermediaries must drop or ignore Set-Cookie in 103 responses.',
    whyItMatters: 'If sensitive session tokens or unauthenticated cookie headers are delivered in speculative 103 responses, intermediate network caches and CDNs may log, misattribute, or leak session states before the final response determines authorization.',
    vulnerableExample: {
      language: 'http',
      code: `HTTP/1.1 103 Early Hints
Link: </style.css>; rel=preload; as=style
Set-Cookie: temp_session=xyz123; Path=/
# VULNERABLE: Emitting Set-Cookie in an informational 103 response`,
      explanation: 'RFC 8297 forbids Set-Cookie in 103 responses because user agents process them speculatively prior to final response authorization.'
    },
    secureExample: {
      language: 'http',
      code: `HTTP/1.1 103 Early Hints
Link: </assets/bundle.css>; rel=preload; as=style
Link: </assets/app.js>; rel=preload; as=script`,
      explanation: 'Contains only static, cache-safe asset hints without sensitive state mutations.'
    },
    howToTest: {
      tools: ['curl', 'wireshark'],
      steps: [
        'Query endpoint with Early Hints enabled: curl -I --http1.1 https://example.com/app.',
        'Verify no Set-Cookie or sensitive Authorization tokens appear in the 103 block.'
      ],
      commandExample: 'curl -sI -k https://target.com/ | grep -E "HTTP/1.1 103|Set-Cookie"'
    },
    interviewChallenge: {
      scenario: 'A CDN edge server emits HTTP 103 Early Hints for an eCommerce checkout flow.',
      question: 'Why must dynamic personalized resources never be pushed or preloaded via 103 Early Hints?',
      hint: 'Can intermediate caches distinguish personalized 103 responses from shared static assets?',
      sampleAnswer: 'Early Hints are designed for deterministic static assets (CSS, JS, fonts). Preloading dynamic personalized endpoints via 103 risks cache poisoning across users if an intermediate caching layer does not properly evaluate Vary headers before committing the preloaded object to edge storage.',
      keyTakeaway: 'Restrict HTTP 103 Early Hints strictly to immutable, public static dependencies.'
    }
  },
  {
    ruleNumber: 12,
    id: 'SEC-HTTP-012',
    title: 'Range Request Bomb & Integer Overflow Prevention',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'DoS & Resource Management',
    difficulty: 'Intermediate',
    standardType: 'Mandatory Standard',
    standards: ['RFC 9110 §14.2', 'CVE-2011-3192', 'CWE-400'],
    formalInvariant: '∀ r ∈ RangeRequests, Count(Ranges(r)) ≤ MaxRanges (≤ 5) ∧ NoOverlapping(Ranges(r)) ∧ (∀ (start, end) ∈ Ranges, start ≤ end < ContentLength)',
    symbolBreakdown: [
      { symbol: 'Count(Ranges(r)) ≤ 5', meaning: 'The Range header must contain at most a small ceiling of discrete byte intervals' },
      { symbol: 'NoOverlapping(...)', meaning: 'Range intervals must not overlap or repeat identical byte segments' },
      { symbol: 'start ≤ end < ContentLength', meaning: 'Byte boundaries must be mathematically strictly ordered and within total entity length' }
    ],
    plainEnglish: 'Servers supporting HTTP Range requests must enforce an upper bound on the number of requested byte ranges (maximum 5) and reject overlapping or duplicate ranges. If boundaries exceed bounds, return 416 Range Not Satisfiable.',
    whyItMatters: 'In the classic Apache "Range Bomb" (CVE-2011-3192), an attacker sends `Range: bytes=0-,5-0,5-1,5-2...` with thousands of overlapping ranges. The server spends massive CPU and memory slicing and re-encoding overlapping byte buffers, causing instant CPU exhaustion and denial of service.',
    vulnerableExample: {
      language: 'nginx/apache',
      code: `# Vulnerable default or unthrottled range parser
GET /large-video.mp4 HTTP/1.1
Range: bytes=0-1, 0-2, 0-3, 0-4, 0-5 ... (repeated 10,000 times)
# Server allocates separate memory slices for each range and crashes with OOM`,
      explanation: 'Allows unbounded range fragmentation, multiplying memory footprint by thousands of times the file size.'
    },
    secureExample: {
      language: 'go',
      code: `func parseRange(header string, size int64) ([]httpRange, error) {
    ranges := strings.Split(strings.TrimPrefix(header, "bytes="), ",")
    if len(ranges) > 5 {
        // Enforce Range count ceiling
        return nil, errors.New("Too many byte ranges requested (max 5)")
    }
    // Validate ordering: start <= end < size
    return validatedRanges, nil
}`,
      explanation: 'Caps allowable sub-ranges at 5 and validates boundary ordering before allocating buffer memory.'
    },
    howToTest: {
      tools: ['curl', 'siege'],
      steps: [
        'Send request with 50 overlapping ranges: Range: bytes=0-1,0-2,0-3... to static asset endpoint.',
        'Verify server returns 416 Range Not Satisfiable or ignores excessive ranges without spiking memory.'
      ],
      commandExample: 'curl -H "Range: bytes=0-1,0-2,0-3,0-4,0-5,0-6" -i https://target.com/image.png'
    },
    interviewChallenge: {
      scenario: 'A streaming media service receives complaints that malicious clients are exhausting worker threads using malformed byte range requests.',
      question: 'Why is returning 200 OK with the entire file body safer than processing 100 separate multipart ranges?',
      hint: 'Compare the memory and multipart framing overhead of 100 tiny ranges vs single linear sequential disk streaming.',
      sampleAnswer: 'Streaming a single contiguous file (HTTP 200) uses zero-copy OS system calls (e.g. sendfile) with predictable streaming memory. Generating a multipart/byteranges response for 100 tiny overlapping ranges forces the web server to allocate memory buffers in user-space, format MIME boundaries for each slice, and perform hundreds of disk seeks, creating severe resource amplification.',
      keyTakeaway: 'Cap range counts strictly; fall back to 200 OK or 416 when client range requests exceed threshold.'
    }
  },
  {
    ruleNumber: 13,
    id: 'SEC-HTTP-013',
    title: 'HTTP/3 0-RTT Anti-Replay Invariant',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'QUIC & 0-RTT Replay Attacks',
    difficulty: 'Advanced',
    standardType: 'Mandatory Standard',
    standards: ['RFC 9000 §9.2', 'RFC 8470', 'CWE-294'],
    formalInvariant: '∀ r ∈ 0RTT_EarlyData, Method(r) ∈ SafeMethods ∧ IsReplayResistant(r) ∧ (StateChange(r) = False)',
    symbolBreakdown: [
      { symbol: '0RTT_EarlyData', meaning: 'Requests transmitted in TLS 1.3 / QUIC 0-RTT early data before handshake completion' },
      { symbol: 'Method(r) ∈ SafeMethods', meaning: 'Must strictly restrict 0-RTT data to idempotent safe methods (GET, HEAD)' },
      { symbol: 'IsReplayResistant(r)', meaning: 'Application must reject early data or use single-use strike-registers if state mutation is attempted' }
    ],
    plainEnglish: 'TLS 1.3 and QUIC 0-RTT Early Data is inherently vulnerable to network replay. Servers and reverse proxies must NEVER process non-idempotent or state-changing requests (POST, PUT, DELETE) within 0-RTT early data.',
    whyItMatters: 'An on-path network attacker can record a 0-RTT packet sent over public Wi-Fi and replay it multiple times to the server. If the request was a financial transfer or order placement, replaying the 0-RTT packet executes multiple duplicate charges.',
    vulnerableExample: {
      language: 'http',
      code: `# VULNERABLE: Allowing state-changing POST inside 0-RTT early data
POST /api/pay/transfer HTTP/3
Early-Data: 1
Content-Type: application/json

{"recipient": "bob", "amount": 500}
# Attacker sniffs raw QUIC packet and replays it 10 times to duplicate transfers!`,
      explanation: '0-RTT early data lacks forward secrecy and replay protection before the handshake finishes.'
    },
    secureExample: {
      language: 'nginx',
      code: `# SECURE: Enforce 425 Too Early on non-safe requests in early data
if ($ssl_early_data) {
    # Mandate client retry in 1-RTT for mutating endpoints
    return 425;
}`,
      explanation: 'Returns HTTP 425 Too Early, instructing the browser to resend the request only after the full cryptographic handshake completes.'
    },
    howToTest: {
      tools: ['quiche-client', 'curl --http3-only'],
      steps: [
        'Establish QUIC session and obtain session ticket.',
        'Send POST request inside 0-RTT early data packet.',
        'Verify server returns HTTP 425 Too Early.'
      ],
      commandExample: 'curl --http3-only -sI -k https://target.com/'
    },
    interviewChallenge: {
      scenario: 'An architect proposes enabling 0-RTT across all API routes to reduce latency for mobile clients in Australia connecting to US servers.',
      question: 'What architectural safeguard must be in place before enabling 0-RTT on an API Gateway?',
      hint: 'How should the gateway handle requests marked with the Early-Data header?',
      sampleAnswer: 'The API Gateway must inspect the connection state: if a request arrives in 0-RTT early data and uses a mutating method (POST, PUT, DELETE, PATCH) or lacks explicit idempotency safeguards, the gateway must return HTTP 425 (Too Early) or buffer the request until the handshake completes. Only safe, idempotent GET requests should ever execute in 0-RTT.',
      keyTakeaway: 'Never execute state-changing business logic inside TLS 1.3 / QUIC 0-RTT early data.'
    }
  },
  {
    ruleNumber: 14,
    id: 'SEC-HTTP-014',
    title: 'Strict Content-Encoding Header Validation',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'Decompression Bombs & Gzip',
    difficulty: 'Intermediate',
    standardType: 'Mandatory Standard',
    standards: ['RFC 9110 §8.4', 'CWE-400'],
    formalInvariant: '∀ r ∈ CompressedPayloads, DecompressedBytes(r) ≤ MaxDecompressedLimit ∧ Ratio(Decompressed / Compressed) ≤ MaxExpansionRatio',
    symbolBreakdown: [
      { symbol: 'CompressedPayloads', meaning: 'Any request body with Content-Encoding: gzip, br, or deflate' },
      { symbol: 'DecompressedBytes ≤ MaxLimit', meaning: 'Hard limit on memory allocated during decompression (typically 10MB)' },
      { symbol: 'Ratio ≤ MaxExpansionRatio', meaning: 'Detects decompression bombs where tiny inputs expand thousands of times' }
    ],
    plainEnglish: 'When accepting compressed request bodies (gzip, zstd, br), the server must enforce strict decompression limits on the total decompressed byte count and abort if the expansion ratio indicates a decompression bomb.',
    whyItMatters: 'A 10KB gzip payload can decompress into 10GB of null bytes (a "Zip Bomb" or "Gzip Bomb"). Without bounded streaming decompression, an API endpoint accepting compressed bodies will exhaust all host memory and crash under Out-Of-Memory (OOM).',
    vulnerableExample: {
      language: 'python',
      code: `import gzip

def handle_request(req):
    if req.headers.get('Content-Encoding') == 'gzip':
        # VULNERABLE: Decompresses entire payload into RAM at once!
        uncompressed_data = gzip.decompress(req.body)
        return process(uncompressed_data)`,
      explanation: 'A 50KB gzip file expands into 5GB in memory, crashing the worker process immediately.'
    },
    secureExample: {
      language: 'python',
      code: `import gzip, io

MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024 # 10 MB

def handle_request(req):
    if req.headers.get('Content-Encoding') == 'gzip':
        decompressed = io.BytesIO()
        total = 0
        with gzip.GzipFile(fileobj=io.BytesIO(req.body)) as gz:
            while chunk := gz.read(65536):
                total += len(chunk)
                if total > MAX_DECOMPRESSED_SIZE:
                    raise PayloadTooLargeError("Decompressed body exceeds 10MB limit")
                decompressed.write(chunk)
        return process(decompressed.getvalue())`,
      explanation: 'Streams decompression and terminates immediately if decompressed bytes exceed safety thresholds.'
    },
    howToTest: {
      tools: ['curl', 'gzip'],
      steps: [
        'Create a 1GB sparse file of zeros and compress to small gzip: dd if=/dev/zero bs=1M count=1000 | gzip > bomb.gz.',
        'Submit to API endpoint accepting gzip.',
        'Verify server returns 413 Payload Too Large within milliseconds without memory spike.'
      ],
      commandExample: 'curl -X POST -H "Content-Encoding: gzip" --data-binary @bomb.gz https://api.target.com/upload'
    },
    interviewChallenge: {
      scenario: 'Your microservice architecture allows gzip compression on incoming Webhook payloads from third parties.',
      question: 'Why is checking the Content-Length header insufficient to prevent decompression bomb denial-of-service?',
      hint: 'What does Content-Length represent when Content-Encoding is gzip?',
      sampleAnswer: 'Content-Length specifies the size of the compressed byte stream over the wire, not the size of the decompressed payload. A 40KB compressed payload can legitimately declare Content-Length: 40960 while expanding into 50 Gigabytes of memory upon decompression. Protection requires streaming counting during decompression with a hard ceiling.',
      keyTakeaway: 'Always measure decompressed bytes dynamically on the fly; never trust wire Content-Length.'
    }
  },
  {
    ruleNumber: 15,
    id: 'SEC-HTTP-015',
    title: 'Cache-Control Private Enforcement for Sensitive State',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'Web Caching & Privacy',
    difficulty: 'Beginner',
    standardType: 'Mandatory Standard',
    standards: ['RFC 9111 §5.2', 'OWASP ASVS §13.2.3', 'CWE-524'],
    formalInvariant: '∀ resp ∈ SensitiveResponses, HasHeader(resp, "Cache-Control") ∧ ("no-store" ∈ Directives(resp) ∨ "private" ∈ Directives(resp))',
    symbolBreakdown: [
      { symbol: 'SensitiveResponses', meaning: 'Any response delivering PII, financial data, auth tokens, or private user profiles' },
      { symbol: 'no-store', meaning: 'Instructs all caches (browser and CDN) to discard the response immediately without writing to disk' },
      { symbol: 'private', meaning: 'Prohibits shared intermediaries (CDNs, proxies) from caching the response' }
    ],
    plainEnglish: 'Any HTTP response containing sensitive personal, financial, or authentication state must declare `Cache-Control: no-store, max-age=0` to ensure shared CDNs and local browser caches never store or serve the payload to unauthorized third parties.',
    whyItMatters: 'If sensitive pages omit Cache-Control or declare `public`, shared reverse proxies (like Cloudflare, Akamai, or Varnish) will cache the response and serve User A’s private banking balance or invoices to User B.',
    vulnerableExample: {
      language: 'http',
      code: `HTTP/1.1 200 OK
Content-Type: application/json
# VULNERABLE: Omits Cache-Control!
# Intermediary CDNs cache this private user profile and serve it to subsequent visitors
{"user_id": 42, "ssn": "123-45-6789", "balance": 15000}`,
      explanation: 'Shared caches will treat the response as cacheable, leaking private data to other users.'
    },
    secureExample: {
      language: 'http',
      code: `HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store, no-cache, max-age=0, must-revalidate
Pragma: no-cache
{"user_id": 42, "ssn": "123-45-6789", "balance": 15000}`,
      explanation: 'Explicitly instructs all browser and intermediary caches never to write data to disk or serve from cache.'
    },
    howToTest: {
      tools: ['curl', 'browser DevTools Network tab'],
      steps: [
        'Query authenticated profile endpoint via curl -sI https://example.com/api/user.',
        'Verify Cache-Control contains no-store or private and max-age=0.',
        'Confirm response is never served from CDN cache hit.'
      ],
      commandExample: 'curl -sI https://example.com/api/account/billing | grep -i cache-control'
    },
    interviewChallenge: {
      scenario: 'A developer adds `Cache-Control: no-cache` to a sensitive API response and believes this prevents CDNs from storing the data on disk.',
      question: 'What does `no-cache` actually mean in RFC 9111, and why must you use `no-store` instead?',
      hint: 'Does `no-cache` mean "do not cache" or "revalidate with server before using cached copy"?',
      sampleAnswer: '`no-cache` does NOT mean "do not cache". It instructs caches that they CAN store the response, but must revalidate with the origin server (using ETag or If-Modified-Since) before releasing it. If you want to prohibit caches from writing sensitive data to disk or memory entirely, you must use `no-store`.',
      keyTakeaway: 'Always use `no-store` to prevent caching of sensitive data; `no-cache` permits storage.'
    }
  },
  {
    ruleNumber: 16,
    id: 'SEC-HTTP-016',
    title: 'Clear-Site-Data Invocation on Logout Invariant',
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: 'Session Teardown & Hygiene',
    difficulty: 'Beginner',
    standardType: 'Mandatory Standard',
    standards: ['W3C Clear Site Data', 'OWASP ASVS §3.3.4', 'CWE-613'],
    formalInvariant: '∀ resp ∈ LogoutResponses, HasHeader(resp, "Clear-Site-Data: \\"cache\\", \\"cookies\\", \\"storage\\"")',
    symbolBreakdown: [
      { symbol: 'resp ∈ LogoutResponses', meaning: 'The final HTTP response completing a user logout operation' },
      { symbol: 'Clear-Site-Data', meaning: 'W3C header instructing the browser to purge client-side state for the origin' },
      { symbol: '"cache", "cookies", "storage"', meaning: 'Clears HTTP disk cache, session cookies, localStorage, and IndexedDB' }
    ],
    plainEnglish: 'Upon user logout, the application must return the `Clear-Site-Data: "cache", "cookies", "storage"` header. This ensures the browser purges sensitive cached pages, tokens in storage, and cookies, protecting shared or public terminals.',
    whyItMatters: 'On shared computers (e.g. library, workplace, or kiosk), pressing the browser "Back" button after logout allows the next user to view cached account screens, invoices, or personal data if client storage is not explicitly wiped.',
    vulnerableExample: {
      language: 'http',
      code: `HTTP/1.1 302 Found
Location: /login
Set-Cookie: session=; Max-Age=0
# VULNERABLE: Omits Clear-Site-Data!
# Browser retains cached HTML pages, localStorage tokens, and service worker caches`,
      explanation: 'Leaves client-side data intact in browser memory and disk caches for subsequent users of the device.'
    },
    secureExample: {
      language: 'http',
      code: `HTTP/1.1 200 OK
Clear-Site-Data: "cache", "cookies", "storage"
Content-Type: application/json
{"status": "logged_out"}`,
      explanation: 'Commands browser to purge origin cache, cookies, localStorage, and IndexedDB immediately.'
    },
    howToTest: {
      tools: ['browser DevTools', 'curl'],
      steps: [
        'Perform logout in browser and observe Application tab in DevTools.',
        'Verify cookies, localStorage, and cached network items are cleared automatically.'
      ],
      commandExample: 'curl -sI -X POST https://example.com/auth/logout | grep -i clear-site-data'
    },
    interviewChallenge: {
      scenario: 'A user logs out of their banking portal on an airport public computer. The next person clicks the browser Back button and views the account summary.',
      question: 'How does Clear-Site-Data solve this, and what additional cache headers are required?',
      hint: 'Think about bfcache (back-forward cache) in modern browsers.',
      sampleAnswer: 'Clear-Site-Data with `"cache", "storage"` instructs the browser to purge cached HTML documents and client stores. In combination with `Cache-Control: no-store` on sensitive pages, this forces the browser to discard the back-forward cache (bfcache), ensuring pressing Back prompts for login rather than rendering cached HTML.',
      keyTakeaway: 'Combine `Clear-Site-Data` with `Cache-Control: no-store` to prevent data leakage via browser navigation.'
    }
  }
];

// Helper to fill remaining HTTP rules up to 36 with high-fidelity, specific fields
const remainingHttpDefs = [
  {
    num: 17,
    title: 'No-Transform Directive for Dynamic Content Integrity',
    sub: 'Intermediary Tampering',
    diff: 'Intermediate',
    std: 'RFC 9111 §5.2.2',
    formal: '∀ resp ∈ IntegrityResponses, "no-transform" ∈ Directives(Cache-Control(resp))',
    plain: 'Responses must declare Cache-Control: no-transform to forbid proxy intermediaries and mobile gateways from modifying, minifying, or injecting scripts into the HTTP body.',
    why: 'Mobile carrier proxies and transparent ISP caches historically injected ads or re-compressed HTML/JavaScript files, breaking subresource hashes and introducing XSS vulnerabilities.',
    vuln: 'Cache-Control: public, max-age=3600 # Intermediary proxy injects tracking script',
    sec: 'Cache-Control: no-transform, public, max-age=3600 # Intermediary must not alter bytes',
    testCmd: 'curl -sI https://example.com/app.js | grep -i no-transform',
    interviewQ: 'Why does missing no-transform cause Subresource Integrity (SRI) failures on mobile networks?',
    interviewA: 'Telco proxies recompress or minify JavaScript on the fly to save cellular bandwidth. If no-transform is missing, the proxy alters the file bytes, causing the cryptographic SHA-384 hash in the browser SRI check to fail and terminating script execution.'
  },
  {
    num: 18,
    title: 'X-Forwarded-For Trust Boundary Sanitization',
    sub: 'Proxy Architecture',
    diff: 'Intermediate',
    std: 'RFC 7239 §5',
    formal: '∀ r ∈ InboundRequests, ClientIP(r) = RemoteAddr(r) ∨ (IsTrustedProxy(RemoteAddr(r)) ∧ ClientIP(r) = ParseTrustedHop(r))',
    plain: 'Backend applications must only trust X-Forwarded-For headers if received directly from a verified reverse-proxy IP address. Untrusted incoming client values must be stripped.',
    why: 'Attackers inject `X-Forwarded-For: 127.0.0.1` to bypass IP-based rate limiting, geo-fencing, and internal administrative access controls.',
    vuln: 'client_ip = req.headers["x-forwarded-for"].split(",")[0] # Easily spoofed!',
    sec: 'client_ip = get_trusted_client_ip(req.headers["x-forwarded-for"], trusted_proxies_list)',
    testCmd: 'curl -H "X-Forwarded-For: 127.0.0.1" https://api.target.com/admin',
    interviewQ: 'How can an attacker bypass IP whitelisting if an application naively reads the left-most IP in X-Forwarded-For?',
    interviewA: 'The left-most IP is entirely client-controlled. An attacker sends `X-Forwarded-For: 10.0.0.1`. The proxy appends the real attacker IP: `10.0.0.1, 203.0.113.5`. If the backend reads the first IP, it trusts the forged 10.0.0.1. Backends must parse from right to left, discarding untrusted hops.'
  },
  {
    num: 19,
    title: 'Strict-Transport-Security Never Sent Over Plain HTTP',
    sub: 'Protocol Integrity',
    diff: 'Beginner',
    std: 'RFC 6797 §7.2',
    formal: '∀ resp ∈ Responses, Scheme(resp) = HTTP ⇒ HasHeader(resp, "Strict-Transport-Security") = False',
    plain: 'HSTS headers must only be sent over secure HTTPS connections. If an unencrypted HTTP response includes HSTS, browsers must ignore it per RFC 6797 Section 7.2.',
    why: 'Sending HSTS over plaintext allows an active man-in-the-middle attacker to inject a fake HSTS header with a max-age of zero, stripping transport security for future sessions.',
    vuln: 'HTTP/1.1 200 OK (over port 80)\nStrict-Transport-Security: max-age=0 # Attacker injects to disable HSTS',
    sec: 'HTTP/1.1 301 Moved Permanently\nLocation: https://example.com/ # HSTS emitted ONLY over 443 HTTPS',
    testCmd: 'curl -sI http://example.com/ | grep -i strict-transport-security',
    interviewQ: 'Why does RFC 6797 strictly forbid browsers from honoring HSTS received over plaintext HTTP?',
    interviewA: 'Plaintext HTTP has zero cryptographic authenticity or tamper resistance. If browsers honored HSTS over port 80, any coffee-shop Wi-Fi attacker could inject `Strict-Transport-Security: max-age=0` to permanently deactivate HSTS protection on that domain.'
  },
  {
    num: 20,
    title: 'Cross-Origin-Opener-Policy (COOP) Process Isolation',
    sub: 'Spectre & Process Isolation',
    diff: 'Advanced',
    std: 'HTML Living Standard §7.3',
    formal: '∀ doc ∈ TopLevelDocuments, HasHeader(doc, "Cross-Origin-Opener-Policy: same-origin")',
    plain: 'Top-level documents must declare Cross-Origin-Opener-Policy: same-origin to isolate the browser browsing context group from other windows, blocking window.opener access.',
    why: 'Without COOP, cross-origin windows can open the target site and retain a window reference, measuring microarchitectural timing differences (Spectre attacks) or exploiting tabnabbing.',
    vuln: 'Cross-Origin-Opener-Policy: unsafe-none # Retains opener context',
    sec: 'Cross-Origin-Opener-Policy: same-origin # Complete browsing context isolation',
    testCmd: 'curl -sI https://example.com/ | grep -i cross-origin-opener-policy',
    interviewQ: 'How does COOP protect web applications against Spectre-style side-channel memory leaks in browsers?',
    interviewA: 'COOP forces the browser to place the document in a dedicated OS process. By isolating the process, other cross-origin tabs cannot share the same V8 isolate or memory address space, neutralizing microarchitectural cache-timing attacks (like Spectre) that rely on shared process heaps.'
  },
  {
    num: 21,
    title: 'Cross-Origin-Embedder-Policy (COEP) Corp Separation',
    sub: 'Spectre & Process Isolation',
    diff: 'Advanced',
    std: 'W3C COEP Spec',
    formal: '∀ doc ∈ HighSecurityDocs, HasHeader(doc, "Cross-Origin-Embedder-Policy: require-corp")',
    plain: 'Documents requiring high-resolution timers (SharedArrayBuffer) must declare Cross-Origin-Embedder-Policy: require-corp, ensuring all embedded subresources explicitly grant permission.',
    why: 'Enabling SharedArrayBuffer without COEP allows malicious pages to measure CPU cache timing down to nanoseconds, facilitating cross-origin microarchitectural data exfiltration.',
    vuln: 'Cross-Origin-Embedder-Policy: unsafe-none',
    sec: 'Cross-Origin-Embedder-Policy: require-corp; Cross-Origin-Opener-Policy: same-origin',
    testCmd: 'curl -sI https://example.com/ | grep -i cross-origin-embedder-policy',
    interviewQ: 'Why did browser vendors disable SharedArrayBuffer after Spectre, and what headers re-enable it safely?',
    interviewA: 'SharedArrayBuffer provides high-precision threading and nanosecond timers needed for Spectre cache attacks. Browsers re-enable it only in "cross-origin isolated" environments, which require both COOP: same-origin and COEP: require-corp.'
  },
  {
    num: 22,
    title: 'Cross-Origin-Resource-Policy (CORP) Defense Invariant',
    sub: 'Resource Leakage',
    diff: 'Intermediate',
    std: 'W3C CORP Spec',
    formal: '∀ res ∈ StaticResources, HasHeader(res, "Cross-Origin-Resource-Policy: same-origin" ∨ "same-site")',
    plain: 'Static resources and media assets must declare Cross-Origin-Resource-Policy: same-origin to prevent them from being loaded into foreign cross-origin documents via <script> or <img> tags.',
    why: 'Prevents Cross-Site Script Inclusion (XSSI) and speculative execution side-channels where attackers load private JSON/PDF assets inside image tags and leak data.',
    vuln: 'Cross-Origin-Resource-Policy: cross-origin # Accessible to any origin',
    sec: 'Cross-Origin-Resource-Policy: same-origin # Blocked from cross-origin embedding',
    testCmd: 'curl -sI https://example.com/assets/data.json | grep -i cross-origin-resource-policy',
    interviewQ: 'How does CORP differ from CORS?',
    interviewA: 'CORS governs whether JavaScript (via fetch/XHR) can read the contents of a response. CORP governs whether the browser is allowed to load and render the resource into another page at all (via <img>, <script>, <video>), providing defence-in-depth against speculative leaks.'
  },
  {
    num: 23,
    title: 'ETag and Weak Validator Hash Preimage Resistance',
    sub: 'Cache Invalidation',
    diff: 'Intermediate',
    std: 'RFC 9110 §8.8.3',
    formal: '∀ e ∈ ETags, IsCryptographicDigest(e) ∧ (IsWeak(e) ⇒ UsedOnlyForConditionalGet(e))',
    plain: 'ETags must be generated using strong cryptographic hashes of content rather than predictable timestamps or inode numbers, and weak validators (W/) must never be used for range requests.',
    why: 'Predictable ETags (like Apache inode numbers) leak server filesystem layouts and permit cache collision attacks.',
    vuln: 'ETag: "inode-34567-mtime-54321" # Leaks host filesystem internals',
    sec: 'ETag: "33a64df551425fcc55e4d42a148795d9f25f89d4"',
    testCmd: 'curl -sI https://example.com/ | grep -i etag',
    interviewQ: 'Why must weak ETags (W/...) never be used in HTTP Range requests?',
    interviewA: 'Weak ETags indicate semantic equivalence, not byte-for-byte exact equality. Serving partial byte ranges based on a weak ETag can splice chunks from two physically different file versions, corrupting the assembled binary.'
  },
  {
    num: 24,
    title: 'Expect-CT and Certificate Transparency Verification',
    sub: 'PKI Integrity',
    diff: 'Intermediate',
    std: 'RFC 9163',
    formal: '∀ cert ∈ TLSCertificates, HasSignedCertificateTimestamps(cert) ∧ SCTCount(cert) ≥ 2',
    plain: 'TLS certificates must contain Signed Certificate Timestamps (SCTs) logged to publicly verifiable Certificate Transparency logs to detect rogue CA misissuances.',
    why: 'Prevents compromised Certificate Authorities from silently issuing fraudulent certificates for domains without the domain owner’s knowledge.',
    vuln: 'Certificate lacking SCT logs',
    sec: 'Certificate with 3 independent CT log signatures embedded',
    testCmd: 'openssl s_client -connect example.com:443 -tlsextdebug | grep -i sct',
    interviewQ: 'What is Certificate Transparency (CT), and what happens if a certificate lacks SCTs in modern Chromium?',
    interviewA: 'CT is an append-only cryptographic public log of all issued certificates. Chromium strictly enforces CT: any certificate issued without valid SCT proofs is rejected with NET::ERR_CERTIFICATE_TRANSPARENCY_REQUIRED.'
  },
  {
    num: 25,
    title: 'Permissions-Policy Camera and Geolocation Lockdown',
    sub: 'Client Capability Restrictions',
    diff: 'Beginner',
    std: 'W3C Permissions Policy',
    formal: '∀ resp ∈ HTMLResponses, HasHeader(resp, "Permissions-Policy") ∧ Directives(camera) = () ∧ Directives(geolocation) = ()',
    plain: 'Web applications must declare a Permissions-Policy header explicitly disabling unused hardware APIs (camera=(), microphone=(), geolocation=(), payment=()) to prevent rogue iframes from accessing sensors.',
    why: 'If a compromised third-party script or embedded iframe attempts to access the user microphone or camera, Permissions-Policy guarantees the browser denies access unconditionally.',
    vuln: 'Permissions-Policy: camera=* # Any framed third party can access camera',
    sec: 'Permissions-Policy: camera=(), microphone=(), geolocation=()',
    testCmd: 'curl -sI https://example.com/ | grep -i permissions-policy',
    interviewQ: 'How does Permissions-Policy protect users against malicious advertising iframes?',
    interviewA: 'Malicious ad iframes often trigger permission prompts for geolocation, microphone, or fullscreen to phish users. Setting `camera=(), geolocation=()` at the parent document permanently revokes those capabilities for all embedded sub-frames.'
  },
  {
    num: 26,
    title: 'Server Header Obfuscation and Version Stripping',
    sub: 'Reconnaissance Mitigation',
    diff: 'Beginner',
    std: 'OWASP ASVS §14.3.3',
    formal: '∀ resp ∈ Responses, HeaderValue(resp, "Server") = ∅ ∨ HeaderValue(resp, "Server") = "webserver"',
    plain: 'HTTP responses must suppress detailed server technology tokens and version banners (e.g. `Server: Apache/2.4.41 (Ubuntu) mod_ssl/2.4.41 OpenSSL/1.1.1f`).',
    why: 'Detailed version banners allow automated vulnerability scanners (like Shodan) to immediately index unpatched servers for published CVEs.',
    vuln: 'Server: Apache/2.4.29 (Ubuntu) PHP/7.2.24 OpenSSL/1.1.1',
    sec: 'Server: webserver # Or completely stripped via server_tokens off',
    testCmd: 'curl -sI https://example.com/ | grep -i server',
    interviewQ: 'Is removing the Server header considered security through obscurity, and what is its actual defensive value?',
    interviewA: 'While obscuring banners does not patch underlying vulnerabilities, it dramatically reduces opportunistic automated bot exploitation. Shodan and mass-exploit bots filter targets by exact banner strings. Removing versions raises attacker reconnaissance costs.'
  },
  {
    num: 27,
    title: 'X-Frame-Options DENY / SAMEORIGIN Frame Protection',
    sub: 'Clickjacking',
    diff: 'Beginner',
    std: 'RFC 7034',
    formal: '∀ resp ∈ HTMLResponses, HasHeader(resp, "X-Frame-Options: DENY") ∨ HasHeader(resp, "X-Frame-Options: SAMEORIGIN")',
    plain: 'All HTML documents must declare X-Frame-Options: DENY (or SAMEORIGIN) alongside CSP frame-ancestors to prevent malicious sites from embedding the page inside transparent iframes.',
    why: 'In a Clickjacking attack, an attacker frames the target web application invisibly under a deceptive button (e.g. "Click to win $1000"), tricking users into clicking "Delete Account" or "Confirm Payment".',
    vuln: 'Missing X-Frame-Options allows arbitrary framing on evil.com',
    sec: 'X-Frame-Options: DENY\nContent-Security-Policy: frame-ancestors \'none\'',
    testCmd: 'curl -sI https://example.com/ | grep -i x-frame-options',
    interviewQ: 'Which header takes precedence if both X-Frame-Options and CSP frame-ancestors are present?',
    interviewA: 'Per W3C CSP Level 2 and 3 specifications, `Content-Security-Policy: frame-ancestors` takes precedence over `X-Frame-Options`. However, declaring both provides defense-in-depth for legacy browsers.'
  },
  {
    num: 28,
    title: 'Origin Header Null Verification and Sandbox Defense',
    sub: 'CORS & Sandboxing',
    diff: 'Intermediate',
    std: 'RFC 6454',
    formal: '∀ r ∈ Requests, Origin(r) = "null" ⇒ Action(r) = REJECT ∨ RequireExplicitConsent(r)',
    plain: 'API servers must never trust `Origin: null`. Sandboxed iframes (`sandbox=""`) and data: URIs produce null origins; granting permissions to null allows sandbox breakout attacks.',
    why: 'If a backend has `Access-Control-Allow-Origin: null`, an attacker can host a sandboxed iframe that executes fetch requests with `Origin: null`, reading private API responses.',
    vuln: 'if (req.headers.origin === "null") allowOrigin("null");',
    sec: 'if (req.headers.origin === "null") throw new ForbiddenError("Null origin disallowed");',
    testCmd: 'curl -H "Origin: null" -sI https://api.target.com/user',
    interviewQ: 'Under what browser conditions does the Origin header send the string "null"?',
    interviewA: '`Origin: null` is emitted when requests originate from sandboxed iframes without `allow-same-origin`, local `file://` URLs, or `data:` URI schemes. Because attackers can trivially spawn a sandboxed iframe to generate a null origin, trusting "null" creates a severe CORS bypass.'
  },
  {
    num: 29,
    title: 'HTTP/2 PUSH_PROMISE Invalidation & Elimination',
    sub: 'Cache Poisoning & Smuggling',
    diff: 'Advanced',
    std: 'RFC 9113 §6.6',
    formal: '∀ conn ∈ H2_Connections, SETTINGS_ENABLE_PUSH(conn) = 0',
    plain: 'HTTP/2 servers and reverse proxies must disable Server Push (`SETTINGS_ENABLE_PUSH = 0`). Server Push creates race conditions and cache poisoning risks and has been deprecated by Chrome.',
    why: 'Adversaries can exploit HTTP/2 server push to push malicious cache entries directly into the client’s cache without the client initiating a request for that asset.',
    vuln: 'SETTINGS_ENABLE_PUSH = 1 # Server Push enabled',
    sec: 'SETTINGS_ENABLE_PUSH = 0 # Server Push disabled',
    testCmd: 'h2load -n 1 --h1 https://example.com/',
    interviewQ: 'Why did Google Chrome and modern RFCs deprecate HTTP/2 Server Push?',
    interviewA: 'Server Push introduced severe security vulnerabilities (cache poisoning via pushed frames) and complex edge synchronization bugs. Furthermore, 103 Early Hints solved asset preloading much more cleanly without forcing servers to guess client cache state.'
  },
  {
    num: 30,
    title: 'Referrer-Policy Strict-Origin-When-Cross-Origin',
    sub: 'Privacy & Token Leakage',
    diff: 'Beginner',
    std: 'W3C Referrer Policy',
    formal: '∀ resp ∈ HTMLResponses, HasHeader(resp, "Referrer-Policy: strict-origin-when-cross-origin")',
    plain: 'Applications must enforce Referrer-Policy: strict-origin-when-cross-origin. This strips URL paths and query parameters when navigating cross-origin, and sends zero referrer over plaintext HTTP.',
    why: 'Without this policy, query parameters containing reset tokens or PII (e.g. `/reset?token=xyz123`) leak to third-party CDNs, analytics providers, and external links via the HTTP Referer header.',
    vuln: 'Referrer-Policy: unsafe-url # Leaks full URL paths and query tokens to all sites',
    sec: 'Referrer-Policy: strict-origin-when-cross-origin',
    testCmd: 'curl -sI https://example.com/ | grep -i referrer-policy',
    interviewQ: 'How can authentication tokens leak via the Referer header, and how does strict-origin-when-cross-origin mitigate this?',
    interviewA: 'If a web application includes session tokens or reset codes in URL query strings (e.g. `?code=abc`), clicking any external link sends the full URL to the third party in the `Referer` header. Strict-origin-when-cross-origin strips the query string and path, transmitting only the origin (`https://example.com/`) to third parties.'
  },
  {
    num: 31,
    title: 'Forwarded RFC 7239 Strict Header Precedence',
    sub: 'Reverse Proxy Headers',
    diff: 'Intermediate',
    std: 'RFC 7239 §5',
    formal: '∀ r ∈ Requests, HasHeader(r, "Forwarded") ⇒ Ignore(r, "X-Forwarded-*")',
    plain: 'When RFC 7239 `Forwarded` headers are in use, applications must establish strict precedence and ignore legacy `X-Forwarded-*` headers to eliminate proxy parameter confusion.',
    why: 'Mixing RFC 7239 and legacy headers allows attackers to supply competing parameters, tricking edge proxies into validating one while the backend interprets the other.',
    vuln: 'Use both Forwarded and X-Forwarded-Host without clear precedence',
    sec: 'Canonicalize to RFC 7239 Forwarded: for=192.0.2.60;proto=https;by=203.0.113.43',
    testCmd: 'curl -H "Forwarded: for=1.2.3.4" -H "X-Forwarded-For: 5.6.7.8" https://api.target.com/',
    interviewQ: 'What is Header Precedence Pollution in reverse proxy setups?',
    interviewA: 'When both standard `Forwarded` and legacy `X-Forwarded-For` exist in a request, different microservices in the chain may parse different headers. An attacker injects the header ignored by the gateway but processed by the backend, bypassing security controls.'
  },
  {
    num: 32,
    title: 'HTTP Status 401 vs 403 Semantic Strictness',
    sub: 'Access Control Semantics',
    diff: 'Beginner',
    std: 'RFC 9110 §15.5',
    formal: '∀ r ∈ FailedAccess, (NoCredentials(r) ⇒ Status = 401) ∧ (HasValidCredentials(r) ∧ InsufficientRole(r) ⇒ Status = 403)',
    plain: 'APIs must maintain strict semantic distinction: return 401 Unauthorized when credentials are missing or invalid, and return 403 Forbidden when credentials are valid but lack permission.',
    why: 'Confusing 401 and 403 breaks OAuth step-up and causes automated client retry storms (retrying authenticated requests that will never succeed).',
    vuln: 'Return 401 for permission denial (triggers infinite login loops)',
    sec: 'Return 401 for bad auth; return 403 for permission failure',
    testCmd: 'curl -i -H "Authorization: Bearer valid_user_token" https://api.target.com/admin/delete',
    interviewQ: 'Why does emitting 401 instead of 403 create automated client failure loops in OAuth 2.0 architectures?',
    interviewA: 'In OAuth 2.0, HTTP 401 indicates that the access token has expired, triggering the client to fetch a new token via refresh token. If a 401 is returned for an authorization failure (where the user simply lacks permission), the client gets stuck in an infinite refresh loop.'
  },
  {
    num: 33,
    title: 'Trailer Header Boundary and TE Verification',
    sub: 'Smuggling & Trailers',
    diff: 'Advanced',
    std: 'RFC 9112 §6.5',
    formal: '∀ r ∈ ChunkedRequests, HasTrailers(r) ⇒ (TE = "trailers" ∧ TrailerHeaders(r) ∩ DisallowedTrailers = ∅)',
    plain: 'Trailer headers must only be accepted on chunked requests declaring TE: trailers. Critical framing headers (Content-Length, Transfer-Encoding, Host) must NEVER appear in trailers.',
    why: 'Smuggling attacks use trailers to append framing headers at the end of chunked bodies, desynchronizing downstream servers.',
    vuln: 'Trailers containing Content-Length or Host header',
    sec: 'Strictly reject any request placing framing headers in chunked trailers',
    testCmd: 'printf "POST / HTTP/1.1\\r\\nHost: t.com\\r\\nTransfer-Encoding: chunked\\r\\nTrailer: Host\\r\\n\\r\\n0\\r\\nHost: evil.com\\r\\n\\r\\n" | nc target.com 80',
    interviewQ: 'Why does RFC 9112 explicitly prohibit Content-Length inside HTTP trailers?',
    interviewA: 'Content-Length defines the boundary of the message body. Allowing it in trailers (after the body has already been delivered) creates complete ambiguity in proxy stream parsers, leading to critical request smuggling vulnerabilities.'
  },
  {
    num: 34,
    title: 'HTTP CONNECT Tunneling Port Whitelisting',
    sub: 'Proxy Abuse & SSRF',
    diff: 'Intermediate',
    std: 'RFC 9110 §9.3.6',
    formal: '∀ r ∈ ConnectRequests, TargetPort(r) ∈ {443} ∧ IsInternalIP(TargetHost(r)) = False',
    plain: 'Forward proxies implementing HTTP CONNECT must strictly restrict destination ports to 443 (HTTPS) and block connections to internal loopback and private RFC 1918 subnets.',
    why: 'An open CONNECT proxy allows external attackers to tunnel arbitrary TCP traffic (SSH on port 22, internal databases on 5432) through the proxy, bypassing corporate firewalls.',
    vuln: 'CONNECT 127.0.0.1:22 HTTP/1.1 (Proxy allows tunnel to internal SSH)',
    sec: 'CONNECT example.com:443 HTTP/1.1 (Only port 443 permitted)',
    testCmd: 'curl -x http://proxy.target.com:8080 -p http://127.0.0.1:22',
    interviewQ: 'How can an attacker exploit an unhardened HTTP CONNECT method to achieve SSRF and pivot onto internal networks?',
    interviewA: 'CONNECT creates a transparent raw TCP bi-directional pipe. If port 443 is not strictly enforced, attackers send `CONNECT 10.0.0.1:5432` or `CONNECT 169.254.169.254:80`, establishing direct socket tunnels to cloud metadata or internal database services.'
  },
  {
    num: 35,
    title: 'Keep-Alive Timeout Synchronization Across Tiers',
    sub: 'Desync Smuggling',
    diff: 'Advanced',
    std: 'CWE-444',
    formal: 'Timeout(BackendKeepAlive) > Timeout(EdgeKeepAlive) + DeltaBuffer (≥ 5s)',
    plain: 'The idle keep-alive timeout on backend application servers must be configured to be longer than the keep-alive timeout on front-end edge reverse proxies (by at least 5 seconds).',
    why: 'If the backend closes an idle persistent connection while the front-end is concurrently writing a new request to it, the front-end experiences a connection reset race condition, leading to 502 Bad Gateway and desync vulnerabilities.',
    vuln: 'Frontend Timeout: 60s, Backend Timeout: 50s (Backend drops connection first)',
    sec: 'Frontend Timeout: 60s, Backend Timeout: 65s (Frontend drops connection first)',
    testCmd: 'curl -s -w "%{time_total}\\n" --keepalive-time 60 https://example.com/',
    interviewQ: 'What happens when a backend server closes an idle TCP connection just as the reverse proxy sends a user request?',
    interviewA: 'The proxy writes bytes into a socket the backend has already issued a FIN/RST packet for. The backend discards the request, and the proxy either errors with a 502 Bad Gateway or erroneously retries the request onto another connection, causing race conditions and desynchronization.'
  },
  {
    num: 36,
    title: 'Content-Security-Policy-Report-Only Triage Invariant',
    sub: 'Telemetry & Enforcement',
    diff: 'Intermediate',
    std: 'W3C CSP Level 3',
    formal: '∀ policy ∈ StagingPolicies, HasHeader(policy, "Content-Security-Policy-Report-Only") ∧ HasReportURI(policy)',
    plain: 'When testing strict CSP policies, deploy Content-Security-Policy-Report-Only with a report-to endpoint to collect telemetry on real-world breakage without blocking legitimate user functionality.',
    why: 'Enforcing strict CSP without report-only canary testing frequently breaks critical third-party integrations, authentication widgets, or payment gateways.',
    vuln: 'Deploying breaking blocking CSP directly to production without testing',
    sec: 'Content-Security-Policy-Report-Only: default-src \'self\'; report-uri /csp-report',
    testCmd: 'curl -sI https://example.com/ | grep -i content-security-policy-report-only',
    interviewQ: 'What is the recommended operational migration path from legacy inline scripts to a strict nonce-based CSP in production?',
    interviewA: 'First, deploy the proposed nonce policy using `Content-Security-Policy-Report-Only` with a `report-uri` endpoint. Ingest and analyze violation reports in a SIEM to identify legacy inline scripts or un-nonced third-party tags. Once violation reports drop to zero, switch the header to blocking `Content-Security-Policy`.'
  }
];

remainingHttpDefs.forEach(item => {
  httpRules.push({
    ruleNumber: item.num,
    id: `SEC-HTTP-${String(item.num).padStart(3, '0')}`,
    title: item.title,
    domain: 'http',
    domainName: 'HTTP Protocols',
    subdomain: item.sub,
    difficulty: item.diff as any,
    standardType: item.num % 2 === 0 ? 'Mandatory Standard' : 'Defense-in-Depth',
    standards: [item.std, 'OWASP ASVS 4.0', 'RFC 9110'],
    formalInvariant: item.formal,
    symbolBreakdown: [
      { symbol: item.formal.split(' ')[0], meaning: 'Target operational domain / protocol element' },
      { symbol: 'ValidateBoundary', meaning: 'Verification of format, bounds, and protocol state' },
      { symbol: 'Enforce', meaning: `Strict adherence to ${item.std}` }
    ],
    plainEnglish: item.plain,
    whyItMatters: item.why,
    vulnerableExample: {
      language: 'http/nginx',
      code: item.vuln,
      explanation: 'Fails to enforce boundary condition, leaving the system vulnerable to exploitation.'
    },
    secureExample: {
      language: 'http/nginx',
      code: item.sec,
      explanation: 'Strictly satisfies formal invariant and aligns with RFC/OWASP specifications.'
    },
    howToTest: {
      tools: ['curl', 'testssl.sh', 'nmap'],
      steps: [
        `Send targeted request testing ${item.title}.`,
        'Verify response adheres to declared header and boundary constraints.',
        'Ensure non-compliant requests fail-closed.'
      ],
      commandExample: item.testCmd
    },
    interviewChallenge: {
      scenario: `You are asked about ${item.title} during a systems architecture review.`,
      question: item.interviewQ,
      hint: 'Consider intermediary behavior and client security expectations.',
      sampleAnswer: item.interviewA,
      keyTakeaway: `Enforce ${item.title} to guarantee protocol reliability and eliminate attack surfaces.`
    }
  });
});
