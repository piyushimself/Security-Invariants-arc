import { SecurityInvariant } from '../../types/invariants';

export const apiRules: SecurityInvariant[] = [
  {
    ruleNumber: 77,
    id: "SEC-API-001",
    title: "BOLA / IDOR Object-Level Ownership Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "Broken Object Level Authorization (BOLA)",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["OWASP API Security API1:2023", "CWE-639", "CWE-285"],
    formalInvariant: "\u2200 req \u2208 Requests_{ObjectAccess}, Authorized(req.Caller, req.TargetObjectId) \u2227 InSameTenant(req.Caller, req.TargetObjectId) \u21d2 GrantAccess(req)",
    symbolBreakdown: [
          {
                "symbol": "\u2200 req \u2208 Requests_{ObjectAccess}",
                "meaning": "For every incoming API request addressing an entity by ID"
          },
          {
                "symbol": "Authorized(Caller, Target)",
                "meaning": "Caller is verified as the direct owner or holds explicit delegated rights over Target"
          },
          {
                "symbol": "InSameTenant(...)",
                "meaning": "Both caller and target object share the identical tenant/organization boundary partition"
          },
          {
                "symbol": "\u21d2 GrantAccess(req)",
                "meaning": "Access granted if and only if both tenancy and object ownership predicates evaluate to True"
          }
    ],
    plainEnglish: "Every API endpoint that accepts a resource identifier (ID) in the URL path, query, or body must verify that the authenticated caller owns that specific object within the same tenant partition. Never rely solely on user authentication or endpoint role checks.",
    whyItMatters: "BOLA/IDOR is the #1 vulnerability on the OWASP API Security Top 10. Attackers simply iterate integer or UUID identifiers in API requests (`GET /api/documents/1002`) to view, modify, or delete sensitive records belonging to other customers.",
    vulnerableExample: {
          "language": "python/fastapi",
          "code": "# VULNERABLE: Only checks if user is logged in, NOT if they own document_id\n@app.get(\"/api/documents/{document_id}\")\ndef get_document(document_id: int, current_user: User = Depends(get_current_user)):\n    doc = db.query(Document).filter(Document.id == document_id).first()\n    if not doc:\n        raise HTTPException(status_code=404)\n    return doc",
          "explanation": "Any authenticated user can read any other user's documents by changing the document_id in the URL."
    },
    secureExample: {
          "language": "python/fastapi",
          "code": "# SECURE: Validates user ownership and tenant partition\n@app.get(\"/api/documents/{document_id}\")\ndef get_document(document_id: int, current_user: User = Depends(get_current_user)):\n    doc = db.query(Document).filter(\n        Document.id == document_id,\n        Document.tenant_id == current_user.tenant_id,\n        Document.owner_id == current_user.id\n    ).first()\n    if not doc:\n        raise HTTPException(status_code=404, detail=\"Document not found\")\n    return doc",
          "explanation": "Scoped query guarantees access is granted only if the document belongs to the caller's tenant and account."
    },
    howToTest: {
          "tools": [
                "curl",
                "Postman",
                "OWASP ZAP",
                "Burp Suite Intruder"
          ],
          "steps": [
                "Create two separate user accounts (User A and User B) in separate tenants.",
                "Using User A's auth token, attempt to GET/PUT/DELETE a resource created by User B.",
                "Verify API returns 403 Forbidden or 404 Not Found without leaking object existence."
          ],
          "commandExample": "curl -H \"Authorization: Bearer userA_token\" https://api.target.com/api/documents/userB_doc_id"
    },
    interviewChallenge: {
          "scenario": "A high-throughput API relies on UUIDv4 instead of auto-incrementing integers for object IDs. The lead developer argues that UUIDs make BOLA impossible because IDs are unguessable.",
          "question": "Why is relying on UUID unguessability an antipattern for object authorization?",
          "hint": "Can UUIDs be leaked, shared, cached, or discovered through other API endpoints?",
          "sampleAnswer": "Unguessability (security through obscurity) is not authorization. UUIDs are routinely leaked in referrer headers, shared links, audit logs, webhooks, search endpoints, or shoulder surfing. Once an attacker obtains a victim's UUID, the absence of server-side object ownership checks allows them to read and modify the victim's data immediately.",
          "keyTakeaway": "Always enforce explicit object ownership and tenancy checks in data queries; never treat UUIDs as an authorization mechanism."
    },
    simulation: {
          "type": "generic",
          "label": "BOLA Object Authorization Engine",
          "defaultInput": "Caller: usr_101 (Tenant: alpha)\nTargetResource: doc_555 (Owner: usr_202, Tenant: beta)\nRequestedAction: GET /api/v1/documents/doc_555",
          "testFunctionDescription": "Evaluates whether request context satisfies tenancy and object ownership predicates."
    }
  },
  {
    ruleNumber: 78,
    id: "SEC-API-002",
    title: "Mass Assignment DTO Strict Parameter Whitelisting Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "Mass Assignment & Parameter Binding",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["OWASP API Security API3:2023", "CWE-915"],
    formalInvariant: "\u2200 p \u2208 IncomingPayload, MutateField(p.key) = True \u21d4 p.key \u2208 DeclaredWritableFields(DTO)",
    symbolBreakdown: [
          {
                "symbol": "IncomingPayload",
                "meaning": "Raw JSON or form body sent by client in POST/PUT/PATCH"
          },
          {
                "symbol": "MutateField(p.key)",
                "meaning": "Application updates property on the database model"
          },
          {
                "symbol": "DeclaredWritableFields(DTO)",
                "meaning": "Strictly defined compile-time Data Transfer Object whitelist of permitted fields"
          }
    ],
    plainEnglish: "APIs must never bind incoming JSON request bodies directly to database entities or ORM models. All mutations must pass through strict Data Transfer Objects (DTOs) that explicitly whitelist assignable fields.",
    whyItMatters: "If an API framework blindly binds JSON keys to an internal database model (e.g. `User.update(req.body)`), an attacker can inject parameters like `{\"role\": \"admin\", \"is_verified\": true, \"account_balance\": 999999}`, elevating their privileges effortlessly.",
    vulnerableExample: {
          "language": "typescript/typeorm",
          "code": "// VULNERABLE: Direct model binding allows privilege escalation\napp.patch('/api/profile', async (req, res) => {\n    const user = await userRepository.findOne({ where: { id: req.user.id } });\n    // Blindly assigns all submitted JSON properties onto the entity:\n    Object.assign(user, req.body);\n    await userRepository.save(user);\n    res.json(user);\n});",
          "explanation": "Attacker sends `{\"role\": \"superuser\"}` in the PATCH body and gets saved directly to the database."
    },
    secureExample: {
          "language": "typescript/zod",
          "code": "import { z } from 'zod';\n\nconst UpdateProfileDTO = z.object({\n    fullName: z.string().min(1).max(100),\n    bio: z.string().max(500).optional(),\n    avatarUrl: z.string().url().optional()\n}).strict(); // Disallows any unlisted keys\n\napp.patch('/api/profile', async (req, res) => {\n    // Validates against explicit whitelist:\n    const safeData = UpdateProfileDTO.parse(req.body);\n    await userRepository.update(req.user.id, safeData);\n    res.json({ status: \"success\" });\n});",
          "explanation": "Uses schema parsing with .strict() to reject or ignore all unapproved properties."
    },
    howToTest: {
          "tools": [
                "curl",
                "Postman"
          ],
          "steps": [
                "Send PATCH request to profile endpoint including extra fields: `{\"isAdmin\": true, \"role\": \"admin\"}`.",
                "Inspect response and database record to ensure the elevated role was rejected or ignored."
          ],
          "commandExample": "curl -X PATCH -H \"Content-Type: application/json\" -d '{\"bio\":\"Hello\", \"role\":\"admin\"}' https://api.target.com/profile"
    },
    interviewChallenge: {
          "scenario": "A startup uses MongoDB with Mongoose. They sanitize inputs by running `delete req.body.role` before updating.",
          "question": "Why is manual field deletion insecure compared to strict DTO whitelisting?",
          "hint": "What happens when new sensitive fields are added to the User model next sprint?",
          "sampleAnswer": "Blacklisting (deleting specific keys) is fragile and prone to human omission. Whenever a developer adds a new sensitive field to the database schema (e.g., `verifiedAt`, `mfa_enabled`, `credits`), they will inevitably forget to update the deletion list in every controller. A strict DTO whitelist fails safe: unlisted fields are rejected by default.",
          "keyTakeaway": "Always use strict positive whitelisting via DTOs or schema validators; never rely on blacklists."
    }
  },
  {
    ruleNumber: 79,
    id: "SEC-API-003",
    title: "GraphQL Query Depth and Complexity Upper-Bound Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "GraphQL & DoS Mitigation",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["OWASP GraphQL Cheat Sheet", "OWASP API4:2023", "CWE-400"],
    formalInvariant: "\u2200 q \u2208 GraphQLQueries, Depth(q) \u2264 MaxDepthLimit \u2227 Cost(q) \u2264 MaxComplexityBudget",
    symbolBreakdown: [
          {
                "symbol": "q \u2208 GraphQLQueries",
                "meaning": "Any incoming GraphQL query document"
          },
          {
                "symbol": "Depth(q)",
                "meaning": "Maximum nesting depth of query selection sets"
          },
          {
                "symbol": "Cost(q)",
                "meaning": "Sum of weighted computational cost calculated by AST analysis before execution"
          }
    ],
    plainEnglish: "GraphQL servers must calculate the syntactic depth and computational cost of every query AST before resolving any field. Queries exceeding depth limits (e.g., depth > 7) or complexity budgets must be aborted before touching backend resolvers.",
    whyItMatters: "Due to circular relationships in GraphQL schemas (e.g., `author { books { author { books ... } } }`), an attacker can send a deeply nested 1KB query that triggers exponential SQL queries or millions of recursive resolver invocations, taking down the entire database cluster.",
    vulnerableExample: {
          "language": "javascript/apollo",
          "code": "// VULNERABLE: Apollo Server without depth or complexity validation\nconst server = new ApolloServer({\n    typeDefs,\n    resolvers,\n    // No validation rules configured!\n});",
          "explanation": "Allows cyclic queries like author -> books -> author -> books repeated 50 times in a single payload."
    },
    secureExample: {
          "language": "javascript/apollo",
          "code": "import depthLimit from 'graphql-depth-limit';\nimport { createComplexityLimitRule } from 'graphql-validation-complexity';\n\nconst server = new ApolloServer({\n    typeDefs,\n    resolvers,\n    validationRules: [\n        depthLimit(7),\n        createComplexityLimitRule(1000, {\n            onCost: (cost) => console.log('Query cost:', cost)\n        })\n    ]\n});",
          "explanation": "Statically inspects query AST prior to execution; rejects queries with depth > 7 or cost > 1000."
    },
    howToTest: {
          "tools": [
                "graphql-fuzzer",
                "curl"
          ],
          "steps": [
                "Craft cyclic GraphQL query nested 15 levels deep.",
                "Send query to endpoint.",
                "Verify server returns 400 Bad Request with complexity/depth error without executing resolvers."
          ],
          "commandExample": "curl -X POST -H \"Content-Type: application/json\" -d '{\"query\":\"{user{posts{author{posts{author{posts{id}}}}}}}\"}' https://api.target.com/graphql"
    },
    interviewChallenge: {
          "scenario": "A GraphQL endpoint protects against depth attacks by limiting depth to 5. An attacker bypasses this by sending 500 aliased root fields: `{ a1: users(first: 100) { id }, a2: users(first: 100) { id } ... }`.",
          "question": "Why did depth limiting fail, and what metric must be paired with depth limiting?",
          "hint": "Is the query deeply nested, or wide at the root?",
          "sampleAnswer": "Depth limiting only inspects vertical AST nesting depth (which is 2 in this case). The attacker exploited horizontal query breadth, creating hundreds of root database queries simultaneously. To defend against this, depth limiting must be paired with AST Complexity Cost Analysis, where each field and pagination multiplier incurs a numerical cost.",
          "keyTakeaway": "Pair AST depth limiting with query cost analysis and strict pagination caps."
    }
  },
  {
    ruleNumber: 80,
    id: "SEC-API-004",
    title: "Idempotency Key Single-Execution Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "Payment & Mutation Concurrency",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["IETF RFC Draft Idempotency-Key", "OWASP API8:2023", "CWE-362"],
    formalInvariant: "\u2200 key \u2208 IdempotencyKeys, ExecuteTransaction(key) occurs AT MOST ONCE \u2227 SubsequentRequests(key) \u21d2 ReturnCachedResponse(key)",
    symbolBreakdown: [
          {
                "symbol": "key \u2208 IdempotencyKeys",
                "meaning": "Unique client-supplied UUID header (Idempotency-Key)"
          },
          {
                "symbol": "ExecuteTransaction(key)",
                "meaning": "Execution of debit, order creation, or non-idempotent state change"
          },
          {
                "symbol": "ReturnCachedResponse(key)",
                "meaning": "Exact cached response of original execution returned without re-executing"
          }
    ],
    plainEnglish: "Financial, debit, and mutation APIs must require an Idempotency-Key header for non-idempotent operations (POST). The server must guarantee that identical keys execute business logic exactly once and return the cached outcome on retries.",
    whyItMatters: "Network drops or aggressive retry loops can cause clients to submit checkout or money transfer requests multiple times. Without idempotency key locking, customers get double-charged or inventory is depleted erroneously.",
    vulnerableExample: {
          "language": "python",
          "code": "@app.post(\"/payments/charge\")\nasync def charge_card(req: ChargeRequest):\n    # VULNERABLE: No idempotency check\n    # Retried requests or double-clicks will execute multiple charges\n    return await stripe_client.charges.create(amount=req.amount, customer=req.customer_id)",
          "explanation": "Every duplicate network packet or browser retry creates a distinct financial transaction."
    },
    secureExample: {
          "language": "python",
          "code": "@app.post(\"/payments/charge\")\nasync def charge_card(req: ChargeRequest, idempotency_key: str = Header(...)):\n    # Atomic distributed lock via Redis\n    lock_acquired = await redis.set(f\"idemp_lock:{idempotency_key}\", \"processing\", nx=True, ex=120)\n    if not lock_acquired:\n        cached_result = await redis.get(f\"idemp_res:{idempotency_key}\")\n        if cached_result:\n            return json.loads(cached_result)\n        raise HTTPException(status_code=409, detail=\"Transaction currently processing\")\n\n    result = await stripe_client.charges.create(...)\n    await redis.set(f\"idemp_res:{idempotency_key}\", json.dumps(result), ex=86400)\n    return result",
          "explanation": "Uses atomic lock with NX flag and caches resulting payload for subsequent retries."
    },
    howToTest: {
          "tools": [
                "curl",
                "k6 concurrent load testing"
          ],
          "steps": [
                "Dispatch 10 simultaneous POST requests with identical Idempotency-Key header.",
                "Verify only 1 transaction is recorded in database/ledger.",
                "Verify all 10 responses return identical transaction IDs."
          ],
          "commandExample": "parallel -j 5 curl -X POST -H \"Idempotency-Key: uuid-1234\" https://api.target.com/pay ::: 1 2 3 4 5"
    },
    interviewChallenge: {
          "scenario": "Two identical payment requests with the same Idempotency-Key hit two separate load-balanced application servers at the exact same millisecond.",
          "question": "How do you prevent a race condition where both servers execute the charge simultaneously?",
          "hint": "Think about database transactions and distributed cache locking semantics.",
          "sampleAnswer": "Use an atomic distributed lock in a centralized high-speed store like Redis (using `SET key value NX EX seconds`) or a unique constraint on the idempotency_key column inside a transactional database. Whichever server fails to acquire the atomic lock must wait or return 409 Conflict, ensuring only one worker ever executes the business transaction.",
          "keyTakeaway": "Idempotency requires atomic locking across distributed nodes before business logic begins."
    }
  },
  {
    ruleNumber: 81,
    id: "SEC-API-081",
    title: "BFLA Broken Function Level Authorization Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "Role & Verb Privileges",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["OWASP API5:2023", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 req \u2208 AdminEndpoints, Role(req.User) = AdminRole \u2227 HTTPMethod(req) \u2208 AllowedMethods(Role(req.User))",
    symbolBreakdown: [
          {
                "symbol": "AdminEndpoints",
                "meaning": "Privileged administrative actions like /api/admin/users/export or user deletion"
          },
          {
                "symbol": "Role(req.User) = AdminRole",
                "meaning": "Cryptographically verified admin claim in user session/token"
          },
          {
                "symbol": "AllowedMethods",
                "meaning": "Explicit authorization mapping per HTTP verb (GET, POST, DELETE)"
          }
    ],
    plainEnglish: "APIs must enforce function-level authorization based on the user's validated role for every HTTP method. Non-admin users must never access administrative controllers, even if endpoint URLs are known.",
    whyItMatters: "Developers often hide admin buttons in the frontend UI while omitting backend role checks on `/api/admin/promoteUser`. Regular users simply send a direct POST request via curl or Postman to promote themselves to superuser.",
    vulnerableExample: {
          "language": "typescript/express",
          "code": "// VULNERABLE: Only verifies user authentication, not role\napp.delete('/api/admin/tenants/:id', authenticate, async (req, res) => {\n    await deleteTenant(req.params.id);\n    res.json({ success: true });\n});",
          "explanation": "Any logged-in member or customer can delete an entire organization tenant."
    },
    secureExample: {
          "language": "typescript/express",
          "code": "// SECURE: Explicit role-based policy guard middleware\napp.delete('/api/admin/tenants/:id', authenticate, requireRole('SUPER_ADMIN'), async (req, res) => {\n    await deleteTenant(req.params.id);\n    res.json({ success: true });\n});",
          "explanation": "Rejects non-superadmin callers with 403 Forbidden before invoking the controller."
    },
    howToTest: {
          "tools": [
                "Postman",
                "OWASP ZAP",
                "curl"
          ],
          "steps": [
                "Log in as standard viewer/customer.",
                "Send DELETE request to `/api/admin/users/123`.",
                "Assert API returns 403 Forbidden and records security alert."
          ],
          "commandExample": "curl -X DELETE -H \"Authorization: Bearer viewer_token\" https://api.target.com/api/admin/users/1"
    },
    interviewChallenge: {
          "scenario": "A developer implements role checks using HTTP method heuristics: `if (req.method === 'POST') requireAdmin()`. How can an attacker bypass this?",
          "question": "Can HTTP verbs like PUT, PATCH, or custom methods bypass the check?",
          "hint": "An attacker can switch to PUT, PATCH, or trigger HTTP verb tunneling (`X-HTTP-Method-Override: POST`) to invoke the function without triggering the POST condition.",
          "sampleAnswer": "Relying on negative method checks fails if the router accepts multiple verbs or supports method-override headers (`X-HTTP-Method-Override`). Furthermore, read operations (`GET /api/admin/export_all_passwords`) leak confidential data if GET is left unprotected.",
          "keyTakeaway": "Enforce fail-closed function authorization on the router/controller decorator regardless of HTTP method."
    }
  },
  {
    ruleNumber: 82,
    id: "SEC-API-082",
    title: "Server-Side Request Forgery (SSRF) Webhook Egress Guard Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "SSRF & Webhooks",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["OWASP API7:2023", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 url \u2208 WebhookDestinations, ResolvedIP(url) \u2209 PrivateSubnets \u2227 ResolvedIP(url) \u2209 CloudMetadataIP \u2227 Protocol(url) = \"https\"",
    symbolBreakdown: [
          {
                "symbol": "WebhookDestinations",
                "meaning": "Customer-supplied callback URLs invoked by the server"
          },
          {
                "symbol": "ResolvedIP \u2209 PrivateSubnets",
                "meaning": "Prohibits RFC 1918 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1)"
          },
          {
                "symbol": "ResolvedIP \u2209 CloudMetadataIP",
                "meaning": "Prohibits cloud metadata endpoint 169.254.169.254"
          }
    ],
    plainEnglish: "When an API fetches customer-supplied URLs (webhooks, avatar importers, OAuth redirect validation), the server must resolve the hostname to an IP and verify that the IP is not in any private, loopback, link-local, or cloud metadata subnet before making the socket connection.",
    whyItMatters: "An attacker registers a webhook destination of `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. The application fetches the URL and returns AWS credentials or forwards internal database dumps.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Direct request to user-supplied webhook URL\nimport requests\n\ndef dispatch_webhook(target_url, payload):\n    # Attacker passes: http://169.254.169.254/latest/meta-data/\n    return requests.post(target_url, json=payload)",
          "explanation": "Allows attacker to probe internal intranet services, Kubernetes etcd, and cloud metadata."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: DNS pre-resolution and IP allowlist validation with socket pinning\nimport socket, ipaddress, urllib.parse\n\ndef validate_safe_webhook(url):\n    parsed = urllib.parse.urlparse(url)\n    if parsed.scheme != 'https': raise SecurityError('HTTPS required')\n    ip_str = socket.gethostbyname(parsed.hostname)\n    ip = ipaddress.ip_address(ip_str)\n    if ip.is_private or ip.is_loopback or ip.is_link_local:\n        raise SecurityError(f'SSRF blocked: IP {ip} is private')",
          "explanation": "Pre-resolves DNS and validates IP against private ranges before creating outbound connection."
    },
    howToTest: {
          "tools": [
                "ssrf-detector",
                "Burp Suite Collaborator"
          ],
          "steps": [
                "Register webhook pointing to `http://127.0.0.1:8080/internal`.",
                "Verify server immediately rejects registration with 400 Bad Request."
          ],
          "commandExample": "curl -X POST -d '{\"webhook\":\"http://169.254.169.254\"}' https://api.target.com/webhooks"
    },
    interviewChallenge: {
          "scenario": "What is a DNS Rebinding attack against an SSRF validator, and how do you protect against it?",
          "question": "What happens between DNS resolution and the actual HTTP request?",
          "hint": "An attacker configures a DNS server that returns a public IP during validation, but returns `127.0.0.1` 10 milliseconds later when the HTTP client connects (Time-of-Check to Time-of-Use flaw).",
          "sampleAnswer": "In DNS Rebinding, the attacker's custom nameserver returns a benign IP with TTL=0 during the validation phase. When the HTTP library initiates the real connection, it re-resolves the domain and connects to `127.0.0.1` or `169.254.169.254`. Defense requires socket pinning (connecting directly to the validated IP address) or using an egress proxy.",
          "keyTakeaway": "Pin the validated IP address to the outbound connection socket; never perform a second DNS resolution."
    }
  },
  {
    ruleNumber: 83,
    id: "SEC-API-083",
    title: "Token Bucket Rate Limiting per Subject & IP Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "Rate Limiting & DoS",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["OWASP API4:2023", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 client \u2208 APICallers, RequestCount(client, 1m) \u2264 MaxRPM(client.Tier) \u2227 ConsumeToken(Bucket) = True",
    symbolBreakdown: [
          {
                "symbol": "APICallers",
                "meaning": "Distinct authenticated user ID, API key, or unauthenticated client IP"
          },
          {
                "symbol": "MaxRPM",
                "meaning": "Maximum allowed requests per minute for caller's tier (e.g., 60 RPM for free, 600 RPM for enterprise)"
          },
          {
                "symbol": "ConsumeToken",
                "meaning": "Atomic decrement of Redis token bucket counter"
          }
    ],
    plainEnglish: "APIs must enforce rate limiting at the API gateway or reverse proxy using atomic algorithms (Token Bucket or Sliding Window Counter) keyed on verified client identity (API key or user ID) and fallback IP address.",
    whyItMatters: "Without rate limits, automated bots perform credential stuffing, scrape private databases, drain cloud budgets, and cause database connection pool exhaustion.",
    vulnerableExample: {
          "language": "javascript/express",
          "code": "// VULNERABLE: No rate limiting configured\napp.post('/api/auth/login', async (req, res) => {\n    // Attacker sends 10,000 passwords per minute without restriction\n    return handleLogin(req.body);\n});",
          "explanation": "Enables brute-force credential stuffing and password guessing at line rate."
    },
    secureExample: {
          "language": "javascript/express",
          "code": "// SECURE: Redis-backed sliding window rate limiter\nimport { rateLimit } from 'express-rate-limit';\nimport RedisStore from 'rate-limit-redis';\n\nconst loginLimiter = rateLimit({\n    store: new RedisStore({ sendCommand: (...args) => redisClient.sendCommand(args) }),\n    windowMs: 15 * 60 * 1000, // 15 minutes\n    max: 5, // 5 failed attempts per IP / account\n    standardHeaders: true, // Return RateLimit headers\n    legacyHeaders: false\n});\napp.post('/api/auth/login', loginLimiter, handleLogin);",
          "explanation": "Restricts login attempts to 5 per 15 minutes, returning 429 Too Many Requests with Retry-After header."
    },
    howToTest: {
          "tools": [
                "k6 load test",
                "curl",
                "OWASP ZAP"
          ],
          "steps": [
                "Send 100 rapid requests in parallel to endpoint.",
                "Verify server returns 429 Too Many Requests after threshold is reached.",
                "Verify `Retry-After` header is included in response."
          ],
          "commandExample": "ab -n 100 -c 10 https://api.target.com/api/search"
    },
    interviewChallenge: {
          "scenario": "Why is rate limiting based purely on client IP address (`req.ip`) ineffective for modern mobile applications?",
          "question": "Do cellular carriers route thousands of users through shared CGNAT gateways?",
          "hint": "Carrier-Grade NAT (CGNAT) groups tens of thousands of mobile users behind single shared public IPs, causing one malicious user to lock out entire geographic regions.",
          "sampleAnswer": "Mobile networks and corporate enterprises route massive user fleets through shared Carrier-Grade NAT (CGNAT) gateway IPs. Relying solely on IP address leads to false positives (blocking innocent users) and allows distributed botnets to bypass limits. Rate limiting must key on verified authenticated subject ID, device fingerprint, and API token.",
          "keyTakeaway": "Key rate limiters primarily on authenticated subject identity and API keys, using IP address only for pre-auth endpoints."
    }
  },
  {
    ruleNumber: 84,
    id: "SEC-API-084",
    title: "API Gateway JSON Schema Strict Validation Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "Payload Validation",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["OpenAPI 3.1 Spec", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 payload \u2208 IncomingJSON, ValidateSchema(payload, OpenAPISpec) = True \u2227 DisallowAdditionalProperties = True",
    symbolBreakdown: [
          {
                "symbol": "IncomingJSON",
                "meaning": "Incoming JSON request body on REST endpoints"
          },
          {
                "symbol": "OpenAPISpec",
                "meaning": "Canonical OpenAPI 3.1 schema definition"
          },
          {
                "symbol": "DisallowAdditionalProperties",
                "meaning": "Rejection of unwhitelisted fields at the gateway"
          }
    ],
    plainEnglish: "The API Gateway must validate every incoming JSON payload against the published OpenAPI schema prior to routing downstream. Payloads containing invalid types, oversized strings, or unwhitelisted properties must be rejected with 400 Bad Request.",
    whyItMatters: "Passing malformed or oversized payloads directly to backend microservices causes JSON parser denial-of-service, unhandled exceptions, and type confusion vulnerabilities in application runtimes.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: OpenAPI schema allowing unrestricted extra properties\nschema:\n  type: object\n  properties:\n    username:\n      type: string\n  # additionalProperties defaults to true in legacy OpenAPI!",
          "explanation": "Allows client to pass arbitrary unvalidated properties through to backend controllers."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Strict schema with bounds and no additional properties\nschema:\n  type: object\n  required: [username, email]\n  additionalProperties: false\n  properties:\n    username:\n      type: string\n      minLength: 3\n      maxLength: 30\n    email:\n      type: string\n      format: email",
          "explanation": "Gateway enforces strict types, string lengths, and rejects all extraneous properties at the perimeter."
    },
    howToTest: {
          "tools": [
                "spectral CLI",
                "prism mock",
                "curl"
          ],
          "steps": [
                "Send payload with 1MB string or extra keys: `{\"extra\": \"val\"}`.",
                "Verify API gateway rejects request with 400 Bad Request before hitting microservice."
          ],
          "commandExample": "curl -X POST -H \"Content-Type: application/json\" -d '{\"invalid\":123}' https://api.target.com/users"
    },
    interviewChallenge: {
          "scenario": "How does strict JSON schema validation at the API Gateway protect backend services from ReDoS and buffer overflow exploits?",
          "question": "What gets blocked before code execution?",
          "hint": "Malicious payloads with 10MB strings or exponential regex structures are dropped at the perimeter without consuming CPU on backend application pods.",
          "sampleAnswer": "Gateway validation acts as an input firewall. By enforcing maximum string lengths, strict regex formats, and valid enum values at the edge reverse proxy (e.g. Envoy/Kong), malicious payloads are dropped before reaching application runtimes where CPU-intensive parsing or database queries occur.",
          "keyTakeaway": "Enforce schema validation with `additionalProperties: false` directly in gateway admission filters."
    }
  },
  {
    ruleNumber: 85,
    id: "SEC-API-085",
    title: "Shadow and Zombie API Endpoint Inventory Bound Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "Asset Management",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["OWASP API9:2023", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 route \u2208 ExposedEndpoints, route \u2208 ServiceRegistry.ActiveRoutes \u2227 Deprecated(route) = False \u2227 HasOwner(route)",
    symbolBreakdown: [
          {
                "symbol": "ExposedEndpoints",
                "meaning": "All routes listening on public or internal network load balancers"
          },
          {
                "symbol": "ActiveRoutes",
                "meaning": "Documented and monitored routes in service catalog (Backstage, Kong)"
          },
          {
                "symbol": "Deprecated = False",
                "meaning": "Zombie v1/v2 endpoints decommissioned after sunset date"
          }
    ],
    plainEnglish: "All publicly and internally routable API endpoints must be documented in a central service registry with an active engineering owner. Deprecated and unmaintained API versions (Zombie APIs) must be permanently decommissioned.",
    whyItMatters: "Attackers discover unmaintained legacy endpoints like `/api/v1/resetPassword` which lack newer MFA and rate limiting defenses, allowing them to bypass modern security controls enforced on `/api/v3/`.",
    vulnerableExample: {
          "language": "nginx",
          "code": "# VULNERABLE: Reverse proxy still routing to abandoned legacy v1 service\nlocation /api/v1/ {\n    proxy_pass http://legacy-auth-cluster:8000; # Deprecated 3 years ago!\n}",
          "explanation": "Leaves old, vulnerable microservice exposed to the Internet without modern WAF or auth guards."
    },
    secureExample: {
          "language": "nginx",
          "code": "# SECURE: Complete deprecation and hard 410 Gone for retired versions\nlocation /api/v1/ {\n    return 410 \"API v1 permanently decommissioned. Upgrade to /api/v3/\";\n}",
          "explanation": "Decommissions legacy clusters and returns HTTP 410 Gone."
    },
    howToTest: {
          "tools": [
                "nmap",
                "kiterunner API directory fuzzer",
                "Amass"
          ],
          "steps": [
                "Run API route discovery scan: `kr scan https://api.target.com -w routes.txt`.",
                "Verify no undocumented or legacy `/api/v1` routes return 200 OK."
          ],
          "commandExample": "kr scan https://api.target.com -w api_wordlist.txt"
    },
    interviewChallenge: {
          "scenario": "What is the difference between a 'Shadow API' and a 'Zombie API'?",
          "question": "Which one was forgotten, and which was never documented in the first place?",
          "hint": "A Shadow API is an undocumented endpoint deployed without security knowledge; a Zombie API is an old, officially retired endpoint that was never turned off.",
          "sampleAnswer": "A Shadow API is an endpoint deployed by developers (for testing, partner demos, or rogue microservices) without formal security review or OpenAPI documentation. A Zombie API is a legitimately built legacy version (e.g. v1) that was superseded by v2 but left running on backend servers.",
          "keyTakeaway": "Implement automated traffic discovery and enforce sunset headers on all retired endpoints."
    }
  },
  {
    ruleNumber: 86,
    id: "SEC-API-086",
    title: "Pagination Limit Upper-Bound and Offset Cap Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "Resource Exhaustion",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["OWASP API4:2023", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 req \u2208 CollectionQueries, req.Limit \u2264 MaxAllowedLimit(100) \u2227 req.Offset \u2264 MaxAllowedOffset(10000)",
    symbolBreakdown: [
          {
                "symbol": "CollectionQueries",
                "meaning": "Endpoints returning lists of records: GET /api/users?limit=N&offset=M"
          },
          {
                "symbol": "MaxAllowedLimit",
                "meaning": "Hard ceiling restricting maximum records per response page (e.g., limit <= 100)"
          },
          {
                "symbol": "MaxAllowedOffset",
                "meaning": "Upper bound on OFFSET to prevent deep database table scanning"
          }
    ],
    plainEnglish: "All collection endpoints must enforce an unbypassable upper bound on page size (e.g. `limit <= 100`) and replace high OFFSET pagination with cursor-based (keyset) pagination to prevent database memory exhaustion.",
    whyItMatters: "An attacker calls `GET /api/transactions?limit=10000000`. The database loads ten million rows into RAM, serializing gigabytes of JSON, crashing the backend with an Out-Of-Memory (OOM) kernel kill.",
    vulnerableExample: {
          "language": "python/sql",
          "code": "# VULNERABLE: Direct client limit passed to database query\n@app.get('/api/records')\ndef get_records(limit: int = 20, offset: int = 0):\n    # Attacker passes: ?limit=5000000\n    return db.query(Record).offset(offset).limit(limit).all()",
          "explanation": "Loads millions of rows into heap memory, triggering database and app server crashes."
    },
    secureExample: {
          "language": "python/sql",
          "code": "# SECURE: Hard cap and cursor-based pagination\nMAX_PAGE_SIZE = 100\n\n@app.get('/api/records')\ndef get_records(limit: int = 20, cursor: Optional[str] = None):\n    safe_limit = min(limit, MAX_PAGE_SIZE)\n    query = db.query(Record).order_by(Record.id)\n    if cursor:\n        query = query.filter(Record.id > decode_cursor(cursor))\n    return query.limit(safe_limit).all()",
          "explanation": "Enforces maximum page ceiling of 100 and uses fast index-backed keyset pagination."
    },
    howToTest: {
          "tools": [
                "curl",
                "k6 load test"
          ],
          "steps": [
                "Call endpoint with `?limit=9999999`.",
                "Verify response contains at most 100 items or returns 400 Bad Request."
          ],
          "commandExample": "curl \"https://api.target.com/api/items?limit=1000000\""
    },
    interviewChallenge: {
          "scenario": "Why does `OFFSET 1000000 LIMIT 20` cause database CPU and I/O starvation even if the limit is small?",
          "question": "How does the database execute an OFFSET query internally?",
          "hint": "The database must read, sort, and discard all 1,000,000 previous rows from disk before returning the 20 requested records.",
          "sampleAnswer": "When a query specifies `OFFSET 1000000`, the database engine cannot simply jump to row 1,000,000. It must traverse the index, fetch all 1,000,000 rows into memory, and discard them, resulting in massive disk I/O and CPU spikes. Keyset pagination (`WHERE id > last_seen_id LIMIT 20`) uses direct index lookups in constant O(1) time.",
          "keyTakeaway": "Enforce cursor-based pagination (`WHERE id > :cursor`) for high-volume collection APIs."
    }
  },
  {
    ruleNumber: 87,
    id: "SEC-API-087",
    title: "Internal Stack Trace Suppression in API Error Payloads",
    domain: "api",
    domainName: "API Security",
    subdomain: "Information Disclosure",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["CWE-209", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 err \u2208 APIErrorResponses, ContainsStackTrace(err) = False \u2227 ContainsInternalPaths(err) = False \u2227 HasCorrelationId(err)",
    symbolBreakdown: [
          {
                "symbol": "APIErrorResponses",
                "meaning": "HTTP 4xx and 5xx error JSON bodies returned to callers"
          },
          {
                "symbol": "ContainsStackTrace = False",
                "meaning": "Zero raw exception class names, file paths, or line numbers exposed"
          },
          {
                "symbol": "HasCorrelationId",
                "meaning": "Opaque UUID returned to client for server-side log correlation"
          }
    ],
    plainEnglish: "API error responses must return generic, sanitized error messages and opaque correlation IDs. Raw exception stack traces, database schema names, file paths, and environment variables must never be returned in HTTP payloads.",
    whyItMatters: "Stack traces reveal database types (PostgreSQL vs Oracle), internal source code file paths (`/var/www/auth/jwt_helper.py:42`), ORM versions, and third-party library vulnerabilities, arming attackers with precise exploit blueprints.",
    vulnerableExample: {
          "language": "javascript/express",
          "code": "// VULNERABLE: Express default error handler leaks stack trace\napp.use((err, req, res, next) => {\n    res.status(500).json({ error: err.message, stack: err.stack });\n});",
          "explanation": "Returns complete stack trace with file paths and line numbers to anyone triggering an error."
    },
    secureExample: {
          "language": "javascript/express",
          "code": "// SECURE: Centralized error sanitizer with correlation ID\napp.use((err, req, res, next) => {\n    const correlationId = crypto.randomUUID();\n    logger.error({ correlationId, error: err.stack }); // Log details internally\n    res.status(500).json({\n        error: \"An unexpected error occurred\",\n        code: \"INTERNAL_ERROR\",\n        correlationId\n    });\n});",
          "explanation": "Logs full stack trace to secure internal logging system while returning an opaque ID to the client."
    },
    howToTest: {
          "tools": [
                "curl",
                "Burp Suite"
          ],
          "steps": [
                "Send malformed JSON (`{bad json}`) or illegal parameter types.",
                "Verify HTTP 500/400 response is clean JSON without file paths, SQL syntax, or line numbers."
          ],
          "commandExample": "curl -X POST -H \"Content-Type: application/json\" -d '{invalid' https://api.target.com/api/test"
    },
    interviewChallenge: {
          "scenario": "In a microservices architecture, how do customer support engineers debug production failures if stack traces are suppressed?",
          "question": "What is the purpose of the Correlation ID?",
          "hint": "The user provides the opaque Correlation ID to support, who queries centralized internal observability tools (Datadog, Splunk) where the unredacted stack trace is securely stored.",
          "sampleAnswer": "The API returns an opaque Correlation ID (or W3C `traceparent`). Internal logging pipelines record the full stack trace tagged with that exact ID. Support and developers look up the ID in internal telemetry systems without ever exposing internal architecture to public clients.",
          "keyTakeaway": "Log unredacted stack traces internally; return only an opaque correlation ID to clients."
    }
  },
  {
    ruleNumber: 88,
    id: "SEC-API-088",
    title: "API Key Entropy and Secret Revocation Verification Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "API Key Management",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-63B", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 key \u2208 APIKeys, Entropy(key) \u2265 128 bits \u2227 Hash(key) \u2208 Database \u2227 IsRevoked(key) = False",
    symbolBreakdown: [
          {
                "symbol": "APIKeys",
                "meaning": "Long-lived machine-to-machine client secrets"
          },
          {
                "symbol": "Entropy >= 128 bits",
                "meaning": "Cryptographically unguessable pseudo-random string"
          },
          {
                "symbol": "Hash(key) \u2208 Database",
                "meaning": "API keys stored exclusively as one-way cryptographic digests (SHA-256), never plaintext"
          }
    ],
    plainEnglish: "API keys must possess at least 128 bits of cryptographic entropy and be stored in databases hashed (e.g. SHA-256) rather than in plaintext. Systems must support instantaneous revocation and rotation without service disruption.",
    whyItMatters: "Storing API keys in plaintext in the database allows anyone with read-only database access or a database backup to steal all customer API keys, compromising external integrations.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Storing raw API key in database\ndef generate_api_key(user_id):\n    raw_key = \"key_\" + os.urandom(16).hex()\n    db.save_key(user_id, raw_key) # Plaintext in database!\n    return raw_key",
          "explanation": "Database compromise leaks active API keys for all tenants."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Hashing API key before storage; returning key only once\nimport hashlib, secrets\n\ndef generate_api_key(user_id):\n    token = secrets.token_urlsafe(32)\n    key_id = f\"ak_{secrets.token_hex(4)}\"\n    full_key = f\"{key_id}_{token}\"\n    # Store SHA-256 digest of secret token:\n    token_hash = hashlib.sha256(token.encode()).hexdigest()\n    db.save_key(key_id=key_id, user_id=user_id, token_hash=token_hash)\n    return full_key # Shown to user once, never stored in plaintext",
          "explanation": "Database only stores key ID and one-way cryptographic hash of secret token."
    },
    howToTest: {
          "tools": [
                "git-secrets",
                "TruffleHog",
                "openssl"
          ],
          "steps": [
                "Verify database schema for api_keys table.",
                "Confirm column stores 64-character SHA-256 hex digest, not original key string."
          ],
          "commandExample": "trufflehog git file://. --only-verified"
    },
    interviewChallenge: {
          "scenario": "Why should API keys include an unhashed prefix or key ID (e.g., `ak_live_...` or `pk_live_...`)?",
          "question": "How does the prefix assist fast database lookups and automated secret scanners?",
          "hint": "The prefix allows GitHub/GitGuardian secret scanners to immediately identify leaked keys via regex, and allows the backend to perform an O(1) index lookup on the key ID before comparing the hash.",
          "sampleAnswer": "A structured key prefix (`sk_live_1234_secrettoken`) serves two critical functions: 1) Secret detection bots (GitHub Secret Scanning) instantly identify and revoke leaked keys in public repositories; 2) The prefix acts as an unhashed database index key, avoiding full table scans when checking the hashed secret token.",
          "keyTakeaway": "Structure API keys with an identifiable prefix, public key ID, and high-entropy secret token."
    }
  },
  {
    ruleNumber: 89,
    id: "SEC-API-089",
    title: "GraphQL Introspection Disabling in Production Environments",
    domain: "api",
    domainName: "API Security",
    subdomain: "Reconnaissance Defense",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["OWASP GraphQL", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 env \u2208 {Production, Staging}, HasFeature(GraphQL, \"__schema\") = False \u2227 HasFeature(GraphQL, \"__type\") = False",
    symbolBreakdown: [
          {
                "symbol": "Production, Staging",
                "meaning": "Live customer-facing deployment environments"
          },
          {
                "symbol": "__schema, __type",
                "meaning": "Meta-fields exposing GraphQL schema introspection AST"
          }
    ],
    plainEnglish: "GraphQL schema introspection queries (`__schema`, `__type`) must be completely disabled in production environments. Attackers must not be able to dump internal types, mutations, and hidden fields.",
    whyItMatters: "Enabling introspection allows attackers using tools like GraphQL Voyager or InQL to download the entire application schema in 2 seconds, exposing unreleased features, internal mutations, and administrative query fields.",
    vulnerableExample: {
          "language": "javascript/apollo",
          "code": "// VULNERABLE: Introspection explicitly enabled in production\nconst server = new ApolloServer({\n    typeDefs,\n    resolvers,\n    introspection: true // VULNERABLE in production!\n});",
          "explanation": "Allows attackers to execute `query { __schema { types { name } } }` and map all backend operations."
    },
    secureExample: {
          "language": "javascript/apollo",
          "code": "// SECURE: Introspection disabled conditionally in production\nconst server = new ApolloServer({\n    typeDefs,\n    resolvers,\n    introspection: process.env.NODE_ENV !== 'production'\n});",
          "explanation": "Disables schema discovery queries in production, returning 400 Bad Request to introspection attempts."
    },
    howToTest: {
          "tools": [
                "graphql-inspector",
                "curl",
                "InQL"
          ],
          "steps": [
                "Send introspection query: `{\"query\":\"{__schema{types{name}}}\"}` to production endpoint.",
                "Verify server rejects query with error: 'GraphQL introspection is not allowed'."
          ],
          "commandExample": "curl -X POST -H \"Content-Type: application/json\" -d '{\"query\":\"{__schema{queryType{name}}}\"}' https://api.target.com/graphql"
    },
    interviewChallenge: {
          "scenario": "If introspection is disabled in production, how can an attacker still discover schema field names?",
          "question": "Can field suggestion error messages leak schema information?",
          "hint": "Yes, if an attacker queries `{ usr }`, the engine returns 'Did you mean \"user\"?', allowing automated tools to reconstruct the schema word-by-word.",
          "sampleAnswer": "GraphQL engines implement 'Field Suggestion' heuristics by default. When an attacker sends a misspelled field name, the engine suggests the correct field (`Did you mean 'creditCardNumber'?`). In high-security production APIs, field suggestions must also be disabled via plugins or error masking.",
          "keyTakeaway": "Disable both GraphQL introspection and field suggestions in production."
    }
  },
  {
    ruleNumber: 90,
    id: "SEC-API-090",
    title: "gRPC Metadata Authentication Header Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "gRPC Security",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["gRPC Auth Spec", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 call \u2208 gRPCServerCalls, HasMetadata(call, \"authorization\") \u2227 VerifyToken(call.Metadata[\"authorization\"]) = True",
    symbolBreakdown: [
          {
                "symbol": "gRPCServerCalls",
                "meaning": "Incoming HTTP/2 gRPC RPC invocations"
          },
          {
                "symbol": "call.Metadata['authorization']",
                "meaning": "gRPC metadata header carrying Bearer token or client certificate"
          },
          {
                "symbol": "VerifyToken",
                "meaning": "Verification of token signature and expiry before method dispatch"
          }
    ],
    plainEnglish: "gRPC services must intercept every incoming call via a server interceptor that validates the `authorization` metadata header before invoking any RPC handler. Unauthenticated calls must return `Status.UNAUTHENTICATED` (code 16).",
    whyItMatters: "gRPC microservices communicating over HTTP/2 often assume internal network security and omit per-RPC authentication. Compromise of a single container allows an attacker to make unauthenticated RPC calls to internal billing or database services.",
    vulnerableExample: {
          "language": "go",
          "code": "// VULNERABLE: Direct gRPC handler without auth interceptor\nfunc (s *Server) TransferFunds(ctx context.Context, req *TransferReq) (*TransferRes, error) {\n    // Omits token check! Blindly executes transfer\n    return s.db.Transfer(req.From, req.To, req.Amount)\n}",
          "explanation": "Any client or pod connected to the gRPC port can trigger financial transfers without credentials."
    },
    secureExample: {
          "language": "go",
          "code": "// SECURE: Server unary interceptor validating metadata token\nfunc AuthInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {\n    md, ok := metadata.FromIncomingContext(ctx)\n    if !ok || len(md[\"authorization\"]) == 0 {\n        return nil, status.Errorf(codes.Unauthenticated, \"missing authorization token\")\n    }\n    if err := validateToken(md[\"authorization\"][0]); err != nil {\n        return nil, status.Errorf(codes.Unauthenticated, \"invalid token: %v\", err)\n    }\n    return handler(ctx, req)\n}",
          "explanation": "Enforces token presence and validity across every gRPC method on the server."
    },
    howToTest: {
          "tools": [
                "grpcurl",
                "grpc-health-probe"
          ],
          "steps": [
                "Call gRPC method without metadata: `grpcurl -plaintext localhost:50051 Bank.Transfer`.",
                "Verify server returns code 16 UNAUTHENTICATED."
          ],
          "commandExample": "grpcurl -H \"authorization: Bearer invalid\" localhost:50051 api.UserService/GetUser"
    },
    interviewChallenge: {
          "scenario": "How does authentication metadata propagation work when microservice A calls microservice B over gRPC on behalf of a user?",
          "question": "How do you pass user context across gRPC hops?",
          "hint": "Microservice A uses an outgoing client interceptor (`metadata.NewOutgoingContext`) to forward the verified user claim or signed JWT down the call chain.",
          "sampleAnswer": "In gRPC distributed systems, incoming context metadata must be extracted, verified, and re-injected into the outgoing context via client interceptors (`metadata.AppendToOutgoingContext`). This ensures identity and distributed tracing headers propagate across all microservice hops.",
          "keyTakeaway": "Implement gRPC interceptors for both inbound validation and outbound token propagation."
    }
  },
  {
    ruleNumber: 91,
    id: "SEC-API-091",
    title: "RESTful URL Entity Relationship Hierarchical Path Validation",
    domain: "api",
    domainName: "API Security",
    subdomain: "Path-Based Authorization",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["OWASP API1:2023", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 req \u2208 NestedResourceRequests, ExistsInDB(Parent(req.ParentId) \u2227 Child(req.ChildId) \u2227 Child.ParentId = Parent.Id)",
    symbolBreakdown: [
          {
                "symbol": "NestedResourceRequests",
                "meaning": "Hierarchical REST URLs like /api/organizations/{orgId}/projects/{projId}"
          },
          {
                "symbol": "Child.ParentId = Parent.Id",
                "meaning": "Verification that the child entity genuinely belongs to the specified parent"
          }
    ],
    plainEnglish: "When an API uses nested RESTful URLs (`/tenants/{tenantId}/users/{userId}/invoices/{invoiceId}`), the controller must verify the entire hierarchical relationship chain. It must not look up the child entity purely by childId while ignoring the parent path parameters.",
    whyItMatters: "An attacker discovers that `/api/tenants/alpha/invoices/999` allows them to view invoice 999 (which actually belongs to tenant 'beta') because the backend only queries `Invoice.findById(999)`, completely ignoring `tenantId` in the path.",
    vulnerableExample: {
          "language": "typescript",
          "code": "// VULNERABLE: Only queries by invoiceId, ignoring orgId parameter!\napp.get('/api/orgs/:orgId/invoices/:invId', authenticate, async (req, res) => {\n    const invoice = await Invoice.findById(req.params.invId); // Bypasses orgId!\n    res.json(invoice);\n});",
          "explanation": "Allows viewing any invoice in the database by passing an arbitrary orgId."
    },
    secureExample: {
          "language": "typescript",
          "code": "// SECURE: Explicit relational query enforcing hierarchy\napp.get('/api/orgs/:orgId/invoices/:invId', authenticate, async (req, res) => {\n    const invoice = await Invoice.findOne({\n        where: {\n            id: req.params.invId,\n            orgId: req.params.orgId,\n            org: { members: { userId: req.user.id } } // Verifies caller belongs to org\n        }\n    });\n    if (!invoice) return res.status(404).json({ error: 'Invoice not found' });\n    res.json(invoice);\n});",
          "explanation": "Enforces that the invoice belongs to the specified org and the user has access to that org."
    },
    howToTest: {
          "tools": [
                "Postman",
                "curl"
          ],
          "steps": [
                "Send request with valid orgId but an invId belonging to another company.",
                "Verify API returns 404 Not Found."
          ],
          "commandExample": "curl -H \"Authorization: Bearer my_token\" https://api.target.com/api/orgs/my_org/invoices/victim_invoice_id"
    },
    interviewChallenge: {
          "scenario": "Why should APIs return HTTP 404 Not Found rather than 403 Forbidden when a nested entity does not belong to the parent?",
          "question": "What information does a 403 status leak to an attacker?",
          "hint": "A 403 leaks that the invoice ID exists in the database, allowing an attacker to enumerate valid IDs across competing companies.",
          "sampleAnswer": "Returning 403 Forbidden confirms to an attacker that the target resource ID exists in the system (resource enumeration). Returning 404 Not Found makes the resource indistinguishable from a non-existent entity, preventing information disclosure.",
          "keyTakeaway": "Return 404 Not Found when entity relational ownership checks fail."
    }
  },
  {
    ruleNumber: 92,
    id: "SEC-API-092",
    title: "Webhook HMAC Signature Verification Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "Webhook Integrity",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 2104", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 hook \u2208 IncomingWebhooks, TimingSafeEqual(ComputeHMAC(hook.RawBody, Secret), hook.Signature) = True \u2227 (Now() - hook.Timestamp \u2264 300s)",
    symbolBreakdown: [
          {
                "symbol": "IncomingWebhooks",
                "meaning": "Inbound callbacks from third-party services like Stripe, GitHub, or Twilio"
          },
          {
                "symbol": "TimingSafeEqual",
                "meaning": "Constant-time byte comparison preventing timing attacks"
          },
          {
                "symbol": "Now() - hook.Timestamp <= 300s",
                "meaning": "Anti-replay protection window restricting timestamp drift to 5 minutes"
          }
    ],
    plainEnglish: "Applications receiving webhooks must verify the cryptographic HMAC signature computed over the raw, unparsed request body using a shared secret. Payloads must include a timestamp to reject replay attacks outside a 5-minute window.",
    whyItMatters: "Without HMAC verification, any attacker on the Internet can send forged `POST /webhooks/stripe` payloads with `{\"type\": \"payment_intent.succeeded\", \"amount\": 500000}`, crediting accounts with fake funds.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Parsing JSON body before verification and using standard ==\napp.post('/webhook', (req, res) => {\n    // Attacker sends forged JSON without signature check!\n    if (req.body.status === 'PAID') {\n        fulfillOrder(req.body.orderId);\n    }\n    res.sendStatus(200);\n});",
          "explanation": "Blindly trusts unauthenticated incoming webhook POST requests."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Raw body HMAC SHA-256 verification with timestamp replay check\nimport crypto from 'crypto';\n\napp.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {\n    const sigHeader = req.headers['x-signature-sha256'];\n    const timestamp = parseInt(req.headers['x-timestamp'], 10);\n    if (Math.abs(Date.now() / 1000 - timestamp) > 300) {\n        return res.status(400).send('Timestamp out of bounds (replay attack)');\n    }\n    const expected = crypto.createHmac('sha256', WEBHOOK_SECRET)\n                           .update(`${timestamp}.${req.body}`)\n                           .digest('hex');\n    if (!crypto.timingSafeEqual(Buffer.from(sigHeader), Buffer.from(expected))) {\n        return res.status(401).send('Invalid signature');\n    }\n    fulfillOrder(JSON.parse(req.body).orderId);\n    res.sendStatus(200);\n});",
          "explanation": "Verifies cryptographic HMAC using raw byte stream and enforces anti-replay timestamp bounds."
    },
    howToTest: {
          "tools": [
                "curl",
                "Stripe CLI `stripe trigger payment_intent.succeeded`"
          ],
          "steps": [
                "Send webhook POST with altered payload byte.",
                "Verify server returns 401 Unauthorized.",
                "Send request with valid signature but timestamp older than 10 minutes; verify 400 Bad Request."
          ],
          "commandExample": "curl -X POST -H \"X-Signature: invalid\" -d '{\"status\":\"PAID\"}' https://api.target.com/webhook"
    },
    interviewChallenge: {
          "scenario": "Why must webhook HMAC verification be computed against the RAW request body bytes rather than a re-serialized JSON object (`JSON.stringify(req.body)`)?",
          "question": "How does JSON key ordering affect HMAC digests?",
          "hint": "Different JSON parsers and serializers alter key ordering, whitespace, and Unicode escaping, changing the byte stream and producing a mismatched HMAC.",
          "sampleAnswer": "Cryptographic hashes are sensitive to a single byte or space discrepancy. When an application parses JSON into an object and re-stringifies it, key order, indentation, and float representations change, completely invalidating the computed HMAC signature. Verification must always consume the raw incoming byte buffer.",
          "keyTakeaway": "Capture raw request body buffers before any JSON parsing middleware executes."
    }
  },
  {
    ruleNumber: 93,
    id: "SEC-API-093",
    title: "Content-Type Negotiation Enforcement (JSON-only Accept)",
    domain: "api",
    domainName: "API Security",
    subdomain: "Parser Exploitation",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["RFC 9110 \u00a712.5", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 req \u2208 APIRequests_{POST, PUT, PATCH}, HeaderValue(req, \"Content-Type\") = \"application/json\" \u2227 MatchesDeclaredParser(req)",
    symbolBreakdown: [
          {
                "symbol": "APIRequests",
                "meaning": "State-mutating API requests"
          },
          {
                "symbol": "Content-Type = application/json",
                "meaning": "Strict MIME type requirement"
          },
          {
                "symbol": "MatchesDeclaredParser",
                "meaning": "Rejection of XML, form-data, or text masquerading as JSON"
          }
    ],
    plainEnglish: "APIs that process JSON must strictly enforce `Content-Type: application/json`. Requests bearing unexpected or ambiguous MIME types (e.g. `text/plain`, `multipart/form-data`) must be rejected immediately with 415 Unsupported Media Type.",
    whyItMatters: "Allowing state-mutating API endpoints to accept `text/plain` or form submissions allows attackers to bypass CORS preflight checks (Simple Requests) and execute Cross-Site Request Forgery (CSRF) attacks against JSON APIs.",
    vulnerableExample: {
          "language": "javascript/express",
          "code": "// VULNERABLE: Permissive parser accepting text/plain without CORS preflight\napp.use(express.text());\napp.post('/api/transfer', (req, res) => {\n    const body = JSON.parse(req.body);\n    executeTransfer(body);\n});",
          "explanation": "Enables cross-origin websites to submit forged transfers via standard HTML forms or text/plain fetch without triggering a CORS preflight."
    },
    secureExample: {
          "language": "javascript/express",
          "code": "// SECURE: Enforce strict application/json Content-Type\napp.post('/api/transfer', (req, res, next) => {\n    if (req.headers['content-type'] !== 'application/json') {\n        return res.status(415).json({ error: 'Unsupported Media Type: application/json required' });\n    }\n    next();\n}, express.json({ strict: true }), executeTransfer);",
          "explanation": "Rejects non-JSON media types with 415, guaranteeing that browsers must send an options preflight before cross-origin POSTs."
    },
    howToTest: {
          "tools": [
                "curl",
                "browser form submission"
          ],
          "steps": [
                "Send POST with header `Content-Type: text/plain` containing JSON string.",
                "Verify server returns 415 Unsupported Media Type."
          ],
          "commandExample": "curl -X POST -H \"Content-Type: text/plain\" -d '{\"amount\":100}' https://api.target.com/api/transfer"
    },
    interviewChallenge: {
          "scenario": "Why does requiring `Content-Type: application/json` protect an API against Cross-Site Request Forgery (CSRF) from traditional web forms?",
          "question": "Can an HTML `<form>` emit an `application/json` Content-Type?",
          "hint": "Standard HTML forms can only emit `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`. They cannot send `application/json`.",
          "sampleAnswer": "Under the W3C Fetch specification, an HTTP POST with `application/json` is NOT a 'simple request' and mandates a CORS preflight (`OPTIONS`) check. Because an HTML `<form>` cannot generate `application/json`, browsers will not send ambient cookies without the target server explicitly authorizing the cross-origin preflight.",
          "keyTakeaway": "Enforce strict Content-Type checks on all state-mutating endpoints."
    }
  },
  {
    ruleNumber: 94,
    id: "SEC-API-094",
    title: "API Version Deprecation Sunset Header Invariant (RFC 8594)",
    domain: "api",
    domainName: "API Security",
    subdomain: "Lifecycle Management",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 8594", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 req \u2208 DeprecatedEndpoints, HasHeader(resp, \"Sunset\", RFC1123Date) \u2227 HasHeader(resp, \"Deprecation\", \"true\")",
    symbolBreakdown: [
          {
                "symbol": "DeprecatedEndpoints",
                "meaning": "API endpoints scheduled for decommissioning"
          },
          {
                "symbol": "Sunset",
                "meaning": "Standard HTTP response header specifying exact cutoff timestamp per RFC 8594"
          },
          {
                "symbol": "Deprecation",
                "meaning": "Standard IETF boolean header signaling deprecation"
          }
    ],
    plainEnglish: "When an API endpoint is marked for deprecation, all responses must include the RFC 8594 `Sunset` header specifying the exact date and time the endpoint will return 410 Gone, alongside the `Deprecation: true` header.",
    whyItMatters: "Silent or unannounced endpoint deprecation leads to unexpected service outages for clients, while keeping deprecated versions alive indefinitely results in Zombie APIs vulnerable to legacy exploits.",
    vulnerableExample: {
          "language": "http",
          "code": "# VULNERABLE: Deprecated endpoint returns no sunset warning\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"data\":\"legacy response\"}",
          "explanation": "Clients have zero programmatic awareness that this endpoint will be shut down."
    },
    secureExample: {
          "language": "http",
          "code": "# SECURE: RFC 8594 Sunset and Deprecation headers\nHTTP/1.1 200 OK\nDeprecation: @1735689600\nSunset: Wed, 01 Jan 2025 00:00:00 GMT\nLink: <https://api.example.com/docs/v3-migration>; rel=\"successor-version\"\nContent-Type: application/json\n\n{\"data\":\"legacy response\"}",
          "explanation": "Provides programmatic advance warning and documentation link to client applications."
    },
    howToTest: {
          "tools": [
                "curl",
                "API linting"
          ],
          "steps": [
                "Send request to deprecated endpoint.",
                "Verify response contains `Sunset` and `Deprecation` headers."
          ],
          "commandExample": "curl -sI https://api.target.com/v1/users | grep -i sunset"
    },
    interviewChallenge: {
          "scenario": "What is the recommended HTTP status code to return when the `Sunset` date has passed and an endpoint is permanently turned off?",
          "question": "Why is 410 Gone preferred over 404 Not Found?",
          "hint": "HTTP 410 Gone explicitly tells clients that the resource was intentionally removed and will never return, allowing automated API clients to stop retrying.",
          "sampleAnswer": "HTTP 404 indicates a resource is not found (which could be temporary or a misconfiguration). HTTP 410 Gone informs client SDKs and search indexing crawlers that the endpoint was permanently removed and will not return, instructing client systems to clean up links and stop polling.",
          "keyTakeaway": "Emit RFC 8594 Sunset headers during deprecation and return 410 Gone after cutoff."
    }
  },
  {
    ruleNumber: 95,
    id: "SEC-API-095",
    title: "XML External Entity (XXE) Parser Disabling in SOAP/REST APIs",
    domain: "api",
    domainName: "API Security",
    subdomain: "XXE Injection",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["CWE-611", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 parser \u2208 XMLParsers, DisallowDoctypeDecl(parser) = True \u2227 DisallowExternalEntities(parser) = True",
    symbolBreakdown: [
          {
                "symbol": "XMLParsers",
                "meaning": "DOM, SAX, or StAX XML parsing libraries in API controllers"
          },
          {
                "symbol": "DisallowDoctypeDecl",
                "meaning": "Prohibits <!DOCTYPE> declarations in incoming XML"
          },
          {
                "symbol": "DisallowExternalEntities",
                "meaning": "Prohibits external entity resolution like SYSTEM 'file:///etc/passwd'"
          }
    ],
    plainEnglish: "All XML parsers handling API requests must disable Document Type Declarations (DTD) and external entity resolution. XML payloads must never fetch external network resources or read local server files.",
    whyItMatters: "An attacker sends an XML document with `<!ENTITY xxe SYSTEM \"file:///etc/passwd\"> <user>&xxe;</user>`. The vulnerable parser reads `/etc/passwd` and echoes it in the API response or performs internal SSRF attacks.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: lxml parser with external entities enabled\nfrom lxml import etree\n\ndef parse_order(xml_data):\n    parser = etree.XMLParser(resolve_entities=True) # VULNERABLE!\n    return etree.fromstring(xml_data, parser)",
          "explanation": "Parses external DTDs and entities, allowing attackers to exfiltrate local files."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: DefusedXML / disabling DTD and entity resolution\nimport defusedxml.ElementTree as ET\n\ndef parse_order(xml_data):\n    # defusedxml disallows all DTDs, entity expansions, and external URLs:\n    return ET.fromstring(xml_data)",
          "explanation": "Completely neutralizes XXE and billion laughs XML entity expansion attacks."
    },
    howToTest: {
          "tools": [
                "curl",
                "Burp Suite XML fuzzer"
          ],
          "steps": [
                "Send XML containing `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/hosts\"> ]><req>&xxe;</req>`.",
                "Verify parser rejects request with XML parsing error."
          ],
          "commandExample": "curl -X POST -H \"Content-Type: application/xml\" -d '<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><root>&xxe;</root>' https://api.target.com/xml"
    },
    interviewChallenge: {
          "scenario": "What is an 'XML Billion Laughs' (XML Bomb) attack, and how does disabling DTD resolution prevent it?",
          "question": "What happens during exponential entity expansion?",
          "hint": "An XML bomb uses nested entities (`&lol1;` expanding to ten `&lol2;`) to turn a 1KB XML payload into 3 gigabytes of memory strings upon parsing, crashing the server.",
          "sampleAnswer": "In a Billion Laughs attack, nested entities recursively reference each other: `<!ENTITY lol \"lol\"> <!ENTITY lol1 \"&lol;&lol;\" ...>`. When the parser resolves the entity, it expands exponentially in memory, consuming all CPU and RAM. Prohibiting DOCTYPE declarations blocks entity definitions entirely.",
          "keyTakeaway": "Use defused XML libraries and disallow DOCTYPE declarations in all XML parsers."
    }
  },
  {
    ruleNumber: 96,
    id: "SEC-API-096",
    title: "CORS Preflight Caching (Max-Age) Ceiling Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "CORS Latency & Security",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["W3C Fetch", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 preflight \u2208 CORSPreflightResponses, HeaderValue(preflight, \"Access-Control-Max-Age\") \u2264 86400",
    symbolBreakdown: [
          {
                "symbol": "CORSPreflightResponses",
                "meaning": "HTTP OPTIONS responses to preflighted cross-origin requests"
          },
          {
                "symbol": "Access-Control-Max-Age",
                "meaning": "Time in seconds browsers are permitted to cache preflight permission"
          },
          {
                "symbol": "<= 86400",
                "meaning": "Maximum 24-hour ceiling to allow timely policy revocation"
          }
    ],
    plainEnglish: "The `Access-Control-Max-Age` header returned on CORS preflight (OPTIONS) requests must not exceed 86,400 seconds (24 hours). Setting excessively long cache durations prevents timely revocation of compromised origins.",
    whyItMatters: "If an API sets `Access-Control-Max-Age: 31536000` (1 year) and an allowed subdomain is subsequently compromised or sold, victim browsers that cached the preflight will continue authorizing the compromised origin for a full year.",
    vulnerableExample: {
          "language": "http",
          "code": "# VULNERABLE: Excessive CORS preflight cache duration\nHTTP/1.1 204 No Content\nAccess-Control-Allow-Origin: https://partner.com\nAccess-Control-Max-Age: 31536000",
          "explanation": "Binds browser to trust partner.com for an entire year without re-verifying policy."
    },
    secureExample: {
          "language": "http",
          "code": "# SECURE: Bounded preflight cache with reasonable lifetime\nHTTP/1.1 204 No Content\nAccess-Control-Allow-Origin: https://partner.com\nAccess-Control-Max-Age: 7200\nVary: Origin",
          "explanation": "Caches preflight for 2 hours, balancing network performance with timely security policy updates."
    },
    howToTest: {
          "tools": [
                "curl",
                "browser DevTools"
          ],
          "steps": [
                "Send OPTIONS preflight request to API.",
                "Verify `Access-Control-Max-Age` is present and does not exceed 86400."
          ],
          "commandExample": "curl -X OPTIONS -H \"Origin: https://partner.com\" -H \"Access-Control-Request-Method: POST\" -sI https://api.target.com | grep -i max-age"
    },
    interviewChallenge: {
          "scenario": "What is the maximum `Access-Control-Max-Age` value that modern Chromium browsers will actually respect, regardless of what the server returns?",
          "question": "Does Chrome cap preflight caching?",
          "hint": "Chromium enforces an internal ceiling of 7,200 seconds (2 hours); Firefox caps it at 86,400 seconds (24 hours).",
          "sampleAnswer": "Modern browsers implement their own safety caps on CORS preflight caching to prevent stale security policies. Chromium caps the value at 7,200 seconds (2 hours), while Firefox allows up to 86,400 seconds (24 hours). Specifying values higher than 86,400 is useless and ignored by browsers.",
          "keyTakeaway": "Set `Access-Control-Max-Age: 7200` to optimize caching without exceeding browser limits."
    }
  },
  {
    ruleNumber: 97,
    id: "SEC-API-097",
    title: "Microservice Service-to-Service mTLS Mutual Authentication Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "Zero Trust Network",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-204", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 conn \u2208 InternalMicroserviceCalls, HasValidClientCert(conn) \u2227 SAN(conn.ClientCert) = SPIFFE_ID \u2227 CipherSuite(conn) = TLS_1_3",
    symbolBreakdown: [
          {
                "symbol": "InternalMicroserviceCalls",
                "meaning": "East-west network communication between backend services"
          },
          {
                "symbol": "SAN = SPIFFE_ID",
                "meaning": "Subject Alternative Name matches cryptographically verifiable service identity"
          },
          {
                "symbol": "TLS_1_3",
                "meaning": "Encrypted mutual TLS transport"
          }
    ],
    plainEnglish: "All east-west communication between internal microservices must mandate mutual TLS (mTLS) with cryptographically validated service identities (SPIFFE/SPIRE). Cleartext internal HTTP or unauthenticated TCP is prohibited.",
    whyItMatters: "In perimeter-only network architectures, an attacker who gains access to a single internal container (via SSRF or dependency vulnerability) can eavesdrop on plaintext database traffic and spoof internal service requests.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Service mesh allowing plaintext traffic\napiVersion: security.istio.io/v1beta1\nkind: PeerAuthentication\nspec:\n  mtls:\n    mode: PERMISSIVE # Allows unencrypted connections without client certs!",
          "explanation": "Permits unauthenticated and unencrypted east-west network traffic inside the cluster."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Strict mutual TLS enforced across namespace\napiVersion: security.istio.io/v1beta1\nkind: PeerAuthentication\nmetadata:\n  name: default\n  namespace: production\nspec:\n  mtls:\n    mode: STRICT",
          "explanation": "Rejects all connections lacking a valid X.509 client certificate issued by the cluster CA."
    },
    howToTest: {
          "tools": [
                "openssl s_client",
                "istioctl authn tls-check"
          ],
          "steps": [
                "Attempt connecting to internal microservice without client certificate.",
                "Verify handshake is aborted: 'certificate required'."
          ],
          "commandExample": "istioctl x describe pod my-service-pod-123.production"
    },
    interviewChallenge: {
          "scenario": "How does mTLS prevent lateral movement during a container breakout in a Kubernetes cluster?",
          "question": "Can an attacker spoof another service if mTLS is STRICT?",
          "hint": "No. The attacker cannot make RPC calls without the private key associated with the target service's X.509 certificate.",
          "sampleAnswer": "Under strict mTLS with SPIFFE IDs, services do not trust network IP addresses. Even if an attacker gains root inside a compromised pod, they cannot communicate with other microservices without presenting a valid X.509 certificate signed by the service mesh CA for that specific service identity.",
          "keyTakeaway": "Enforce STRICT mTLS across all Kubernetes service mesh namespaces."
    }
  },
  {
    ruleNumber: 98,
    id: "SEC-API-098",
    title: "API Response PII Filtering and DTO Serialization Sanitization",
    domain: "api",
    domainName: "API Security",
    subdomain: "Data Leakage",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["OWASP API3:2023", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 resp \u2208 APIResponses, Keys(resp.Body) \u2229 {password_hash, ssn, stripe_secret, credit_card} = \u2205",
    symbolBreakdown: [
          {
                "symbol": "APIResponses",
                "meaning": "Outbound JSON bodies delivered to API clients"
          },
          {
                "symbol": "Keys(resp.Body)",
                "meaning": "All JSON properties in response payload"
          },
          {
                "symbol": "\u2205",
                "meaning": "Strictly zero leakage of sensitive database columns"
          }
    ],
    plainEnglish: "API responses must serialize outgoing data through explicit response DTOs or serializers. Database entity objects must never be returned directly, preventing accidental leakage of password hashes, internal secrets, or PII.",
    whyItMatters: "A developer writes `return res.json(user)`. The ORM serializes the entire `users` table row, including `password_hash`, `mfa_secret`, and `password_reset_token`, delivering them to the frontend where attackers can read them.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Direct entity serialization\napp.get('/api/users/:id', async (req, res) => {\n    const user = await User.findById(req.params.id);\n    // Returns password_hash, ssn, and internal admin notes!\n    res.json(user);\n});",
          "explanation": "Leaks confidential database attributes in client-facing JSON payloads."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Response DTO whitelist serialization\nimport { z } from 'zod';\n\nconst UserPublicDTO = z.object({\n    id: z.string(),\n    displayName: z.string(),\n    avatarUrl: z.string().url()\n});\n\napp.get('/api/users/:id', async (req, res) => {\n    const user = await User.findById(req.params.id);\n    // Only serializes explicitly permitted public fields:\n    res.json(UserPublicDTO.parse(user));\n});",
          "explanation": "Guarantees that sensitive entity properties are stripped before JSON serialization."
    },
    howToTest: {
          "tools": [
                "curl",
                "Burp Suite"
          ],
          "steps": [
                "Call user profile endpoint.",
                "Inspect response body; verify fields like password_hash, salt, and stripe_token are completely absent."
          ],
          "commandExample": "curl -H \"Authorization: Bearer test_token\" https://api.target.com/api/users/me"
    },
    interviewChallenge: {
          "scenario": "Why does using JavaScript `delete user.password_hash` often fail to prevent data leakage in complex ORMs?",
          "question": "Can deleted properties be re-populated by virtual getters or serialization hooks?",
          "hint": "ORM entities (like Sequelize/Mongoose) often have internal getters, toJSON() methods, or private state that re-inject properties during JSON serialization.",
          "sampleAnswer": "In many ORMs, properties defined on the prototype or accessed via getters are not removed by `delete obj.prop`. When `JSON.stringify(obj)` is called, the entity's `toJSON()` method re-serializes the underlying database row, re-introducing the secret.",
          "keyTakeaway": "Use explicit outbound DTO schemas (Zod/Pydantic) to construct response objects from scratch."
    }
  },
  {
    ruleNumber: 99,
    id: "SEC-API-099",
    title: "JWT Claims Re-Validation on High-Privilege State Mutations",
    domain: "api",
    domainName: "API Security",
    subdomain: "Token Freshness",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-63B", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 req \u2208 HighPrivilegeActions, VerifyFreshSession(req.User) = True \u2227 (Now() - req.User.AuthTime \u2264 600s)",
    symbolBreakdown: [
          {
                "symbol": "HighPrivilegeActions",
                "meaning": "Operations like changing master passwords, transferring funds, or updating MFA settings"
          },
          {
                "symbol": "VerifyFreshSession",
                "meaning": "Validation that user actively authenticated within the last 10 minutes"
          },
          {
                "symbol": "AuthTime",
                "meaning": "The auth_time claim in the JWT or session store"
          }
    ],
    plainEnglish: "High-privilege actions (e.g. changing email, generating API keys, transferring money) must require re-authentication (Step-Up Auth) and verify that the authentication event occurred within the last 10 minutes (`auth_time <= 600s`).",
    whyItMatters: "If an attacker steals an active 24-hour access token, they can quietly navigate to `/api/account/email` and change the account email to their own, locking the real user out permanently.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Allows password change with stale 24-hour token\n@app.post('/api/user/change-password')\ndef change_password(req: ChangePasswordReq, user: User = Depends(get_current_user)):\n    # Does not verify when the user last logged in!\n    update_password(user.id, req.new_password)",
          "explanation": "An attacker with a stolen token can take over the account without knowing the current password."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Enforcing fresh authentication (auth_time <= 10m)\n@app.post('/api/user/change-password')\ndef change_password(req: ChangePasswordReq, token_data: TokenPayload = Depends(get_token)):\n    if time.time() - token_data.auth_time > 600:\n        raise HTTPException(status_code=403, detail='Step-up authentication required: re-enter password')\n    verify_current_password(token_data.user_id, req.current_password)\n    update_password(token_data.user_id, req.new_password)",
          "explanation": "Forces user to prove possession of current password or re-authenticate before critical state changes."
    },
    howToTest: {
          "tools": [
                "curl",
                "Postman"
          ],
          "steps": [
                "Wait 15 minutes after login.",
                "Attempt to call `/api/user/change-email`; verify API returns 403 demanding re-authentication."
          ],
          "commandExample": "curl -X POST -H \"Authorization: Bearer stale_token\" https://api.target.com/api/user/change-email"
    },
    interviewChallenge: {
          "scenario": "What is the difference between token expiration (`exp`) and authentication time (`auth_time`) in an OpenID Connect ID token?",
          "question": "Why can an access token be unexpired while its auth_time is stale?",
          "hint": "A token may have an `exp` valid for 8 hours, but `auth_time` records the exact second the user entered their password; high-risk actions check `auth_time`.",
          "sampleAnswer": "The `exp` claim specifies when the token itself ceases to be valid for general API calls. The `auth_time` claim specifies when the human user actually completed credentials verification. A token can be valid (`exp` is in the future) while the human login is stale (`auth_time` was 6 hours ago).",
          "keyTakeaway": "Inspect `auth_time` and demand step-up authentication on high-risk operations."
    }
  },
  {
    ruleNumber: 100,
    id: "SEC-API-100",
    title: "Bulk API Operation Transactional Atomicity and Batch Size Limit",
    domain: "api",
    domainName: "API Security",
    subdomain: "Resource Management",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["OWASP API4:2023", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 batch \u2208 BulkRequests, Count(batch.Items) \u2264 MaxBatchLimit(50) \u2227 ExecuteAtomicallyInTransaction(batch) = True",
    symbolBreakdown: [
          {
                "symbol": "BulkRequests",
                "meaning": "Endpoints accepting arrays of records: POST /api/v1/invoices/batch"
          },
          {
                "symbol": "MaxBatchLimit",
                "meaning": "Strict upper bound preventing batch array inflation (limit <= 50)"
          },
          {
                "symbol": "ExecuteAtomicallyInTransaction",
                "meaning": "All items commit together or rollback entirely on any failure"
          }
    ],
    plainEnglish: "Bulk and batch endpoints must enforce a strict upper bound on array items (e.g. `items.length <= 50`) and execute all items inside a single atomic database transaction. Partial commits and unbounded batch processing are prohibited.",
    whyItMatters: "Attackers send a batch request containing 100,000 items in a single HTTP POST, causing database lock contention, transaction log exhaustion, and multi-hour API timeouts.",
    vulnerableExample: {
          "language": "typescript",
          "code": "// VULNERABLE: Unbounded batch processing without transaction\napp.post('/api/records/batch', async (req, res) => {\n    // Client sends 50,000 items\n    for (const item of req.body.items) {\n        await Record.create(item); // Partial failures leave database inconsistent!\n    }\n    res.json({ success: true });\n});",
          "explanation": "Causes database connection starvation and leaves inconsistent partial state on errors."
    },
    secureExample: {
          "language": "typescript",
          "code": "// SECURE: Batch limit and atomic database transaction\nconst MAX_BATCH = 50;\n\napp.post('/api/records/batch', async (req, res) => {\n    if (!Array.isArray(req.body.items) || req.body.items.length > MAX_BATCH) {\n        return res.status(400).json({ error: `Batch size exceeds limit of ${MAX_BATCH}` });\n    }\n    await sequelize.transaction(async (t) => {\n        for (const item of req.body.items) {\n            await Record.create(item, { transaction: t });\n        }\n    });\n    res.json({ status: 'committed' });\n});",
          "explanation": "Enforces strict batch ceiling and rolls back all items if any single record fails validation."
    },
    howToTest: {
          "tools": [
                "k6",
                "curl"
          ],
          "steps": [
                "Send POST with 500 items in JSON array.",
                "Verify server rejects with 400 Bad Request.",
                "Send batch where item 49 has invalid syntax; confirm items 1-48 are rolled back."
          ],
          "commandExample": "curl -X POST -H \"Content-Type: application/json\" -d '{\"items\":[...]}' https://api.target.com/api/batch"
    },
    interviewChallenge: {
          "scenario": "What is the 'partial state inconsistency' problem in non-atomic bulk APIs, and how does it create business logic vulnerabilities?",
          "question": "What happens if an order batch fails midway?",
          "hint": "If items 1-5 create account credits but item 6 fails, the user receives partial money without completing the order.",
          "sampleAnswer": "In non-atomic bulk APIs, if processing fails halfway through an array, some database mutations commit while others abort. In financial or inventory systems, this creates state desynchronization (e.g. inventory decremented without payment recorded), leading to reconciliation errors or financial exploitation.",
          "keyTakeaway": "Wrap batch mutations in atomic database transactions and enforce small batch limits."
    }
  },
  {
    ruleNumber: 101,
    id: "SEC-API-101",
    title: "Distributed Tracing W3C Baggage Header Sanitization Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "Header Injection",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["W3C Trace Context", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 header \u2208 IncomingHeaders, (header.Name = \"baggage\") \u21d2 ValidateBaggageFormat(header) \u2227 StripDisallowedKeys(header)",
    symbolBreakdown: [
          {
                "symbol": "W3C Trace Context",
                "meaning": "Distributed tracing headers propagated across microservices (traceparent, baggage)"
          },
          {
                "symbol": "ValidateBaggageFormat",
                "meaning": "Strict regex validation of key-value pairs"
          },
          {
                "symbol": "StripDisallowedKeys",
                "meaning": "Removal of sensitive user claims or internal credentials"
          }
    ],
    plainEnglish: "APIs that propagate W3C distributed tracing headers (`traceparent`, `baggage`) must validate their format at the edge gateway and strip unapproved metadata keys. Sensitive tokens and PII must never be injected into tracing baggage.",
    whyItMatters: "Attackers inject malicious control characters, CRLF delimiters, or unauthorized internal claims into the `baggage` header. Downstream microservices blindly propagate the baggage, causing log injection or unauthorized security bypasses.",
    vulnerableExample: {
          "language": "go",
          "code": "// VULNERABLE: Blindly forwarding untrusted client baggage headers\nfunc ProxyHandler(w http.ResponseWriter, r *http.Request) {\n    // Forwards client-supplied baggage directly to internal services:\n    downstreamReq.Header.Set(\"baggage\", r.Header.Get(\"baggage\"))\n}",
          "explanation": "Client injects `baggage: role=admin,tenant=internal` which downstream services trust as authenticated context."
    },
    secureExample: {
          "language": "go",
          "code": "// SECURE: Parsing, whitelisting, and sanitizing trace context\nfunc CleanBaggageMiddleware(next http.Handler) http.Handler {\n    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n        cleanBaggage := sanitizeBaggage(r.Header.Get(\"baggage\"))\n        r.Header.Set(\"baggage\", cleanBaggage)\n        next.ServeHTTP(w, r)\n    })\n}",
          "explanation": "Strips all non-whitelisted keys from the baggage header before downstream propagation."
    },
    howToTest: {
          "tools": [
                "curl",
                "Jaeger / OpenTelemetry collector"
          ],
          "steps": [
                "Send request with malformed `baggage` header containing newlines or internal keys.",
                "Verify gateway strips or normalizes the header before passing downstream."
          ],
          "commandExample": "curl -H \"baggage: internal_role=admin\" https://api.target.com/api/orders"
    },
    interviewChallenge: {
          "scenario": "How does W3C Trace Context distinguish between `traceparent` and `baggage`?",
          "question": "Which one carries the trace ID, and which carries arbitrary application key-value pairs?",
          "hint": "`traceparent` contains the fixed 4-part trace/span ID; `baggage` carries arbitrary key-value pairs that travel across microservice hops.",
          "sampleAnswer": "`traceparent` is a strictly formatted 4-part string (`00-traceid-spanid-flags`) used by distributed tracing systems to stitch spans together. `baggage` is a comma-separated key-value store intended for contextual telemetry. Because baggage is open-ended, it is vulnerable to injection if exposed to untrusted external callers.",
          "keyTakeaway": "Sanitize and filter W3C baggage at the perimeter API gateway."
    }
  },
  {
    ruleNumber: 102,
    id: "SEC-API-102",
    title: "GraphQL Batch Request (Array Query) Throttling Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "GraphQL DoS",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["OWASP GraphQL", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 req \u2208 GraphQLRequests, IsArray(req.Body) \u21d2 Length(req.Body) \u2264 MaxBatchArraySize(5) \u2227 ApplyCumulativeCost(req.Body)",
    symbolBreakdown: [
          {
                "symbol": "GraphQLRequests",
                "meaning": "POST requests to /graphql"
          },
          {
                "symbol": "IsArray(req.Body)",
                "meaning": "JSON array containing multiple queries: [ {query: ...}, {query: ...} ]"
          },
          {
                "symbol": "MaxBatchArraySize",
                "meaning": "Hard cap on query array length (<= 5)"
          }
    ],
    plainEnglish: "GraphQL servers that support batch requests (sending an array of queries in one HTTP POST) must enforce a strict upper bound on array length (e.g. <= 5) and calculate cumulative cost across all queries in the batch.",
    whyItMatters: "An attacker bypasses HTTP rate limiting by sending a single HTTP request containing an array of 5,000 GraphQL queries. The reverse proxy counts it as 1 HTTP request, while the backend database executes 5,000 complex queries.",
    vulnerableExample: {
          "language": "javascript/apollo",
          "code": "// VULNERABLE: Unbounded batch query execution\n// Client sends: [ {query: '{users{id}}'}, {query: '{users{id}}'}, ... 5000 times ]\n// Server executes all 5000 queries sequentially or concurrently!",
          "explanation": "Bypasses perimeter HTTP request rate limiters and overwhelms backend database connection pools."
    },
    secureExample: {
          "language": "javascript/apollo",
          "code": "// SECURE: Enforcing batch array limit at middleware\napp.use('/graphql', (req, res, next) => {\n    if (Array.isArray(req.body)) {\n        if (req.body.length > 5) {\n            return res.status(400).json({ error: 'Batch query exceeds maximum limit of 5' });\n        }\n    }\n    next();\n});",
          "explanation": "Rejects batch requests exceeding the configured safety ceiling."
    },
    howToTest: {
          "tools": [
                "curl",
                "GraphQL batch tester"
          ],
          "steps": [
                "Send JSON payload containing array of 50 queries.",
                "Verify server returns 400 Bad Request with batch limit error."
          ],
          "commandExample": "curl -X POST -H \"Content-Type: application/json\" -d '[{\"query\":\"{__typename}\"},{\"query\":\"{__typename}\"}]' https://api.target.com/graphql"
    },
    interviewChallenge: {
          "scenario": "Why do HTTP-level rate limiters fail to detect GraphQL batch array attacks?",
          "question": "How does the gateway see a batch request?",
          "hint": "The gateway sees 1 single HTTP POST request, but the GraphQL execution engine unpacks and executes dozens or hundreds of independent operations.",
          "sampleAnswer": "HTTP-level rate limiters operate on HTTP request counters. To an API gateway, a batch request is just a single HTTP POST request. Inside the engine, however, the array unpacks into hundreds of operations. Without middleware inspecting array lengths and cumulative AST costs, the rate limiter is blinded.",
          "keyTakeaway": "Enforce batch array limits in middleware or disable batch queries entirely in public APIs."
    }
  },
  {
    ruleNumber: 103,
    id: "SEC-API-103",
    title: "API ETag Concurrency Precondition (If-Match) Enforcement",
    domain: "api",
    domainName: "API Security",
    subdomain: "Lost Update Problem",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["RFC 9110 \u00a713.1.1", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 req \u2208 ResourceUpdateRequests, HasHeader(req, \"If-Match\") \u2227 ETagMatchesCurrentVersion(req.Header[\"If-Match\"]) = True \u2228 REJECT(412)",
    symbolBreakdown: [
          {
                "symbol": "ResourceUpdateRequests",
                "meaning": "PUT and PATCH requests updating concurrent shared resources"
          },
          {
                "symbol": "If-Match",
                "meaning": "Client-supplied ETag representing the version of the resource the client read"
          },
          {
                "symbol": "REJECT(412)",
                "meaning": "412 Precondition Failed returned on version conflict"
          }
    ],
    plainEnglish: "When clients update shared resources via PUT or PATCH, the API must require an `If-Match` header containing the resource's current ETag. If the resource was updated concurrently by another user, the server must reject with 412 Precondition Failed.",
    whyItMatters: "Without `If-Match` optimistic concurrency control, two administrators editing a customer account simultaneously will overwrite each other's changes (the Lost Update Problem), corrupting critical data.",
    vulnerableExample: {
          "language": "python/fastapi",
          "code": "# VULNERABLE: Blind update overwriting concurrent edits\n@app.put('/api/settings')\ndef update_settings(new_settings: Settings):\n    # Overwrites whatever is in the database regardless of concurrent edits!\n    db.save(new_settings)\n    return {\"status\": \"updated\"}",
          "explanation": "Last-write-wins strategy silently obliterates edits made by concurrent users."
    },
    secureExample: {
          "language": "python/fastapi",
          "code": "# SECURE: RFC 9110 optimistic locking with If-Match ETag\n@app.put('/api/settings')\ndef update_settings(new_settings: Settings, if_match: str = Header(None)):\n    current = db.get_settings()\n    current_etag = generate_etag(current)\n    if not if_match or if_match != current_etag:\n        raise HTTPException(status_code=412, detail=\"Precondition Failed: Resource was modified concurrently\")\n    db.save(new_settings)\n    return Response(headers={\"ETag\": generate_etag(new_settings)})",
          "explanation": "Guarantees updates only succeed if the client holds the latest version of the resource."
    },
    howToTest: {
          "tools": [
                "curl",
                "Postman"
          ],
          "steps": [
                "Fetch resource and note ETag.",
                "Perform PUT with stale ETag; verify server returns 412 Precondition Failed.",
                "Perform PUT with matching ETag; verify 200 OK."
          ],
          "commandExample": "curl -X PUT -H \"If-Match: \\\"stale_etag\\\"\" -d '{\"status\":\"active\"}' https://api.target.com/settings"
    },
    interviewChallenge: {
          "scenario": "What is the difference between a 'Strong ETag' and a 'Weak ETag' (`W/\"...\"`) in HTTP caching and concurrency?",
          "question": "Can weak ETags be used for byte-for-byte concurrency validation in `If-Match`?",
          "hint": "A strong ETag guarantees byte-for-byte identity of the representation; a weak ETag only guarantees semantic equivalence and is disallowed in standard `If-Match` byte-level updates.",
          "sampleAnswer": "A strong ETag changes whenever any byte of the response changes. A weak ETag is prefixed with `W/` and indicates semantic equivalence (e.g. same data, different whitespace or compression). RFC 9110 mandates that `If-Match` requires strong comparison; weak ETags cannot be used for strict range or write concurrency checks.",
          "keyTakeaway": "Emit strong ETags for mutation endpoints and require `If-Match` on all PUT/PATCH calls."
    }
  },
  {
    ruleNumber: 104,
    id: "SEC-API-104",
    title: "HTTP OPTIONS Method Safe Reflection Without State Mutation",
    domain: "api",
    domainName: "API Security",
    subdomain: "CORS Preflight",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["RFC 9110 \u00a79.3.7", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 req \u2208 Requests_{OPTIONS}, IsSafeMethod(req) = True \u2227 MutatesDatabase(req) = False \u2227 HasHeader(resp, \"Allow\")",
    symbolBreakdown: [
          {
                "symbol": "Requests_{OPTIONS}",
                "meaning": "HTTP OPTIONS requests probing server capabilities and CORS permissions"
          },
          {
                "symbol": "IsSafeMethod",
                "meaning": "RFC 9110 requirement that method is read-only and safe"
          },
          {
                "symbol": "MutatesDatabase = False",
                "meaning": "Zero state modification or side effects"
          }
    ],
    plainEnglish: "HTTP OPTIONS requests must be completely safe and idempotent. OPTIONS handlers must only return capability metadata and CORS headers; they must never trigger database mutations, dispatch webhooks, or increment counters.",
    whyItMatters: "A developer binds an action controller to all HTTP verbs (`app.all('/api/deleteAccount')`). When a browser dispatches an automatic preflight `OPTIONS` request before sending a DELETE, the server executes the account deletion prematurely during the preflight.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Route handler executes on ALL methods including OPTIONS\napp.all('/api/orders/:id/cancel', (req, res) => {\n    // Prematurely cancels order when browser sends CORS preflight OPTIONS request!\n    cancelOrder(req.params.id);\n    res.json({ status: 'canceled' });\n});",
          "explanation": "CORS preflight request triggers order cancellation before user even submits confirmation."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Explicit method routing with safe OPTIONS handling\napp.options('/api/orders/:id/cancel', cors()); // Only handles CORS preflight headers\napp.post('/api/orders/:id/cancel', cors(), authenticate, async (req, res) => {\n    await cancelOrder(req.params.id);\n    res.json({ status: 'canceled' });\n});",
          "explanation": "Separates preflight capability negotiation from actual transactional mutation logic."
    },
    howToTest: {
          "tools": [
                "curl",
                "browser preflight test"
          ],
          "steps": [
                "Send HTTP OPTIONS request to mutation endpoint.",
                "Verify response contains `Allow` header and zero database records are modified."
          ],
          "commandExample": "curl -X OPTIONS -sI https://api.target.com/api/orders/1/cancel"
    },
    interviewChallenge: {
          "scenario": "Why does the browser automatically send an HTTP OPTIONS request before certain cross-origin fetch calls?",
          "question": "What characteristics make a request 'preflighted'?",
          "hint": "If a cross-origin request uses non-standard methods (PUT, DELETE) or custom headers (`Authorization`), the browser must check permissions with an OPTIONS request first.",
          "sampleAnswer": "The browser must verify that the target server understands and permits the method and custom headers before sending potentially dangerous requests. This preflight prevents legacy servers from being subjected to cross-origin state changes they cannot defend against.",
          "keyTakeaway": "Ensure OPTIONS routes are handled by dedicated CORS middleware and never touch business logic."
    }
  },
  {
    ruleNumber: 105,
    id: "SEC-API-105",
    title: "API Key Extraction Isolation (Headers-Only, Never Query Strings)",
    domain: "api",
    domainName: "API Security",
    subdomain: "Credential Leakage",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["OWASP ASVS \u00a73.1", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 req \u2208 APIRequests, KeyLocation(req.APIKey) \u2208 Headers \u2227 KeyLocation(req.APIKey) \u2209 QueryParameters \u2227 KeyLocation(req.APIKey) \u2209 URLPath",
    symbolBreakdown: [
          {
                "symbol": "APIRequests",
                "meaning": "Authenticated client API calls"
          },
          {
                "symbol": "KeyLocation \u2208 Headers",
                "meaning": "Keys extracted strictly from Authorization or X-API-Key headers"
          },
          {
                "symbol": "\u2209 QueryParameters",
                "meaning": "Prohibition of credentials in GET query strings like ?api_key=secret"
          }
    ],
    plainEnglish: "API keys and bearer tokens must only be accepted via HTTP request headers (`Authorization: Bearer ...` or `X-API-Key`). Servers must reject authentication credentials passed in URL query parameters or paths.",
    whyItMatters: "URLs are logged by reverse proxies, cloud load balancers, CDN access logs, browser history, and proxy monitoring tools. Passing `?api_key=secret` leaks customer API keys into hundreds of plaintext log files across the Internet.",
    vulnerableExample: {
          "language": "python/fastapi",
          "code": "# VULNERABLE: Extracting API key from query parameter\n@app.get('/api/data')\ndef get_data(api_key: str = Query(...)):\n    # Key appears in proxy access logs, browser history, and Referer headers!\n    validate_key(api_key)\n    return fetch_data()",
          "explanation": "Exposes API secrets in plaintext server access logs and telemetry dashboards."
    },
    secureExample: {
          "language": "python/fastapi",
          "code": "# SECURE: Extracting API key strictly from secure headers\n@app.get('/api/data')\ndef get_data(api_key: str = Header(..., alias=\"X-API-Key\")):\n    # Headers are not recorded in standard web access logs\n    validate_key(api_key)\n    return fetch_data()",
          "explanation": "Ensures API credentials travel inside HTTP headers which are omitted from standard access logs."
    },
    howToTest: {
          "tools": [
                "curl",
                "access.log inspection"
          ],
          "steps": [
                "Call endpoint with query param: `GET /api/data?key=12345`.",
                "Verify API rejects request with 401 demanding header authentication."
          ],
          "commandExample": "curl -H \"X-API-Key: valid_key\" https://api.target.com/api/data"
    },
    interviewChallenge: {
          "scenario": "Why is the `Referer` header particularly dangerous when API keys are passed in URL query parameters?",
          "question": "Where does the browser send the Referer header?",
          "hint": "When a user clicks an external link on a page containing query credentials, the full URL with the secret key is transmitted to the external third-party server in the Referer header.",
          "sampleAnswer": "Whenever a browser navigates away from a page or loads an external asset (image, font, script), it transmits the current page's full URL in the HTTP `Referer` header. If the URL contains `?api_key=secret`, the secret is leaked directly to external third-party server logs.",
          "keyTakeaway": "Always transmit credentials via headers; never query parameters."
    }
  },
  {
    ruleNumber: 106,
    id: "SEC-API-106",
    title: "Automated OpenAPI Schema Divergence Detection Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "API Governance",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["OWASP API9:2023", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 endpoint \u2208 DeployedAPI, ContractMatchesSpec(endpoint, GitOpenAPISpec) = True \u2227 UndocumentedParams(endpoint) = \u2205",
    symbolBreakdown: [
          {
                "symbol": "DeployedAPI",
                "meaning": "Live running backend application routes"
          },
          {
                "symbol": "ContractMatchesSpec",
                "meaning": "Automated contract test validating schema parity"
          },
          {
                "symbol": "UndocumentedParams = \u2205",
                "meaning": "Zero unapproved parameters allowed"
          }
    ],
    plainEnglish: "Continuous integration (CI) pipelines must execute contract testing (e.g. Prism or Dredd) to verify that deployed API routes strictly conform to published OpenAPI specifications. Undocumented parameters and schema divergence must fail the build.",
    whyItMatters: "Developers add debug flags (`?debug=true` or `?skip_auth=1`) during testing and accidentally merge them to production without documenting them in the OpenAPI spec, creating critical security backdoors.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: CI pipeline builds and deploys without contract validation\nsteps:\n  - run: npm run build\n  - run: docker push registry/api:latest # No schema parity check!",
          "explanation": "Deploys shadow parameters and diverging endpoints without verification."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Automated contract validation step in GitHub Actions\nsteps:\n  - run: npm run test:contract # Runs Prism / Dredd against live mock\n  - run: npx openapi-diff openapi-prev.yaml openapi-new.yaml --fail-on-breaking\n  - run: docker push registry/api:latest",
          "explanation": "Blocks deployment if backend code diverges from approved OpenAPI contract specifications."
    },
    howToTest: {
          "tools": [
                "prism",
                "dredd",
                "openapi-diff"
          ],
          "steps": [
                "Add undocumented query parameter to route in code.",
                "Run contract test suite; confirm build fails with schema mismatch error."
          ],
          "commandExample": "npx @stoplight/spectral-cli lint openapi.yaml"
    },
    interviewChallenge: {
          "scenario": "How does contract testing using OpenAPI diff tools prevent breaking changes and unauthorized endpoint drift in microservice teams?",
          "question": "What does openapi-diff detect?",
          "hint": "It detects when a team removes fields, changes types, or adds unapproved endpoints, blocking pipeline deployment before production breakages occur.",
          "sampleAnswer": "Contract testing validates that the API implementation matches the machine-readable specification. In distributed organizations, `openapi-diff` prevents breaking changes (e.g., removing a required field) and detects unauthorized changes (e.g., developers adding undocumented endpoints), enforcing security governance automatically.",
          "keyTakeaway": "Integrate OpenAPI linting and diff tools directly into PR validation pipelines."
    }
  },
  {
    ruleNumber: 107,
    id: "SEC-API-107",
    title: "GraphQL Field-Level Authorization Directive Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "GraphQL Authz",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["OWASP API1:2023", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 field \u2208 GraphQLSchemaFields, HasAuthDirective(field) \u2227 VerifyFieldPermission(Caller, field) = True",
    symbolBreakdown: [
          {
                "symbol": "GraphQLSchemaFields",
                "meaning": "Every field defined in the GraphQL schema types"
          },
          {
                "symbol": "HasAuthDirective",
                "meaning": "Schema directive like @auth(requires: ADMIN)"
          },
          {
                "symbol": "VerifyFieldPermission",
                "meaning": "Field resolver enforces permission before evaluating data"
          }
    ],
    plainEnglish: "GraphQL schemas must enforce authorization at the individual field level using schema directives or resolver middleware. Authorizing queries only at the root query level is prohibited.",
    whyItMatters: "A developer checks admin role on `Query.user`, but inside the `User` type, the `ssn` and `salary` fields have no field-level authorization. Any query that reaches `User` (e.g. via `Post.author`) leaks the confidential fields.",
    vulnerableExample: {
          "language": "graphql",
          "code": "# VULNERABLE: Root query checked, but sensitive fields on type are unshielded\ntype User {\n    id: ID!\n    name: String!\n    ssn: String! # VULNERABLE: No field-level authorization!\n    salary: Int! # Anyone who can query a User can read these fields\n}",
          "explanation": "Leaks sensitive fields whenever the User type is queried through other public relationships."
    },
    secureExample: {
          "language": "graphql",
          "code": "# SECURE: Field-level schema directive authorization\ntype User {\n    id: ID!\n    name: String!\n    ssn: String! @auth(requires: \"HR_ADMIN\")\n    salary: Int! @auth(requires: \"HR_ADMIN\")\n}",
          "explanation": "Resolver engine checks caller permissions before returning the field; returns null/error if unauthorized."
    },
    howToTest: {
          "tools": [
                "graphql-shield",
                "InQL",
                "curl"
          ],
          "steps": [
                "Query sensitive field as non-admin: `{ user(id:1) { ssn } }`.",
                "Verify field returns null with an authorization error in the errors array."
          ],
          "commandExample": "curl -X POST -H \"Authorization: Bearer viewer\" -d '{\"query\":\"{user(id:1){ssn}}\"}' https://api.target.com/graphql"
    },
    interviewChallenge: {
          "scenario": "Why does root-level query authorization fail to protect GraphQL applications with deeply interconnected graph relationships?",
          "question": "What happens when an entity is reachable through multiple graph paths?",
          "hint": "An entity can be reached through multiple root queries (e.g. `user(id)`, `posts -> author`, `comments -> author`). Root checks on `user` are bypassed by querying through `posts`.",
          "sampleAnswer": "In GraphQL, any entity in the schema can typically be reached through multiple paths in the graph. Authorizing only the top-level query leaves the same entity unprotected when traversed through relational edges (e.g. `team -> members -> user`). Authorization must be bound to the field resolver itself.",
          "keyTakeaway": "Enforce field-level authorization using libraries like GraphQL Shield or schema directives."
    }
  },
  {
    ruleNumber: 108,
    id: "SEC-API-108",
    title: "Public Storage Presigned URL Expiration Ceiling (\u2264 900s)",
    domain: "api",
    domainName: "API Security",
    subdomain: "Storage Access",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["AWS S3 Best Practices", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 url \u2208 PresignedStorageURLs, (url.Expires - url.Created) \u2264 900s \u2227 HasRestrictedHTTPVerb(url)",
    symbolBreakdown: [
          {
                "symbol": "PresignedStorageURLs",
                "meaning": "Temporary cryptographic upload/download URLs for S3, GCS, or Azure Blob"
          },
          {
                "symbol": "(Expires - Created) <= 900s",
                "meaning": "Maximum 15-minute lifetime"
          },
          {
                "symbol": "HasRestrictedHTTPVerb",
                "meaning": "Strictly bound to GET or PUT, never wildcard"
          }
    ],
    plainEnglish: "Presigned storage URLs (AWS S3, Google Cloud Storage) generated by APIs for direct client uploads or downloads must enforce an expiration ceiling of at most 900 seconds (15 minutes). Long-lived presigned URLs are prohibited.",
    whyItMatters: "Generating presigned URLs with 7-day expiration allows anyone who intercepts the URL in logs, chat messages, or proxy caches to download confidential customer files long after the user's session has terminated.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Generating 7-day presigned S3 URL\ns3_client.generate_presigned_url(\n    'get_object',\n    Params={'Bucket': 'confidential-docs', 'Key': file_key},\n    ExpiresIn=604800 # VULNERABLE: Valid for 7 full days!\n)",
          "explanation": "URL remains active for a week, exposing file to anyone who discovers the link."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Short-lived presigned URL capped at 15 minutes (900s)\ns3_client.generate_presigned_url(\n    'get_object',\n    Params={'Bucket': 'confidential-docs', 'Key': file_key},\n    ExpiresIn=900 # SECURE: Expires in 15 minutes\n)",
          "explanation": "Restricts access window to the immediate download operation."
    },
    howToTest: {
          "tools": [
                "aws-cli",
                "curl"
          ],
          "steps": [
                "Generate presigned URL.",
                "Inspect `X-Amz-Expires` query parameter; verify value is <= 900."
          ],
          "commandExample": "aws s3 presign s3://mybucket/file.txt --expires-in 900"
    },
    interviewChallenge: {
          "scenario": "Why cannot standard IAM revocation policies easily cancel an already-issued presigned S3 URL before its expiration time?",
          "question": "What is required to revoke an active presigned URL immediately?",
          "hint": "Presigned URLs are evaluated based on the IAM credentials that generated them; revoking them immediately requires rotating or deleting the underlying IAM user/role credentials.",
          "sampleAnswer": "A presigned URL is signed with an IAM credential. As long as the signature is valid and the credential exists, S3 honors the URL until expiration. Revoking an individual presigned URL immediately requires attaching an explicit Deny policy to the IAM role or rotating the role's temporary session keys.",
          "keyTakeaway": "Always issue presigned URLs with short lifetimes (under 15 minutes)."
    }
  },
  {
    ruleNumber: 109,
    id: "SEC-API-109",
    title: "JSON Web Encryption (JWE) for Sensitive PII Query Results",
    domain: "api",
    domainName: "API Security",
    subdomain: "End-to-End Encryption",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["RFC 7516", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 res \u2208 HighlyConfidentialData, ResponseFormat(res) = JWE(CompactSerialization, ECDH_ES_A256KW \u2227 A256GCM)",
    symbolBreakdown: [
          {
                "symbol": "HighlyConfidentialData",
                "meaning": "Tax returns, bank account numbers, or national identification records"
          },
          {
                "symbol": "JWE",
                "meaning": "RFC 7516 JSON Web Encryption format providing confidentiality and integrity"
          },
          {
                "symbol": "ECDH_ES_A256KW",
                "meaning": "Key agreement with client public key"
          }
    ],
    plainEnglish: "High-security financial and healthcare APIs must encrypt sensitive payloads end-to-end using JSON Web Encryption (JWE) per RFC 7516. Transport-layer TLS is necessary but insufficient when data traverses multiple untrusted proxies.",
    whyItMatters: "In zero-trust and banking ecosystems, API requests traverse edge gateways, service meshes, and observability proxies that terminate TLS. Without application-layer encryption (JWE), intermediate microservices and logging tools can read raw PII in memory.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Returning raw plaintext tax ID over TLS\n@app.get('/api/tax-id')\ndef get_tax_id(user: User = Depends(auth)):\n    return {\"ssn\": user.raw_ssn} # Plaintext readable by API gateway and logs!",
          "explanation": "Exposes raw SSN to intermediate load balancers and logging proxies."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Encrypting response payload with client's public key via JWE\nfrom jwcrypto import jwe, jwk\n\n@app.get('/api/tax-id')\ndef get_tax_id(user: User = Depends(auth)):\n    payload = json.dumps({\"ssn\": user.raw_ssn})\n    jwe_token = jwe.JWE(payload.encode('utf-8'),\n                        recipient=client_public_jwk,\n                        protected={'alg': 'ECDH-ES+A256KW', 'enc': 'A256GCM'})\n    return Response(jwe_token.serialize(), media_type='application/jose')",
          "explanation": "Payload is ciphertext; only decodable by the client holding the private decryption key."
    },
    howToTest: {
          "tools": [
                "jwt.io",
                "jose CLI",
                "curl"
          ],
          "steps": [
                "Send request to encrypted data endpoint.",
                "Verify response payload is 5-part compact JWE string starting with `eyJhbGciOiJ...`."
          ],
          "commandExample": "curl -H \"Authorization: Bearer client_token\" https://api.target.com/api/ssn"
    },
    interviewChallenge: {
          "scenario": "What is the structural difference between a standard JWS (JSON Web Signature) and a JWE (JSON Web Encryption)?",
          "question": "How many segments do JWS and JWE have?",
          "hint": "JWS has 3 segments (`header.payload.signature`) and is plaintext base64; JWE has 5 segments (`header.encrypted_key.iv.ciphertext.tag`) and provides confidentiality.",
          "sampleAnswer": "A JWS (3 parts) only provides integrity and authentication; its payload is merely base64URL-encoded and can be read by anyone. A JWE (5 parts) provides true confidentiality: the payload is encrypted with an AEAD cipher (e.g. A256GCM), ensuring intermediate proxies cannot read the data.",
          "keyTakeaway": "Use JWE when payloads require confidentiality across untrusted proxy hops."
    }
  },
  {
    ruleNumber: 110,
    id: "SEC-API-110",
    title: "API Gateway Downstream Circuit Breaker Fault Isolation Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "Cascading Failures",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-160", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 downstream \u2208 Microservices, ErrorRate(downstream, 10s) > 50% \u21d2 CircuitState(downstream) = OPEN \u2227 FailFast(503)",
    symbolBreakdown: [
          {
                "symbol": "Microservices",
                "meaning": "Downstream internal services called by the gateway"
          },
          {
                "symbol": "ErrorRate > 50%",
                "meaning": "Consecutive 5xx errors or timeouts exceeding threshold"
          },
          {
                "symbol": "CircuitState = OPEN",
                "meaning": "Gateway trips breaker, immediately returning 503 without forwarding traffic to ailing service"
          }
    ],
    plainEnglish: "The API Gateway must implement Circuit Breaker patterns for all downstream microservices. If a downstream service's error rate exceeds 50% or latency spikes over thresholds, the gateway must trip the breaker and fail fast with 503 Service Unavailable.",
    whyItMatters: "When one backend database or microservice slows down, incoming requests queue up across all API gateways. Threads and sockets are exhausted, causing cascading failures that take down the entire global API fleet.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Indefinite blocking without circuit breaker\napp.get('/api/recommendations', async (req, res) => {\n    // If recommendations-service hangs, this request hangs forever,\n    // exhausting Node.js memory and worker pool!\n    const data = await fetch('http://recommendations-service/get');\n    res.json(data);\n});",
          "explanation": "Causes thread pool exhaustion across all gateway instances during downstream outages."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Circuit breaker with Opossum / Resilience4j\nimport CircuitBreaker from 'opossum';\n\nconst breaker = new CircuitBreaker(fetchRecommendations, {\n    timeout: 3000, // 3 seconds timeout\n    errorThresholdPercentage: 50, // Trip if > 50% fail\n    resetTimeout: 30000 // Test again after 30s\n});\nbreaker.fallback(() => ({ recommendations: [] })); // Safe graceful fallback\n\napp.get('/api/recommendations', async (req, res) => {\n    const data = await breaker.fire();\n    res.json(data);\n});",
          "explanation": "Fails fast, protects gateway worker threads, and provides graceful fallback responses."
    },
    howToTest: {
          "tools": [
                "k6 chaos test",
                "Toxiproxy"
          ],
          "steps": [
                "Inject 10-second latency into downstream mock service.",
                "Verify gateway trips circuit breaker within 10 seconds and returns 503/fallback in <5ms."
          ],
          "commandExample": "k6 run --vus 50 --duration 30s chaos_test.js"
    },
    interviewChallenge: {
          "scenario": "What are the three operational states of a standard Circuit Breaker, and what does the `HALF-OPEN` state do?",
          "question": "What triggers the transition from OPEN to HALF-OPEN?",
          "hint": "The states are `CLOSED` (normal operation), `OPEN` (tripped, failing fast), and `HALF-OPEN` (tentatively allowing a trial request through to see if the downstream service has recovered).",
          "sampleAnswer": "In the `CLOSED` state, traffic flows normally. When failures cross the threshold, it transitions to `OPEN`, immediately rejecting calls to allow the downstream service to heal. After a cooldown duration (`resetTimeout`), it enters `HALF-OPEN`: a limited canary request is sent. If it succeeds, it resets to `CLOSED`; if it fails, it returns to `OPEN`.",
          "keyTakeaway": "Configure circuit breakers on all inter-service HTTP and gRPC network boundaries."
    }
  },
  {
    ruleNumber: 111,
    id: "SEC-API-111",
    title: "Client IP Geo-Velocity Anomaly Detection Invariant",
    domain: "api",
    domainName: "API Security",
    subdomain: "Credential Stuffing",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["OWASP Automated Threats", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 login \u2208 AuthAttempts, Distance(login.IP, LastLogin.IP) / TimeDelta(login, LastLogin) \u2264 MaxPossibleSpeed(1000 km/h)",
    symbolBreakdown: [
          {
                "symbol": "AuthAttempts",
                "meaning": "User login or token generation requests"
          },
          {
                "symbol": "Distance / TimeDelta",
                "meaning": "Calculated geographic speed between consecutive logins"
          },
          {
                "symbol": "MaxPossibleSpeed <= 1000 km/h",
                "meaning": "Speed of commercial airline travel"
          }
    ],
    plainEnglish: "Authentication APIs must calculate the physical geographic velocity between consecutive user logins. If a user logs in from New York and 15 minutes later logs in from London, the request exceeds physical human travel speed (Impossible Travel) and must trigger immediate MFA challenge.",
    whyItMatters: "Attackers buy leaked credentials from data breaches and test them against customer accounts via automated botnets scattered across foreign proxies. Without geo-velocity checks, compromised accounts are accessed invisibly.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Blind login without location velocity analysis\n@app.post('/api/login')\ndef login(credentials: LoginDto):\n    user = verify_credentials(credentials)\n    # Ignores that user logged in from Tokyo 5 minutes ago and is now in Paris!\n    return issue_token(user)",
          "explanation": "Allows attackers on commercial VPNs or botnets to use stolen credentials without challenge."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Impossible travel geo-velocity verification\ndef verify_geo_velocity(user_id, current_ip):\n    last_login = db.get_last_login(user_id)\n    if last_login:\n        current_loc = geoip.lookup(current_ip)\n        distance_km = haversine(last_login.lat, last_login.lon, current_loc.lat, current_loc.lon)\n        hours_elapsed = (time.time() - last_login.timestamp) / 3600.0\n        if hours_elapsed > 0 and (distance_km / hours_elapsed) > 1000.0:\n            # Impossible travel speed (>1000 km/h)!\n            trigger_mfa_challenge(user_id)\n            record_security_alert(user_id, 'Impossible Travel Detected')",
          "explanation": "Detects simultaneous logins across distant locations and mandates step-up MFA verification."
    },
    howToTest: {
          "tools": [
                "curl with X-Forwarded-For headers",
                "MaxMind GeoIP testbench"
          ],
          "steps": [
                "Simulate login from US IP, then send second request from UK IP 30 seconds later.",
                "Verify second request triggers mandatory MFA challenge or 403 step-up response."
          ],
          "commandExample": "node -e 'console.log(\"Testing geo-velocity impossible travel calculation\")'"
    },
    interviewChallenge: {
          "scenario": "Why must security systems trigger an MFA challenge rather than an immediate account ban when 'Impossible Travel' is detected?",
          "question": "What legitimate user software causes sudden geographic IP changes?",
          "hint": "Corporate VPNs and privacy relays (like Apple iCloud Private Relay) route user traffic through different countries instantaneously, causing benign velocity anomalies.",
          "sampleAnswer": "Legitimate users frequently switch on enterprise VPNs, route through Tor, or use Apple iCloud Private Relay, causing their apparent IP location to jump across continents in seconds. Hard-locking the account causes immense user frustration. Triggering a step-up MFA challenge protects the account while allowing legitimate users to proceed.",
          "keyTakeaway": "Trigger step-up MFA challenges rather than hard bans on impossible travel anomalies."
    }
  },
  {
    ruleNumber: 112,
    id: "SEC-API-112",
    title: "Strict API Subdomain Isolation (Separation from Web Origin)",
    domain: "api",
    domainName: "API Security",
    subdomain: "Origin Isolation",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["OWASP ASVS \u00a714.3", "OWASP API Security Top 10", "CWE-862"],
    formalInvariant: "\u2200 api \u2208 ProductionAPIs, Hostname(api) \u2209 WebAppHostnames \u2227 Domain(api) = \"api.\" + RootDomain",
    symbolBreakdown: [
          {
                "symbol": "ProductionAPIs",
                "meaning": "Backend REST and GraphQL service endpoints"
          },
          {
                "symbol": "WebAppHostnames",
                "meaning": "Web application domains serving interactive HTML documents (app.example.com)"
          },
          {
                "symbol": "api.example.com",
                "meaning": "Isolated dedicated subdomain without HTML rendering"
          }
    ],
    plainEnglish: "APIs must be hosted on an isolated dedicated subdomain (e.g. `api.example.com`) strictly separated from the domain serving HTML web applications (`app.example.com`). APIs must never share cookies, localStorage, or origins with user-generated content.",
    whyItMatters: "Hosting APIs on the same origin as a web app allows an XSS flaw in any HTML view to read all API cookies, bypass CORS restrictions, and execute arbitrary API commands with ambient user privileges.",
    vulnerableExample: {
          "language": "nginx",
          "code": "# VULNERABLE: API co-located on same origin as HTML web app\nserver {\n    server_name example.com;\n    location / { root /var/www/html; } # Serves user-generated pages\n    location /api/ { proxy_pass http://backend; } # Shares cookies and origin!\n}",
          "explanation": "An XSS flaw in any HTML page gains full access to all API endpoints with zero CORS protection."
    },
    secureExample: {
          "language": "nginx",
          "code": "# SECURE: Isolated API subdomain with distinct origin boundaries\nserver {\n    server_name api.example.com;\n    # Only returns JSON; never serves HTML documents\n    location / {\n        add_header X-Content-Type-Options \"nosniff\";\n        proxy_pass http://backend;\n    }\n}",
          "explanation": "Establishes independent origin boundary; client apps must access API via explicit CORS authorization."
    },
    howToTest: {
          "tools": [
                "curl",
                "browser origin inspector"
          ],
          "steps": [
                "Inspect API domain architecture.",
                "Verify API traffic routes to `api.example.com` and emits `Content-Type: application/json` exclusively."
          ],
          "commandExample": "curl -sI https://api.target.com/ | grep -i content-type"
    },
    interviewChallenge: {
          "scenario": "How does isolating the API on `api.example.com` help prevent cookie scoping vulnerabilities compared to hosting on the apex domain `example.com`?",
          "question": "Where do cookies set on an apex domain flow?",
          "hint": "Cookies set on an apex domain (`example.com`) are automatically transmitted to all subdomains, exposing them to compromised subdomains.",
          "sampleAnswer": "When a session cookie is set on the apex domain (`example.com`), browsers automatically transmit it to every subdomain (`marketing.example.com`, `blog.example.com`). If a vulnerability exists on an unmaintained WordPress blog, attackers can steal the apex cookie. Subdomain isolation with `__Host-` prefixes locks cookies strictly to that single hostname.",
          "keyTakeaway": "Host APIs on dedicated subdomains (`api.domain.com`) and avoid apex domain cookie scoping."
    }
  }
];
