import { SecurityInvariant } from '../../types/invariants';

export const oauthRules: SecurityInvariant[] = [
  {
    ruleNumber: 187,
    id: "SEC-OAUTH-001",
    title: "PKCE Code Challenge S256 Mandatory Invariant",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Authorization Code Grant & PKCE",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 7636", "RFC 9700 \u00a72.1.1", "OAuth 2.1 Draft \u00a74.1"],
    formalInvariant: "\u2200 req \u2208 AuthCodeExchanges, (req.CodeChallengeMethod = \"S256\") \u2227 (SHA256(req.CodeVerifier) = req.CodeChallenge)",
    symbolBreakdown: [
          {
                "symbol": "AuthCodeExchanges",
                "meaning": "Token endpoint requests exchanging authorization code for access token"
          },
          {
                "symbol": "CodeChallengeMethod = \"S256\"",
                "meaning": "Code challenge method must be S256 (SHA-256); \"plain\" is strictly prohibited"
          },
          {
                "symbol": "SHA256(CodeVerifier) = CodeChallenge",
                "meaning": "Base64URL SHA-256 digest of client verifier strictly matches authorization challenge"
          }
    ],
    plainEnglish: "Every authorization code exchange must mandate Proof Key for Code Exchange (PKCE) using the S256 transformation. The authorization server must reject authorization requests without code_challenge and reject token exchanges without code_verifier.",
    whyItMatters: "On mobile devices and SPAs, native custom URI schemes (e.g. `myapp://oauth`) can be registered by malicious applications. An attacker intercepting the authorization code cannot exchange it for an access token without possessing the unhashed code_verifier secret.",
    vulnerableExample: {
          "language": "python/auth",
          "code": "# VULNERABLE: Token endpoint exchanges code without verifying PKCE\n@app.post('/oauth/token')\ndef exchange_token(code: str, client_id: str):\n    # FLAW: Code is exchanged directly; stolen code can be redeemed by attacker!\n    grant = db.get_code(code)\n    return issue_access_token(grant.user_id)",
          "explanation": "If authorization code is intercepted in browser history or custom URI scheme, attacker redeems it immediately."
    },
    secureExample: {
          "language": "python/auth",
          "code": "# SECURE: Mandatory S256 PKCE verification\n@app.post('/oauth/token')\ndef exchange_token(code: str, code_verifier: str, client_id: str):\n    grant = db.get_code(code)\n    if not grant.code_challenge or grant.code_challenge_method != 'S256':\n        raise InvalidRequest('PKCE S256 challenge required')\n    computed_challenge = base64url(hashlib.sha256(code_verifier.encode()).digest())\n    if not crypto.timingSafeEqual(computed_challenge, grant.code_challenge):\n        raise InvalidGrant('PKCE verification failed: invalid code_verifier')\n    return issue_access_token(grant.user_id)",
          "explanation": "Guarantees that only the client instance that initiated the authorization flow can redeem the authorization code."
    },
    howToTest: {
          "tools": [
                "curl",
                "Postman",
                "OAuth 2.0 Debugger"
          ],
          "steps": [
                "Initiate auth flow without `code_challenge`; confirm authorization server rejects request with 400 Bad Request.",
                "Complete flow with valid challenge but supply invalid `code_verifier` at token endpoint; confirm token request fails with `invalid_grant`."
          ],
          "commandExample": "curl -X POST -d 'grant_type=authorization_code&code=abc&client_id=myclient' https://auth.target.com/oauth/token"
    },
    interviewChallenge: {
          "scenario": "A mobile bank app developer argues that PKCE is only needed for public clients, so their confidential backend web app does not need PKCE because it uses a client_secret.",
          "question": "Why does the latest OAuth 2.1 specification mandate PKCE for confidential clients as well as public clients?",
          "hint": "What attack does PKCE prevent even when client_secret is present?",
          "sampleAnswer": "PKCE prevents Authorization Code Injection. If an attacker intercepts a victim's authorization code, in traditional OAuth 2.0 the attacker could inject the code into their own client session. With PKCE, the client session has a unique in-memory code_verifier: the authorization server will reject the token exchange because the injected code does not match the attacker session's code_verifier.",
          "keyTakeaway": "PKCE protects confidential clients against code injection and CSRF; enforce S256 everywhere."
    }
  },
  {
    ruleNumber: 188,
    id: "SEC-OAUTH-002",
    title: "Redirect URI Exact String Matching Invariant",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Redirect URI Hardening",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["RFC 6749 \u00a73.1.2", "RFC 9700 \u00a74.1", "CWE-601"],
    formalInvariant: "\u2200 req \u2208 AuthorizationRequests, req.RedirectURI \u2208 RegisteredRedirectURIs \u2227 IsExactLiteralMatch(req.RedirectURI) \u2227 ContainsNoWildcards(req.RedirectURI)",
    symbolBreakdown: [
          {
                "symbol": "RegisteredRedirectURIs",
                "meaning": "Pre-registered exact URI allowlist configured in developer portal"
          },
          {
                "symbol": "IsExactLiteralMatch",
                "meaning": "Strict binary string comparison against allowlist; no regex, subdomain matching, or directory traversal"
          },
          {
                "symbol": "ContainsNoWildcards",
                "meaning": "Asterisks (*) in path or domain are strictly prohibited"
          }
    ],
    plainEnglish: "Authorization servers must perform exact literal string comparison when validating incoming redirect_uri parameters against pre-registered client URIs. Wildcards (*), regex matches, and path traversal sequences (../) are strictly prohibited.",
    whyItMatters: "Permissive redirect URI matching (e.g. `https://example.com/*`) allows attackers to supply redirect URIs pointing to open redirects on the same domain (`https://example.com/oauth/callback/../../redirect?to=evil.com`), leaking authorization codes to the attacker's server.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Substring / regex matching on redirect URI\ndef validate_redirect(client, redirect_uri):\n    # FLAW: Matches any URL containing the client domain!\n    if client.domain in redirect_uri:\n        return True",
          "explanation": "Allows redirect_uri='https://attacker.com?client.domain' or open redirect chaining."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Exact literal equality against registered URI set\ndef validate_redirect(client, redirect_uri):\n    # Strict literal string match against pre-registered set:\n    if redirect_uri not in client.registered_redirect_uris:\n        raise InvalidRedirectUriError('Redirect URI must match registered URI exactly')\n    return True",
          "explanation": "Guarantees authorization codes can only ever be delivered to pre-approved exact URLs."
    },
    howToTest: {
          "tools": [
                "curl",
                "Burp Suite"
          ],
          "steps": [
                "Register redirect URI: `https://app.example.com/callback`.",
                "Send authorization request with: `https://app.example.com/callback/../open-redirect`.",
                "Verify authorization server rejects request with 400 Bad Request: 'Invalid redirect_uri'."
          ],
          "commandExample": "curl \"https://auth.target.com/authorize?client_id=1&redirect_uri=https://app.example.com/callback/..\""
    },
    interviewChallenge: {
          "scenario": "A cloud provider's developer console allows wildcard redirect URIs: `https://*.example.com/oauth/callback` to support multiple dev staging subdomains.",
          "question": "How can an attacker exploit this wildcard to steal production OAuth authorization codes?",
          "hint": "Can an attacker control any subdomain, like a customer blog or unclaimed S3 bucket?",
          "sampleAnswer": "If any subdomain in `*.example.com` has an open redirect, hosts user-generated content (e.g. `user-sites.example.com`), or points to a dangling CNAME (subdomain takeover), the attacker specifies that subdomain as the redirect_uri (`https://takeover.example.com/oauth/callback`). The authorization server sends the authorization code to the compromised subdomain, enabling account takeover.",
          "keyTakeaway": "Never allow wildcard redirect URIs in OAuth; require explicit registration of full literal paths."
    }
  },
  {
    ruleNumber: 189,
    id: "SEC-OAUTH-189",
    title: "Single-Use Authorization Code Invalidation Invariant",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Authorization Code Grant",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["RFC 6749 \u00a74.1.2", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 code \u2208 AuthorizationCodes, ConsumeCode(code) \u21d2 IsBurned(code) = True \u2227 (AttemptReplay(code) \u21d2 RevokeIssuedTokens(code))",
    symbolBreakdown: [
          {
                "symbol": "AuthorizationCodes",
                "meaning": "Temporary codes issued on authorization endpoint"
          },
          {
                "symbol": "IsBurned = True",
                "meaning": "Code marked used and deleted atomically"
          },
          {
                "symbol": "RevokeIssuedTokens",
                "meaning": "Automatic revocation of tokens issued by compromised code"
          }
    ],
    plainEnglish: "Authorization codes must be single-use and have a maximum lifetime of 10 minutes (60 seconds recommended). If an authorization code is presented a second time, the authorization server must revoke all tokens previously issued by that code.",
    whyItMatters: "If an authorization code is intercepted and redeemed by an attacker, but the legitimate client attempts to redeem it a second later, the server must recognize the replay attack and immediately revoke the attacker's newly issued access token.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Code not invalidated upon redemption\n@app.post('/token')\ndef redeem(code: str):\n    grant = db.get_code(code) # Code remains valid in DB!\n    return issue_token(grant.user_id)",
          "explanation": "Allows attacker to reuse intercepted authorization codes repeatedly."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Atomic code invalidation and replay detection (RFC 6749 \u00a74.1.2)\n@app.post('/token')\ndef redeem(code: str):\n    grant = db.get_and_delete_code_atomically(code)\n    if not grant:\n        # Code already used! Possible replay attack!\n        revoke_all_tokens_for_grant(code)\n        raise InvalidGrant('Authorization code already redeemed. Tokens revoked for security.')\n    return issue_token(grant.user_id)",
          "explanation": "Burns code atomically on first use and revokes issued tokens if a duplicate redemption is detected."
    },
    howToTest: {
          "tools": [
                "curl",
                "unit tests"
          ],
          "steps": [
                "Redeem authorization code once; confirm 200 OK.",
                "Redeem exact same code a second time; confirm 400 error and verify first token is revoked."
          ],
          "commandExample": "curl -X POST -d 'code=xyz' https://auth.target.com/oauth/token"
    },
    interviewChallenge: {
          "scenario": "Why does RFC 6749 mandate that if an authorization code is presented more than once, the server must revoke all tokens previously issued using that code?",
          "question": "What does a second attempt indicate?",
          "hint": "It indicates that an attacker and the legitimate client both possess the code (the code was intercepted in transit), so all tokens issued from it are suspect.",
          "sampleAnswer": "A duplicate redemption attempt is definitive proof of an interception attack. The server cannot know whether the first or second redemption was the legitimate user. To protect the user, it revokes all tokens issued from that authorization code, forcing a clean re-authentication.",
          "keyTakeaway": "Treat duplicate code redemption as an active breach: burn codes atomically and revoke child tokens."
    }
  },
  {
    ruleNumber: 190,
    id: "SEC-OAUTH-190",
    title: "State Parameter Cryptographic Binding and CSRF Prevention",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Client CSRF Defense",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["RFC 6749 \u00a710.12", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 req \u2208 AuthFlows, HasState(req) \u2227 (req.State = CSPRNG(\u2265 128b)) \u2227 VerifyClientSessionBinding(req.State) = True",
    symbolBreakdown: [
          {
                "symbol": "HasState",
                "meaning": "Mandatory presence of state parameter in authorization URL"
          },
          {
                "symbol": "CSPRNG >= 128b",
                "meaning": "Cryptographically unguessable random token"
          },
          {
                "symbol": "VerifyClientSessionBinding",
                "meaning": "State matches anti-CSRF token in client's local session cookie"
          }
    ],
    plainEnglish: "OAuth 2.0 clients must generate a cryptographically unguessable `state` parameter bound to the user's browser session. The redirect handler must verify that the returned state matches the stored session state before requesting tokens.",
    whyItMatters: "Without the `state` parameter, an attacker tricks a victim into clicking a link that redeems the ATTACKER'S authorization code in the victim's browser, binding the victim's bank account or profile to the attacker's identity (OAuth Login CSRF).",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Omitting state parameter verification\napp.get('/oauth/callback', async (req, res) => {\n    // Blindly exchanges code without validating state!\n    const tokens = await exchangeCode(req.query.code);\n    req.session.userId = tokens.userId;\n});",
          "explanation": "Enables OAuth login CSRF attacks binding victim sessions to attacker credentials."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Cryptographic state generation and session validation\napp.get('/login', (req, res) => {\n    const state = crypto.randomBytes(16).toString('hex');\n    res.cookie('oauth_state', state, { httpOnly: true, secure: true, sameSite: 'lax' });\n    res.redirect(`https://auth.com/authorize?client_id=123&state=${state}`);\n});\n\napp.get('/oauth/callback', async (req, res) => {\n    if (!req.query.state || req.query.state !== req.cookies.oauth_state) {\n        return res.status(403).send('OAuth State mismatch: potential CSRF attack');\n    }\n    res.clearCookie('oauth_state');\n    const tokens = await exchangeCode(req.query.code);\n});",
          "explanation": "Guarantees the OAuth response was initiated by the exact same browser session."
    },
    howToTest: {
          "tools": [
                "browser DevTools",
                "curl"
          ],
          "steps": [
                "Attempt OAuth callback with mismatched or missing state query parameter; verify 403 Forbidden."
          ],
          "commandExample": "curl \"https://app.example.com/oauth/callback?code=abc&state=wrong\""
    },
    interviewChallenge: {
          "scenario": "How does an attacker exploit OAuth Login CSRF against an e-commerce website that omits `state` verification?",
          "question": "What does the attacker link to the victim's account?",
          "hint": "The attacker completes the OAuth flow halfway, takes their own authorization code, and sends it to the victim. The victim's browser redeems the attacker's code, linking the victim's credit card to the attacker's account.",
          "sampleAnswer": "The attacker generates an authorization code for their own Google account. They trick the victim into visiting `app.com/callback?code=ATTACKER_CODE`. The victim's browser logs in as the attacker. When the victim enters payment details or uploads documents, they are stored in the attacker's account, allowing the attacker to view them.",
          "keyTakeaway": "Always validate cryptographically random state tokens bound to session cookies."
    }
  },
  {
    ruleNumber: 191,
    id: "SEC-OAUTH-191",
    title: "OpenID Connect Nonce Replay Elimination Invariant",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "OIDC ID Token Validation",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["OpenID Connect Core 1.0 \u00a73.1.2.1", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 idToken \u2208 IssuedIDTokens, VerifyIDTokenSignature(idToken) \u2227 (idToken.nonce = ClientSession.InitiatedNonce) \u2227 MarkNonceUsed(idToken.nonce)",
    symbolBreakdown: [
          {
                "symbol": "IssuedIDTokens",
                "meaning": "OpenID Connect identity tokens signed by IdP"
          },
          {
                "symbol": "idToken.nonce",
                "meaning": "Cryptographic challenge embedded in ID token payload"
          },
          {
                "symbol": "ClientSession.InitiatedNonce",
                "meaning": "Exact nonce generated when authorization request was created"
          }
    ],
    plainEnglish: "OpenID Connect clients must supply a cryptographically random `nonce` in authorization requests. When validating the ID Token, the client must verify that the `nonce` claim matches the value stored in the user's session.",
    whyItMatters: "If the `nonce` parameter is omitted, an attacker who intercepts an ID Token (e.g. from network traffic or browser history) can replay the token into a client application to authenticate as the victim.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Omitting nonce validation on ID token\nfunction handleIdToken(idToken, session) {\n    const payload = jwt.decode(idToken);\n    // FLAW: Doesn't check if payload.nonce matches session.nonce!\n    session.user = payload.sub;\n}",
          "explanation": "Allows replayed ID tokens from other sessions to authenticate users."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Cryptographic nonce generation and strict matching\nfunction handleIdToken(idToken, session) {\n    const payload = verifyIdToken(idToken);\n    if (!payload.nonce || payload.nonce !== session.expectedNonce) {\n        throw new SecurityError('Invalid ID Token nonce: replay attack detected');\n    }\n    delete session.expectedNonce; // Burn nonce\n    session.user = payload.sub;\n}",
          "explanation": "Binds the ID Token cryptographically to the specific client authentication session."
    },
    howToTest: {
          "tools": [
                "OIDC debugger",
                "unit tests"
          ],
          "steps": [
                "Supply ID token with mismatched nonce; confirm verification exception."
          ],
          "commandExample": "node -e 'console.log(\"Testing OIDC nonce verification\")'"
    },
    interviewChallenge: {
          "scenario": "What is the difference between the OAuth 2.0 `state` parameter and the OpenID Connect `nonce` parameter?",
          "question": "Where does state live, and where does nonce live?",
          "hint": "`state` is verified by the client on the authorization redirect URL; `nonce` is embedded inside the cryptographically signed ID Token itself by the Identity Provider.",
          "sampleAnswer": "The `state` parameter protects the authorization code exchange from CSRF at the HTTP redirect layer. The `nonce` parameter is cryptographically signed into the ID Token payload by the IdP, binding the issued token directly to the client's session and preventing token replay attacks.",
          "keyTakeaway": "Generate and verify both `state` and `nonce` parameters in OpenID Connect flows."
    }
  },
  {
    ruleNumber: 192,
    id: "SEC-OAUTH-192",
    title: "Access Token Audience (aud) Strict Restriction Invariant",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "JWT Token Validation",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 7519 \u00a74.1.3", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 token \u2208 AccessTokens, ExpectedAudience \u2208 Audience(token) \u2228 RejectToken(401)",
    symbolBreakdown: [
          {
                "symbol": "ExpectedAudience",
                "meaning": "The explicit API identifier (e.g. https://api.payments.example.com)"
          },
          {
                "symbol": "Audience(token)",
                "meaning": "The aud claim in the JWT access token payload"
          }
    ],
    plainEnglish: "Resource servers (APIs) must verify that the `aud` (audience) claim in incoming access tokens contains their specific API identifier. Tokens issued for other services or clients must be rejected with 401 Unauthorized.",
    whyItMatters: "An attacker receives a valid access token for a low-security public forum API. If an internal billing API accepts any token signed by the company IdP without checking `aud`, the attacker uses the forum token to execute billing transactions.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Verifying signature but ignoring audience\nfunction authenticateApi(token) {\n    const payload = jwt.verify(token, JWKS_KEY);\n    // FLAW: Does not check aud! Accepts tokens intended for other microservices!\n    return payload;\n}",
          "explanation": "Allows cross-service token substitution attacks."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Strict audience and issuer validation\nfunction authenticateApi(token) {\n    return jwt.verify(token, JWKS_KEY, {\n        audience: 'https://api.payments.example.com', // Must match this API exactly\n        issuer: 'https://auth.example.com'\n    });\n}",
          "explanation": "Rejects tokens intended for other microservices even if signed by the same IdP."
    },
    howToTest: {
          "tools": [
                "jwt.io",
                "curl"
          ],
          "steps": [
                "Generate token with `aud: 'https://api.forums.com'`.",
                "Send to payments API; verify API rejects with 401 Unauthorized: 'jwt audience invalid'."
          ],
          "commandExample": "curl -H \"Authorization: Bearer forum_token\" https://api.payments.com/charge"
    },
    interviewChallenge: {
          "scenario": "What is the 'Token Substitution' (Confused Deputy) attack that occurs when an API fails to validate the `aud` claim?",
          "question": "How does an attacker reuse a benign token?",
          "hint": "An attacker registers a harmless third-party app with the company's IdP, gets the victim to sign in, takes the victim's access token (issued for the harmless app), and presents it to the company's internal management API.",
          "sampleAnswer": "When an identity provider issues tokens for multiple APIs, the `aud` claim restricts which resource server can accept the token. If Resource Server A does not check `aud`, any token issued for Resource Server B can be reused against Server A, violating microservice isolation.",
          "keyTakeaway": "Always enforce explicit `audience` validation on every API endpoint."
    }
  },
  {
    ruleNumber: 193,
    id: "SEC-OAUTH-193",
    title: "JWT alg \"none\" Header Rejection Invariant",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Algorithm Confusion",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["RFC 8725 \u00a73.1", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 jwt \u2208 IncomingJWTs, Header(jwt).alg \u2260 \"none\" \u2227 Header(jwt).alg \u2208 WhitelistedAlgorithms",
    symbolBreakdown: [
          {
                "symbol": "Header(jwt).alg",
                "meaning": "The algorithm parameter in the JWT JOSE header"
          },
          {
                "symbol": "\"none\"",
                "meaning": "Unsigned plaintext JWT token specification per RFC 7519"
          },
          {
                "symbol": "WhitelistedAlgorithms",
                "meaning": "Explicit whitelist: RS256, ES256, EdDSA"
          }
    ],
    plainEnglish: "JWT libraries and API gateways must reject tokens with `alg: \"none\"` (or case variations like `None`, `NONE`). The algorithm header must be strictly verified against an explicit allowlist of approved cryptographic algorithms.",
    whyItMatters: "In 2015, major JWT libraries accepted tokens with `alg: \"none\"` without checking signatures. Attackers took valid tokens, set `\"alg\": \"none\"`, modified `\"role\": \"admin\"`, stripped the signature, and took over accounts globally.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Naive verification accepting alg none\nconst decoded = jwt.verify(token, secret, {\n    // FLAW: If library defaults to permissive algorithms, alg 'none' bypasses signature check!\n});",
          "explanation": "Permits unsigned tokens to pass as legitimate authenticated sessions."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Strict algorithm whitelist enforcement (RFC 8725)\nconst decoded = jwt.verify(token, publicKey, {\n    algorithms: ['RS256', 'ES256'], // Explicitly prohibits 'none' and symmetric algorithms\n    issuer: 'https://auth.example.com'\n});",
          "explanation": "Hardens JWT verification against algorithm confusion and unsigned tokens."
    },
    howToTest: {
          "tools": [
                "jwt.io",
                "curl"
          ],
          "steps": [
                "Create token with header `{\"alg\":\"none\",\"typ\":\"JWT\"}` and payload `{\"admin\":true}`.",
                "Send to API; verify server rejects with 401 Unauthorized."
          ],
          "commandExample": "curl -H \"Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.\" https://api.target.com/data"
    },
    interviewChallenge: {
          "scenario": "Why did the original JWT specification (RFC 7519) define the `none` algorithm in the first place?",
          "question": "What legitimate use case was envisioned?",
          "hint": "The IETF working group envisioned scenarios where integrity was already guaranteed by transport layers (e.g. inside an established TLS or IPsec tunnel) and signing was deemed redundant.",
          "sampleAnswer": "RFC 7519 defined `none` for environments where security was provided by another layer. However, embedding the algorithm in the untrusted token header created a catastrophic flaw: clients could tell the server how to verify the token. RFC 8725 (JWT BCP) now mandates that servers must restrict allowed algorithms.",
          "keyTakeaway": "Strictly whitelist allowed JWT algorithms in verification options."
    }
  },
  {
    ruleNumber: 194,
    id: "SEC-OAUTH-194",
    title: "JWT Asymmetric Key (RS256 vs HS256) Confusion Ban Invariant",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Signature Verification",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["RFC 8725 \u00a73.2", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 jwt \u2208 IncomingJWTs, (ServerKeyType = Asymmetric) \u21d2 (Header(jwt).alg \u2209 {\"HS256\", \"HS384\", \"HS512\"})",
    symbolBreakdown: [
          {
                "symbol": "ServerKeyType = Asymmetric",
                "meaning": "Server uses RSA or ECDSA public keys to verify tokens"
          },
          {
                "symbol": "\u2209 {\"HS256\", ...}",
                "meaning": "Prohibition of HMAC symmetric ciphers when verifying asymmetric tokens"
          }
    ],
    plainEnglish: "When a server verifies tokens signed with asymmetric keys (RS256), the verification function must never permit symmetric HMAC algorithms (HS256). The verification algorithm must be pinned and independent of the token's header.",
    whyItMatters: "In Key Confusion attacks, the attacker takes the server's public RSA key (which is publicly accessible) and uses it as the secret key to sign an HMAC-SHA256 token. If the server permits HS256, it uses its RSA public key string as the HMAC secret, verifying the forged token successfully.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Algorithm determined by unverified token header\ndef verify_token(token):\n    header = jwt.get_unverified_header(token)\n    # If attacker sends HS256, PyJWT uses the RSA public key PEM string as HMAC secret!\n    return jwt.decode(token, PUBLIC_KEY, algorithms=[header['alg']])",
          "explanation": "Allows attackers to forge arbitrary administrative tokens using the public key."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Hardcoded asymmetric algorithm whitelist (RFC 8725 \u00a73.2)\ndef verify_token(token):\n    # Server dictates algorithm, completely ignoring attacker-controlled header:\n    return jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])",
          "explanation": "Completely neutralizes Key Confusion by prohibiting HMAC verification with asymmetric keys."
    },
    howToTest: {
          "tools": [
                "jwt-tool",
                "python-jwt testbench"
          ],
          "steps": [
                "Forge token using RSA public key as HS256 secret.",
                "Send to endpoint; verify server rejects token with 'Algorithm not allowed'."
          ],
          "commandExample": "python3 -m jwt_tool token -X k -pk public.pem"
    },
    interviewChallenge: {
          "scenario": "How does an attacker obtain the server's public key to execute an RS256/HS256 Key Confusion attack?",
          "question": "Where are public keys published?",
          "hint": "OAuth 2.0 authorization servers publish their public keys openly on the Internet at `/.well-known/jwks.json` so that APIs and clients can verify signatures.",
          "sampleAnswer": "Because public keys are public by design, anyone on the Internet can curl `https://auth.example.com/.well-known/jwks.json` and download the RSA public key. If the target API allows HS256, the attacker hashes their forged token with that public key PEM string, achieving full authentication bypass.",
          "keyTakeaway": "Always pin the expected verification algorithm (`algorithms=['RS256']`)."
    }
  },
  {
    ruleNumber: 195,
    id: "SEC-OAUTH-195",
    title: "Demonstrating Proof-of-Possession (DPoP) Sender-Constraining (RFC 9449)",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Sender-Constrained Tokens",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["RFC 9449", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 req \u2208 APIRequests_{DPoP}, HasHeader(req, \"DPoP\") \u2227 VerifyDPoPProof(req.Header[\"DPoP\"], req.Token.jkt, req.HTTPMethod, req.URI) = True",
    symbolBreakdown: [
          {
                "symbol": "DPoP",
                "meaning": "RFC 9449 Demonstrating Proof-of-Possession header"
          },
          {
                "symbol": "req.Token.jkt",
                "meaning": "JSON Web Key Thumbprint claim binding access token to client private key"
          },
          {
                "symbol": "HTTPMethod, URI",
                "meaning": "Cryptographic signature over active request target"
          }
    ],
    plainEnglish: "OAuth access tokens must be sender-constrained using Demonstrating Proof-of-Possession (DPoP) per RFC 9449. The client must sign a real-time DPoP proof with its private key on every request. Bearer tokens without sender-constraining are prohibited for high-risk APIs.",
    whyItMatters: "Standard 'Bearer' tokens act like cash: anyone who steals the token (via proxy logs, memory dumps, or SSRF) can use it anywhere. DPoP sender-constraining renders stolen tokens useless because the thief does not hold the client's local private key.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Unconstrained Bearer token acceptance\napp.get('/api/account', (req, res) => {\n    // Token stolen from proxy logs can be replayed from any computer!\n    const token = req.headers.authorization.split(' ')[1];\n    verifyBearerToken(token);\n});",
          "explanation": "Exposes API to stolen token replay across any external network."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: RFC 9449 DPoP sender-constraining verification\nimport { verifyDPoPProof } from 'dpop-verifier';\n\napp.get('/api/account', async (req, res) => {\n    const token = req.headers.authorization.replace('DPoP ', '');\n    const dpopHeader = req.headers['dpop'];\n    // Verifies: 1) DPoP signature, 2) HTTP method/URI match, 3) key thumbprint matches token 'cnf.jkt'\n    const valid = await verifyDPoPProof(dpopHeader, token, req.method, req.originalUrl);\n    if (!valid) return res.status(401).send('DPoP Proof-of-Possession verification failed');\n});",
          "explanation": "Guarantees token cannot be used without possession of the private signing key."
    },
    howToTest: {
          "tools": [
                "dpop-cli",
                "curl"
          ],
          "steps": [
                "Send valid access token with missing or forged DPoP proof header.",
                "Verify API rejects request with 401 Unauthorized: 'invalid_dpop_proof'."
          ],
          "commandExample": "curl -H \"Authorization: DPoP token123\" -H \"DPoP: proof_jwt\" https://api.target.com/account"
    },
    interviewChallenge: {
          "scenario": "Why does DPoP represent a major security improvement over traditional OAuth 2.0 Bearer tokens for browser SPAs?",
          "question": "What happens if an XSS attacker steals a DPoP-bound access token from memory?",
          "hint": "The stolen access token is bound to a non-extractable private key in the user's browser `SubtleCrypto` store. The attacker cannot use the token from their own server because they cannot generate valid DPoP proof signatures.",
          "sampleAnswer": "Bearer tokens are vulnerable to exfiltration: if an attacker steals the token string, they have complete access. DPoP generates an asymmetric keypair in the browser's non-extractable WebCrypto storage. The token is bound to that key. Even if the attacker steals the token, they cannot use it from another machine without the private key.",
          "keyTakeaway": "Deploy RFC 9449 DPoP to sender-constrain OAuth access tokens."
    }
  },
  {
    ruleNumber: 196,
    id: "SEC-OAUTH-196",
    title: "Mutual-TLS (mTLS) Client Certificate Bound Access Tokens (RFC 8705)",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Sender-Constrained Tokens",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["RFC 8705", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 req \u2208 FinTechAPIRequests, HasTLSClientCert(req) \u2227 Hash(req.ClientCert) = req.Token.cnf.x5t_S256",
    symbolBreakdown: [
          {
                "symbol": "HasTLSClientCert",
                "meaning": "Mutual TLS handshake establishes verified client certificate"
          },
          {
                "symbol": "req.Token.cnf.x5t_S256",
                "meaning": "Confirmation claim containing SHA-256 thumbprint of client certificate"
          }
    ],
    plainEnglish: "Financial-grade APIs (FAPI) must enforce Mutual-TLS Client Certificate-Bound Access Tokens per RFC 8705. The access token must contain the client certificate thumbprint (`cnf.x5t#S256`), and the resource server must verify it matches the active TLS client certificate.",
    whyItMatters: "Without certificate-bound tokens, an insider or compromised proxy that intercepts access tokens in banking microservices can replay them to drain accounts.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Bare access token without mTLS certificate binding\ndef process_payment(token, client_cert):\n    payload = verify_jwt(token)\n    # FLAW: Does not verify that client_cert matches token 'cnf' thumbprint!\n    execute_payment(payload)",
          "explanation": "Allows stolen banking tokens to be used across different TLS connections."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: RFC 8705 mTLS token certificate binding verification\ndef process_payment(token, client_cert_der):\n    payload = verify_jwt(token)\n    cert_thumbprint = base64url(hashlib.sha256(client_cert_der).digest())\n    expected_thumbprint = payload.get('cnf', {}).get('x5t#S256')\n    if not expected_thumbprint or cert_thumbprint != expected_thumbprint:\n        raise SecurityException('mTLS Certificate binding mismatch: token stolen!')\n    execute_payment(payload)",
          "explanation": "Cryptographically binds token usage strictly to the TLS connection carrying the matching client certificate."
    },
    howToTest: {
          "tools": [
                "openssl s_client",
                "curl --cert client.crt --key client.key"
          ],
          "steps": [
                "Present valid token over TLS connection with different client certificate.",
                "Verify server returns 401 Unauthorized: 'certificate thumbprint mismatch'."
          ],
          "commandExample": "curl --cert valid.crt --key valid.key -H \"Authorization: Bearer token\" https://fapi.bank.com/transfer"
    },
    interviewChallenge: {
          "scenario": "Why does the Open Banking / Financial-Grade API (FAPI) standard mandate RFC 8705 mTLS or RFC 9449 DPoP for all financial transactions?",
          "question": "What regulatory requirement does sender-constraining fulfill?",
          "hint": "It fulfills the regulatory mandate that stolen credentials or intercepted network packets cannot be replayed by unauthorized third parties.",
          "sampleAnswer": "Banking regulations (PSD2 RTS, Open Banking UK) legally mandate sender-constrained tokens. If a malicious payment gateway or compromised proxy intercepts a customer's token, the token is dead on arrival on any other network connection because the attacker lacks the private key or mTLS certificate.",
          "keyTakeaway": "Enforce mTLS client-certificate binding for high-value financial endpoints."
    }
  },
  {
    ruleNumber: 197,
    id: "SEC-OAUTH-197",
    title: "Refresh Token Rotation and Reuse Detection Invariant (RFC 9700)",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Token Lifecycle",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["RFC 9700 \u00a74.14.2", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 req \u2208 RefreshRequests, ConsumeToken(req.RefreshToken) \u21d2 IssueNewRefreshToken(Family) \u2227 (Reused(req.RefreshToken) \u21d2 RevokeTokenFamily(Family))",
    symbolBreakdown: [
          {
                "symbol": "RefreshRequests",
                "meaning": "Token endpoint requests with grant_type=refresh_token"
          },
          {
                "symbol": "IssueNewRefreshToken",
                "meaning": "Server issues a fresh refresh token and invalidates the old one"
          },
          {
                "symbol": "RevokeTokenFamily",
                "meaning": "Immediate destruction of all tokens in the family upon reuse detection"
          }
    ],
    plainEnglish: "Authorization servers must implement Refresh Token Rotation (RTR). Every time a refresh token is used, it must be invalidated and replaced with a new one. If an invalidated refresh token is presented again, the server must treat it as a breach and revoke the entire token family.",
    whyItMatters: "If an attacker steals a user's refresh token from a mobile device or browser, the user will eventually use their own token. Without reuse detection, both attacker and user maintain perpetual access. With reuse detection, the attacker is locked out immediately.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Static long-lived refresh tokens without rotation\n@app.post('/oauth/refresh')\ndef refresh_token(token: str):\n    # Re-uses the exact same refresh token forever!\n    return {'access_token': issue_access(), 'refresh_token': token}",
          "explanation": "A stolen refresh token grants attackers permanent, undetectable account access."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Refresh Token Rotation with automatic family revocation (RFC 9700)\n@app.post('/oauth/refresh')\ndef refresh_token(token: str):\n    record = db.find_refresh_token(token)\n    if record.used:\n        # REUSE DETECTED: Token was already consumed! Attacker or victim replayed it!\n        db.revoke_entire_token_family(record.family_id)\n        raise InvalidGrant('Compromised token family detected. All sessions revoked.')\n    db.mark_used(token)\n    new_refresh = generate_token(family_id=record.family_id)\n    return {'access_token': issue_access(), 'refresh_token': new_refresh}",
          "explanation": "Invalidates old refresh token immediately; revokes all sessions if an old token is ever reused."
    },
    howToTest: {
          "tools": [
                "curl",
                "unit tests"
          ],
          "steps": [
                "Use refresh token once; confirm new token pair returned.",
                "Attempt to use the old refresh token again; verify server returns error and revokes all active tokens."
          ],
          "commandExample": "curl -X POST -d 'grant_type=refresh_token&refresh_token=old_token' https://auth.target.com/token"
    },
    interviewChallenge: {
          "scenario": "Why does Refresh Token Rotation provide self-healing security against token theft in Single Page Applications (SPAs)?",
          "question": "How does the server discover that a token was stolen?",
          "hint": "Because either the attacker or the real user will use the token first, the other party will inevitably attempt to use the now-invalidated token, immediately alerting the server to revoke the entire session.",
          "sampleAnswer": "When an attacker steals a refresh token, two parties now possess it. Whichever party refreshes first invalidates the token. When the second party attempts to refresh, the server detects token reuse, invalidates the entire token family, and ejects the attacker completely.",
          "keyTakeaway": "Implement Refresh Token Rotation with family revocation on all OAuth servers."
    }
  },
  {
    ruleNumber: 198,
    id: "SEC-OAUTH-198",
    title: "OAuth Implicit Grant (response_type=token) Deprecation",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Token Security",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["RFC 9700 \u00a72.1.2", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 req \u2208 AuthRequests, req.ResponseType \u2260 \"token\" \u2227 req.ResponseType \u2260 \"id_token token\"",
    symbolBreakdown: [
          {
                "symbol": "ResponseType \u2260 'token'",
                "meaning": "Complete prohibition of returning access tokens directly in URL hash fragments"
          }
    ],
    plainEnglish: "The OAuth 2.0 Implicit Grant (`response_type=token`) is officially deprecated by RFC 9700 and prohibited by OAuth 2.1. Authorization servers must reject requests with `response_type=token` and enforce Authorization Code Grant with PKCE.",
    whyItMatters: "The Implicit Grant delivers access tokens directly in the URL hash fragment (`#access_token=...`). URLs are logged in browser history, visible in HTTP `Referer` headers, and exposed to malicious browser extensions.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Supporting deprecated Implicit Grant\nif request.response_type == 'token':\n    # Returns access token directly in URL fragment!\n    return redirect(f\"{redirect_uri}#access_token={token}\")",
          "explanation": "Exposes access tokens directly in URLs, browser history, and proxy logs."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Rejecting Implicit Grant per RFC 9700 / OAuth 2.1\nif 'token' in request.response_type:\n    raise UnsupportedResponseTypeError(\n        'Implicit Grant is deprecated. Use response_type=code with PKCE.'\n    )",
          "explanation": "Enforces modern, secure Authorization Code with PKCE grant flow."
    },
    howToTest: {
          "tools": [
                "curl",
                "OAuth conformance suite"
          ],
          "steps": [
                "Send request with `response_type=token`.",
                "Verify server returns 400 Bad Request with `unsupported_response_type`."
          ],
          "commandExample": "curl \"https://auth.target.com/authorize?response_type=token&client_id=123\""
    },
    interviewChallenge: {
          "scenario": "Why was the Implicit Grant originally invented in 2012, and why is it obsolete today?",
          "question": "What browser capability was missing in 2012?",
          "hint": "In 2012, browsers lacked Cross-Origin Resource Sharing (CORS) support, so JavaScript applications could not make backend POST requests to the `/token` endpoint.",
          "sampleAnswer": "In 2012, JavaScript in browsers could not make cross-origin POST requests to exchange authorization codes due to early browser restrictions. The Implicit Grant was a workaround to pass tokens in URL fragments. With universal modern CORS support and PKCE, the Implicit Grant is entirely obsolete and dangerous.",
          "keyTakeaway": "Disable the Implicit Grant on all authorization servers."
    }
  },
  {
    ruleNumber: 199,
    id: "SEC-OAUTH-199",
    title: "JWT Expiration (exp) Mandatory Field and Clock Skew Bound (\u2264 60s)",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Token Lifespan",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["RFC 7519 \u00a74.1.4", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 jwt \u2208 JWTs, HasClaim(jwt, \"exp\") \u2227 (Now() - ClockSkew(60s) \u2264 jwt.exp)",
    symbolBreakdown: [
          {
                "symbol": "HasClaim(jwt, 'exp')",
                "meaning": "Expiration claim is strictly mandatory; tokens without exp must be rejected"
          },
          {
                "symbol": "ClockSkew(60s)",
                "meaning": "Maximum permitted time tolerance across server clocks (at most 60 seconds)"
          }
    ],
    plainEnglish: "All JWT access tokens must declare the `exp` (expiration) claim with a short lifespan (e.g. 15 to 60 minutes). Verification engines must enforce expiration and restrict clock skew tolerance to at most 60 seconds.",
    whyItMatters: "A JWT without an `exp` claim remains valid forever. An attacker who steals a token can use it months or years later, long after the employee has left the company.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Issuing JWT without expiration\nconst token = jwt.sign({ userId: 123 }, SECRET); // Valid forever!",
          "explanation": "Generates immortal tokens that cannot expire."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Mandatory expiration and bounded clock skew\nconst token = jwt.sign({ userId: 123 }, PRIVATE_KEY, {\n    expiresIn: '15m', // Expires in 15 minutes\n    algorithm: 'RS256'\n});\n// Verifier enforces exp and bounds clock skew:\njwt.verify(token, PUBLIC_KEY, { clockTolerance: 30 }); // 30 seconds max clock skew",
          "explanation": "Restricts token validity to 15 minutes with tight clock drift tolerance."
    },
    howToTest: {
          "tools": [
                "jwt.io",
                "curl"
          ],
          "steps": [
                "Verify decoded token payload contains `exp` integer timestamp.",
                "Wait until expiration; confirm API returns 401: 'jwt expired'."
          ],
          "commandExample": "node -e 'console.log(\"Testing JWT exp claim enforcement\")'"
    },
    interviewChallenge: {
          "scenario": "Why should JWT clock skew tolerance (`clockTolerance`) never exceed 60 seconds in production systems?",
          "question": "What vulnerability is introduced by large clock tolerances (e.g. 10 minutes)?",
          "hint": "A large clock tolerance extends the window during which an expired, stolen token remains accepted by API servers, defeating the purpose of short-lived tokens.",
          "sampleAnswer": "Server clocks synchronized via NTP drift by at most a few milliseconds. Allowing a generous clock skew (like 10 minutes) keeps expired tokens alive for an extra 10 minutes, exposing the API to replay attacks long after the token was revoked or refreshed.",
          "keyTakeaway": "Enforce short-lived tokens (`exp <= 15m`) with tight clock skew bounds (`clockTolerance <= 60s`)."
    }
  },
  {
    ruleNumber: 200,
    id: "SEC-OAUTH-200",
    title: "OIDC Discovery (.well-known/openid-configuration) TLS Enforcement",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Federation Discovery",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["OIDC Discovery 1.0", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 meta \u2208 OIDCDiscoveryRequests, Scheme(meta.URL) = \"https\" \u2227 (meta.Issuer = Response.issuer)",
    symbolBreakdown: [
          {
                "symbol": "OIDCDiscoveryRequests",
                "meaning": "Automated fetching of Identity Provider configuration"
          },
          {
                "symbol": "Scheme = 'https'",
                "meaning": "Mandatory TLS encrypted transport"
          },
          {
                "symbol": "meta.Issuer = Response.issuer",
                "meaning": "Exact string equality between requested URL and issuer claim"
          }
    ],
    plainEnglish: "OpenID Connect discovery endpoints (`/.well-known/openid-configuration`) must be fetched strictly over HTTPS. The client must verify that the `issuer` claim returned in the metadata JSON matches the requested discovery URL exactly.",
    whyItMatters: "An attacker on an unencrypted network manipulates the discovery document via DNS spoofing, altering `jwks_uri` to point to the attacker's public keys, causing clients to trust attacker-signed identity tokens.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Allowing HTTP discovery or omitting issuer match check\nconfig = requests.get('http://auth.example.com/.well-known/openid-configuration').json()",
          "explanation": "Allows network attackers to inject malicious JWKS endpoints via plaintext HTTP."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Mandatory HTTPS and strict issuer match validation\ndef fetch_oidc_config(issuer_url):\n    if not issuer_url.startswith('https://'):\n        raise SecurityError('HTTPS required for OIDC discovery')\n    res = requests.get(f\"{issuer_url}/.well-known/openid-configuration\", timeout=5).json()\n    if res['issuer'] != issuer_url:\n        raise SecurityError('Issuer mismatch in OIDC discovery document')\n    return res",
          "explanation": "Enforces TLS integrity and verifies exact issuer domain binding."
    },
    howToTest: {
          "tools": [
                "curl",
                "OIDC client testbench"
          ],
          "steps": [
                "Fetch discovery document over HTTP; confirm client library throws SecurityError."
          ],
          "commandExample": "curl -sI https://accounts.google.com/.well-known/openid-configuration | grep -i 'strict-transport-security'"
    },
    interviewChallenge: {
          "scenario": "Why must OpenID Connect clients verify that the `issuer` claim in the discovery document matches the expected issuer string exactly, character-for-character?",
          "question": "Can trailing slashes or subdomains bypass issuer checks?",
          "hint": "Discrepancies in trailing slashes (`https://auth.com` vs `https://auth.com/`) or subdomain aliasing allow attackers to spoof identity providers and substitute tokens across different realms.",
          "sampleAnswer": "OIDC specifications require strict binary equality for the `issuer` identifier. If a client accepts mismatched issuer values, an attacker who compromises a test realm or partner IdP can issue tokens that the client mistakenly attributes to the primary enterprise authority.",
          "keyTakeaway": "Enforce exact literal matching between discovery URL and `issuer` claim."
    }
  },
  {
    ruleNumber: 201,
    id: "SEC-OAUTH-201",
    title: "JWKS Key ID (kid) SQL/Path Injection Prevention Invariant",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Key Discovery Hardening",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["RFC 7517", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 kid \u2208 JWTHeaders, SanitizeKID(kid) \u2227 IsAlphanumeric(kid) \u2227 kid \u2209 PathTraversalSequences",
    symbolBreakdown: [
          {
                "symbol": "kid",
                "meaning": "Key ID header in JWT specifying which public key in JWKS signed the token"
          },
          {
                "symbol": "IsAlphanumeric",
                "meaning": "Strict character whitelist rejecting quotes, dashes, or slashes"
          }
    ],
    plainEnglish: "When resolving public keys using the JWT `kid` (Key ID) header, the server must sanitize and validate `kid` as a safe alphanumeric identifier. Raw `kid` strings must never be passed to SQL queries, file system lookups, or shell commands.",
    whyItMatters: "Attackers inject directory traversal in `kid`: `\"kid\": \"../../dev/null\"` or SQL injection: `\"kid\": \"' UNION SELECT 'secret'--\"`. If the server uses `kid` to read keys from disk, it reads `/dev/null` (an empty string), verifying a token signed with an empty secret.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Path traversal in kid key resolution\ndef get_key(kid):\n    # Attacker sends kid='../../dev/null'!\n    with open(f\"/etc/keys/{kid}.pem\", \"r\") as f:\n        return f.read()",
          "explanation": "Allows attacker to force key lookup against empty files or known system paths."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: In-memory JWKS dictionary lookup with strict regex validation\nKID_REGEX = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')\n\ndef get_key(kid, jwks):\n    if not kid or not KID_REGEX.match(kid):\n        raise SecurityError('Invalid kid format')\n    key = jwks.get(kid)\n    if not key:\n        raise SecurityError('Key ID not found in authorized JWKS')\n    return key",
          "explanation": "Constrains kid to safe format and performs lookup in an in-memory dictionary."
    },
    howToTest: {
          "tools": [
                "jwt-tool",
                "curl"
          ],
          "steps": [
                "Forge token with header `\"kid\": \"../../../../dev/null\"`.",
                "Send to API; verify server rejects with 401: 'Invalid kid format'."
          ],
          "commandExample": "python3 -m jwt_tool token -I -hc kid -hv \"../../dev/null\""
    },
    interviewChallenge: {
          "scenario": "How did the famous 'Directory Traversal in Key ID' vulnerability against the `node-jose` and `ruby-jwt` libraries work?",
          "question": "What file did attackers point to?",
          "hint": "Attackers pointed `kid` to `/dev/null` or empty configuration files. Because an empty file has a length of 0 bytes, the HMAC verification checked the token against an empty secret `\"\"`, allowing instantaneous signature forgery.",
          "sampleAnswer": "When an application resolved public keys by dynamically reading `/keys/${header.kid}`, passing `../../../../dev/null` caused the file reader to return an empty string. The JWT library then verified the signature using an empty HMAC key `\"\"`. An attacker could sign any administrative payload with an empty key and achieve full root bypass.",
          "keyTakeaway": "Never resolve `kid` via file paths or SQL queries; use strict in-memory key maps."
    }
  },
  {
    ruleNumber: 202,
    id: "SEC-OAUTH-202",
    title: "Client Secret Storage in Public Clients (Mobile/SPA) Prohibition",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Client Credentials",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["RFC 6749 \u00a72.1", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 client \u2208 PublicClients_{Mobile, SPA}, StoresClientSecret(client) = False \u2227 AuthMethod(client) = PKCE_Only",
    symbolBreakdown: [
          {
                "symbol": "PublicClients",
                "meaning": "Applications running entirely in browser JavaScript or compiled mobile native apps"
          },
          {
                "symbol": "StoresClientSecret = False",
                "meaning": "Prohibition of embedded client_secret in client bundles"
          }
    ],
    plainEnglish: "Public clients (Single Page Applications, iOS/Android mobile apps, desktop apps) must never possess or transmit a `client_secret`. Public clients must use the Authorization Code Flow with PKCE without client credentials.",
    whyItMatters: "Embedding a `client_secret` in a React app or mobile APK is completely futile: any user can open Chrome DevTools or decompile the APK with `apktool` in 10 seconds, extracting the secret and impersonating the application.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Hardcoding client_secret in React frontend\nconst oauthConfig = {\n    clientId: 'my_client_id',\n    clientSecret: 'secret_1234567890abcdef' // Leaked to every visitor in bundle.js!\n};",
          "explanation": "Exposes secret to all web visitors and automated scrapers."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Public client configuration without client_secret\nconst oauthConfig = {\n    clientId: 'my_public_app',\n    // No clientSecret! Protected via PKCE S256:\n    usePKCE: true,\n    codeChallengeMethod: 'S256'\n};",
          "explanation": "Conforms to RFC 6749 public client specifications without secret leakage."
    },
    howToTest: {
          "tools": [
                "strings on mobile APK",
                "grep on webpack bundle"
          ],
          "steps": [
                "Inspect compiled JavaScript bundle: `grep -rn 'client_secret' ./dist/`.",
                "Confirm zero client secrets are packaged in client-facing builds."
          ],
          "commandExample": "grep -rn 'client_secret' dist/"
    },
    interviewChallenge: {
          "scenario": "Why is a compiled iOS or Android mobile binary considered a 'Public Client' rather than a 'Confidential Client' in OAuth architecture?",
          "question": "Can binary obfuscation protect a client_secret?",
          "hint": "No. Decompilers (Ghidra, apktool, Frida) extract embedded strings in seconds. A client is only confidential if code executes on a private, secured server where users cannot inspect memory.",
          "sampleAnswer": "Confidentiality requires that end-users and attackers cannot inspect the execution environment or memory. Because users physically own mobile devices, they can run debuggers, extract runtime strings, inspect memory via Frida, and decompile binaries. Therefore, mobile apps are public clients by definition.",
          "keyTakeaway": "Treat mobile and browser clients as public; never embed client secrets in client code."
    }
  },
  {
    ruleNumber: 203,
    id: "SEC-OAUTH-203",
    title: "Resource Owner Password Credentials (ROPC) Deprecation",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Legacy Grants",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["RFC 9700 \u00a72.4", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 req \u2208 TokenRequests, req.GrantType \u2260 \"password\"",
    symbolBreakdown: [
          {
                "symbol": "grant_type = 'password'",
                "meaning": "Resource Owner Password Credentials grant passing username and password directly to /token"
          }
    ],
    plainEnglish: "The Resource Owner Password Credentials (ROPC / 'password' grant) is officially deprecated and prohibited by RFC 9700 and OAuth 2.1. Authorization servers must reject `grant_type=password` requests.",
    whyItMatters: "ROPC trains users to enter their master passwords directly into third-party client apps, bypasses multi-factor authentication (MFA), and exposes user passwords to client memory compromise and credential logging.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Supporting deprecated ROPC password grant\nif request.grant_type == 'password':\n    user = verify_password(request.username, request.password)\n    return issue_tokens(user)",
          "explanation": "Circumvents SSO, bypasses MFA, and exposes master password directly to client."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Rejecting ROPC grant per RFC 9700\nif request.grant_type == 'password':\n    raise UnsupportedGrantTypeError(\n        'grant_type=password is deprecated. Use Authorization Code with PKCE.'\n    )",
          "explanation": "Enforces browser-based redirection flow with modern MFA support."
    },
    howToTest: {
          "tools": [
                "curl",
                "OAuth conformance suite"
          ],
          "steps": [
                "Send request with `grant_type=password`.",
                "Verify server returns 400 Bad Request with `unsupported_grant_type`."
          ],
          "commandExample": "curl -X POST -d 'grant_type=password&username=u&password=p' https://auth.target.com/token"
    },
    interviewChallenge: {
          "scenario": "Why does the ROPC ('password' grant) completely dismantle federated Single Sign-On (SSO) and biometric authentication?",
          "question": "What can a client app NOT do when it accepts raw passwords?",
          "hint": "The client app cannot trigger hardware WebAuthn biometrics, conditional access device checks, or enterprise IdP MFA sheets if it only collects raw username/password strings.",
          "sampleAnswer": "ROPC reduces modern identity architecture to 1990s-style password scraping. Modern authenticators (FIDO2, WebAuthn, Touch ID, push notifications, conditional device posture checks) require rich browser interactions. ROPC bypasses the IdP's login page, breaking all advanced security controls.",
          "keyTakeaway": "Decommission the ROPC password grant entirely."
    }
  },
  {
    ruleNumber: 204,
    id: "SEC-OAUTH-204",
    title: "Token Introspection Endpoint Client Authentication Invariant",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Token Introspection",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 7662", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 req \u2208 IntrospectionRequests, AuthenticateClient(req) = True \u2227 (req.Client \u2208 AuthorizedResourceServers)",
    symbolBreakdown: [
          {
                "symbol": "IntrospectionRequests",
                "meaning": "POST requests to /oauth/introspect querying token validity"
          },
          {
                "symbol": "AuthenticateClient",
                "meaning": "Mandatory client credentials or mTLS certificate check on the caller"
          }
    ],
    plainEnglish: "The OAuth 2.0 Token Introspection endpoint (`/oauth/introspect`) defined in RFC 7662 must enforce strict client authentication. Only pre-authorized internal resource servers may introspect tokens; unauthenticated access is prohibited.",
    whyItMatters: "If the introspection endpoint is public or unauthenticated, an attacker can submit random strings or intercepted tokens to learn user IDs, scopes, tenant partitions, and expiration dates without authorization.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Unauthenticated token introspection endpoint\n@app.post('/oauth/introspect')\ndef introspect(token: str):\n    # FLAW: Anyone on the Internet can introspect tokens and harvest user metadata!\n    return get_token_metadata(token)",
          "explanation": "Allows unauthorized attackers to probe token validity and extract user scopes."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Mandatory client authentication on introspection (RFC 7662)\n@app.post('/oauth/introspect')\ndef introspect(token: str, client = Depends(authenticate_resource_server)):\n    # Only verified internal microservices can query token state:\n    return verify_and_get_token_metadata(token)",
          "explanation": "Guarantees only authorized resource servers can query token status."
    },
    howToTest: {
          "tools": [
                "curl",
                "unit tests"
          ],
          "steps": [
                "Attempt to call `/oauth/introspect` without client credentials; verify 401 Unauthorized."
          ],
          "commandExample": "curl -X POST -d 'token=abc' https://auth.target.com/oauth/introspect"
    },
    interviewChallenge: {
          "scenario": "What sensitive security information does an RFC 7662 token introspection response disclose?",
          "question": "What claims are returned in an introspection JSON object?",
          "hint": "It discloses the user's `sub`, `scope`, `client_id`, `exp`, `tenant_id`, and active status, revealing authorization boundaries to anyone who queries the endpoint.",
          "sampleAnswer": "An introspection response returns the full metadata payload of the token: `{\"active\": true, \"scope\": \"read write admin\", \"client_id\": \"crm_app\", \"sub\": \"user_99\"}`. In the hands of an attacker, this metadata facilitates user enumeration, scope discovery, and token expiration mapping.",
          "keyTakeaway": "Require mutual authentication on all token introspection endpoints."
    }
  },
  {
    ruleNumber: 205,
    id: "SEC-OAUTH-205",
    title: "Token Revocation Endpoint RFC 7009 Instant Invalidation",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Token Revocation",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["RFC 7009", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 req \u2208 RevocationRequests, RevokeToken(req.Token) \u21d2 (Status(req.Token) = Inactive \u2227 Status(AssociatedTokens) = Inactive)",
    symbolBreakdown: [
          {
                "symbol": "RevocationRequests",
                "meaning": "POST requests to /oauth/revoke per RFC 7009"
          },
          {
                "symbol": "AssociatedTokens",
                "meaning": "Refresh token revokes its paired access tokens"
          }
    ],
    plainEnglish: "The OAuth 2.0 Token Revocation endpoint (`/oauth/revoke`) must immediately invalidate the submitted token and all associated tokens (e.g. revoking a refresh token must invalidate its issued access tokens) per RFC 7009.",
    whyItMatters: "When a user clicks 'Disconnect Google Integration', if the application only deletes the token locally without calling `/oauth/revoke`, the token remains active on the provider for months, allowing attackers who breach backups to access user data.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Client disconnects without calling revocation endpoint\ndef disconnect_service(user):\n    user.oauth_token = None # Local wipe only! Token remains active at IdP!\n    db.save(user)",
          "explanation": "Leaves live credentials active on the authorization server indefinitely."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: RFC 7009 Token Revocation request\ndef disconnect_service(user):\n    # Notify IdP to destroy token permanently:\n    requests.post('https://auth.provider.com/oauth/revoke', data={\n        'token': user.refresh_token,\n        'token_type_hint': 'refresh_token',\n        'client_id': CLIENT_ID,\n        'client_secret': CLIENT_SECRET\n    })\n    user.oauth_token = None\n    db.save(user)",
          "explanation": "Destroys credential on authorization server and invalidates token downstream."
    },
    howToTest: {
          "tools": [
                "curl",
                "OAuth testbench"
          ],
          "steps": [
                "Call `/oauth/revoke` with valid token.",
                "Immediately attempt to use token on API; verify 401 Unauthorized."
          ],
          "commandExample": "curl -X POST -u \"client:secret\" -d 'token=abc' https://auth.target.com/oauth/revoke"
    },
    interviewChallenge: {
          "scenario": "Why does RFC 7009 mandate that `/oauth/revoke` must return HTTP 200 OK even if the submitted token does not exist or was already revoked?",
          "question": "Why not return 404?",
          "hint": "Returning 404 would leak information about whether a token string was valid, enabling token enumeration attacks.",
          "sampleAnswer": "RFC 7009 specifies that revocation requests for invalid, expired, or non-existent tokens must still return HTTP 200 OK. This prevents attackers from using the revocation endpoint as an oracle to test whether a guessed token string is active in the database.",
          "keyTakeaway": "Return HTTP 200 OK unconditionally on revocation to prevent token enumeration."
    }
  },
  {
    ruleNumber: 206,
    id: "SEC-OAUTH-206",
    title: "Scope Downgrade / Consent Phishing Mitigation Invariant",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Consent Architecture",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 6749 \u00a73.3", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 consent \u2208 UserConsents, RenderExplicitScopes(consent) \u2227 IssuedScopes(Token) \u2286 ApprovedScopes(consent)",
    symbolBreakdown: [
          {
                "symbol": "UserConsents",
                "meaning": "Interactive consent screens displaying requested API access"
          },
          {
                "symbol": "RenderExplicitScopes",
                "meaning": "Clear, human-readable description of requested permissions"
          },
          {
                "symbol": "IssuedScopes \u2286 ApprovedScopes",
                "meaning": "Token scopes cannot exceed user approval"
          }
    ],
    plainEnglish: "The authorization server must display an explicit, unbundled consent screen clearly identifying the requested scopes and client identity. The server must never issue scopes that were not approved by the user, and must mitigate Consent Phishing.",
    whyItMatters: "In Consent Phishing (Illicit Consent Grants), an attacker registers an OAuth app named 'Microsoft Office Update' and requests `Mail.ReadWrite`. Users click 'Accept' thinking it is an official tool, granting the attacker permanent access to all corporate emails.",
    vulnerableExample: {
          "language": "html",
          "code": "# VULNERABLE: Bundled or deceptive consent screen\n<!-- Displays technical scope strings like 'offline_access User.ReadWrite.All' without clear risk explanations -->",
          "explanation": "Tricks users into granting broad permissions to deceptive third-party apps."
    },
    secureExample: {
          "language": "html",
          "code": "# SECURE: Explicit unbundled consent screen with publisher verification\n<!-- Clearly displays: Verified Publisher badge, exact granular permissions, and separate toggle checkboxes -->\n<div class=\"consent-card\">\n  <h3>App: Acme CRM (Verified Publisher)</h3>\n  <p>Requests permission to: Read your calendar events</p>\n  <button onclick=\"approve()\">Grant Scoped Access</button>\n</div>",
          "explanation": "Prevents consent phishing by showing verified publisher badges and granular toggles."
    },
    howToTest: {
          "tools": [
                "browser consent test",
                "OAuth policy validator"
          ],
          "steps": [
                "Inspect OAuth consent screen.",
                "Confirm publisher domain is verified and high-risk scopes (e.g. Mail.Read) display prominent security warnings."
          ],
          "commandExample": "node -e 'console.log(\"Testing OAuth consent screen scope display\")'"
    },
    interviewChallenge: {
          "scenario": "What is an 'Illicit Consent Grant' attack in enterprise Microsoft 365 / Google Workspace environments, and why does it bypass MFA?",
          "question": "Why doesn't changing passwords stop an illicit consent grant?",
          "hint": "Because the user legitimately signed in and granted OAuth consent to the attacker's third-party app, the attacker has their own OAuth refresh token. Password changes and MFA do not revoke third-party OAuth app tokens.",
          "sampleAnswer": "In an Illicit Consent Grant attack, no credentials are stolen. The victim signs into their legitimate account and grants permissions to an attacker-controlled OAuth application. The attacker receives an OAuth token with API access. Because access is token-based, future password rotations and MFA resets do not disconnect the app until an admin revokes the OAuth grant.",
          "keyTakeaway": "Enforce admin consent workflows for third-party OAuth applications in enterprise environments."
    }
  },
  {
    ruleNumber: 207,
    id: "SEC-OAUTH-207",
    title: "Pushed Authorization Requests (PAR) RFC 9126 Enforcement",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Front-Channel Hardening",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["RFC 9126", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 auth \u2208 AuthorizationFlows, InitiatedViaPAR(auth) = True \u2227 (request_uri = \"urn:ietf:params:oauth:request_uri:\" + UUID)",
    symbolBreakdown: [
          {
                "symbol": "InitiatedViaPAR",
                "meaning": "Client pushes authorization parameters directly to back-channel /as/par endpoint"
          },
          {
                "symbol": "request_uri",
                "meaning": "Single-use reference URI passed in browser redirect"
          }
    ],
    plainEnglish: "High-security OAuth deployments must mandate Pushed Authorization Requests (PAR) per RFC 9126. Clients must push authorization parameters directly to the back-channel `/as/par` endpoint rather than passing query parameters in the browser URL.",
    whyItMatters: "Passing authorization parameters (`client_id`, `redirect_uri`, `scope`, `claims`) in the front-channel browser URL exposes parameters to URL length limits, browser history, network proxies, and query string manipulation attacks.",
    vulnerableExample: {
          "language": "http",
          "code": "# VULNERABLE: Front-channel URL containing all parameters in query string\nGET /authorize?client_id=123&redirect_uri=https://app.com/cb&scope=read+write&state=xyz HTTP/1.1\nHost: auth.example.com",
          "explanation": "Exposes all parameters to proxy logs, browser history, and parameter tampering."
    },
    secureExample: {
          "language": "http",
          "code": "# SECURE: Pushed Authorization Request (RFC 9126)\n# Step 1: Client POSTs parameters over back-channel:\nPOST /as/par HTTP/1.1\nHost: auth.example.com\nContent-Type: application/x-www-form-urlencoded\n\nclient_id=123&redirect_uri=https://app.com/cb&scope=read+write&state=xyz\n\n# Response returns single-use request_uri:\n{\"request_uri\": \"urn:ietf:params:oauth:request_uri:6b12a8...\", \"expires_in\": 60}\n\n# Step 2: Browser redirect only contains opaque request_uri:\nGET /authorize?client_id=123&request_uri=urn:ietf:params:oauth:request_uri:6b12a8...",
          "explanation": "Shields authorization parameters from front-channel inspection and tampering."
    },
    howToTest: {
          "tools": [
                "curl",
                "PAR test suite"
          ],
          "steps": [
                "Send authorization request directly to `/authorize` without `request_uri`.",
                "Verify server rejects with 400: 'Pushed Authorization Requests (PAR) required'."
          ],
          "commandExample": "curl -X POST -u \"client:secret\" -d 'response_type=code' https://auth.target.com/as/par"
    },
    interviewChallenge: {
          "scenario": "Why does RFC 9126 Pushed Authorization Requests (PAR) provide immediate client authentication BEFORE the user ever sees the login screen?",
          "question": "When is the client authenticated in PAR?",
          "hint": "In PAR, the client authenticates using client_secret or private_key_jwt during the initial POST to `/as/par` before the browser is redirected, ensuring rogue apps cannot initiate flows.",
          "sampleAnswer": "In traditional OAuth, client authentication only occurs at the very end when the code is exchanged at `/token`. In PAR, the client must authenticate during Step 1 at `/as/par` before the user is ever redirected to the login page. This prevents unauthorized clients from initiating authorization flows or tricking users with fake consent screens.",
          "keyTakeaway": "Enforce Pushed Authorization Requests (PAR) for enterprise and financial APIs."
    }
  },
  {
    ruleNumber: 208,
    id: "SEC-OAUTH-208",
    title: "Rich Authorization Requests (RAR) Fine-Grained Authorization Invariant",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Advanced Authorization",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["RFC 9396", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 rar \u2208 RichAuthRequests, ValidateAuthDetails(rar.authorization_details, Schema) = True \u2227 BindToToken(rar.authorization_details)",
    symbolBreakdown: [
          {
                "symbol": "RichAuthRequests",
                "meaning": "OAuth requests utilizing authorization_details JSON structure"
          },
          {
                "symbol": "ValidateAuthDetails",
                "meaning": "Schema validation of fine-grained payment or resource instructions per RFC 9396"
          }
    ],
    plainEnglish: "When an application requests fine-grained transaction permissions (e.g. initiating a bank transfer for exactly $500 to account #1234), it must use Rich Authorization Requests (RAR) per RFC 9396 instead of coarse scope strings.",
    whyItMatters: "Coarse scope strings like `scope=payment` only convey binary permission (can make payments: yes/no). An attacker can hijack the authorization flow to transfer $500,000 instead of the $50 intended by the user.",
    vulnerableExample: {
          "language": "json",
          "code": "// VULNERABLE: Coarse scope string lacking transaction bounds\n// GET /authorize?scope=payment_initiate\n// Allows ANY payment of ANY amount to ANY recipient!",
          "explanation": "Lacks transaction-specific constraints."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: RFC 9396 Rich Authorization Request (authorization_details)\n{\n  \"type\": \"payment_initiation\",\n  \"instructedAmount\": {\n    \"amount\": \"50.00\",\n    \"currency\": \"USD\"\n  },\n  \"creditorAccount\": {\n    \"iban\": \"US1234567890\"\n  }\n}",
          "explanation": "Cryptographically locks authorization strictly to the specific $50 payment instruction."
    },
    howToTest: {
          "tools": [
                "curl",
                "RAR testbench"
          ],
          "steps": [
                "Send authorization request with invalid `authorization_details` JSON schema.",
                "Verify server rejects with 400 Bad Request: `invalid_authorization_details`."
          ],
          "commandExample": "node -e 'console.log(\"Testing RFC 9396 Rich Authorization Requests\")'"
    },
    interviewChallenge: {
          "scenario": "How does RFC 9396 Rich Authorization Requests (RAR) solve the limitation of OAuth 2.0 scope strings for Open Banking APIs?",
          "question": "Can scopes encode structured JSON parameters?",
          "hint": "Scope strings are simple space-delimited words that cannot represent structured data (amounts, account numbers, currencies). RAR provides a structured JSON object (`authorization_details`) for granular intent.",
          "sampleAnswer": "OAuth scopes were designed for coarse permissions (`read:email`). In financial transactions, permissions must be granular (`transfer $25.00 to account X`). Attempting to encode this in scope strings produces unmanageable strings (`scope=transfer_25_USD_accountX`). RAR allows rich, structured JSON authorization contracts.",
          "keyTakeaway": "Deploy RFC 9396 RAR for fine-grained transactional authorization."
    }
  },
  {
    ruleNumber: 209,
    id: "SEC-OAUTH-209",
    title: "Cross-Tenant Token Substitution Prevention (iss and aud Match)",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Federation Security",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["RFC 8725", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 token \u2208 MultiTenantTokens, (token.iss = ExpectedIdP) \u2227 (token.tid = ExpectedTenantID)",
    symbolBreakdown: [
          {
                "symbol": "MultiTenantTokens",
                "meaning": "Tokens accepted by multi-tenant SaaS APIs"
          },
          {
                "symbol": "token.iss",
                "meaning": "Issuer identifier"
          },
          {
                "symbol": "token.tid",
                "meaning": "Tenant ID claim verified against database record"
          }
    ],
    plainEnglish: "Multi-tenant APIs accepting federated identity tokens must verify both `iss` (issuer) and `tid` (tenant ID). A token issued by Azure AD or Okta for Tenant Alpha must never be accepted to authorize operations in Tenant Beta.",
    whyItMatters: "An attacker creates their own free tenant in Azure AD, logs into the SaaS app, and presents their token to another enterprise customer's tenant endpoint. If the backend only checks that the token is signed by Microsoft, cross-tenant takeover succeeds.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Only checking that token was signed by Microsoft Azure AD\ndef authenticate(token):\n    payload = jwt.verify(token, AZURE_JWKS)\n    # FLAW: Doesn't verify that payload['tid'] matches the requested organization!\n    return payload",
          "explanation": "Allows any Azure AD user in the world to access another company's tenant data."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Enforcing tenant ID binding in token claims (RFC 8725)\ndef authenticate(token, requested_org):\n    payload = jwt.verify(token, AZURE_JWKS, issuer=f'https://login.microsoftonline.com/{requested_org.azure_tenant_id}/v2.0')\n    if payload.get('tid') != requested_org.azure_tenant_id:\n        raise SecurityException('Cross-tenant token substitution blocked: tenant ID mismatch')\n    return payload",
          "explanation": "Guarantees token was issued specifically for the target enterprise tenant."
    },
    howToTest: {
          "tools": [
                "curl",
                "Azure AD multi-tenant testbench"
          ],
          "steps": [
                "Send token from Tenant A to Tenant B endpoint.",
                "Verify server returns 401 Unauthorized: 'Tenant ID mismatch'."
          ],
          "commandExample": "curl -H \"Authorization: Bearer tenantA_token\" https://api.target.com/tenants/tenantB/data"
    },
    interviewChallenge: {
          "scenario": "Why is the Azure AD 'Common' endpoint (`https://login.microsoftonline.com/common/v2.0`) particularly dangerous if API verifiers do not check the `tid` claim?",
          "question": "What does the common endpoint accept?",
          "hint": "The common endpoint accepts logins from ANY Microsoft account in the world (personal, educational, corporate).",
          "sampleAnswer": "When an app configures Azure AD with the `/common/` endpoint, Microsoft issues validly signed tokens for any of its 1 billion users. If the application checks only the digital signature without verifying that `tid` matches its approved customer organization, anyone with a Hotmail account can log into the enterprise database.",
          "keyTakeaway": "Always validate `iss` and `tid` against the customer's specific tenant identifier."
    }
  },
  {
    ruleNumber: 210,
    id: "SEC-OAUTH-210",
    title: "OIDC ID Token at_hash and c_hash Verification Invariant",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "OIDC Hybrid Flow",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["OIDC Core 1.0 \u00a73.3.2.11", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 idToken \u2208 HybridFlowIDTokens, VerifyHash(idToken.at_hash, AccessToken) = True \u2227 VerifyHash(idToken.c_hash, AuthCode) = True",
    symbolBreakdown: [
          {
                "symbol": "HybridFlowIDTokens",
                "meaning": "ID Tokens issued alongside access tokens or authorization codes on the front channel"
          },
          {
                "symbol": "at_hash",
                "meaning": "Base64URL SHA-256 of left-most half of access token"
          },
          {
                "symbol": "c_hash",
                "meaning": "Base64URL SHA-256 of left-most half of authorization code"
          }
    ],
    plainEnglish: "When an ID Token is returned alongside an access token or authorization code in the front channel (Hybrid Flow), the client must cryptographically verify the `at_hash` and `c_hash` claims to guarantee token integrity.",
    whyItMatters: "Without `at_hash` and `c_hash` verification, an attacker who intercepts the front-channel redirect can swap out the access token for their own while leaving the legitimate ID Token untouched, hijacking the user's session.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Accepting access token without verifying at_hash\ndef handle_hybrid(id_token, access_token):\n    claims = verify_jwt(id_token)\n    # FLAW: Does not verify that access_token matches claims['at_hash']!\n    save_session(claims['sub'], access_token)",
          "explanation": "Vulnerable to access token substitution on the front-channel redirect."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Cryptographic verification of at_hash (OIDC Core \u00a73.3.2.11)\ndef handle_hybrid(id_token, access_token):\n    claims = verify_jwt(id_token)\n    expected_at_hash = claims.get('at_hash')\n    # Compute SHA-256 of access token and take first 128 bits (16 bytes):\n    digest = hashlib.sha256(access_token.encode()).digest()[:16]\n    computed_hash = base64url(digest)\n    if not crypto.timingSafeEqual(computed_hash, expected_at_hash):\n        raise SecurityError('at_hash verification failed: access token was substituted!')\n    save_session(claims['sub'], access_token)",
          "explanation": "Cryptographically proves the access token was issued in the same transaction as the ID Token."
    },
    howToTest: {
          "tools": [
                "oidc-debugger",
                "unit tests"
          ],
          "steps": [
                "Substitute access token in hybrid flow redirect; confirm at_hash check fails."
          ],
          "commandExample": "node -e 'console.log(\"Testing OIDC at_hash verification\")'"
    },
    interviewChallenge: {
          "scenario": "How is the `at_hash` value mathematically derived from an access token in OpenID Connect?",
          "question": "What hash algorithm and what slice of the hash is used?",
          "hint": "The hash algorithm is determined by the ID Token's signing algorithm (e.g. SHA-256 for RS256). The access token is hashed, and the left-most half (first 16 bytes for SHA-256) is base64URL encoded.",
          "sampleAnswer": "If the ID Token is signed with RS256, the client computes the SHA-256 hash of the ASCII access token. It takes the first 128 bits (first half of the 256-bit hash) and encodes it with base64URL. If this matches `at_hash` in the signed ID token, the access token is mathematically bound to the ID token.",
          "keyTakeaway": "Always verify `at_hash` and `c_hash` when processing OIDC hybrid responses."
    }
  },
  {
    ruleNumber: 211,
    id: "SEC-OAUTH-211",
    title: "OAuth 2.0 Authorization Server Metadata RFC 8414 Conformance",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "IdP Metadata",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["RFC 8414", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 as \u2208 AuthorizationServers, ExistsMetadata(as, \"/.well-known/oauth-authorization-server\") \u2227 ValidatesJWKS_URI(as)",
    symbolBreakdown: [
          {
                "symbol": "AuthorizationServers",
                "meaning": "OAuth 2.0 Identity Providers"
          },
          {
                "symbol": "RFC 8414",
                "meaning": "Standardized server metadata discovery endpoint"
          }
    ],
    plainEnglish: "OAuth 2.0 Authorization Servers must publish their metadata document conforming to RFC 8414 at `/.well-known/oauth-authorization-server`. Servers must advertise supported grant types, signing algorithms, and endpoint URLs.",
    whyItMatters: "Hardcoding authorization server endpoint URLs in client configurations causes outages when providers rotate keys or change token endpoints, and prevents automated security configuration validation.",
    vulnerableExample: {
          "language": "json",
          "code": "// VULNERABLE: Client hardcodes brittle endpoint URLs\n{\n  \"authorize\": \"https://auth.com/oauth2/v1/auth\",\n  \"token\": \"https://auth.com/oauth2/v1/token\"\n  // Missing automated discovery and key rotation updates!\n}",
          "explanation": "Fails to discover updated security endpoints and key rotation schedules."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: RFC 8414 compliant discovery metadata document\n{\n  \"issuer\": \"https://auth.example.com\",\n  \"authorization_endpoint\": \"https://auth.example.com/oauth2/v1/authorize\",\n  \"token_endpoint\": \"https://auth.example.com/oauth2/v1/token\",\n  \"jwks_uri\": \"https://auth.example.com/oauth2/v1/keys\",\n  \"token_endpoint_auth_methods_supported\": [\"private_key_jwt\", \"client_secret_post\"],\n  \"code_challenge_methods_supported\": [\"S256\"]\n}",
          "explanation": "Allows client applications to automatically discover endpoints and enforce secure parameters."
    },
    howToTest: {
          "tools": [
                "curl",
                "RFC 8414 validator"
          ],
          "steps": [
                "Fetch `/.well-known/oauth-authorization-server`.",
                "Verify JSON contains required fields: `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`."
          ],
          "commandExample": "curl -s https://auth.target.com/.well-known/oauth-authorization-server | jq ."
    },
    interviewChallenge: {
          "scenario": "How does RFC 8414 OAuth Metadata differ from OpenID Connect Discovery 1.0?",
          "question": "Where is the discovery file located in each standard?",
          "hint": "OpenID Connect discovery is located at `/.well-known/openid-configuration`; RFC 8414 OAuth discovery is located at `/.well-known/oauth-authorization-server` or at the path suffix.",
          "sampleAnswer": "OpenID Connect discovery defines OIDC-specific identity fields (`userinfo_endpoint`, `claims_supported`, `id_token_signing_alg_values_supported`). RFC 8414 is a generalized discovery specification for pure OAuth 2.0 authorization servers that may not support OpenID Connect (e.g. machine-to-machine APIs).",
          "keyTakeaway": "Support RFC 8414 metadata for OAuth servers and OIDC Discovery for identity providers."
    }
  },
  {
    ruleNumber: 212,
    id: "SEC-OAUTH-212",
    title: "JWT \"typ\" Header Explicit Verification (typ: \"at+jwt\") Invariant",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Token Confusion",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 9068", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 token \u2208 APIAccessTokens, Header(token).typ = \"at+jwt\" \u2228 Header(token).typ = \"application/at+jwt\"",
    symbolBreakdown: [
          {
                "symbol": "APIAccessTokens",
                "meaning": "JWT access tokens consumed by resource servers"
          },
          {
                "symbol": "typ: 'at+jwt'",
                "meaning": "RFC 9068 explicit type header identifying JWT as an access token"
          }
    ],
    plainEnglish: "Resource servers validating JWT access tokens must verify the `typ` header is explicitly set to `at+jwt` per RFC 9068. Systems must never accept tokens with missing or incorrect `typ` headers to prevent Token Confusion attacks.",
    whyItMatters: "In Token Confusion attacks, an attacker takes an OpenID Connect ID Token (which has `typ: JWT`) and submits it to an API endpoint expecting an access token. Because both tokens are signed by the same IdP, the API accepts the ID token, bypassing scope and audience checks.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Verifying JWT without checking typ header\ndef verify_token(token):\n    payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])\n    # FLAW: Accepts ID tokens or refresh tokens as access tokens!\n    return payload",
          "explanation": "Vulnerable to Token Confusion: accepts ID tokens where access tokens are required."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Explicit typ header verification per RFC 9068\ndef verify_access_token(token):\n    header = jwt.get_unverified_header(token)\n    if header.get('typ') != 'at+jwt':\n        raise SecurityError('Invalid token type: expected at+jwt (RFC 9068)')\n    return jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'], audience='https://api.example.com')",
          "explanation": "Enforces strict token type separation, preventing ID tokens from masquerading as access tokens."
    },
    howToTest: {
          "tools": [
                "jwt.io",
                "curl"
          ],
          "steps": [
                "Send ID token (with `typ: JWT`) to API endpoint.",
                "Verify API rejects request with 401 Unauthorized: 'Invalid token type: expected at+jwt'."
          ],
          "commandExample": "node -e 'console.log(\"Testing RFC 9068 typ header validation\")'"
    },
    interviewChallenge: {
          "scenario": "What is an 'Access Token vs ID Token Confusion' attack, and how does RFC 9068 mitigate it?",
          "question": "Why are ID tokens not meant for APIs?",
          "hint": "An ID token is intended strictly for the client application to read user profile information; an access token is intended for resource servers (APIs) to authorize operations.",
          "sampleAnswer": "An ID token contains user identity claims intended for the frontend client app, but lacks API scopes. If an API accepts any token signed by the IdP without checking `typ: at+jwt`, an attacker can use an ID token from a harmless mobile app to bypass API scope restrictions. RFC 9068 explicitly distinguishes access tokens.",
          "keyTakeaway": "Enforce `typ: 'at+jwt'` on all JWT access token verifiers."
    }
  },
  {
    ruleNumber: 213,
    id: "SEC-OAUTH-213",
    title: "JWKS Caching and Cache-Control Header Respect Invariant",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Key Rotation Resilience",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["RFC 7517", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 req \u2208 JWKS_Fetches, CacheTTL(req) \u2264 MaxJWKSCache(86400s) \u2227 OnUnknownKID(req) \u21d2 RateLimitedRefresh()",
    symbolBreakdown: [
          {
                "symbol": "JWKS_Fetches",
                "meaning": "HTTP requests fetching public keys from /.well-known/jwks.json"
          },
          {
                "symbol": "MaxJWKSCache <= 86400s",
                "meaning": "Maximum 24-hour cache lifetime"
          },
          {
                "symbol": "RateLimitedRefresh",
                "meaning": "Fetching fresh JWKS on unknown kid at most once per 60s"
          }
    ],
    plainEnglish: "Resource servers must cache the Identity Provider's JSON Web Key Set (JWKS) in memory respecting HTTP `Cache-Control` headers. If an unknown `kid` is encountered, the server must refresh the JWKS, rate-limited to at most once per 60 seconds.",
    whyItMatters: "If an API does not cache the JWKS, every single incoming API request triggers an outbound HTTP call to the IdP, creating a Denial of Service. If it caches indefinitely, rotating the IdP's signing key breaks the entire application.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Fetching JWKS on every single API request\napp.use(async (req, res, next) => {\n    // Fetches keys from network for EVERY request! Causes DDoS and latency spikes!\n    const jwks = await fetch('https://auth.com/.well-known/jwks.json').then(r => r.json());\n});",
          "explanation": "Causes network latency spikes and crashes authorization server during traffic surges."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Resilient JWKS caching with jwks-rsa\nimport jwksRsa from 'jwks-rsa';\n\nconst client = jwksRsa({\n    jwksUri: 'https://auth.com/.well-known/jwks.json',\n    cache: true,\n    cacheMaxEntries: 5,\n    cacheMaxAge: 24 * 60 * 60 * 1000, // 24 hours\n    rateLimit: true,\n    jwksRequestsPerMinute: 10 // Prevents cache-busting DoS\n});",
          "explanation": "Caches keys for 24 hours while gracefully refreshing when new signing keys appear."
    },
    howToTest: {
          "tools": [
                "k6 load test",
                "curl"
          ],
          "steps": [
                "Simulate 1,000 rapid API requests.",
                "Verify server makes only 1 outbound JWKS HTTP request and serves remaining verifications from cache."
          ],
          "commandExample": "node -e 'console.log(\"Testing JWKS cache resilience and rate limiting\")'"
    },
    interviewChallenge: {
          "scenario": "What is a 'JWKS Cache-Busting Denial of Service' attack against an API gateway?",
          "question": "How does an attacker exploit unknown `kid` lookups?",
          "hint": "An attacker sends 10,000 requests per second with random `kid` headers (`kid: uuid1`, `kid: uuid2`). If the API fetches fresh JWKS on every unknown kid, it overwhelms the IdP with outbound HTTP calls.",
          "sampleAnswer": "If an API gateway fetches the JWKS from the IdP whenever it encounters an unknown `kid`, an attacker can flood the gateway with requests containing random `kid` values. The gateway floods the IdP with discovery requests, crashing both systems. Rate-limiting JWKS refreshes (e.g. max 10/min) mitigates this attack.",
          "keyTakeaway": "Cache JWKS in memory and enforce strict rate limits on cache refreshes."
    }
  },
  {
    ruleNumber: 214,
    id: "SEC-OAUTH-214",
    title: "OAuth Token Exchange RFC 8693 Subject Delegation Bounds",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Microservices Delegation",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["RFC 8693", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 ex \u2208 TokenExchanges, ValidateAudience(ex) \u2227 ActClaimPresent(ex) \u2227 Actor(ex) = DownstreamService",
    symbolBreakdown: [
          {
                "symbol": "TokenExchanges",
                "meaning": "Requests to /token with grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
          },
          {
                "symbol": "ActClaimPresent",
                "meaning": "Mandatory 'act' (actor) claim in issued token recording delegation chain"
          }
    ],
    plainEnglish: "When microservices exchange incoming user tokens for downstream service tokens using RFC 8693, the new token must embed an explicit `act` (actor) claim documenting the delegation chain. Downstream tokens must be scoped to the target service.",
    whyItMatters: "If Microservice A blindly forwards the user's full access token to Microservice B, Microservice B can abuse that token to call unrelated billing or administrative APIs, violating microservice privilege isolation.",
    vulnerableExample: {
          "language": "json",
          "code": "// VULNERABLE: Direct token forwarding across microservice hops\n// Microservice A passes raw user token to Microservice B;\n// Microservice B can now impersonate user across ALL company services!",
          "explanation": "Violates least privilege across microservice boundaries."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: RFC 8693 Token Exchange with 'act' delegation claim\n{\n  \"sub\": \"user_123\",\n  \"aud\": \"https://api.inventory.com\",\n  \"scope\": \"inventory:read\",\n  \"act\": {\n    \"sub\": \"client:frontend_service\"\n  }\n}",
          "explanation": "Downstream service receives scoped token explicitly documenting the delegation chain."
    },
    howToTest: {
          "tools": [
                "curl",
                "OAuth Token Exchange testbench"
          ],
          "steps": [
                "Call `/token` with RFC 8693 token-exchange grant.",
                "Verify issued token contains `act` claim and scoped audience."
          ],
          "commandExample": "curl -X POST -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' https://auth.target.com/token"
    },
    interviewChallenge: {
          "scenario": "What is the difference between 'Impersonation' and 'Delegation' in RFC 8693 OAuth Token Exchange?",
          "question": "How does the audit trail differ between the two?",
          "hint": "In Impersonation, the actor acts as the subject without disclosing their own identity; in Delegation, the token explicitly records that the client is acting ON BEHALF OF the user via the `act` claim.",
          "sampleAnswer": "In impersonation, the downstream service only sees `sub: user_123` and has no record that the frontend service made the call. In delegation, the token contains `sub: user_123` AND `act: { sub: service_A }`, preserving the full provenance chain for audit logs and non-repudiation.",
          "keyTakeaway": "Enforce RFC 8693 delegation with `act` claims for inter-service token exchanges."
    }
  },
  {
    ruleNumber: 215,
    id: "SEC-OAUTH-215",
    title: "Device Authorization Grant RFC 8628 Polling Interval Bound",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Smart TV / CLI Auth",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["RFC 8628", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 poll \u2208 DevicePollRequests, (Now() - LastPoll(poll.DeviceCode)) \u2265 poll.Interval \u2228 ReturnSlowDown(400)",
    symbolBreakdown: [
          {
                "symbol": "DevicePollRequests",
                "meaning": "Smart TV, game console, or CLI polling /token with device_code"
          },
          {
                "symbol": "poll.Interval",
                "meaning": "Minimum polling interval in seconds (default 5s)"
          },
          {
                "symbol": "ReturnSlowDown",
                "meaning": "HTTP 400 with error: slow_down if client polls too fast"
          }
    ],
    plainEnglish: "The OAuth 2.0 Device Authorization Grant (`device_code`) per RFC 8628 must enforce a minimum polling interval (e.g. 5 seconds). If a device polls faster than the declared interval, the server must return `error: slow_down` and increase the interval by 5 seconds.",
    whyItMatters: "Millions of Smart TVs or CLI tools polling the token endpoint every 100 milliseconds will overwhelm the authorization server, triggering a Denial of Service outage.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Unbounded rapid polling of device code endpoint\n@app.post('/token')\ndef poll_device(device_code: str):\n    # FLAW: Allows client to poll 100 times per second without backoff!\n    if is_authorized(device_code):\n        return issue_tokens()",
          "explanation": "Enables client polling loops to overwhelm the token server."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: RFC 8628 rate-limited polling with slow_down error\n@app.post('/token')\ndef poll_device(device_code: str):\n    grant = db.get_device_grant(device_code)\n    if time.time() - grant.last_polled < grant.interval:\n        grant.interval += 5 # Penalize client by increasing interval\n        db.save(grant)\n        return Response(status_code=400, content={'error': 'slow_down'})\n    grant.last_polled = time.time()\n    if grant.status == 'PENDING':\n        return Response(status_code=400, content={'error': 'authorization_pending'})\n    return issue_tokens()",
          "explanation": "Enforces minimum polling intervals and slows down aggressive clients."
    },
    howToTest: {
          "tools": [
                "curl",
                "RFC 8628 testbench"
          ],
          "steps": [
                "Poll device code endpoint twice in 1 second.",
                "Verify server returns HTTP 400 with `error: slow_down`."
          ],
          "commandExample": "curl -X POST -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=xyz' https://auth.target.com/token"
    },
    interviewChallenge: {
          "scenario": "Why does the RFC 8628 Device Authorization Grant use both a `device_code` and a `user_code`?",
          "question": "Which code is shown on the TV screen?",
          "hint": "The `user_code` (e.g. `WDJB-KJHT`) is a short, human-friendly code shown on the TV screen for the user to type on their phone; the `device_code` is a high-entropy secret held in TV memory.",
          "sampleAnswer": "Smart TV keyboards are awkward. If a user had to type a 64-character UUID on their phone, usability would be terrible. RFC 8628 provides a short 8-character `user_code` for human entry at `example.com/activate`, while the device uses the long, unguessable `device_code` to poll the token endpoint.",
          "keyTakeaway": "Enforce slow_down backoff intervals on Device Authorization polling."
    }
  },
  {
    ruleNumber: 216,
    id: "SEC-OAUTH-216",
    title: "OAuth Front-Channel Logout iframe CSP Isolation Invariant",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Session Logout",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["OIDC Front-Channel Logout", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 iframe \u2208 FrontChannelLogoutIframes, HasAttr(iframe, \"sandbox\", \"allow-scripts\") \u2227 CSP(frame-ancestors) = IdP_Origin",
    symbolBreakdown: [
          {
                "symbol": "FrontChannelLogoutIframes",
                "meaning": "Hidden iframes rendered by IdP to trigger logout across registered RP apps"
          },
          {
                "symbol": "allow-scripts",
                "meaning": "Minimal sandbox permission"
          },
          {
                "symbol": "CSP(frame-ancestors)",
                "meaning": "Restricts framing strictly to the Identity Provider"
          }
    ],
    plainEnglish: "When an Identity Provider executes OpenID Connect Front-Channel Logout by rendering logout iframes, the iframes must be sandboxed and the client logout endpoints must enforce `Content-Security-Policy: frame-ancestors` restricted strictly to the IdP origin.",
    whyItMatters: "Without framing restrictions on the logout endpoint, any malicious website can embed `<iframe src='https://app.com/logout'>`, silently logging users out of their applications (Logout CSRF / Denial of Service).",
    vulnerableExample: {
          "language": "html",
          "code": "<!-- VULNERABLE: Open logout endpoint without framing restriction -->\n<iframe src=\"https://victim-bank.com/oauth/logout\"></iframe>",
          "explanation": "Malicious site embeds iframe to log victim out of banking portal continuously."
    },
    secureExample: {
          "language": "html",
          "code": "<!-- SECURE: CSP frame-ancestors restricted to Identity Provider -->\nHTTP/1.1 200 OK\nContent-Security-Policy: frame-ancestors https://auth.example.com;\n\n<script>\n  // Clears local session storage\n  sessionStorage.clear();\n</script>",
          "explanation": "Ensures logout endpoint can only be framed by the verified Identity Provider."
    },
    howToTest: {
          "tools": [
                "browser DevTools",
                "curl"
          ],
          "steps": [
                "Attempt embedding client logout URL in unauthorized third-party HTML page.",
                "Verify browser refuses to render iframe due to CSP frame-ancestors violation."
          ],
          "commandExample": "curl -sI https://app.example.com/oauth/logout | grep -i frame-ancestors"
    },
    interviewChallenge: {
          "scenario": "What is the operational reliability difference between OIDC 'Front-Channel Logout' and 'Back-Channel Logout'?",
          "question": "Why does Back-Channel Logout work even if the user closes their browser?",
          "hint": "Front-Channel Logout relies on browser iframes, which fail if the user closes the tab, has third-party cookie blocking, or has network drops. Back-Channel Logout sends direct server-to-server HTTP POST requests.",
          "sampleAnswer": "Front-Channel logout depends on the user's browser rendering an iframe for every single logged-in application. Modern browsers block third-party cookies by default, breaking iframe sessions. Back-Channel logout operates via direct server-to-server POST calls carrying a Logout Token, guaranteeing 100% session termination.",
          "keyTakeaway": "Prefer OIDC Back-Channel Logout over Front-Channel iframe logout."
    }
  },
  {
    ruleNumber: 217,
    id: "SEC-OAUTH-217",
    title: "Back-Channel Logout RFC 8693 Token Signature Validation",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Session Logout",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["OIDC Back-Channel Logout", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 token \u2208 LogoutTokens, VerifySignature(token) = True \u2227 HasClaim(token, \"events\") \u2227 HasNoNonce(token)",
    symbolBreakdown: [
          {
                "symbol": "LogoutTokens",
                "meaning": "Signed JWT delivered via server-to-server POST to client logout endpoint"
          },
          {
                "symbol": "HasNoNonce",
                "meaning": "OIDC specification requirement: Logout Tokens MUST NOT contain a nonce claim"
          }
    ],
    plainEnglish: "Clients receiving OpenID Connect Back-Channel Logout tokens must verify the JWT signature against the IdP's public keys, verify the `events` claim contains the logout URI, and verify the token does NOT contain a `nonce` claim.",
    whyItMatters: "Failing to verify the signature on back-channel logout endpoints allows attackers to forge logout requests, terminating user sessions across the cluster without authorization.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Accepting back-channel logout without signature check\n@app.post('/oauth/backchannel-logout')\ndef logout(logout_token: str = Form(...)):\n    payload = jwt.decode(logout_token, options={'verify_signature': False})\n    destroy_session(payload['sub'])",
          "explanation": "Attacker sends fake logout JWT to terminate arbitrary user sessions."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Cryptographic verification of Back-Channel Logout Token\n@app.post('/oauth/backchannel-logout')\ndef logout(logout_token: str = Form(...)):\n    payload = jwt.decode(logout_token, IDP_PUBLIC_KEY, algorithms=['RS256'], audience=CLIENT_ID)\n    if 'http://schemas.openid.net/event/backchannel-logout' not in payload.get('events', {}):\n        raise SecurityError('Invalid logout event in token')\n    if 'nonce' in payload:\n        raise SecurityError('Logout Token must not contain a nonce (OIDC Spec \u00a72.4)')\n    destroy_session_by_sub(payload['sub'])",
          "explanation": "Verifies signature, validates events namespace, and enforces OIDC spec compliance."
    },
    howToTest: {
          "tools": [
                "curl",
                "OIDC backchannel testbench"
          ],
          "steps": [
                "Send forged logout token.",
                "Verify endpoint returns 400 Bad Request with signature verification error."
          ],
          "commandExample": "curl -X POST -d 'logout_token=fake' https://app.example.com/oauth/backchannel-logout"
    },
    interviewChallenge: {
          "scenario": "Why does the OpenID Connect Back-Channel Logout specification explicitly mandate that a Logout Token MUST NOT contain a `nonce` claim?",
          "question": "What attack does this prohibition prevent?",
          "hint": "It prevents an attacker from replaying an old ID Token (which contains a nonce) to a Back-Channel Logout endpoint to cause a false logout.",
          "sampleAnswer": "An ID Token and a Logout Token have very similar structures. If Logout Tokens allowed nonces, an attacker who intercepted a user's ID Token could submit it to `/backchannel-logout`. The server would see a valid signature and erroneously terminate the user's session. Disallowing `nonce` guarantees structural separation.",
          "keyTakeaway": "Strictly validate OIDC Logout Tokens and verify the absence of nonce claims."
    }
  },
  {
    ruleNumber: 218,
    id: "SEC-OAUTH-218",
    title: "Access Token Leakage via Referer Header Elimination",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Browser Leakage",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["RFC 6749 \u00a710.13", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 page \u2208 OAuthCallbackPages, HeaderValue(page, \"Referrer-Policy\") \u2208 {\"no-referrer\", \"same-origin\"}",
    symbolBreakdown: [
          {
                "symbol": "OAuthCallbackPages",
                "meaning": "Redirect endpoints receiving authorization codes or tokens"
          },
          {
                "symbol": "no-referrer",
                "meaning": "Browser completely suppresses Referer header on outbound asset requests"
          }
    ],
    plainEnglish: "OAuth callback and redirect landing pages must emit `Referrer-Policy: no-referrer`. This prevents the authorization code or fragment parameters from leaking to third-party CDNs, analytics scripts, or external links.",
    whyItMatters: "When a user lands on `https://app.com/callback?code=abc1234`, if the page loads an external Google Font, analytics tracker, or partner logo without `no-referrer`, the browser sends `Referer: https://app.com/callback?code=abc1234` to the third party.",
    vulnerableExample: {
          "language": "html",
          "code": "# VULNERABLE: Default browser referrer leaks code to external trackers\n<!-- Page loads: <script src=\"https://tracker.com/analytics.js\"></script> -->\n<!-- Browser sends: Referer: https://app.com/callback?code=SECRET_CODE -->",
          "explanation": "Leaks authorization codes directly into third-party server access logs."
    },
    secureExample: {
          "language": "html",
          "code": "# SECURE: Explicit no-referrer policy header\nHTTP/1.1 200 OK\nReferrer-Policy: no-referrer\nContent-Type: text/html\n\n<!-- Browser guarantees zero Referer header is sent to any external resource -->",
          "explanation": "Completely eliminates credential leakage in outgoing HTTP requests."
    },
    howToTest: {
          "tools": [
                "browser DevTools Network tab",
                "curl"
          ],
          "steps": [
                "Load callback page in browser.",
                "Inspect third-party asset requests; confirm `Referer` header is completely omitted."
          ],
          "commandExample": "curl -sI https://app.example.com/oauth/callback | grep -i referrer-policy"
    },
    interviewChallenge: {
          "scenario": "Why does modern Chromium default to `strict-origin-when-cross-origin` instead of `no-referrer`, and why is that insufficient for OAuth callback URLs?",
          "question": "What does strict-origin-when-cross-origin still send to same-origin resources?",
          "hint": "It sends the full URL (including query parameters) to same-origin requests, leaking codes to relative assets, and older browsers do not support it.",
          "sampleAnswer": "Under `strict-origin-when-cross-origin`, the full URL path and query parameters are still sent on same-origin requests (e.g. to local CDN assets or error loggers). Furthermore, older mobile browsers send the full URL everywhere. Setting `Referrer-Policy: no-referrer` guarantees absolute suppression across all assets.",
          "keyTakeaway": "Always set `Referrer-Policy: no-referrer` on all OAuth callback endpoints."
    }
  },
  {
    ruleNumber: 219,
    id: "SEC-OAUTH-219",
    title: "OIDC Prompt=Consent Step-Up Invariant for Sensitive Scopes",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Consent Verification",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["OIDC Core 1.0", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 req \u2208 SensitiveScopeRequests, (req.Scopes \u2229 HighRiskScopes \u2260 \u2205) \u21d2 (req.Prompt = \"consent\")",
    symbolBreakdown: [
          {
                "symbol": "SensitiveScopeRequests",
                "meaning": "Requests asking for offline_access, payment scopes, or administrative writes"
          },
          {
                "symbol": "prompt = 'consent'",
                "meaning": "Forces Identity Provider to present interactive consent screen even if user previously consented"
          }
    ],
    plainEnglish: "When an OAuth client requests sensitive scopes (e.g. `offline_access`, payment permissions, or admin rights), it must pass `prompt=consent`. This forces the IdP to display an interactive consent sheet, preventing silent background token grants.",
    whyItMatters: "Attackers abuse silent background logins (`prompt=none`) to harvest tokens for newly added high-privilege scopes without the victim ever realizing permissions were expanded.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Silent authorization for high-risk permissions\nauth_url = f\"https://auth.com/authorize?client_id=123&scope=admin_write&prompt=none\"",
          "explanation": "Attempts silent background grant without user awareness."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Enforcing explicit interactive consent for sensitive scopes\nauth_url = f\"https://auth.com/authorize?client_id=123&scope=admin_write&prompt=consent\"",
          "explanation": "Forces IdP to present interactive confirmation dialog to user."
    },
    howToTest: {
          "tools": [
                "curl",
                "OIDC playground"
          ],
          "steps": [
                "Initiate flow with sensitive scope without `prompt=consent`.",
                "Verify security policy mandates prompt=consent parameter."
          ],
          "commandExample": "curl \"https://auth.target.com/authorize?scope=admin&prompt=none\""
    },
    interviewChallenge: {
          "scenario": "What is the purpose of `prompt=none` in OpenID Connect, and what error must the IdP return if user interaction is required?",
          "question": "What happens if interaction is needed?",
          "hint": "The IdP must immediately return an HTTP redirect with `error=interaction_required`, preventing UI dialogs from disrupting background iframe checks.",
          "sampleAnswer": "`prompt=none` is used for silent session checks in single-page applications. The IdP must never display UI when `prompt=none` is present. If the user is logged out, needs to grant consent, or requires MFA, the IdP must fail fast and return `error=interaction_required` or `error=login_required`.",
          "keyTakeaway": "Require `prompt=consent` when upgrading scopes to privileged tiers."
    }
  },
  {
    ruleNumber: 220,
    id: "SEC-OAUTH-220",
    title: "Dynamic Client Registration (RFC 7591) Initial Token Requirement",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Client Onboarding",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["RFC 7591", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 reg \u2208 ClientRegistrationRequests, HasBearerToken(reg) \u2227 VerifyInitialAccessToken(reg.Token) = True",
    symbolBreakdown: [
          {
                "symbol": "ClientRegistrationRequests",
                "meaning": "POST requests to /register creating new OAuth client IDs"
          },
          {
                "symbol": "VerifyInitialAccessToken",
                "meaning": "Software Statement or Initial Access Token (IAT) issued by administrator"
          }
    ],
    plainEnglish: "Dynamic Client Registration (DCR) endpoints (`/register`) conforming to RFC 7591 must require an Initial Access Token (IAT) or signed Software Statement. Public unauthenticated client registration is prohibited.",
    whyItMatters: "An unauthenticated registration endpoint allows attackers to run automated scripts that register 100,000 rogue client IDs, exhausting database capacity and bypassing client rate limits.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Unauthenticated dynamic client registration\n@app.post('/register')\ndef register_client(metadata: ClientDto):\n    # FLAW: Anyone on the Internet can register an OAuth client!\n    return db.create_client(metadata)",
          "explanation": "Enables botnets to spam client registrations and exhaust database resources."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Enforcing Initial Access Token (IAT) per RFC 7591\n@app.post('/register')\ndef register_client(metadata: ClientDto, token: str = Depends(get_bearer_token)):\n    if not verify_initial_access_token(token):\n        raise HTTPException(401, 'Valid Initial Access Token required to register clients')\n    return db.create_client(metadata)",
          "explanation": "Restricts client registration strictly to authorized developers with valid onboarding tokens."
    },
    howToTest: {
          "tools": [
                "curl",
                "RFC 7591 testbench"
          ],
          "steps": [
                "Send POST to `/register` without Authorization header.",
                "Verify server rejects with 401 Unauthorized."
          ],
          "commandExample": "curl -X POST -H \"Content-Type: application/json\" -d '{\"client_name\":\"test\"}' https://auth.target.com/register"
    },
    interviewChallenge: {
          "scenario": "What is a 'Software Statement' in RFC 7591 Dynamic Client Registration, and how does it cryptographically verify client software?",
          "question": "Who signs the software statement?",
          "hint": "A Software Statement is a signed JWT issued by a central authority (e.g. Open Banking Directory) that asserts the client's software metadata, verified public keys, and regulatory accreditation.",
          "sampleAnswer": "In regulated ecosystems like Open Banking (OBIE), third-party fintechs obtain a signed Software Statement from the central banking authority. When registering with individual banks, the fintech submits the statement. The bank validates the authority's signature, onboarding the fintech automatically without manual human review.",
          "keyTakeaway": "Require Initial Access Tokens or signed Software Statements on Dynamic Client Registration endpoints."
    }
  },
  {
    ruleNumber: 221,
    id: "SEC-OAUTH-221",
    title: "OAuth Error Response RFC 6749 Format Conformance (No Stack Traces)",
    domain: "oauth",
    domainName: "OAuth 2.0 & OIDC",
    subdomain: "Error Handling",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["RFC 6749 \u00a75.2", "RFC 9700", "OWASP ASVS \u00a73.6"],
    formalInvariant: "\u2200 err \u2208 OAuthErrorResponses, HasField(err, \"error\") \u2227 (err.error \u2208 StandardOAuthErrors) \u2227 HasStackTrace(err) = False",
    symbolBreakdown: [
          {
                "symbol": "OAuthErrorResponses",
                "meaning": "Error JSON payloads returned by token and authorization endpoints"
          },
          {
                "symbol": "StandardOAuthErrors",
                "meaning": "invalid_request, invalid_client, invalid_grant, unauthorized_client, unsupported_grant_type"
          }
    ],
    plainEnglish: "OAuth 2.0 error responses must adhere strictly to the RFC 6749 \u00a75.2 JSON specification (`error` and optional `error_description`). Responses must use standard error codes and never leak stack traces or internal server paths.",
    whyItMatters: "Returning unhandled exceptions or custom error formats breaks automated client SDK error handling and leaks database table names and library versions to attackers.",
    vulnerableExample: {
          "language": "json",
          "code": "// VULNERABLE: Custom error payload leaking stack trace\n{\n  \"status\": 500,\n  \"exception\": \"NullPointerException at com.auth.server.TokenEndpoint.java:142\",\n  \"db_query\": \"SELECT * FROM oauth_clients WHERE id = 'xyz'\"\n}",
          "explanation": "Exposes internal code paths and database syntax in error responses."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: Standard RFC 6749 \u00a75.2 compliant error response\n{\n  \"error\": \"invalid_grant\",\n  \"error_description\": \"The provided authorization code is invalid or expired.\"\n}",
          "explanation": "Returns clean, standardized OAuth error codes without internal telemetry leakage."
    },
    howToTest: {
          "tools": [
                "curl",
                "OAuth conformance suite"
          ],
          "steps": [
                "Send malformed token request.",
                "Verify response status is 400 Bad Request with valid JSON containing `error` property."
          ],
          "commandExample": "curl -X POST -d 'grant_type=bad' https://auth.target.com/token"
    },
    interviewChallenge: {
          "scenario": "What is the difference between `invalid_client` and `invalid_grant` in OAuth 2.0 error responses?",
          "question": "Which one indicates client authentication failure, and which indicates code/token failure?",
          "hint": "`invalid_client` means the client authentication failed (bad client_id or client_secret); `invalid_grant` means the authorization grant (code, refresh token, credentials) is invalid or expired.",
          "sampleAnswer": "RFC 6749 \u00a75.2 establishes strict semantic boundaries: `invalid_client` indicates that the client application failed to authenticate itself to the token endpoint. `invalid_grant` indicates that the client is authentic, but the authorization code, refresh token, or user credentials presented are invalid, expired, or revoked.",
          "keyTakeaway": "Emit RFC 6749 compliant `error` and `error_description` payloads."
    }
  }
];
