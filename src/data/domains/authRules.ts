import { SecurityInvariant } from '../../types/invariants';

export const authRules: SecurityInvariant[] = [
  {
    ruleNumber: 113,
    id: "SEC-AUTH-001",
    title: "Argon2id Memory-Hard Password Hashing Work Factor",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Credential Storage & Hashing",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 9106", "NIST SP 800-63B \u00a75.1.1.2", "OWASP Password Storage Cheat Sheet"],
    formalInvariant: "\u2200 u \u2208 Users, Hash(u.Password) = Argon2id(m \u2265 64MB, t \u2265 3, p = 4, Salt_{CSPRNG} \u2265 128 bits)",
    symbolBreakdown: [
          {
                "symbol": "Argon2id",
                "meaning": "Hybrid memory-hard password hashing algorithm resistant to GPU and side-channel attacks"
          },
          {
                "symbol": "m \u2265 64MB",
                "meaning": "Memory cost parameter requiring at least 64 megabytes of RAM per hash"
          },
          {
                "symbol": "t \u2265 3",
                "meaning": "Time cost parameter requiring 3 iterations over memory matrix"
          },
          {
                "symbol": "p = 4",
                "meaning": "Parallelism parameter utilizing 4 concurrent execution threads"
          },
          {
                "symbol": "Salt_{CSPRNG} \u2265 128 bits",
                "meaning": "Cryptographically random per-user salt of at least 16 bytes"
          }
    ],
    plainEnglish: "User passwords must never be stored in plaintext, with MD5/SHA, or with fast hashes. They must be hashed using Argon2id with at least 64MB memory, 3 iterations, 4 parallel threads, and a unique 128-bit CSPRNG salt per user.",
    whyItMatters: "Using fast cryptographic hashes (SHA-256, MD5) allows attackers who steal a database dump to crack billions of passwords per second using commodity GPUs or ASIC rigs. Argon2id forces high memory requirements, making hardware cracking infeasible.",
    vulnerableExample: {
          "language": "python",
          "code": "import hashlib\n\ndef store_password(user_id, password):\n    # VULNERABLE: Fast unsalted SHA-256 hash\n    # Attackers crack billions per second with Hashcat on GPUs\n    password_hash = hashlib.sha256(password.encode()).hexdigest()\n    db.save(user_id, password_hash)",
          "explanation": "SHA-256 is designed for fast verification of data, not slow resistance against brute-force password cracking."
    },
    secureExample: {
          "language": "python",
          "code": "from argon2 import PasswordHasher\n\nph = PasswordHasher(\n    time_cost=3,        # 3 iterations\n    memory_cost=65536,  # 64 MiB\n    parallelism=4,      # 4 parallel threads\n    hash_len=32,\n    salt_len=16\n)\n\ndef store_password(user_id, password):\n    # Generates secure per-user salt and Argon2id hash string automatically\n    password_hash = ph.hash(password)\n    db.save(user_id, password_hash)",
          "explanation": "Uses modern memory-hard Argon2id with standardized high-resistance cost parameters."
    },
    howToTest: {
          "tools": [
                "hashcat",
                "python-argon2-cffi",
                "openssl"
          ],
          "steps": [
                "Inspect hash strings stored in database.",
                "Verify format starts with $argon2id$v=19$m=65536,t=3,p=4$...",
                "Benchmark verification latency on production hardware; ensure it takes between 100ms and 500ms."
          ],
          "commandExample": "python3 -c \"import argon2; print(argon2.PasswordHasher().hash('secret'))\""
    },
    interviewChallenge: {
          "scenario": "A financial institution currently hashes passwords with SHA-256. They want to upgrade 10 million users to Argon2id without forcing a mass password reset.",
          "question": "How do you migrate legacy password hashes to Argon2id transparently during runtime?",
          "hint": "What opportunity do you have every time an active user logs in?",
          "sampleAnswer": "Use an incremental 'upgrade-on-login' strategy. When a user submits their plaintext password during login, verify it against the old SHA-256 hash. If valid, immediately compute the new Argon2id hash from the plaintext and overwrite the database record. For dormant accounts that never log in, wrap the existing SHA-256 hash in Argon2id: `Argon2id(SHA256(password))`.",
          "keyTakeaway": "Migrate legacy password hashes incrementally upon successful user login without disrupting operations."
    },
    simulation: {
          "type": "generic",
          "label": "Argon2id Parameter & Memory Work Factor Validator",
          "defaultInput": "Algorithm: Argon2id\nMemoryCost: 65536 KiB (64 MiB)\nTimeIterations: 3\nParallelism: 4 threads\nSaltLength: 16 bytes",
          "testFunctionDescription": "Evaluates memory hardness and time parameters against NIST SP 800-63B standards."
    }
  },
  {
    ruleNumber: 114,
    id: "SEC-AUTH-002",
    title: "Constant-Time Comparison Timing Oracle Elimination Invariant",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Side-Channel Attack Defense",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-63B", "CWE-208", "CWE-385"],
    formalInvariant: "\u2200 tokenA, tokenB \u2208 SecretStrings, ExecutionTime(Compare(tokenA, tokenB)) = C \u2227 (tokenA[i] \u2260 tokenB[i] \u21d2 NoEarlyExit)",
    symbolBreakdown: [
          {
                "symbol": "ExecutionTime(...) = C",
                "meaning": "Comparison routine executes in constant time C regardless of input byte values"
          },
          {
                "symbol": "NoEarlyExit",
                "meaning": "Algorithm does not return early on the first mismatched byte"
          },
          {
                "symbol": "SecretStrings",
                "meaning": "API tokens, session cookies, password reset tokens, or HMAC signatures"
          }
    ],
    plainEnglish: "Whenever comparing secret tokens, HMAC signatures, or password hashes, applications must use a constant-time comparison function (e.g. `crypto.timingSafeEqual`). Standard equality operators (`===` or `strcmp`) that exit on the first mismatched byte are prohibited.",
    whyItMatters: "Standard string comparison returns false as soon as it encounters a mismatch. An attacker measuring execution time over thousands of network requests can determine which character is correct one byte at a time, reconstructing secret HMACs without knowing the key.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Standard equality comparison exits early\nfunction verifySignature(userSig, expectedSig) {\n    // === returns immediately on first mismatched byte\n    return userSig === expectedSig;\n}",
          "explanation": "Allows timing side-channel attacks where correct initial characters take measurably longer to evaluate."
    },
    secureExample: {
          "language": "javascript",
          "code": "import crypto from 'crypto';\n\nfunction verifySignature(userSig, expectedSig) {\n    const bufUser = Buffer.from(userSig);\n    const bufExpected = Buffer.from(expectedSig);\n    if (bufUser.length !== bufExpected.length) {\n        return false;\n    }\n    // Always scans all bytes in constant time:\n    return crypto.timingSafeEqual(bufUser, bufExpected);\n}",
          "explanation": "Guarantees execution latency is statistically uniform regardless of where mismatches occur."
    },
    howToTest: {
          "tools": [
                "python",
                "timing-attack-bench",
                "wireshark"
          ],
          "steps": [
                "Measure latency of 10,000 comparisons with 0 matching characters vs 15 matching characters.",
                "Verify statistical variance is within noise threshold and no timing oracle exists."
          ],
          "commandExample": "python3 -m unittest timing_attack_test.py"
    },
    interviewChallenge: {
          "scenario": "A developer writes `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))`, but `Buffer.from()` throws an exception if the lengths do not match.",
          "question": "How does comparing buffers of different lengths leak information, and how do you fix it?",
          "hint": "What does a length check leak to an attacker?",
          "sampleAnswer": "If the function checks length first and returns false immediately, the attacker learns the exact length of the secret key or token. To fix this without timing leaks, compare the HMAC of both strings: `crypto.timingSafeEqual(hmac(a), hmac(b))`. Because HMAC outputs have fixed lengths, length differences are completely masked.",
          "keyTakeaway": "Hash variable-length secrets with HMAC before performing constant-time equality comparisons."
    }
  },
  {
    ruleNumber: 115,
    id: "SEC-AUTH-003",
    title: "Session Identifier Re-Generation on Authentication (Anti-Fixation)",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Session Management & Fixation",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["OWASP ASVS 4.0 \u00a73.2.1", "CWE-384"],
    formalInvariant: "\u2200 u \u2208 Users, Authenticate(u) \u21d2 InvalidateSession(CurrentSessionID) \u2227 SessionID_{New} = GenerateCSPRNG(128b) \u2227 Bind(u, SessionID_{New})",
    symbolBreakdown: [
          {
                "symbol": "CurrentSessionID",
                "meaning": "Pre-login anonymous session cookie value"
          },
          {
                "symbol": "InvalidateSession(...)",
                "meaning": "Old session key is destroyed on server"
          },
          {
                "symbol": "SessionID_{New}",
                "meaning": "Fresh cryptographically random session identifier issued immediately upon login"
          }
    ],
    plainEnglish: "Whenever an unauthenticated or lower-privilege session transitions to an authenticated or elevated state, the server must destroy the old session identifier and issue a fresh cryptographic session token. Never bind a user identity to an existing pre-login session ID.",
    whyItMatters: "In a Session Fixation attack, an attacker tricks a victim into using a known session ID (e.g. via an open redirect or link). If the server fails to regenerate the ID upon login, the attacker's pre-set cookie becomes authenticated, giving them full access to the victim's account.",
    vulnerableExample: {
          "language": "python",
          "code": "def login(request):\n    user = authenticate(request.form['username'], request.form['password'])\n    if user:\n        # FLAW: Attaches user to existing session ID without regenerating it!\n        request.session['user_id'] = user.id\n        return redirect('/dashboard')",
          "explanation": "Keeps the pre-authenticated session cookie alive, allowing the attacker who supplied it to inherit user authorization."
    },
    secureExample: {
          "language": "python",
          "code": "def login(request):\n    user = authenticate(request.form['username'], request.form['password'])\n    if user:\n        # SECURE: Invalidate previous session and cycle session token\n        request.session.cycle_key() # In Django / Express: req.session.regenerate()\n        request.session['user_id'] = user.id\n        return redirect('/dashboard')",
          "explanation": "Invalidates the existing session ID and generates a completely fresh cryptographic token upon login."
    },
    howToTest: {
          "tools": [
                "browser DevTools",
                "curl"
          ],
          "steps": [
                "Visit login page as guest and record the session cookie value.",
                "Submit valid login credentials.",
                "Inspect new session cookie value; confirm it has changed completely.",
                "Attempt to make authenticated requests with the old pre-login cookie; confirm 401 Unauthorized."
          ],
          "commandExample": "curl -c cookies.txt https://target.com/login && curl -b cookies.txt https://target.com/api/user"
    },
    interviewChallenge: {
          "scenario": "An application regenerates the session ID on login, but the user's shopping cart stored in the session is lost upon login.",
          "question": "How do you preserve user cart items without introducing session fixation?",
          "hint": "Can you migrate data objects between old and new session keys?",
          "sampleAnswer": "Extract the anonymous shopping cart state into a temporary memory variable, call session.regenerate() to issue a fresh cryptographic session ID, and then re-assign the cart data into the newly generated authenticated session store.",
          "keyTakeaway": "Regenerate session identifiers upon any privilege change; migrate data attributes, never session tokens."
    }
  },
  {
    ruleNumber: 116,
    id: "SEC-AUTH-116",
    title: "Multi-Factor Authentication (MFA) Step-Up Invariant",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "MFA & Step-Up Auth",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-63B AAL2", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 act \u2208 HighRiskActions, RequiresMFA(act) = True \u2227 (SatisfiedFactors(User) \u2287 {Knowledge, Possession})",
    symbolBreakdown: [
          {
                "symbol": "HighRiskActions",
                "meaning": "Wire transfers, password updates, API key creation"
          },
          {
                "symbol": "Knowledge",
                "meaning": "Password or PIN"
          },
          {
                "symbol": "Possession",
                "meaning": "FIDO2 key, TOTP authenticator, or hardware token"
          }
    ],
    plainEnglish: "High-risk administrative and financial actions must require multi-factor authentication (MFA) step-up. The server must verify both knowledge and possession factors before executing state changes.",
    whyItMatters: "If an attacker steals a user's session token via XSS or info-stealer malware, the absence of MFA step-up allows them to immediately transfer money or add an attacker recovery email.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Wire transfer without step-up MFA\n@app.post('/transfer')\ndef transfer(amount: float, recipient: str, user = Depends(auth)):\n    execute_transfer(user.id, recipient, amount)",
          "explanation": "A hijacked session can drain accounts without secondary verification."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Mandatory MFA token verification on transfer\n@app.post('/transfer')\ndef transfer(req: TransferDto, mfa_code: str = Header(...), user = Depends(auth)):\n    if not verify_totp(user.mfa_secret, mfa_code):\n        raise HTTPException(403, 'Valid MFA token required for financial transfers')\n    execute_transfer(user.id, req.recipient, req.amount)",
          "explanation": "Demands real-time possession factor verification before executing high-risk action."
    },
    howToTest: {
          "tools": [
                "curl",
                "Google Authenticator"
          ],
          "steps": [
                "Attempt transfer without MFA header; verify 403.",
                "Send valid TOTP code; verify 200 OK."
          ],
          "commandExample": "curl -X POST -H 'X-MFA-Code: 123456' https://api.target.com/transfer"
    },
    interviewChallenge: {
          "scenario": "Why is SMS-based verification increasingly prohibited for NIST AAL2/AAL3 authentication?",
          "question": "What attacks bypass SMS?",
          "hint": "SIM swapping and SS7 cell network interception allow remote attackers to redirect SMS messages.",
          "sampleAnswer": "SIM swapping and telecom interception (SS7) allow attackers to impersonate the victim's phone number and intercept SMS OTP codes remotely without touching the user's phone. FIDO2 / WebAuthn is immune because private keys cannot be intercepted over the cellular network.",
          "keyTakeaway": "Enforce app-based TOTP or hardware FIDO2 passkeys for MFA step-up."
    }
  },
  {
    ruleNumber: 117,
    id: "SEC-AUTH-117",
    title: "FIDO2 / WebAuthn Public-Key Authenticator Binding",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Phishing-Resistant MFA",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["FIDO2 / W3C WebAuthn", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 auth \u2208 WebAuthnAssertions, VerifySignature(auth.Signature, PublicKey) \u2227 auth.RP_ID = ExpectedOrigin \u2227 auth.UserPresent = True",
    symbolBreakdown: [
          {
                "symbol": "WebAuthnAssertions",
                "meaning": "Cryptographic assertion signed by hardware security key or biometric enclave"
          },
          {
                "symbol": "RP_ID",
                "meaning": "Relying Party ID matching exact browser domain"
          },
          {
                "symbol": "UserPresent",
                "meaning": "Physical touch or biometric verification"
          }
    ],
    plainEnglish: "WebAuthn authentications must verify the relying party identifier (`rpId`) matches the origin domain, the challenge matches server state, and the user presence flag is set. Phishing-resistant FIDO2 must be preferred over OTP.",
    whyItMatters: "Adversary-in-the-Middle (AitM) phishing proxies (Evilginx) steal passwords and TOTP codes in real time. WebAuthn authenticators bind the signature to the exact browser domain, causing signatures sent to phishing sites to fail completely.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Verifying WebAuthn without validating rpId origin\nconst isValid = verifySignature(clientDataJSON, signature, pubKey);\n// FLAW: Omitted origin / rpId verification!",
          "explanation": "Allows phishing proxy on evil.com to replay credentials."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Strict origin and challenge validation in WebAuthn\nconst { verified, authenticationInfo } = await verifyAuthenticationResponse({\n    response: credential,\n    expectedChallenge: session.challenge,\n    expectedOrigin: 'https://app.example.com',\n    expectedRPID: 'example.com',\n    authenticator: userKey\n});",
          "explanation": "Browser hardware binds cryptographic signature to the exact application domain, neutralizing phishing proxies."
    },
    howToTest: {
          "tools": [
                "YubiKey",
                "webauthn.io testbench"
          ],
          "steps": [
                "Simulate login via reverse proxy domain; confirm WebAuthn assertion fails domain check."
          ],
          "commandExample": "node -e 'console.log(\"Testing WebAuthn assertion origin binding\")'"
    },
    interviewChallenge: {
          "scenario": "How does WebAuthn mathematically defeat Adversary-in-the-Middle (Evilginx) phishing proxies?",
          "question": "What domain is signed by the hardware key?",
          "hint": "The browser directly queries the actual domain in the address bar (e.g. `evil-phish.com`) and passes it to the security key. The key signs `evil-phish.com`. When the phishing proxy forwards this to the real bank (`bank.com`), the bank rejects the signature because `rpId` is `evil-phish.com`, not `bank.com`.",
          "sampleAnswer": "WebAuthn's origin binding cannot be intercepted or modified by proxies: the browser supplies the active URL to the hardware authenticator directly.",
          "keyTakeaway": "Deploy WebAuthn/Passkeys for phishing-resistant credential security."
    }
  },
  {
    ruleNumber: 118,
    id: "SEC-AUTH-118",
    title: "Account Lockout Exponential Backoff and Tarpitting Invariant",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Brute-Force Protection",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["OWASP ASVS \u00a72.2", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 u \u2208 Accounts, FailedAttempts(u, 1h) \u2265 5 \u21d2 DelayNextAttempt(2^{FailedAttempts - 5} seconds) \u2227 AlertUser(u)",
    symbolBreakdown: [
          {
                "symbol": "FailedAttempts",
                "meaning": "Consecutive incorrect password attempts against user account"
          },
          {
                "symbol": "DelayNextAttempt",
                "meaning": "Exponential sleep (tarpit) added to server response time"
          },
          {
                "symbol": "AlertUser",
                "meaning": "Notification email sent to account owner"
          }
    ],
    plainEnglish: "Authentication services must enforce exponential backoff (tarpitting) or progressive delays after 5 failed password attempts on an account, rather than permanently locking accounts which enables Denial-of-Service attacks.",
    whyItMatters: "Hard account lockouts allow attackers to submit 5 bad passwords for every executive in the company, locking all legitimate employees out of their accounts (Denial of Service). Exponential backoff stops brute-force without locking users out.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Hard account lockout enables DoS\nif failed_attempts >= 5:\n    user.is_locked = True # Attacker locks out CEO account on purpose!\n    db.save(user)",
          "explanation": "Attacker locks out all employee accounts effortlessly with automated scripts."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Exponential backoff delay (tarpitting)\nif failed_attempts >= 5:\n    delay_sec = min(2 ** (failed_attempts - 5), 60)\n    time.sleep(delay_sec) # Slows down brute-force without permanent lock\n    if failed_attempts >= 10:\n        require_captcha_or_mfa(user)",
          "explanation": "Increases attack time exponentially while allowing legitimate users with MFA to log in."
    },
    howToTest: {
          "tools": [
                "hydra",
                "curl"
          ],
          "steps": [
                "Send 10 rapid incorrect login attempts; observe response time increasing exponentially from 1s to 32s."
          ],
          "commandExample": "hydra -l user@example.com -P /dev/null target.com http-post-form"
    },
    interviewChallenge: {
          "scenario": "Why is progressive tarpitting (adding artificial response delays) superior to hard account lockouts in public-facing SaaS applications?",
          "question": "How does tarpitting affect attacker economics?",
          "hint": "Tarpitting slows automated brute-force tools from 1,000 guesses per second down to 1 guess per minute, destroying attacker throughput without creating denial-of-service lockout tickets for customer support.",
          "sampleAnswer": "Tarpitting eliminates the denial-of-service vector where attackers lock out legitimate users, while drastically degrading automated password spraying throughput.",
          "keyTakeaway": "Use IP and account rate limiting with progressive backoff delays instead of permanent lockouts."
    }
  },
  {
    ruleNumber: 119,
    id: "SEC-AUTH-119",
    title: "Credential Stuffing Breached Password Check (HaveIBeenPwned)",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Password Hygiene",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-63B \u00a75.1.1.2", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 pwd \u2208 NewPasswords, k_AnonymityCheck(SHA1(pwd), HaveIBeenPwned) = True \u21d2 RejectPassword(pwd)",
    symbolBreakdown: [
          {
                "symbol": "NewPasswords",
                "meaning": "Passwords entered during registration or password change"
          },
          {
                "symbol": "k_AnonymityCheck",
                "meaning": "Querying first 5 hex characters of SHA-1 hash to public breach database"
          },
          {
                "symbol": "RejectPassword",
                "meaning": "Mandating user choose an unbreached credential"
          }
    ],
    plainEnglish: "Applications must check proposed passwords against known breached password databases using k-Anonymity (e.g. HaveIBeenPwned API) during registration and password rotation. Known compromised passwords must be rejected.",
    whyItMatters: "Users frequently reuse passwords across sites. When a third-party site is breached, credential-stuffing bots immediately test the compromised password on your platform, taking over the account on day one.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Accepts known compromised passwords\n@app.post('/register')\ndef register(pwd: str):\n    # Accepts 'password123' or 'P@ssword2024' because it meets basic regex length!\n    db.save_user(hash_password(pwd))",
          "explanation": "Permits credentials that appear in billions of public breach dumps."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: k-Anonymity breached password validation via HIBP\nimport hashlib, requests\n\ndef check_breached(password: str) -> bool:\n    sha1_pwd = hashlib.sha1(password.encode()).hexdigest().upper()\n    prefix, suffix = sha1_pwd[:5], sha1_pwd[5:]\n    res = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')\n    return suffix in res.text\n\nif check_breached(new_password):\n    raise ValidationError('This password has appeared in a known data breach. Choose another.')",
          "explanation": "Checks breached database without ever sending the plaintext password or full hash across the network."
    },
    howToTest: {
          "tools": [
                "curl",
                "HIBP API"
          ],
          "steps": [
                "Submit 'password123' during registration; confirm API returns 400 Bad Request: 'Compromised password'."
          ],
          "commandExample": "curl https://api.pwnedpasswords.com/range/21BD1"
    },
    interviewChallenge: {
          "scenario": "How does the k-Anonymity model used by HaveIBeenPwned allow checking a password without revealing the password to Troy Hunt or network eavesdroppers?",
          "question": "How much of the hash is sent to the server?",
          "hint": "Only the first 5 characters of the SHA-1 hash are sent. The API returns all ~500 hash suffixes matching that prefix; the client checks its own suffix locally.",
          "sampleAnswer": "Under k-Anonymity, the client computes SHA-1 of the password and sends only the first 5 hex characters (e.g., `21BD1`). The server returns all matching breached hash suffixes. The client checks if its full hash is in the list locally in memory, ensuring neither the password nor the full hash is ever exposed.",
          "keyTakeaway": "Implement k-Anonymity breach verification on registration and password updates."
    }
  },
  {
    ruleNumber: 120,
    id: "SEC-AUTH-120",
    title: "Universal Session Revocation (Log Out All Devices)",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Session Management",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["OWASP ASVS \u00a73.3.4", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 u \u2208 Users, RevokeAllSessions(u) \u21d2 InvalidateTokens(u.AllSessionIDs) \u2227 IncrementTokenVersion(u)",
    symbolBreakdown: [
          {
                "symbol": "RevokeAllSessions",
                "meaning": "Security action triggered when user suspects account theft"
          },
          {
                "symbol": "InvalidateTokens",
                "meaning": "Purging all session tokens from Redis session store"
          },
          {
                "symbol": "IncrementTokenVersion",
                "meaning": "Invalidating stateless JWTs via user token_version counter"
          }
    ],
    plainEnglish: "Applications must provide a 'Log Out All Devices' capability that instantaneously invalidates all active sessions, refresh tokens, and JWTs across all mobile, desktop, and web clients.",
    whyItMatters: "If an employee loses a phone or suspects credential compromise, but the application only invalidates the current browser cookie, the thief's session on the stolen phone remains authenticated indefinitely.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Only deletes current cookie\napp.post('/logout', (req, res) => {\n    res.clearCookie('session_id'); // Other active devices remain logged in!\n    res.sendStatus(200);\n});",
          "explanation": "Fails to terminate active attacker sessions on other devices."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Universal revocation via session store and user token version\napp.post('/logout-all', authenticate, async (req, res) => {\n    // Purge all Redis sessions for this user:\n    await redis.del(`user_sessions:${req.user.id}`);\n    // Increment token_version in database to invalidate active JWTs:\n    await db.users.update(req.user.id, { $inc: { token_version: 1 } });\n    res.clearCookie('session_id');\n    res.json({ message: 'All sessions successfully revoked' });\n});",
          "explanation": "Atomically destroys all session state and forces all connected clients to re-authenticate."
    },
    howToTest: {
          "tools": [
                "redis-cli",
                "curl"
          ],
          "steps": [
                "Log in on two browsers.",
                "Click 'Log Out All Devices' in browser 1.",
                "Attempt request in browser 2; verify 401 Unauthorized."
          ],
          "commandExample": "redis-cli keys 'user_sessions:123*'"
    },
    interviewChallenge: {
          "scenario": "How do you invalidate stateless JWT access tokens immediately if they do not exist in a central database?",
          "question": "What claim links a stateless JWT to database revocation?",
          "hint": "Include a `token_version` integer claim in the JWT. Incrementing `token_version` on the user's database record causes all existing JWTs with the old version to fail verification immediately.",
          "sampleAnswer": "Pure stateless JWTs cannot be revoked without state. By embedding a `token_version` claim in the JWT and caching the user's current `token_version` in high-speed Redis memory, any JWT presenting an outdated version is rejected immediately at the gateway.",
          "keyTakeaway": "Store a `token_version` or `revoked_at` timestamp in user profiles to invalidate stateless tokens."
    }
  },
  {
    ruleNumber: 121,
    id: "SEC-AUTH-121",
    title: "Generic Authentication Failure Message Invariant",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "User Enumeration Defense",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["OWASP ASVS \u00a72.1.8", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 attempt \u2208 FailedLogins, ResponseMessage(attempt) = \"Invalid email or password\" \u2227 ResponseTiming(attempt) = ConstantTime",
    symbolBreakdown: [
          {
                "symbol": "FailedLogins",
                "meaning": "Authentication attempts with either bad password or non-existent username"
          },
          {
                "symbol": "ResponseMessage",
                "meaning": "Identical error message returned regardless of which field was incorrect"
          },
          {
                "symbol": "ResponseTiming = ConstantTime",
                "meaning": "Equal execution latency preventing username enumeration via timing"
          }
    ],
    plainEnglish: "Authentication endpoints must return an identical generic error message ('Invalid email or password') and take statistically identical time whether the email exists or not, preventing account enumeration.",
    whyItMatters: "Returning 'Email does not exist' vs 'Incorrect password' allows automated scrapers to upload lists of millions of emails to determine which celebrities, politicians, or employees have accounts on the platform.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Leaking user existence in error message\n@app.post('/login')\ndef login(req: LoginDto):\n    user = db.find_user(req.email)\n    if not user:\n        return {'error': 'Email not registered'} # Enumeration leak!\n    if not verify_password(req.password, user.password_hash):\n        return {'error': 'Incorrect password'}",
          "explanation": "Attackers easily enumerate which email addresses exist in the customer database."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Generic error message and constant-time dummy hashing\n@app.post('/login')\ndef login(req: LoginDto):\n    user = db.find_user(req.email)\n    # If user doesn't exist, run dummy hash to avoid timing differences:\n    stored_hash = user.password_hash if user else DUMMY_HASH\n    password_valid = verify_argon2id(req.password, stored_hash)\n    if not user or not password_valid:\n        return JSONResponse(status_code=401, content={'error': 'Invalid email or password'})\n    return issue_session(user)",
          "explanation": "Returns identical error message and runs hash computation regardless of user existence."
    },
    howToTest: {
          "tools": [
                "curl",
                "Burp Suite Intruder"
          ],
          "steps": [
                "Send login request for registered email with bad password.",
                "Send login request for unregistered email.",
                "Verify HTTP status codes, JSON responses, and response times are identical."
          ],
          "commandExample": "curl -X POST -d '{\"email\":\"fake@example.com\",\"password\":\"x\"}' https://api.target.com/login"
    },
    interviewChallenge: {
          "scenario": "Why must authentication controllers compute a 'dummy password hash' when a queried email does NOT exist in the database?",
          "question": "How does skipping the hash create a timing leak?",
          "hint": "Argon2id takes ~200ms to compute. If the user doesn't exist and the code returns immediately, it responds in 5ms, revealing that the email is not registered.",
          "sampleAnswer": "Password hashing algorithms like Argon2id or Bcrypt are intentionally slow (100ms - 300ms). If an application returns immediately when an email is not found, the response takes 5ms, but takes 200ms when the email exists and the password is checked. Attackers measure this timing difference to enumerate registered accounts without relying on error messages.",
          "keyTakeaway": "Always execute a dummy password verification when the username is not found."
    }
  },
  {
    ruleNumber: 122,
    id: "SEC-AUTH-122",
    title: "Password Reset Token Single-Use and Short Expiry (\u2264 15m)",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Account Recovery",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-63B", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 tok \u2208 ResetTokens, (Now() - tok.Created \u2264 900s) \u2227 SingleUse(tok) = True \u2227 IsHashedInDatabase(tok) = True",
    symbolBreakdown: [
          {
                "symbol": "ResetTokens",
                "meaning": "Cryptographic tokens generated during forgot-password workflows"
          },
          {
                "symbol": "<= 900s",
                "meaning": "Strict 15-minute expiration window"
          },
          {
                "symbol": "SingleUse",
                "meaning": "Immediate invalidation upon first consumption"
          }
    ],
    plainEnglish: "Password reset tokens must have an expiration lifetime of at most 15 minutes (900 seconds), be single-use, and be stored hashed in the database. Successful password resets must invalidate all other active tokens.",
    whyItMatters: "Long-lived or reusable reset tokens allow attackers who gain access to old emails or network logs to reset account passwords days later, locking out legitimate users.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: 24-hour reusable reset token stored in plaintext\ndef create_reset_token(user_id):\n    token = secrets.token_hex(16)\n    db.save_token(user_id, token, expires_in=86400) # 24 hours!\n    return token",
          "explanation": "Token remains valid for a day and is stored in plaintext in database dumps."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: 15-minute single-use token stored as SHA-256 hash\ndef create_reset_token(user_id):\n    raw_token = secrets.token_urlsafe(32)\n    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()\n    # Expires in 15 minutes (900 seconds):\n    db.save_reset_record(user_id, token_hash, expires_at=time.time() + 900, used=False)\n    return raw_token",
          "explanation": "Stores only cryptographic hash of token; token expires in 15 minutes and burns on first use."
    },
    howToTest: {
          "tools": [
                "curl",
                "unit tests"
          ],
          "steps": [
                "Generate reset token.",
                "Use token once to change password.",
                "Attempt to use the identical token a second time; verify server rejects with 400."
          ],
          "commandExample": "curl -X POST -d '{\"token\":\"used_token\",\"new_pass\":\"ValidPass123!\"}' https://api.target.com/reset"
    },
    interviewChallenge: {
          "scenario": "Why should password reset tokens be stored in the database as SHA-256 hashes rather than plaintext?",
          "question": "What happens if a database backup is leaked?",
          "hint": "If a database backup or read-only replica is compromised, plaintext reset tokens allow the attacker to immediately reset passwords for all accounts before the breach is discovered.",
          "sampleAnswer": "Storing reset tokens hashed ensures that even if an attacker obtains a database dump, they cannot use the stored tokens to reset account passwords because they cannot reverse the SHA-256 hash to obtain the raw token delivered to the user's email.",
          "keyTakeaway": "Store password reset tokens as SHA-256 hashes in the database."
    }
  },
  {
    ruleNumber: 123,
    id: "SEC-AUTH-123",
    title: "TOTP Time-Step Drift Window Restriction (\u00b11 Step)",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "MFA Hardening",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["RFC 6238", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 code \u2208 SubmittedTOTPs, DriftWindow(code) \u2208 {-1, 0, +1} \u2227 IsConsumed(code, User) = False",
    symbolBreakdown: [
          {
                "symbol": "SubmittedTOTPs",
                "meaning": "6-digit RFC 6238 time-based one-time passwords"
          },
          {
                "symbol": "DriftWindow \u2208 {-1, 0, +1}",
                "meaning": "Allows at most 30 seconds of clock drift before or after current time"
          },
          {
                "symbol": "IsConsumed = False",
                "meaning": "Prevents replay of the same 6-digit OTP within the same 30-second window"
          }
    ],
    plainEnglish: "Time-based One-Time Password (TOTP) verifiers must limit clock drift acceptance to at most \u00b11 time step (\u00b130 seconds) and mark submitted codes as consumed. Replaying the same code within the 30-second window must be rejected.",
    whyItMatters: "Permitting large drift windows (e.g. \u00b110 steps = 5 minutes) allows attackers who intercept a TOTP code over Wi-Fi or via phishing to reuse it long after the user entered it.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Excessive drift window and no replay check\ndef verify_otp(secret, code):\n    # Allows codes from 10 minutes ago, and doesn't record consumption!\n    totp = pyotp.TOTP(secret)\n    return totp.verify(code, valid_window=20)",
          "explanation": "Allows wide window for attackers to replay stolen one-time codes."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Strict \u00b11 step drift with atomic replay prevention\ndef verify_otp(user_id, secret, code):\n    totp = pyotp.TOTP(secret)\n    # valid_window=1 allows only current step and \u00b11 step (30s):\n    if not totp.verify(code, valid_window=1):\n        return False\n    # Prevent replay within current time-step:\n    key = f\"used_totp:{user_id}:{code}\"\n    if not redis.set(key, \"1\", nx=True, ex=90):\n        raise HTTPException(400, 'One-time code already used; wait for next code')\n    return True",
          "explanation": "Limits acceptance to 90 seconds total and rejects replayed codes immediately."
    },
    howToTest: {
          "tools": [
                "pyotp",
                "Google Authenticator",
                "curl"
          ],
          "steps": [
                "Submit valid TOTP code.",
                "Immediately submit the exact same code a second time within 10 seconds.",
                "Verify second submission is rejected with 400: Code already used."
          ],
          "commandExample": "python3 -c 'import pyotp; print(pyotp.TOTP(\"JBSWY3DPEHPK3PXP\").now())'"
    },
    interviewChallenge: {
          "scenario": "Why must a TOTP verification engine record previously consumed codes in Redis or a cache?",
          "question": "Can a 6-digit code be reused before its 30-second window expires?",
          "hint": "Yes, because the code is valid for the full 30 seconds, an attacker sniffing the wire could replay it within that remaining window unless the server marks it as consumed.",
          "sampleAnswer": "RFC 6238 codes are valid throughout their 30-second time-step. Without recording consumed codes, an attacker who eavesdrops on the network or operates a malicious Wi-Fi access point can replay the user's code within the remaining seconds before the step advances.",
          "keyTakeaway": "Track used TOTP codes in a cache to prevent intra-step replay attacks."
    }
  },
  {
    ruleNumber: 124,
    id: "SEC-AUTH-124",
    title: "Remember-Me Token Re-Authentication Invariant",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Session Hardening",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["OWASP ASVS \u00a73.8", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 req \u2208 SensitiveSettingsEndpoints, AuthSource(req.Session) = RememberMeToken \u21d2 RequireFullPasswordReAuth()",
    symbolBreakdown: [
          {
                "symbol": "RememberMeToken",
                "meaning": "Persistent multi-week token stored in client cookie for convenience"
          },
          {
                "symbol": "RequireFullPasswordReAuth",
                "meaning": "Mandatory step-up prompt for user's master password"
          }
    ],
    plainEnglish: "Persistent 'Remember Me' cookies must only grant access to low-risk browse operations. Sensitive operations (viewing billing, changing passwords, modifying bank accounts) must require full password re-authentication.",
    whyItMatters: "If a laptop is briefly left unattended or a remember-me cookie is extracted, the attacker can access the account settings and transfer ownership without ever knowing the user's real password.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Treating remember-me cookie as full authentication\n@app.post('/billing/update-card')\ndef update_billing(req: BillingDto, user = Depends(get_session_user)):\n    # Executes without verifying if user recently re-entered password!\n    update_payment_details(user.id, req)",
          "explanation": "Allows persistent cookie to modify billing and sensitive profile settings."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Enforcing full password re-auth on sensitive operations\n@app.post('/billing/update-card')\ndef update_billing(req: BillingDto, session = Depends(get_session)):\n    if session.is_remember_me and (time.time() - session.last_full_auth > 900):\n        raise HTTPException(403, detail='Password re-authentication required for billing changes')\n    update_payment_details(session.user_id, req)",
          "explanation": "Restricts persistent token privileges and demands fresh password entry for sensitive workflows."
    },
    howToTest: {
          "tools": [
                "browser DevTools",
                "curl"
          ],
          "steps": [
                "Log in with 'Remember Me' checked.",
                "Attempt to change account password without providing current password.",
                "Verify API returns 403 demanding password verification."
          ],
          "commandExample": "curl -b 'remember_me=token123' https://api.target.com/settings/security"
    },
    interviewChallenge: {
          "scenario": "How did Charles Miller and security researchers formalize the 'Two-Tier Authentication' model popularized by Amazon for Remember-Me cookies?",
          "question": "What does Amazon allow with a remember-me cookie, and what does it block?",
          "hint": "Amazon allows browsing recommendations and adding to cart with a persistent cookie, but forces password entry the moment you click 'Checkout' or 'Account Settings'.",
          "sampleAnswer": "The two-tier authentication model treats persistent remember-me tokens as convenience identifiers (AAL1) suitable only for reading public/personalized content. Any operation that touches money, account credentials, or PII elevates the required assurance level to AAL2, demanding fresh password entry.",
          "keyTakeaway": "Treat remember-me sessions as low-privilege; demand step-up auth on critical paths."
    }
  },
  {
    ruleNumber: 125,
    id: "SEC-AUTH-125",
    title: "Password Composition Arbitrary Rule Prohibition (NIST SP 800-63B)",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Password Modernization",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-63B", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 policy \u2208 PasswordPolicies, MinLength(policy) \u2265 8 \u2227 DisallowSpecialCharMandates(policy) = True \u2227 DisallowArbitraryPeriodicRotation(policy) = True",
    symbolBreakdown: [
          {
                "symbol": "MinLength >= 8",
                "meaning": "Minimum length threshold (15+ recommended for privileged accounts)"
          },
          {
                "symbol": "DisallowSpecialCharMandates",
                "meaning": "Prohibits requiring specific combinations of uppercase, numbers, and symbols"
          },
          {
                "symbol": "DisallowArbitraryPeriodicRotation",
                "meaning": "Eliminates mandatory 90-day password expiration"
          }
    ],
    plainEnglish: "Password policies must adhere to modern NIST SP 800-63B guidelines: require a minimum length of at least 8 characters (15+ for admins), permit all printable ASCII and Unicode/emojis, and eliminate mandatory periodic expiration (e.g. 90-day resets).",
    whyItMatters: "Forcing users to change passwords every 90 days or require '!@#' characters results in predictable patterns (`Spring2024!`, `Summer2024!`) that are easy for attackers to guess while frustrating legitimate users.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Legacy complex password rules that reduce real security\nconst legacyRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,16}$/;\n// Rejects 30-character passphrases with spaces or emojis!",
          "explanation": "Forces users into predictable patterns like P@ssw0rd1 and caps length at 16."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: NIST SP 800-63B compliant password policy\nimport { z } from 'zod';\n\nconst PasswordSchema = z.string()\n    .min(12, 'Password must be at least 12 characters long')\n    .max(128, 'Password must not exceed 128 characters')\n    // Permits spaces, emojis, and all Unicode characters:\n    .refine(pwd => !checkBreached(pwd), 'Password has appeared in a breach');",
          "explanation": "Encourages long passphrases and checks against breached databases rather than arbitrary character rules."
    },
    howToTest: {
          "tools": [
                "zxcvbn",
                "unit tests"
          ],
          "steps": [
                "Test passphrase with spaces: `correct horse battery staple`.",
                "Verify modern validator accepts it; verify legacy regex rejects it."
          ],
          "commandExample": "node -e 'console.log(\"Testing NIST SP 800-63B password validation\")'"
    },
    interviewChallenge: {
          "scenario": "Why does NIST SP 800-63B officially advise AGAINST mandatory 60-day or 90-day password expiration policies?",
          "question": "What do users do when forced to rotate passwords frequently?",
          "hint": "Users make minor predictable edits (e.g. changing `Winter2023!` to `Spring2024!`), which weakens security compared to maintaining an uncompromised high-entropy passphrase.",
          "sampleAnswer": "Empirical security studies proved that forced periodic password rotation causes users to select predictable variants of existing passwords (incrementing a trailing digit or season name). Attackers who know an old password can easily guess the new one. Passwords should only be changed upon evidence of compromise.",
          "keyTakeaway": "Follow NIST SP 800-63B: prioritize length and breach checking over periodic expiration."
    }
  },
  {
    ruleNumber: 126,
    id: "SEC-AUTH-126",
    title: "Cryptographic Salt Uniqueness and CSPRNG Generation",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Credential Storage",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-132", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 u \u2208 Users, Salt(u) = CSPRNG(\u2265 128 bits) \u2227 (u_1 \u2260 u_2 \u21d2 Salt(u_1) \u2260 Salt(u_2))",
    symbolBreakdown: [
          {
                "symbol": "Salt(u)",
                "meaning": "Cryptographic random salt prepended to password before hashing"
          },
          {
                "symbol": "CSPRNG(>= 128 bits)",
                "meaning": "Generated using cryptographically secure pseudo-random number generator"
          },
          {
                "symbol": "Salt(u1) != Salt(u2)",
                "meaning": "Strict global uniqueness across all accounts"
          }
    ],
    plainEnglish: "Password salts must be generated using a cryptographically secure pseudo-random number generator (CSPRNG), be at least 128 bits (16 bytes) in length, and be strictly unique per user. Static or global application salts ('peppers' used as salts) are prohibited.",
    whyItMatters: "Without unique per-user salts, attackers use precomputed Rainbow Tables to crack millions of hashes in seconds, and identical passwords across different users produce identical hash strings in database dumps.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Static application-wide salt\nAPP_SALT = \"my_static_secret_salt\"\n\ndef hash_password(password):\n    # Two users with password 'Welcome1' have the exact same hash!\n    return hashlib.sha256((password + APP_SALT).encode()).hexdigest()",
          "explanation": "Allows attackers to identify users with identical passwords and use precomputed tables."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Unique 16-byte CSPRNG salt per user\nimport os, hashlib\n\ndef hash_password(password):\n    salt = os.urandom(16) # 128 bits from kernel CSPRNG\n    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations=600000)\n    return salt + key",
          "explanation": "Guarantees two users with identical passwords have completely different cryptographic hashes."
    },
    howToTest: {
          "tools": [
                "openssl",
                "python"
          ],
          "steps": [
                "Inspect database hash records.",
                "Verify no two users share the same salt bytes."
          ],
          "commandExample": "python3 -c 'import os; print(os.urandom(16).hex())'"
    },
    interviewChallenge: {
          "scenario": "What is the mathematical purpose of a cryptographic salt, and why does salting NOT protect against single-target dictionary attacks?",
          "question": "Does salting slow down cracking a single known hash?",
          "hint": "Salting stops precomputed Rainbow Table attacks and multi-hash batch cracking across an entire database, but it does NOT slow down an attacker cracking a single specific user hash. Slowness comes from work factors (Argon2id/Bcrypt), not salting.",
          "sampleAnswer": "A salt guarantees that identical passwords hash to different digests, neutralizing precomputed rainbow tables and forcing attackers to crack each hash individually. However, salting does not make hashing slow: compute hardness must be provided by memory-hard work factors.",
          "keyTakeaway": "Always generate salts via CSPRNG (16+ bytes) and pair with memory-hard algorithms like Argon2id."
    }
  },
  {
    ruleNumber: 127,
    id: "SEC-AUTH-127",
    title: "Bcrypt Work Factor Minimum Cost (Cost \u2265 12)",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Legacy Hash Hardening",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["OWASP Password Storage", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 h \u2208 BcryptHashes, CostParameter(h) \u2265 12 \u2227 CostParameter(h) \u2264 15",
    symbolBreakdown: [
          {
                "symbol": "BcryptHashes",
                "meaning": "Hashes starting with $2a$, $2b$, or $2y$"
          },
          {
                "symbol": "CostParameter >= 12",
                "meaning": "Work factor dictating 2^12 = 4,096 key expansion rounds (taking ~250ms per verification)"
          }
    ],
    plainEnglish: "When Bcrypt is used for credential storage, the work factor (cost parameter) must be set to at least 12 (2^12 iterations). Legacy cost factors like 8 or 10 must be upgraded immediately.",
    whyItMatters: "A Bcrypt hash with cost 8 takes under 1 millisecond on a modern GPU rig, allowing attackers who steal database dumps to crack complex passwords in hours.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Outdated Bcrypt work factor\nimport bcrypt\n\ndef hash_password(password):\n    # Cost 8 is easily cracked on modern RTX 4090 GPUs!\n    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=8))",
          "explanation": "Enables high-speed offline dictionary attacks on leaked database dumps."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Hardened Bcrypt cost factor 12\nimport bcrypt\n\ndef hash_password(password):\n    # 2^12 = 4,096 rounds, taking ~250ms on server hardware:\n    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))",
          "explanation": "Slows hardware cracking by orders of magnitude."
    },
    howToTest: {
          "tools": [
                "bcrypt CLI",
                "hashcat"
          ],
          "steps": [
                "Extract cost factor from hash string: `$2b$12$...`.",
                "Confirm integer between 2nd and 3rd dollar sign is >= 12."
          ],
          "commandExample": "python3 -c 'import bcrypt; print(bcrypt.hashpw(b\"test\", bcrypt.gensalt(12))[:7])'"
    },
    interviewChallenge: {
          "scenario": "What is the 72-byte truncation limit flaw in Bcrypt, and how can an attacker exploit it?",
          "question": "What happens to characters past byte 72 in Bcrypt?",
          "hint": "Bcrypt silently truncates all password input at byte 72. Any characters entered after the 72nd byte are ignored by the algorithm.",
          "sampleAnswer": "Bcrypt's underlying algorithm (Blowfish key setup) only accepts keys up to 72 bytes long. If a user enters an 80-character password, the last 8 bytes are silently dropped. If not mitigated, an attacker can log in by guessing only the first 72 bytes. Modern architectures pre-hash long passwords with SHA-256 before passing to Bcrypt.",
          "keyTakeaway": "Pre-hash passwords with SHA-256 before Bcrypt or migrate to Argon2id."
    }
  },
  {
    ruleNumber: 128,
    id: "SEC-AUTH-128",
    title: "Session Inactivity Absolute Timeout Bound (Idle \u2264 15m)",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Session Expiration",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["OWASP ASVS \u00a73.3.2", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 s \u2208 ActiveSessions, (Now() - s.LastActivityTimestamp > 900s) \u21d2 InvalidateSession(s) \u2227 Reject(401)",
    symbolBreakdown: [
          {
                "symbol": "ActiveSessions",
                "meaning": "Authenticated web and mobile sessions"
          },
          {
                "symbol": "LastActivityTimestamp",
                "meaning": "Timestamp updated on every authenticated user request"
          },
          {
                "symbol": "> 900s",
                "meaning": "15 minutes of user inactivity"
          }
    ],
    plainEnglish: "Authentication sessions must enforce an idle inactivity timeout of at most 15 minutes (900 seconds) for standard business and financial applications. If no requests are received within the window, the session must be destroyed.",
    whyItMatters: "If a user steps away from an unlocked computer or public kiosk without logging out, an infinite idle timeout allows anyone who walks by to access the user's account.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Session never expires on idle\napp.use(session({\n    secret: 'secret',\n    resave: false,\n    saveUninitialized: false\n    // No idle timeout configured! Session lasts forever.\n}));",
          "explanation": "Leaves unattended sessions open indefinitely."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Enforcing 15-minute rolling idle timeout\napp.use(session({\n    secret: SESSION_SECRET,\n    cookie: {\n        maxAge: 15 * 60 * 1000 // 15 minutes\n    },\n    rolling: true // Reset expiration timer on user activity\n}));",
          "explanation": "Automatically expires and destroys session after 15 minutes of silence."
    },
    howToTest: {
          "tools": [
                "curl",
                "browser session testing"
          ],
          "steps": [
                "Log in, wait 16 minutes without sending requests.",
                "Attempt request; verify server returns 401 Unauthorized."
          ],
          "commandExample": "curl -b 'session=abc' https://api.target.com/api/profile"
    },
    interviewChallenge: {
          "scenario": "Why must high-security systems implement both an 'Idle Inactivity Timeout' AND an 'Absolute Maximum Lifetime' for sessions?",
          "question": "Can an active user keep an idle-only session alive forever?",
          "hint": "An idle-only session with a rolling timer can be kept alive indefinitely by an automated script or keep-alive ping, allowing stolen sessions to persist for months.",
          "sampleAnswer": "An idle timeout only detects inactivity. If an attacker steals a session cookie and sets up an automated script to ping the server every 5 minutes, a rolling idle timeout will NEVER expire. Enforcing an Absolute Lifetime (e.g. 12 hours) guarantees the session terminates regardless of activity.",
          "keyTakeaway": "Combine a 15-minute rolling idle timeout with a 12-hour absolute session ceiling."
    }
  },
  {
    ruleNumber: 129,
    id: "SEC-AUTH-129",
    title: "Session Maximum Absolute Lifetime Bound (Life \u2264 12h)",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Session Expiration",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-63B", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 s \u2208 ActiveSessions, (Now() - s.CreatedAtTimestamp > 43200s) \u21d2 DestroySession(s) \u2227 ForceReAuthentication()",
    symbolBreakdown: [
          {
                "symbol": "CreatedAtTimestamp",
                "meaning": "Immutable timestamp recording the moment the session was first created"
          },
          {
                "symbol": "> 43200s",
                "meaning": "12 hours absolute maximum lifetime ceiling"
          }
    ],
    plainEnglish: "All authenticated sessions must enforce an absolute maximum lifetime (e.g. 12 hours). Sessions must be permanently destroyed when this ceiling is reached, regardless of ongoing user activity.",
    whyItMatters: "Without an absolute session lifetime, a stolen session cookie can be kept alive indefinitely by an attacker sending periodic background pings, maintaining unauthorized access for months.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Only sliding idle timeout; no absolute cap\ndef check_session(session):\n    # Session can be kept alive for 5 years if active every 10 minutes!\n    if time.time() - session.last_active > 900:\n        raise Unauthorized()\n    session.last_active = time.time()",
          "explanation": "Allows active sessions to persist indefinitely without periodic re-authentication."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Enforcing 12-hour absolute lifetime ceiling\nABSOLUTE_LIFETIME = 12 * 3600 # 12 hours\n\ndef check_session(session):\n    now = time.time()\n    if now - session.created_at > ABSOLUTE_LIFETIME:\n        destroy_session(session.id)\n        raise Unauthorized('Session expired: absolute lifetime reached')\n    if now - session.last_active > 900:\n        destroy_session(session.id)\n        raise Unauthorized('Session expired: idle timeout')",
          "explanation": "Guarantees all sessions terminate after 12 hours, forcing credential re-validation."
    },
    howToTest: {
          "tools": [
                "curl",
                "unit tests"
          ],
          "steps": [
                "Set session.created_at to 13 hours ago.",
                "Send request; verify server returns 401 Unauthorized."
          ],
          "commandExample": "node -e 'console.log(\"Testing absolute session lifetime\")'"
    },
    interviewChallenge: {
          "scenario": "In financial banking systems, why is the absolute session lifetime typically set to 15 to 30 minutes, whereas consumer social apps use 30 days?",
          "question": "How does threat modeling govern session lifetimes?",
          "hint": "Banking systems prioritize confidentiality and fraud prevention over convenience, minimizing the window of opportunity for stolen session tokens.",
          "sampleAnswer": "Session lifetime is a direct trade-off between user friction and risk exposure. In banking, the financial blast radius of an unattended session is catastrophic, requiring aggressive absolute limits (15-30m). In social apps, convenience dominates, relying on device-level lockouts and push notifications.",
          "keyTakeaway": "Set absolute session lifetimes aligned with the financial and operational risk of the application."
    }
  },
  {
    ruleNumber: 130,
    id: "SEC-AUTH-130",
    title: "Biometric Authenticator Liveness Verification Invariant",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Biometrics",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["ISO/IEC 30107-3", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 bio \u2208 BiometricMatchRequests, PresentationAttackDetected(bio) = False \u2227 LivenessScore(bio) \u2265 Threshold",
    symbolBreakdown: [
          {
                "symbol": "BiometricMatchRequests",
                "meaning": "Facial recognition or fingerprint authentication events"
          },
          {
                "symbol": "PresentationAttackDetected",
                "meaning": "Detection of 3D masks, printed photos, or video replays (PAD per ISO 30107-3)"
          }
    ],
    plainEnglish: "Biometric authentication systems must implement Presentation Attack Detection (PAD) and liveness verification conforming to ISO/IEC 30107-3. Raw 2D image matching without 3D depth or active challenge-response is prohibited.",
    whyItMatters: "Attackers hold up a printed high-resolution photograph or play a video of the user on an iPad in front of the camera, easily unlocking systems that lack active 3D liveness detection.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: 2D facial comparison without liveness\ndef authenticate_face(captured_image, registered_face):\n    # Matches facial landmarks but fails to check if it is a live human or a photo!\n    return face_recognition.compare_faces([registered_face], captured_image)[0]",
          "explanation": "Vulnerable to printed photo and screen replay spoofing attacks."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Passive and active 3D liveness analysis (ISO/IEC 30107-3)\ndef authenticate_face(captured_frames, registered_face):\n    liveness_passed = liveness_engine.verify_3d_liveness(\n        captured_frames,\n        check_depth=True,\n        check_texture_micro_reflections=True\n    )\n    if not liveness_passed:\n        raise SecurityError('Presentation attack detected (photo/mask spoof)')\n    return face_recognition.compare_faces([registered_face], captured_frames[-1])[0]",
          "explanation": "Detects micro-movements, pupil dilation, and 3D depth to guarantee a live human subject."
    },
    howToTest: {
          "tools": [
                "ISO 30107-3 test kit",
                "photo spoof simulation"
          ],
          "steps": [
                "Present high-res screen photo to camera.",
                "Verify system detects presentation attack and aborts authentication."
          ],
          "commandExample": "node -e 'console.log(\"Testing biometric liveness validation\")'"
    },
    interviewChallenge: {
          "scenario": "Why does NIST SP 800-63B state that biometrics alone do not constitute a secret (knowledge factor) and should be used only as an activation mechanism for a private key?",
          "question": "Can you revoke a compromised fingerprint?",
          "hint": "No. Biometric traits (face, fingerprints) are public identifiers that can be photographed or lifted from glasses, and they can never be changed or rotated if breached.",
          "sampleAnswer": "You cannot revoke your face or fingerprint. Biometrics are not secrets: high-resolution cameras can capture fingerprints from photos across a room. Therefore, NIST requires biometrics to serve only as a local unlocking mechanism for a cryptographic hardware private key (e.g. Touch ID unlocking a WebAuthn key).",
          "keyTakeaway": "Use biometrics only as local device unlockers for cryptographic keys; never transmit raw biometric data over the wire."
    }
  },
  {
    ruleNumber: 131,
    id: "SEC-AUTH-131",
    title: "SMS OTP Deprecation for Financial & High-Value Systems",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "MFA Risk Management",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-63B", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 flow \u2208 HighValueMFAFlows, AllowedMFAMethods(flow) \u2286 {FIDO2_Passkey, App_TOTP} \u2227 AllowedMFAMethods(flow) \u2229 {SMS, VoiceCall} = \u2205",
    symbolBreakdown: [
          {
                "symbol": "HighValueMFAFlows",
                "meaning": "MFA verification for bank transfers, account recovery, or admin logins"
          },
          {
                "symbol": "\u2205",
                "meaning": "Strict exclusion of SMS and voice call OTP delivery"
          }
    ],
    plainEnglish: "Financial, enterprise, and high-value systems must deprecate SMS and voice-call OTPs in accordance with NIST SP 800-63B. Multi-factor authentication must be delivered via authenticator apps (TOTP) or hardware tokens (FIDO2/WebAuthn).",
    whyItMatters: "Criminals bribe telecom store employees or use social engineering to execute SIM-swap attacks, transferring the victim's phone number to an attacker SIM card and receiving all bank 2FA SMS messages in seconds.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Offering SMS as primary 2FA for banking\ndef send_mfa(user):\n    # Easily intercepted via SIM swapping or SS7 exploitation!\n    twilio.send_sms(to=user.phone, body=f\"Your bank transfer code is {code}\")",
          "explanation": "Vulnerable to SIM swapping, SS7 interception, and mobile malware."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Enforcing app-based TOTP or hardware FIDO2 for MFA\ndef verify_mfa(user, submission):\n    # Rejects SMS; requires WebAuthn or TOTP authenticator:\n    if user.mfa_type not in ['WEBAUTHN', 'TOTP']:\n        raise SecurityPolicyError('SMS is deprecated. Register an Authenticator App or Passkey.')\n    return verify_authenticator_token(user, submission)",
          "explanation": "Eliminates reliance on vulnerable telecom carrier infrastructure."
    },
    howToTest: {
          "tools": [
                "twilio simulator",
                "SIM swap audit"
          ],
          "steps": [
                "Attempt enabling SMS 2FA on high-risk admin tier.",
                "Verify security policy restricts MFA selection to Authenticator App or Security Key."
          ],
          "commandExample": "node -e 'console.log(\"SMS MFA deprecation policy check\")'"
    },
    interviewChallenge: {
          "scenario": "What is an SS7 (Signaling System No. 7) network attack, and how does it allow foreign adversaries to intercept SMS verification codes globally?",
          "question": "Can an attacker intercept an SMS without physically SIM-swapping the victim's phone?",
          "hint": "Yes. By leasing access to global telecom SS7 signaling hubs, attackers can send routing updates (MAP SRI4SM) that divert all incoming SMS text messages to an attacker server anywhere in the world.",
          "sampleAnswer": "SS7 is the legacy global routing protocol used by telecom carriers. Attackers with access to SS7 gateways exploit the lack of mutual authentication between international carriers to update location registers (HLR), causing the cellular network to route the victim's SMS messages directly to an attacker-controlled receiver.",
          "keyTakeaway": "Deprecate SMS 2FA in favor of cryptographic WebAuthn credentials."
    }
  },
  {
    ruleNumber: 132,
    id: "SEC-AUTH-132",
    title: "Magic Link Token One-Time Consumption and Invalidation",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Passwordless Auth",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["OWASP Cheat Sheet", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 link \u2208 MagicLinks, ConsumeToken(link.Token) \u21d2 InvalidateToken(link.Token) \u2227 LinkLifetime(link) \u2264 600s",
    symbolBreakdown: [
          {
                "symbol": "MagicLinks",
                "meaning": "Passwordless email login links containing a cryptographic token"
          },
          {
                "symbol": "ConsumeToken",
                "meaning": "Token verified upon user clicking link"
          },
          {
                "symbol": "<= 600s",
                "meaning": "10-minute maximum lifetime"
          }
    ],
    plainEnglish: "Passwordless 'magic link' authentication tokens must be single-use, cryptographically bound to the initiating session, expire within 10 minutes (600 seconds), and require a confirmation click if triggered by automated email scanners.",
    whyItMatters: "Corporate email security gateways (e.g. Proofpoint, Mimecast) automatically pre-fetch and scan every link in incoming emails. Without a confirmation button, the scanner consumes the magic link token before the user even opens the email.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Direct login on GET request without confirmation\n@app.get('/auth/magic')\ndef magic_login(token: str):\n    user = verify_and_burn_token(token) # Consumed by email scanner bot!\n    return issue_session(user)",
          "explanation": "Email scanners pre-fetch link, burning the token or logging into the session on a scanner server."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Two-phase magic link with landing confirmation click\n@app.get('/auth/magic')\ndef magic_landing(token: str):\n    # Returns HTML page with 'Confirm Login' button; ignores GET bot clicks\n    return render_template('confirm_login.html', token=token)\n\n@app.post('/auth/magic/confirm')\ndef magic_confirm(token: str):\n    user = verify_and_burn_token(token)\n    return issue_session(user)",
          "explanation": "Requires manual user click on POST endpoint, neutralizing automated email link pre-fetch scanners."
    },
    howToTest: {
          "tools": [
                "curl",
                "browser automated test"
          ],
          "steps": [
                "Send magic link.",
                "Simulate automated email scanner GET request.",
                "Verify token is NOT burned and real user can still complete login via POST confirmation."
          ],
          "commandExample": "curl \"https://api.target.com/auth/magic?token=valid_token\""
    },
    interviewChallenge: {
          "scenario": "Why does the HTTP GET method violate RFC 9110 if used to log a user into an account or invalidate a token?",
          "question": "Why should state-changing actions use POST?",
          "hint": "RFC 9110 defines GET as a safe, idempotent method that must not cause state changes. Browser pre-fetching, search crawlers, and antivirus proxies trigger GET requests automatically.",
          "sampleAnswer": "HTTP GET is defined as a 'safe' method: intermediaries, browser URL pre-fetchers, and email scanners feel free to fetch GET URLs without expecting side effects. If a magic link uses GET to authenticate a session, email scanners will log in or consume the token. State changes must require a POST request.",
          "keyTakeaway": "Use a landing page with a POST confirmation button for magic link authentication."
    }
  },
  {
    ruleNumber: 133,
    id: "SEC-AUTH-133",
    title: "Re-Authentication Required for Sensitive Security Actions",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Step-Up Auth",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-63B", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 act \u2208 {ChangePassword, ChangeEmail, AddMFAKey, DeleteAccount}, LastAuthTime(User) \u2264 300s \u2228 TriggerReAuthentication()",
    symbolBreakdown: [
          {
                "symbol": "SensitiveSecurityActions",
                "meaning": "Modifications to identity credentials or security settings"
          },
          {
                "symbol": "LastAuthTime <= 300s",
                "meaning": "User verified their master password or biometrics within the last 5 minutes"
          }
    ],
    plainEnglish: "Critical account actions (changing passwords, updating recovery emails, adding MFA devices, or deleting accounts) must demand password re-authentication if the user's last password entry was more than 5 minutes ago.",
    whyItMatters: "If a user leaves their laptop unlocked at a coffee shop or office, a passerby can quickly navigate to account settings, change the email, and lock the user out permanently in under 30 seconds.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Updating email without password challenge\napp.post('/api/user/email', authenticate, async (req, res) => {\n    await db.user.update(req.user.id, { email: req.body.email });\n    res.json({ status: 'updated' });\n});",
          "explanation": "Anyone with physical access to an unlocked browser can steal the account."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Enforcing password re-authentication before email change\napp.post('/api/user/email', authenticate, async (req, res) => {\n    const isPasswordValid = await verifyPassword(req.user.id, req.body.currentPassword);\n    if (!isPasswordValid) {\n        return res.status(401).json({ error: 'Current password required to update email' });\n    }\n    await db.user.update(req.user.id, { email: req.body.email });\n    res.json({ status: 'updated' });\n});",
          "explanation": "Requires physical possession of the current password to modify security settings."
    },
    howToTest: {
          "tools": [
                "curl",
                "browser test"
          ],
          "steps": [
                "Attempt updating recovery email without submitting current password.",
                "Verify API returns 401 Unauthorized."
          ],
          "commandExample": "curl -X POST -H \"Authorization: Bearer token\" -d '{\"email\":\"new@test.com\"}' https://api.target.com/user/email"
    },
    interviewChallenge: {
          "scenario": "How do GitHub and Google implement 'Sudo Mode' for sensitive web actions?",
          "question": "How long does Sudo Mode stay active?",
          "hint": "When you attempt a sensitive action (like adding an SSH key), you are prompted for your password. Once entered, Sudo Mode grants a temporary 10-15 minute window where subsequent sensitive actions proceed without re-prompting.",
          "sampleAnswer": "Sudo Mode maintains an ephemeral timestamp (`sudo_authenticated_at`) in session state. Once verified, the user enters an elevated state for a short window (e.g. 15 minutes). After expiration, any new security-sensitive action re-prompts for the credential, balancing friction with security.",
          "keyTakeaway": "Implement temporary Sudo Mode sessions for administrative workflows."
    }
  },
  {
    ruleNumber: 134,
    id: "SEC-AUTH-134",
    title: "Authentication Audit Logging (Tamper-Resistant Events)",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Audit & Accountability",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-53 AU-2", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 evt \u2208 AuthAuditEvents, WriteToAppendOnlyLog(evt) \u2227 PII_Masked(evt) \u2227 HasFields(evt, {Subject, IP, Action, Status, Timestamp})",
    symbolBreakdown: [
          {
                "symbol": "AuthAuditEvents",
                "meaning": "Login successes, failures, password resets, MFA changes, lockouts"
          },
          {
                "symbol": "WriteToAppendOnlyLog",
                "meaning": "WORM storage (Write Once Read Many) or write-only log stream (CloudWatch, Splunk)"
          },
          {
                "symbol": "PII_Masked",
                "meaning": "Passwords and full card numbers never logged"
          }
    ],
    plainEnglish: "All authentication events (successes, failures, password changes, token revocations) must be recorded in an immutable, append-only audit log containing timestamp, subject ID, client IP, user agent, and event type. Credentials must be redacted.",
    whyItMatters: "Without tamper-resistant audit logs, security teams cannot detect ongoing credential-stuffing campaigns, investigate data breaches, or prove regulatory compliance (PCI-DSS, HIPAA).",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Logging sensitive passwords or omitting audit trail\ndef login(username, password):\n    # VULNERABLE: Logs plaintext password!\n    logger.info(f\"Login attempt for {username} with password {password}\")",
          "explanation": "Exposes user passwords in plaintext logging aggregators and SIEM tools."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Structured append-only audit logging with credential redaction\ndef audit_auth_event(event_type, user_id, ip_address, status):\n    audit_logger.info({\n        \"event\": event_type,\n        \"user_id\": user_id,\n        \"ip\": ip_address,\n        \"status\": status,\n        \"timestamp\": datetime.utcnow().isoformat(),\n        \"correlation_id\": get_correlation_id()\n    })",
          "explanation": "Emits structured security telemetry while strictly preventing password ingestion."
    },
    howToTest: {
          "tools": [
                "Splunk",
                "grep access.log"
          ],
          "steps": [
                "Trigger 5 failed logins.",
                "Inspect security log stream; confirm 5 structured JSON audit events exist with zero passwords logged."
          ],
          "commandExample": "grep 'AUTH_LOGIN' /var/log/app/security.log"
    },
    interviewChallenge: {
          "scenario": "Why is logging user-submitted passwords (even accidentally during failed logins) a major compliance and security catastrophe?",
          "question": "What happens if a user accidentally types their password into the username field?",
          "hint": "If an application logs the username on failure, mistyped passwords end up in plaintext log files indexed by thousands of internal employees in Datadog or Splunk.",
          "sampleAnswer": "Users frequently type their password into the username field by accident. If the application logs failed usernames verbatim, internal developers and log-pipeline administrators gain access to real user passwords. Modern audit loggers sanitize and scrub input fields before writing to disk.",
          "keyTakeaway": "Sanitize all auth logs and store security audit trails in append-only storage."
    }
  },
  {
    ruleNumber: 135,
    id: "SEC-AUTH-135",
    title: "Concurrent Session Ceiling per User Account Invariant",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Session Governance",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["OWASP ASVS \u00a73.3.3", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 u \u2208 Users, Count(ActiveSessions(u)) \u2264 MaxConcurrentLimit(5) \u2227 EvictOldestSessionOnExceed()",
    symbolBreakdown: [
          {
                "symbol": "ActiveSessions",
                "meaning": "Simultaneous active session tokens in Redis"
          },
          {
                "symbol": "MaxConcurrentLimit <= 5",
                "meaning": "Ceiling on simultaneous active devices"
          },
          {
                "symbol": "EvictOldestSessionOnExceed",
                "meaning": "Automatic revocation of least-recently-used session"
          }
    ],
    plainEnglish: "Applications must enforce a ceiling on concurrent active sessions per user account (e.g. at most 5 concurrent devices). When the ceiling is exceeded, the oldest least-recently-used session must be automatically revoked.",
    whyItMatters: "Unbounded concurrent sessions allow compromised accounts to be shared across hundreds of unauthorized users on dark-web forums without triggering notice.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Unbounded session creation\ndef create_session(user_id):\n    # Generates infinite sessions; an attacker can stay logged in forever\n    session_id = secrets.token_hex(16)\n    db.save(user_id, session_id)\n    return session_id",
          "explanation": "Allows thousands of concurrent sessions across malicious networks."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Enforcing maximum concurrent session bound\nMAX_SESSIONS = 5\n\ndef create_session(user_id):\n    user_sessions = redis.zrange(f\"sessions:{user_id}\", 0, -1)\n    if len(user_sessions) >= MAX_SESSIONS:\n        # Evict oldest session:\n        oldest = user_sessions[0]\n        redis.zrem(f\"sessions:{user_id}\", oldest)\n        redis.delete(f\"session:{oldest}\")\n    new_session = secrets.token_hex(16)\n    redis.zadd(f\"sessions:{user_id}\", {new_session: time.time()})\n    return new_session",
          "explanation": "Maintains strict upper bound on active devices by evicting oldest sessions."
    },
    howToTest: {
          "tools": [
                "redis-cli",
                "curl"
          ],
          "steps": [
                "Log in on 6 separate browsers/curl sessions.",
                "Confirm browser 1 receives 401 Unauthorized because it was evicted by the 6th login."
          ],
          "commandExample": "redis-cli zcard 'sessions:user_123'"
    },
    interviewChallenge: {
          "scenario": "How does enforcing concurrent session limits help detect credential sharing in enterprise B2B SaaS platforms?",
          "question": "What happens when multiple employees share a single license?",
          "hint": "When user 6 logs in, user 1 is kicked out, creating immediate operational friction for account sharing and incentivizing proper seat licensing.",
          "sampleAnswer": "In enterprise software, concurrent session bounds prevent credential sharing where an entire department shares a single high-privilege account. When a new person logs in, the previous user is bumped off, enforcing individual accountability and proper audit trails.",
          "keyTakeaway": "Enforce concurrent session bounds in Redis sorted sets."
    }
  },
  {
    ruleNumber: 136,
    id: "SEC-AUTH-136",
    title: "Password Change Invalidates All Other Active Sessions",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Account Security",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["OWASP ASVS \u00a73.3.4", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 u \u2208 Users, OnPasswordChange(u) \u21d2 InvalidateSessions(AllExceptCurrent(u)) \u2227 ReissueSessionToken(u)",
    symbolBreakdown: [
          {
                "symbol": "OnPasswordChange",
                "meaning": "Successful password update event"
          },
          {
                "symbol": "AllExceptCurrent",
                "meaning": "All other mobile apps, browsers, and API tokens"
          }
    ],
    plainEnglish: "When a user successfully changes their password, the system must immediately invalidate all other active sessions and refresh tokens. Only the current browser performing the update may remain authenticated.",
    whyItMatters: "If an account was compromised, the real user logs in and changes their password to secure the account. If active sessions are not revoked, the attacker's existing session remains valid, and the intruder retains full control.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Changing password without revoking active sessions\ndef update_password(user, new_pwd):\n    user.password_hash = hash(new_pwd)\n    db.save(user) # Attacker's active session cookie is still valid!",
          "explanation": "Attacker remains logged in and steals data even after password change."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Revoking all other sessions upon password change\ndef update_password(user, new_pwd, current_session_id):\n    user.password_hash = hash(new_pwd)\n    db.save(user)\n    # Destroy all other sessions in Redis:\n    revoke_all_sessions_except(user.id, current_session_id)",
          "explanation": "Immediately severs attacker access across all devices."
    },
    howToTest: {
          "tools": [
                "curl",
                "multi-session testing"
          ],
          "steps": [
                "Log in on browser A and browser B.",
                "Change password in browser A.",
                "Attempt to make request in browser B; verify browser B receives 401 Unauthorized."
          ],
          "commandExample": "curl -b 'session=sessionB' https://api.target.com/profile"
    },
    interviewChallenge: {
          "scenario": "Why should the current browser that performed the password change be spared from logout, while all other devices are terminated?",
          "question": "What user experience problem does logging out the current browser cause?",
          "hint": "If the current browser is logged out, the user must immediately re-enter the password they just typed, causing confusion and frustration.",
          "sampleAnswer": "Sparing the active session provides clean UX: the user sees confirmation that their password was changed without being immediately ejected. However, all other remote sessions (which might belong to the intruder) are terminated immediately.",
          "keyTakeaway": "Revoke all remote sessions while re-issuing a fresh token for the current window."
    }
  },
  {
    ruleNumber: 137,
    id: "SEC-AUTH-137",
    title: "Single Sign-On (SSO) SAML Response Assertion Signature Validation",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Enterprise SSO",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["OASIS SAML 2.0", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 resp \u2208 SAMLResponses, VerifySignature(resp.Assertion, IdP_Cert) = True \u2227 (Now() \u2264 resp.NotOnOrAfter) \u2227 (resp.Audience = SP_EntityID)",
    symbolBreakdown: [
          {
                "symbol": "SAMLResponses",
                "meaning": "SAML 2.0 XML authentication assertions from Okta, Azure AD, or Ping"
          },
          {
                "symbol": "VerifySignature",
                "meaning": "XML signature verification of the Assertion element, not just the Response wrapper"
          },
          {
                "symbol": "NotOnOrAfter",
                "meaning": "Strict timestamp expiry window"
          },
          {
                "symbol": "Audience",
                "meaning": "Service Provider Entity ID matching application"
          }
    ],
    plainEnglish: "SAML Service Providers must cryptographically verify the signature of the `<Assertion>` element using the Identity Provider's verified X.509 certificate. Systems must check `NotOnOrAfter` and match the `Audience` to the Service Provider Entity ID.",
    whyItMatters: "If an application only verifies the outer `<Response>` signature instead of the `<Assertion>`, an attacker can inject an unsigned child assertion (XML Signature Wrapping), forging identity as the company CEO.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Only checking outer response signature\ndef process_saml(xml_response):\n    # FLAW: If response is signed but inner assertion is swapped, attacker takes over accounts!\n    if saml.verify_response_signature(xml_response):\n        return saml.get_user(xml_response)",
          "explanation": "Vulnerable to XML Signature Wrapping (XSW) attacks."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Validating inner Assertion signature, Audience, and expiration\ndef process_saml(xml_response):\n    authn = OneLogin_Saml2_Auth(req, custom_settings)\n    authn.process_response()\n    errors = authn.get_errors()\n    if errors or not authn.is_authenticated():\n        raise SecurityError(f'SAML validation failed: {authn.get_last_error_reason()}')\n    return authn.get_attributes()",
          "explanation": "Enforces cryptographic verification of inner assertion, audience restriction, and time window."
    },
    howToTest: {
          "tools": [
                "saml-tracer browser extension",
                "python-saml"
          ],
          "steps": [
                "Inspect SAMLResponse XML in transit.",
                "Confirm `<ds:Signature>` is embedded directly inside `<saml:Assertion>`."
          ],
          "commandExample": "xmlsec1 --verify --pubkey-cert-pem idp.crt saml_response.xml"
    },
    interviewChallenge: {
          "scenario": "What is an XML Signature Wrapping (XSW) attack in SAML authentication?",
          "question": "How do attackers deceive XML parsers with duplicate assertion elements?",
          "hint": "An attacker copies the legitimate signed assertion to an innocuous XML location and injects an unsigned malicious assertion into the location parsed by application business logic.",
          "sampleAnswer": "In an XSW attack, the XML signature verification library validates a legitimate, untouched signed `<Assertion>` located elsewhere in the document. However, the application controller's XPath query locates an attacker-modified `<Assertion>` at the top of the tree, granting the attacker access as an arbitrary user.",
          "keyTakeaway": "Use battle-tested SAML libraries (python-saml, passport-saml) that strictly enforce Assertion-level signatures."
    }
  },
  {
    ruleNumber: 138,
    id: "SEC-AUTH-138",
    title: "Email Verification Token Cryptographic Binding and Expiry",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Registration Security",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["OWASP ASVS \u00a72.4", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 tok \u2208 VerificationTokens, (Now() - tok.CreatedAt \u2264 86400s) \u2227 VerifyHash(tok, db.StoredHash) = True \u2227 ConsumeToken(tok)",
    symbolBreakdown: [
          {
                "symbol": "VerificationTokens",
                "meaning": "Account activation tokens delivered via email upon registration"
          },
          {
                "symbol": "<= 86400s",
                "meaning": "24-hour expiration window"
          },
          {
                "symbol": "ConsumeToken",
                "meaning": "Token invalidated immediately upon first verification"
          }
    ],
    plainEnglish: "Email verification tokens must be cryptographically unguessable (>= 128 bits), expire within 24 hours, and be stored as hashes in the database. Unverified accounts must have restricted capabilities until activation.",
    whyItMatters: "Allowing unverified accounts to perform actions enables attackers to register thousands of accounts using victims' email addresses, flooding victims with notifications and spamming external users.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Predictable sequential email verification token\ndef generate_verify_link(user_id):\n    # Attacker guesses tokens for any account!\n    return f\"https://target.com/verify?uid={user_id}&token={user_id * 7}\"",
          "explanation": "Enables automated activation of fake or hijacked accounts."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: CSPRNG token stored as SHA-256 hash\ndef generate_verify_link(user_id):\n    raw_token = secrets.token_urlsafe(32)\n    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()\n    db.save_verification(user_id, token_hash, expires_at=time.time() + 86400)\n    return f\"https://target.com/verify?token={raw_token}\"",
          "explanation": "Cryptographically unguessable token valid for 24 hours."
    },
    howToTest: {
          "tools": [
                "curl",
                "unit tests"
          ],
          "steps": [
                "Attempt activating account with modified token byte; verify 400 Bad Request."
          ],
          "commandExample": "curl https://api.target.com/verify?token=invalid_token"
    },
    interviewChallenge: {
          "scenario": "Why should an unverified account be prevented from changing its registered email address?",
          "question": "What vulnerability arises if an unverified user changes their email?",
          "hint": "An attacker registers a victim's email, changes it to their own before verifying, and bypasses registration validation checks or corrupts identity records.",
          "sampleAnswer": "If an unverified account can update its email address without re-initiating the entire verification cycle, attackers can exploit race conditions or transfer account metadata across domains without proving domain ownership.",
          "keyTakeaway": "Lock identity attributes until email verification is complete."
    }
  },
  {
    ruleNumber: 139,
    id: "SEC-AUTH-139",
    title: "Account Recovery Primary Channel Isolation (No In-App Secrets)",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Account Recovery",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-63B", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 recovery \u2208 AccountRecoveryRequests, Channel(recovery) = OutOfBand \u2227 DisclosesInAppSecrets(recovery) = False",
    symbolBreakdown: [
          {
                "symbol": "AccountRecoveryRequests",
                "meaning": "Password reset and account unlock requests"
          },
          {
                "symbol": "OutOfBand",
                "meaning": "Delivered exclusively to verified secondary channel: email, SMS, hardware admin"
          },
          {
                "symbol": "DisclosesInAppSecrets = False",
                "meaning": "Never echoes current passwords, PINs, or recovery questions in UI"
          }
    ],
    plainEnglish: "Account recovery workflows must operate out-of-band via verified communication channels. Recovery flows must never echo secrets in the UI, hint at password contents, or disclose answers to security questions.",
    whyItMatters: "In-app recovery flaws allow attackers who hijack a browser or compromise an API endpoint to view password hints or reset credentials directly without receiving email authorization.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: In-app password hint or secret disclosure\n@app.get('/recover')\ndef recover(email: str):\n    user = db.find(email)\n    # Leaks password hint and secret answers directly in HTTP response!\n    return {\"hint\": user.password_hint, \"security_question\": user.question}",
          "explanation": "Exposes user credentials directly to web scrapers and unauthorized callers."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Pure out-of-band recovery token dispatch\n@app.post('/recover')\ndef recover(req: RecoverDto):\n    user = db.find(req.email)\n    if user:\n        token = generate_secure_token(user.id)\n        send_out_of_band_email(user.email, token)\n    # Always return generic message to prevent enumeration:\n    return {\"message\": \"If the account exists, a recovery link has been sent.\"}",
          "explanation": "Dispatches one-time token out-of-band without leaking account existence or secrets in response."
    },
    howToTest: {
          "tools": [
                "curl",
                "OWASP ZAP"
          ],
          "steps": [
                "Submit recovery request for test account.",
                "Inspect JSON response; verify zero hints, tokens, or personal data returned in payload."
          ],
          "commandExample": "curl -X POST -d '{\"email\":\"test@example.com\"}' https://api.target.com/recover"
    },
    interviewChallenge: {
          "scenario": "Why does NIST SP 800-63B explicitly ban knowledge-based security questions ('What was your first pet's name?') for account recovery?",
          "question": "How do attackers find answers to security questions?",
          "hint": "Answers to security questions are readily discovered via public social media profiles (LinkedIn, Facebook, Instagram) or public record databases.",
          "sampleAnswer": "Security questions possess extremely low entropy and are easily discoverable via social media or data broker sites. Furthermore, users often forget their answers or enter false answers they cannot recall. Modern systems rely on out-of-band cryptographic tokens or FIDO2 recovery keys.",
          "keyTakeaway": "Eliminate security questions; use out-of-band cryptographic tokens for recovery."
    }
  },
  {
    ruleNumber: 140,
    id: "SEC-AUTH-140",
    title: "Client IP and User-Agent Session Binding Anomaly Guard",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Session Hijacking",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["OWASP Session Management", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 req \u2208 AuthenticatedRequests, (Subnet(req.IP) \u2260 Session.InitialSubnet \u2228 req.UserAgent \u2260 Session.UserAgent) \u21d2 TriggerAnomalyAlert()",
    symbolBreakdown: [
          {
                "symbol": "AuthenticatedRequests",
                "meaning": "Requests bearing active session cookies"
          },
          {
                "symbol": "InitialSubnet",
                "meaning": "IP /24 subnet recorded when session was established"
          },
          {
                "symbol": "UserAgent",
                "meaning": "Client browser user agent string"
          }
    ],
    plainEnglish: "When an incoming session cookie is presented from a drastically different IP subnet or a completely different User-Agent string, the application must flag a session hijacking anomaly and mandate re-authentication.",
    whyItMatters: "An attacker who steals a session cookie from an executive in California via an XSS flaw imports the cookie into their browser in Russia. Without anomaly detection, the Russian attacker takes over the session immediately.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Blindly trusting session cookie from any IP/browser\ndef check_session(req):\n    session = db.get_session(req.cookies.get('session_id'))\n    # Ignores that IP jumped from Texas to Ukraine and User-Agent changed from Safari to Chrome!\n    return session.user",
          "explanation": "Allows stolen session cookies to be used anywhere in the world."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Session binding and anomaly detection\ndef check_session(req):\n    session = db.get_session(req.cookies.get('session_id'))\n    if not session: raise Unauthorized()\n    current_subnet = get_subnet_24(req.client_ip)\n    if current_subnet != session.initial_subnet or req.user_agent != session.initial_ua:\n        # Anomaly detected: terminate session or challenge with MFA\n        destroy_session(session.id)\n        raise Unauthorized('Session anomaly detected: please log in again')",
          "explanation": "Detects IP and User-Agent jumps indicative of session cookie theft."
    },
    howToTest: {
          "tools": [
                "curl with modified User-Agent",
                "curl with proxy"
          ],
          "steps": [
                "Log in via browser.",
                "Extract cookie and send request via curl with different User-Agent: `curl -H 'User-Agent: AttackBot' -b 'session=...'`.",
                "Verify server rejects with 401."
          ],
          "commandExample": "curl -H \"User-Agent: Attacker\" -b \"session=abc\" https://api.target.com/api/profile"
    },
    interviewChallenge: {
          "scenario": "Why should IP binding checks inspect the `/24` subnet rather than requiring the exact 32-bit IPv4 address?",
          "question": "What happens to mobile users on cellular networks as they move?",
          "hint": "Mobile devices constantly hop across cellular towers and IP addresses while walking, which would prematurely terminate legitimate sessions if exact IP matching were enforced.",
          "sampleAnswer": "Cellular networks and dynamic ISPs regularly rotate user IP addresses within their assigned subnet pool during active browsing. Strict 32-bit IP binding causes frequent session drops for mobile users. Checking the `/24` subnet or pairing with ASN checks balances security with usability.",
          "keyTakeaway": "Inspect `/24` subnets and User-Agent headers to catch cross-country session theft without breaking mobile clients."
    }
  },
  {
    ruleNumber: 141,
    id: "SEC-AUTH-141",
    title: "Security Questions Deprecation Invariant",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Knowledge-Based Auth",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-63B \u00a75.1.1.2", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 flow \u2208 AuthWorkflows, UsesKnowledgeBasedQuestions(flow) = False",
    symbolBreakdown: [
          {
                "symbol": "UsesKnowledgeBasedQuestions",
                "meaning": "Queries like 'mother's maiden name', 'first car', 'elementary school'"
          }
    ],
    plainEnglish: "Applications must not use knowledge-based security questions for authentication, password resets, or account recovery. All knowledge-based authentication mechanisms must be completely removed in accordance with NIST SP 800-63B.",
    whyItMatters: "Security questions are shared secrets with low entropy. Attackers easily guess them through social engineering, open-source intelligence (OSINT), or public genealogy records.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Using security questions for password reset\nif user.security_answer == submitted_answer:\n    reset_password(user)",
          "explanation": "Vulnerable to OSINT and social engineering attacks."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Phishing-resistant recovery without security questions\ndef initiate_recovery(user):\n    send_secure_recovery_email(user)\n    require_mfa_token_or_backup_code(user)",
          "explanation": "Relies on out-of-band tokens and cryptographic backup codes."
    },
    howToTest: {
          "tools": [
                "audit tools",
                "OWASP ASVS checker"
          ],
          "steps": [
                "Audit user profile schema.",
                "Confirm zero 'security_question' or 'security_answer' fields exist in the database."
          ],
          "commandExample": "grep -rn 'security_question' src/"
    },
    interviewChallenge: {
          "scenario": "Why do security questions frequently fail even for legitimate users?",
          "question": "Do users remember their answers accurately over years?",
          "hint": "Users often forget what capitalization, abbreviations, or false answers they gave years earlier, resulting in massive customer support lockouts.",
          "sampleAnswer": "Users often provide whimsical or intentionally false answers to avoid tracking, only to forget their specific answers when locked out years later. Real answers are readily discoverable by relatives or attackers, while fake answers lead to permanent account abandonment.",
          "keyTakeaway": "Completely deprecate knowledge-based security questions across all systems."
    }
  },
  {
    ruleNumber: 142,
    id: "SEC-AUTH-142",
    title: "Brute-Force CAPTCHA / Proof-of-Work Adaptive Trigger",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Bot Mitigation",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["OWASP Automated Threats", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 ip \u2208 ClientIPs, FailedRate(ip, 1m) > 10 \u21d2 RequireProofOfWork(ip) \u2228 PresentTurnstileCAPTCHA(ip)",
    symbolBreakdown: [
          {
                "symbol": "FailedRate > 10",
                "meaning": "More than 10 failed login attempts from an IP or subnet in 1 minute"
          },
          {
                "symbol": "RequireProofOfWork",
                "meaning": "Client must solve computational cryptographic puzzle before next request"
          },
          {
                "symbol": "PresentTurnstileCAPTCHA",
                "meaning": "Cloudflare Turnstile or reCAPTCHA v3 challenge"
          }
    ],
    plainEnglish: "When an IP address or subnet exceeds failure thresholds, authentication endpoints must adaptively require a cryptographic Proof-of-Work or non-intrusive CAPTCHA challenge before processing further credentials.",
    whyItMatters: "Automated botnets distribute credential-stuffing attacks across thousands of residential proxy IPs. Adaptive CAPTCHA and Proof-of-Work puzzles introduce computational and financial friction that stops distributed attacks.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: No bot friction on repeated failures\n@app.post('/login')\ndef login(req: LoginDto):\n    # Allows bots to guess millions of credentials without friction\n    return verify(req)",
          "explanation": "Allows automated bots to spray millions of credentials with zero computational cost."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Adaptive CAPTCHA verification on failure surge\n@app.post('/login')\ndef login(req: LoginDto, captcha_token: Optional[str] = Header(None)):\n    if redis.get(f'bot_alert:{req.client_ip}'):\n        if not captcha_token or not verify_turnstile(captcha_token):\n            raise HTTPException(403, 'CAPTCHA verification required due to suspicious activity')\n    return verify(req)",
          "explanation": "Forces client to complete CAPTCHA verification when suspicious activity is detected."
    },
    howToTest: {
          "tools": [
                "puppeteer bot tester",
                "curl"
          ],
          "steps": [
                "Simulate 15 rapid failed logins from same IP.",
                "Verify 16th request returns 403 demanding CAPTCHA token."
          ],
          "commandExample": "curl -X POST -d '{\"user\":\"a\",\"pass\":\"b\"}' https://api.target.com/login"
    },
    interviewChallenge: {
          "scenario": "How does Proof-of-Work (PoW) client-side hashing mitigate bot attacks without annoying legitimate human users?",
          "question": "What does the browser compute in the background?",
          "hint": "The client's browser calculates a SHA-256 hash collision (taking ~500ms of CPU). To a human, 500ms is unnoticeable, but to a bot trying 100,000 requests, it requires massive CPU farms.",
          "sampleAnswer": "Proof-of-Work forces the client's browser to compute a cryptographic puzzle (e.g. finding a hash with 4 leading zeroes) using JavaScript or WebAssembly before submitting the form. A single human user barely notices a 200ms CPU pause, but a botnet attempting 10,000 logins per second requires gigawatts of compute power.",
          "keyTakeaway": "Deploy adaptive proof-of-work or invisible CAPTCHA when bot velocity spikes."
    }
  },
  {
    ruleNumber: 143,
    id: "SEC-AUTH-143",
    title: "SAML XML Signature Wrapping (XSW) Exclusion Invariant",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "SSO Protocol Hardening",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["OWASP SAML Security", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 saml \u2208 SAMLDocuments, Count(saml.XPath(\"//saml:Assertion\")) = 1 \u2227 SignatureTargetsID(saml.Signature, saml.Assertion.ID)",
    symbolBreakdown: [
          {
                "symbol": "SAMLDocuments",
                "meaning": "Raw SAML XML response documents"
          },
          {
                "symbol": "Count(//saml:Assertion) = 1",
                "meaning": "Prohibits multiple or nested assertions"
          },
          {
                "symbol": "SignatureTargetsID",
                "meaning": "XML digital signature URI attribute matches assertion ID exactly"
          }
    ],
    plainEnglish: "SAML Service Providers must verify that the incoming SAML document contains exactly one `<saml:Assertion>` and that the digital signature reference targets that specific Assertion ID directly. Documents with multiple assertions must be rejected.",
    whyItMatters: "In an XML Signature Wrapping (XSW) attack, an attacker embeds a genuine signed assertion alongside an injected unsigned rogue assertion. Vulnerable XML libraries validate the real assertion but evaluate the rogue assertion, granting administrative account takeover.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: Loose XPath query finding first assertion\ndef get_saml_user(xml_doc):\n    # Attacker injects a rogue assertion at top; genuine signed assertion is hidden at bottom\n    assertion = xml_doc.xpath('//saml:Assertion')[0] # Grabs the malicious unsigned one!\n    return assertion.find('Subject').text",
          "explanation": "Vulnerable to XSW attacks that bypass cryptographic signature verification."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Strict signature target validation and single-assertion enforcement\ndef get_saml_user(xml_doc):\n    assertions = xml_doc.xpath('//saml:Assertion')\n    if len(assertions) != 1:\n        raise SecurityError('SAML document must contain exactly one Assertion (Anti-XSW)')\n    verify_exact_signed_element(xml_doc, assertions[0])\n    return assertions[0].find('Subject').text",
          "explanation": "Rejects documents with duplicate or wrapped assertions and verifies exact signature URI binding."
    },
    howToTest: {
          "tools": [
                "saml-raider Burp extension",
                "xmlsec1"
          ],
          "steps": [
                "Inject duplicate assertion into SAML response using SAML Raider.",
                "Verify server rejects response with 'Multiple assertions detected'."
          ],
          "commandExample": "node -e 'console.log(\"Testing SAML XML Signature Wrapping defense\")'"
    },
    interviewChallenge: {
          "scenario": "What are the 8 common variants of XML Signature Wrapping (XSW1 through XSW8)?",
          "question": "How do attackers reposition signed elements?",
          "hint": "Attackers reposition the signed assertion inside the Header, as a sibling, or within Extensions, while injecting an unsigned assertion in the original location.",
          "sampleAnswer": "XSW variants exploit differences in how the signature verifier and the business logic navigator traverse the XML tree. Attackers place the signed assertion as a sibling, child, or wrapper of other elements while placing a forged assertion where the application looks for user identity.",
          "keyTakeaway": "Use hardened SAML parsers that enforce single assertion presence and strict ID reference binding."
    }
  },
  {
    ruleNumber: 144,
    id: "SEC-AUTH-144",
    title: "SCIM User Provisioning Deprovisioning Latency SLA Invariant",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Identity Lifecycle",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 7644", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 event \u2208 DeprovisionEvents, DeprovisionUser(event.User) \u21d2 RevokeAllCredentials(event.User) \u2227 ProcessingLatency(event) \u2264 30s",
    symbolBreakdown: [
          {
                "symbol": "DeprovisionEvents",
                "meaning": "SCIM 2.0 DELETE or active:false requests from corporate IdP (Okta, Azure AD)"
          },
          {
                "symbol": "RevokeAllCredentials",
                "meaning": "Destroys all active sessions, API keys, and OAuth grants"
          },
          {
                "symbol": "ProcessingLatency <= 30s",
                "meaning": "Must take effect immediately"
          }
    ],
    plainEnglish: "When an enterprise IdP sends a SCIM deprovisioning request (`active: false` or `DELETE /Users/{id}`), the application must terminate all active user sessions and revoke all API tokens within 30 seconds.",
    whyItMatters: "When an employee is terminated for misconduct, the company deprovisions them in Okta. If the target SaaS application caches the user's session or delays deprovisioning, the terminated employee retains access for hours or days, enabling IP theft.",
    vulnerableExample: {
          "language": "python",
          "code": "# VULNERABLE: SCIM deprovisioning only sets database flag without session kill\n@app.patch('/scim/v2/Users/{user_id}')\ndef scim_update(user_id: str, patch: ScimPatchDto):\n    if patch.active is False:\n        db.set_user_inactive(user_id) # Active sessions in Redis are NOT killed!",
          "explanation": "Terminated employee continues using active mobile and browser sessions."
    },
    secureExample: {
          "language": "python",
          "code": "# SECURE: Instantaneous credential and session eviction upon SCIM deprovision\n@app.patch('/scim/v2/Users/{user_id}')\ndef scim_update(user_id: str, patch: ScimPatchDto):\n    if patch.active is False:\n        db.set_user_inactive(user_id)\n        # Kill all sessions, refresh tokens, and API keys immediately:\n        revoke_all_user_sessions(user_id)\n        revoke_all_user_oauth_tokens(user_id)\n        emit_audit_event('SCIM_USER_DEPROVISIONED', user_id)",
          "explanation": "Instantly terminates all active connections within seconds of termination in Okta."
    },
    howToTest: {
          "tools": [
                "curl",
                "Okta SCIM simulator"
          ],
          "steps": [
                "Send SCIM PATCH setting `active: false`.",
                "Immediately send authenticated API request with user's token.",
                "Verify request returns 401 Unauthorized within 30 seconds."
          ],
          "commandExample": "curl -X PATCH -H \"Content-Type: application/scim+json\" -d '{\"Operations\":[{\"op\":\"replace\",\"path\":\"active\",\"value\":false}]}' https://api.target.com/scim/v2/Users/123"
    },
    interviewChallenge: {
          "scenario": "Why does OpenID Connect Shared Signals and Events (SSE / CAEP) represent the modern evolution of SCIM for real-time deprovisioning?",
          "question": "What does CAEP broadcast across SaaS apps?",
          "hint": "Continuous Access Evaluation Protocol (CAEP) broadcasts real-time security events (e.g. device compliance lost, session revoked) to all connected SaaS apps instantaneously.",
          "sampleAnswer": "While SCIM is primarily a provisioning/CRUD protocol that syncs directory state, CAEP (Continuous Access Evaluation Protocol) pushes real-time security events directly to participating apps. If a user's corporate laptop fails compliance or the user is fired, CAEP broadcasts a webhook that kills active sessions across all SaaS tools within seconds.",
          "keyTakeaway": "Integrate real-time SCIM and CAEP listeners to enforce instantaneous session termination."
    }
  },
  {
    ruleNumber: 145,
    id: "SEC-AUTH-145",
    title: "Hardware Security Key Attestation Certificate Verification",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Hardware Tokens",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["FIDO Alliance Specs", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 key \u2208 RegisteredSecurityKeys, VerifyAttestationChain(key.AttestationCert, FIDO_MDS_RootCA) = True",
    symbolBreakdown: [
          {
                "symbol": "RegisteredSecurityKeys",
                "meaning": "FIDO2 / U2F hardware tokens registered by users"
          },
          {
                "symbol": "VerifyAttestationChain",
                "meaning": "Validation of X.509 certificate against FIDO Metadata Service (MDS)"
          },
          {
                "symbol": "FIDO_MDS_RootCA",
                "meaning": "Trusted root certificate authority of certified hardware manufacturers (Yubico, Google, Feitian)"
          }
    ],
    plainEnglish: "High-security systems registering FIDO2 hardware keys must verify the key's Attestation Certificate against the FIDO Metadata Service (MDS). This guarantees the token is a genuine, certified physical hardware authenticator rather than software emulation.",
    whyItMatters: "Without attestation verification, an attacker can register a software-based virtual authenticator on a compromised laptop, bypassing corporate policies that mandate tamper-resistant physical YubiKeys.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Accepting any authenticator without checking attestation\nconst verification = await verifyRegistrationResponse({\n    response: credential,\n    expectedChallenge: challenge,\n    expectedOrigin: origin,\n    attestationType: 'none' // Skips hardware provenance validation!\n});",
          "explanation": "Allows software emulators or uncertified cheap tokens to register."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Enforcing FIDO Metadata Service (MDS) hardware attestation\nconst verification = await verifyRegistrationResponse({\n    response: credential,\n    expectedChallenge: challenge,\n    expectedOrigin: origin,\n    requireUserVerification: true,\n    // Validates X.509 attestation certificate against FIDO MDS root certs:\n    attestationType: 'direct'\n});\nconst aaguid = verification.registrationInfo.aaguid;\nverifyAgainstFidoMetadataService(aaguid, verification.registrationInfo.attestationObject);",
          "explanation": "Proves the physical device is a certified hardware authenticator from an audited vendor."
    },
    howToTest: {
          "tools": [
                "FIDO Metadata Service CLI",
                "YubiKey Manager"
          ],
          "steps": [
                "Attempt registering software virtual authenticator.",
                "Verify registration fails: 'Hardware attestation certificate failed validation'."
          ],
          "commandExample": "node -e 'console.log(\"Testing FIDO hardware attestation chain\")'"
    },
    interviewChallenge: {
          "scenario": "What is an AAGUID (Authenticator Attestation Globally Unique Identifier) in WebAuthn registration?",
          "question": "What information does the AAGUID disclose to the server?",
          "hint": "The AAGUID is a 16-byte identifier indicating the exact make and model of the hardware authenticator (e.g., YubiKey 5 NFC vs Titan Security Key).",
          "sampleAnswer": "The AAGUID identifies the specific hardware model and firmware version of the authenticator. Enterprise administrators use AAGUIDs to enforce corporate hardware allowlists (e.g., allowing only FIPS-140 certified YubiKey 5 models while rejecting uncertified consumer dongles).",
          "keyTakeaway": "Inspect AAGUID and attestation certificates to enforce enterprise hardware policies."
    }
  },
  {
    ruleNumber: 146,
    id: "SEC-AUTH-146",
    title: "Passkey Cross-Platform Sync and Credential Vault Isolation",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Passkeys / WebAuthn",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["FIDO Passkeys", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 passkey \u2208 SyncedPasskeys, IsMultiDeviceCredential(passkey) = True \u21d2 EndToEndEncryptedInCloudVault(passkey)",
    symbolBreakdown: [
          {
                "symbol": "SyncedPasskeys",
                "meaning": "Multi-device passkeys synced via Apple iCloud Keychain, Google Password Manager, or 1Password"
          },
          {
                "symbol": "EndToEndEncryptedInCloudVault",
                "meaning": "Decryption keys derived from user device hardware passcode, inaccessible to cloud provider"
          }
    ],
    plainEnglish: "When deploying multi-device passkeys, systems must support both device-bound passkeys (FIPS/enterprise) and synced passkeys (consumer). Synced passkeys must rely on cloud keychain providers that enforce zero-knowledge end-to-end encryption.",
    whyItMatters: "If passkey sync lacked end-to-end encryption, a breach of Apple or Google cloud infrastructure would expose millions of private authentication keys to cloud attackers.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Disallowing passkeys or forcing SMS fallbacks\n// Forcing users off modern passkeys into insecure SMS channels",
          "explanation": "Degrades security by falling back to phishable legacy factors."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: WebAuthn passkey registration with backup state awareness\nconst credential = await navigator.credentials.create({\n    publicKey: {\n        challenge: serverChallenge,\n        rp: { name: 'Acme Bank', id: 'acme.com' },\n        user: { id: userBytes, name: 'alice@acme.com', displayName: 'Alice' },\n        pubKeyCredParams: [{ alg: -7, type: 'public-key' }], // ES256\n        authenticatorSelection: {\n            residentKey: 'required',\n            userVerification: 'required'\n        }\n    }\n});\n// Server inspects flags: credential.response.getAuthenticatorData() & 0x08 (Backup State)",
          "explanation": "Registers modern discoverable passkey with user verification enforced."
    },
    howToTest: {
          "tools": [
                "Passkey tester (passkeys.io)",
                "browser DevTools"
          ],
          "steps": [
                "Register passkey in Chrome; confirm resident key is saved to platform authenticator.",
                "Sign in without typing username (discoverable credential flow)."
          ],
          "commandExample": "node -e 'console.log(\"Testing passkey discoverable credential flow\")'"
    },
    interviewChallenge: {
          "scenario": "What is the difference between a 'Device-Bound Passkey' and a 'Synced (Multi-Device) Passkey'?",
          "question": "Which one can be backed up to the cloud?",
          "hint": "A device-bound passkey cannot leave the physical chip (e.g. YubiKey); a synced passkey is securely synced across the user's Apple or Google devices via an end-to-end encrypted keychain.",
          "sampleAnswer": "A synced passkey is designed for consumer convenience, allowing a user to authenticate across their iPhone, Mac, and iPad seamlessly via iCloud Keychain. A device-bound passkey is tied to a single physical hardware module (like a YubiKey) and cannot be copied, which is mandatory for high-security defense and enterprise environments.",
          "keyTakeaway": "Support synced passkeys for consumers and enforce device-bound keys for privileged admins."
    }
  },
  {
    ruleNumber: 147,
    id: "SEC-AUTH-147",
    title: "Emergency Break-Glass Account Multi-Custodian Requirement",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Privileged Access",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-53 AC-2", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 access \u2208 BreakGlassEvents, RequiredCustodians(access) \u2265 2 \u2227 MOfNThreshold(access, 2, 3) = True \u2227 AutoNotifySecurityTeam(access)",
    symbolBreakdown: [
          {
                "symbol": "BreakGlassEvents",
                "meaning": "Emergency root/superadmin access to cloud or directory services when IdP fails"
          },
          {
                "symbol": "MOfNThreshold(2, 3)",
                "meaning": "Shamir secret sharing or dual-custodian approval required to unlock password vault"
          },
          {
                "symbol": "AutoNotifySecurityTeam",
                "meaning": "High-priority SMS/pager alerts dispatched immediately"
          }
    ],
    plainEnglish: "Emergency 'break-glass' accounts (used when Okta or Azure AD is completely down) must require dual-custody authorization (M-of-N threshold sharing where at least 2 authorized executives approve access). Every break-glass use must trigger immediate emergency alarms.",
    whyItMatters: "If a break-glass superadmin account has a static password held by one engineer, an attacker or disgruntled admin can log in as global administrator, delete all cloud backups, and destroy enterprise infrastructure undetected.",
    vulnerableExample: {
          "language": "terraform",
          "code": "# VULNERABLE: Single-person break-glass account with static credentials\nresource \"aws_iam_user\" \"break_glass\" {\n  name = \"emergency_admin\"\n  # Single static password stored in 1Password accessible by 1 person!\n}",
          "explanation": "Lacks dual-custody controls; vulnerable to insider threat or single credential theft."
    },
    secureExample: {
          "language": "terraform",
          "code": "# SECURE: Break-glass account monitored by real-time CloudWatch alarm\nresource \"aws_cloudwatch_metric_alarm\" \"break_glass_alert\" {\n  alarm_name          = \"BreakGlassAccountUsed\"\n  metric_name         = \"BreakGlassLoginCount\"\n  namespace           = \"Security/Audit\"\n  period              = 60\n  statistic           = \"Sum\"\n  threshold           = 1\n  alarm_actions       = [aws_sns_topic.pagers.arn]\n  # Credential split between CISO and VP Engineering via Shamir Secret Sharing\n}",
          "explanation": "Alerts security response team via pager within seconds of break-glass account utilization."
    },
    howToTest: {
          "tools": [
                "AWS CloudTrail",
                "Vault secret split CLI"
          ],
          "steps": [
                "Simulate break-glass account login in staging.",
                "Verify pager alert is triggered within 60 seconds across all security channels."
          ],
          "commandExample": "aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=emergency_admin"
    },
    interviewChallenge: {
          "scenario": "What is Shamir's Secret Sharing (M-of-N threshold scheme), and how does it protect break-glass master keys?",
          "question": "How many keys are needed to reconstruct the secret?",
          "hint": "The master password is split into N shares (e.g. 3 shares); any M shares (e.g. 2 shares) must be combined to reconstruct the password, ensuring no single human can access the account alone.",
          "sampleAnswer": "Shamir's Secret Sharing mathematically splits a cryptographic secret into N pieces. Any M pieces (e.g., 2 out of 3 held by the CISO, VP of Infrastructure, and Legal Counsel) can reconstruct the secret, but a single piece reveals zero information. This guarantees that emergency access requires collusion of at least two independent leaders.",
          "keyTakeaway": "Split emergency break-glass credentials across multiple senior custodians."
    }
  },
  {
    ruleNumber: 148,
    id: "SEC-AUTH-148",
    title: "API Client Secret Masking in Admin Consoles and Logs",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Credential Masking",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["PCI-DSS v4.0 \u00a78", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 sec \u2208 ClientSecrets, RenderInUI(sec) \u21d2 Value(sec) = MaskSecret(sec, \"\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\" + Last4(sec)) \u2227 Logged(sec) = False",
    symbolBreakdown: [
          {
                "symbol": "ClientSecrets",
                "meaning": "OAuth client secrets, payment gateway keys, webhook signing secrets"
          },
          {
                "symbol": "MaskSecret",
                "meaning": "Displaying only the last 4 characters and masking the remainder in UI and logs"
          }
    ],
    plainEnglish: "Administrative dashboards and API consoles must display client secrets only once upon creation. Subsequently, secrets must be masked (e.g. `\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022abcd`). Applications must never echo full secrets in HTML DOM attributes or server logs.",
    whyItMatters: "Support staff, internal developers, or shoulder-surfers viewing admin dashboards can copy customer API keys or payment secrets, leading to internal data theft and insider leaks.",
    vulnerableExample: {
          "language": "html",
          "code": "<!-- VULNERABLE: Client secret rendered in plaintext input in admin UI -->\n<input type=\"text\" name=\"client_secret\" value=\"sk_live_9876543210abcdef9876543210\">",
          "explanation": "Exposes secret to browser extensions, DOM scrapers, and shoulder-surfers."
    },
    secureExample: {
          "language": "html",
          "code": "<!-- SECURE: Masked display; raw secret never returned after initial creation -->\n<div class=\"secret-display\">\n  <span>Client Secret: \u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022abcd</span>\n  <button onclick=\"rotateSecret()\">Roll Secret</button>\n</div>",
          "explanation": "Secret is never delivered to client; only last 4 characters are shown for identification."
    },
    howToTest: {
          "tools": [
                "browser DevTools Elements tab",
                "curl"
          ],
          "steps": [
                "Inspect admin API credentials page in DevTools.",
                "Confirm input value or DOM does NOT contain raw secret string."
          ],
          "commandExample": "curl -H \"Authorization: Bearer admin\" https://api.target.com/api/clients/123"
    },
    interviewChallenge: {
          "scenario": "Why should cloud platforms like AWS, Stripe, and GitHub display an API secret key only ONCE upon generation and refuse to reveal it again?",
          "question": "How does the server store the key?",
          "hint": "Because the server only stores a one-way cryptographic hash of the secret (SHA-256), the server itself does NOT know the original secret and cannot display it again.",
          "sampleAnswer": "Once generated, modern platforms hash the secret with SHA-256 and store only the digest in the database. Because one-way hashes cannot be reversed, the platform literally cannot display the original secret again. If the customer loses the secret, they must rotate and generate a new one.",
          "keyTakeaway": "Store API secrets hashed and display them only once upon generation."
    }
  },
  {
    ruleNumber: 149,
    id: "SEC-AUTH-149",
    title: "Password Entropy Estimation (zxcvbn Score \u2265 3)",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Password Policy",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-63B", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 pwd \u2208 SubmittedPasswords, zxcvbn_Score(pwd) \u2265 3 \u2227 EntropyBits(pwd) \u2265 50",
    symbolBreakdown: [
          {
                "symbol": "zxcvbn_Score",
                "meaning": "Realistic entropy estimation model analyzing common patterns, names, l33tspeak, and spatial keyboard walks"
          },
          {
                "symbol": ">= 3",
                "meaning": "Score 3 or 4 indicating high resistance to offline cracking rigs"
          }
    ],
    plainEnglish: "Password validators must use realistic pattern-matching entropy calculators (such as Dropbox's `zxcvbn`) and require a score of at least 3 out of 4. Naive character-count or regex policies that permit `P@ssword1!` must be rejected.",
    whyItMatters: "A password like `P@ssword1!` passes naive regex rules (has upper, lower, digit, symbol, 8+ chars), but takes less than 1 second to crack on a dictionary attack. `zxcvbn` recognizes the dictionary word and l33tspeak substitution, flagging it as weak.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Naive regex that accepts predictable passwords\nconst regex = /^(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*]).{8,}$/;\nregex.test('P@ssword1!'); // Returns TRUE! Very weak password.",
          "explanation": "Permits dictionary words with trivial substitutions that crackers guess instantly."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Pattern-matching entropy analysis with zxcvbn\nimport zxcvbn from 'zxcvbn';\n\nfunction validatePasswordEntropy(password, userInputs = []) {\n    const result = zxcvbn(password, userInputs);\n    if (result.score < 3) {\n        throw new Error(`Password too weak: ${result.feedback.warning || 'Choose a longer passphrase.'}`);\n    }\n    return true;\n}",
          "explanation": "Detects dictionary words, keyboard walks (qwerty), date patterns, and name substitutions."
    },
    howToTest: {
          "tools": [
                "zxcvbn CLI",
                "unit tests"
          ],
          "steps": [
                "Test 'P@ssword1!'; verify zxcvbn returns score 1 or 2 and fails validation.",
                "Test 'battery horse staple blue'; verify score 4."
          ],
          "commandExample": "node -e 'const z = require(\"zxcvbn\"); console.log(z(\"P@ssword1!\").score)'"
    },
    interviewChallenge: {
          "scenario": "Why is `correct horse battery staple` significantly stronger than `Tr0ub4dor&3`, despite lacking complex symbols?",
          "question": "How does password length exponentially defeat brute force?",
          "hint": "Entropy scales with the search space of combinations: 4 random dictionary words provide ~44 bits of entropy and are easy to remember, whereas 8-character mixed strings provide fewer bits and are easily cracked by modern GPU dictionary attacks.",
          "sampleAnswer": "Length dominates character composition in password cracking math. A 28-character passphrase composed of 4 random dictionary words creates a combinatorial search space that takes centuries to brute-force, while an 8-character password with symbols has a tiny search space easily exhausted by GPU clusters.",
          "keyTakeaway": "Enforce entropy scoring with zxcvbn and encourage multi-word passphrases."
    }
  },
  {
    ruleNumber: 150,
    id: "SEC-AUTH-150",
    title: "Authentication Service High-Availability Fail-Closed Invariant",
    domain: "auth",
    domainName: "Authentication",
    subdomain: "Resilience & Auth",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-53", "NIST SP 800-63B", "OWASP ASVS 4.0"],
    formalInvariant: "\u2200 req \u2208 AuthRequests, ServiceDegraded(AuthService) \u2228 DatabaseUnreachable(AuthService) \u21d2 DenyAccess(req) \u2227 Status(req) = 503",
    symbolBreakdown: [
          {
                "symbol": "AuthRequests",
                "meaning": "Identity verification requests entering the gateway"
          },
          {
                "symbol": "ServiceDegraded",
                "meaning": "Failure of backend LDAP, database, or Redis rate-limiter"
          },
          {
                "symbol": "DenyAccess",
                "meaning": "Mandatory rejection of unauthenticated requests (Fail-Closed)"
          }
    ],
    plainEnglish: "When authentication or authorization services experience database outages, network partitions, or internal crashes, the system must FAIL CLOSED: reject all requests with HTTP 503 Service Unavailable. Systems must NEVER fail open to maintain availability.",
    whyItMatters: "In 2021, a major healthcare provider's authentication middleware had an unhandled exception handler that returned `next()` when the Redis database was down, allowing unauthenticated Internet users to access all patient medical records without logging in.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Failing open during error/exception\napp.use(async (req, res, next) => {\n    try {\n        await verifyTokenWithDatabase(req.headers.authorization);\n        next();\n    } catch (err) {\n        // FATAL FLAW: Failing open to 'keep app working' during DB outage!\n        console.error('Auth DB down; allowing request through');\n        next();\n    }\n});",
          "explanation": "Grants complete unauthenticated access to all endpoints whenever database experiences an outage."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Strict Fail-Closed implementation\napp.use(async (req, res, next) => {\n    try {\n        const user = await verifyTokenWithDatabase(req.headers.authorization);\n        req.user = user;\n        next();\n    } catch (err) {\n        // SECURE: Fail closed immediately\n        logger.error('Authentication service failure:', err);\n        return res.status(503).json({\n            error: 'Authentication service temporarily unavailable',\n            code: 'SERVICE_UNAVAILABLE'\n        });\n    }\n});",
          "explanation": "Guarantees zero unauthenticated access occurs during infrastructure failures."
    },
    howToTest: {
          "tools": [
                "chaos monkey",
                "kill -9 redis-server"
          ],
          "steps": [
                "Terminate Redis or auth database in staging.",
                "Send API request; verify server returns 503 Service Unavailable, NEVER 200 OK."
          ],
          "commandExample": "curl -sI https://api.target.com/protected-endpoint"
    },
    interviewChallenge: {
          "scenario": "Why is the 'Fail-Closed' principle fundamental to the security architecture of all access control mechanisms?",
          "question": "What is the security risk of choosing availability over confidentiality in auth failures?",
          "hint": "Failing open converts any infrastructure outage, DDoS attack, or database crash into a complete catastrophic data breach.",
          "sampleAnswer": "In the CIA triad (Confidentiality, Integrity, Availability), authentication exists to protect Confidentiality and Integrity. If an authentication system fails open when overwhelmed, an attacker can simply launch a Denial-of-Service attack against the auth database to instantly unlock the entire application.",
          "keyTakeaway": "Every authentication and authorization check must fail closed unconditionally."
    }
  }
];
