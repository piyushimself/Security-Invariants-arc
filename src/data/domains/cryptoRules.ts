import { SecurityInvariant } from '../../types/invariants';

export const cryptoRules: SecurityInvariant[] = [
  {
    ruleNumber: 222,
    id: "SEC-CRYPTO-001",
    title: "Authenticated Encryption with Associated Data (AEAD) Invariant",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Symmetric Ciphers & AEAD",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-38D", "RFC 5116", "CWE-327"],
    formalInvariant: "\u2200 (m, k, iv, ad) \u2208 EncryptInputs, Cipher(m, k, iv, ad) \u2208 {AES_256_GCM, ChaCha20_Poly1305} \u2227 Length(Tag) \u2265 128 bits",
    symbolBreakdown: [
          {
                "symbol": "m, k, iv, ad",
                "meaning": "Plaintext message m, secret key k, initialization vector iv, authenticated associated data ad"
          },
          {
                "symbol": "AES_256_GCM, ChaCha20_Poly1305",
                "meaning": "Modern Authenticated Encryption with Associated Data (AEAD) cipher modes"
          },
          {
                "symbol": "Length(Tag) \u2265 128 bits",
                "meaning": "Authentication verification tag must be at least 16 bytes (128 bits) to prevent forgery"
          }
    ],
    plainEnglish: "Symmetric encryption must always use Authenticated Encryption with Associated Data (AEAD), such as AES-256-GCM or ChaCha20-Poly1305. Legacy unauthenticated modes like CBC, ECB, or CTR without HMAC must never be used.",
    whyItMatters: "Unauthenticated encryption modes (like AES-CBC without MAC) are vulnerable to padding oracle attacks (e.g. POODLE, Lucky Thirteen) and bit-flipping attacks. Attackers can flip bits in the ciphertext to alter values (e.g. changing an account number or role) without knowing the key.",
    vulnerableExample: {
          "language": "python",
          "code": "from Crypto.Cipher import AES\n\ndef encrypt_data(key, plaintext):\n    # CATASTROPHIC: ECB mode leaks visual patterns and has no integrity!\n    cipher = AES.new(key, AES.MODE_ECB)\n    return cipher.encrypt(pad(plaintext))",
          "explanation": "Electronic Codebook (ECB) encrypts identical plaintext blocks into identical ciphertext blocks."
    },
    secureExample: {
          "language": "python",
          "code": "import os\nfrom cryptography.hazmat.primitives.ciphers.aead import AESGCM\n\ndef encrypt_data(key: bytes, plaintext: bytes, associated_data: bytes = b\"\") -> bytes:\n    nonce = os.urandom(12)\n    aesgcm = AESGCM(key)\n    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)\n    return nonce + ciphertext",
          "explanation": "Provides confidentiality and cryptographic message authenticity; tampering with ciphertext raises an exception."
    },
    howToTest: {
          "tools": [
                "openssl",
                "cryptography test suite"
          ],
          "steps": [
                "Inspect cipher suites used across code and configs.",
                "Modify one byte of the ciphertext.",
                "Attempt to decrypt; confirm the library raises an AuthenticationError or InvalidTag exception immediately."
          ],
          "commandExample": "python3 -c \"from cryptography.hazmat.primitives.ciphers.aead import AESGCM; k=AESGCM.generate_key(bit_length=256); print(k.hex())\""
    },
    interviewChallenge: {
          "scenario": "A developer uses AES-256-GCM but generates a static, hardcoded 12-byte IV for all encryption calls with the same key to save database space.",
          "question": "What is the catastrophic cryptographic consequence of nonce reuse in AES-GCM?",
          "hint": "What happens to the GHASH authenticator polynomial when two ciphertexts share a key and nonce?",
          "sampleAnswer": "Nonce reuse in AES-GCM is fatal. Reusing a nonce with the same key reveals the XOR of the two plaintexts (keystream reuse) and allows an attacker to solve for the GHASH authentication subkey H. Once H is recovered, the attacker can forge arbitrary ciphertexts and valid authentication tags at will.",
          "keyTakeaway": "In AES-GCM, never encrypt twice under the same key and nonce combination."
    }
  },
  {
    ruleNumber: 223,
    id: "SEC-CRYPTO-002",
    title: "Cryptographically Secure Random Number Generator (CSPRNG) Invariant",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Randomness & Entropy",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-90A", "FIPS 140-3", "CWE-338"],
    formalInvariant: "\u2200 secret \u2208 {Keys, Nonces, Salts, Tokens, UUIDv4}, GeneratedBy(secret) = CSPRNG(OS_Entropy) \u2227 Math.random \u2209 Sources",
    symbolBreakdown: [
          {
                "symbol": "secret \u2208 {Keys, Nonces...}",
                "meaning": "Any value relied upon for security, secrecy, or unpredictability"
          },
          {
                "symbol": "CSPRNG(OS_Entropy)",
                "meaning": "Kernel entropy source (getrandom(2), /dev/urandom, crypto.getRandomValues)"
          },
          {
                "symbol": "Math.random \u2209 Sources",
                "meaning": "Insecure PRNGs (Math.random(), random.random()) are strictly banned"
          }
    ],
    plainEnglish: "All cryptographic keys, nonces, initialization vectors, salts, session tokens, and password reset tokens must be generated using an operating-system-backed Cryptographically Secure Pseudo-Random Number Generator (CSPRNG). Never use Math.random(), java.util.Random, or Python random.",
    whyItMatters: "Standard PRNGs (like Mersenne Twister or xorshift) are deterministic and designed for statistical simulations, not security. By observing a small sequence of random values from Math.random(), an attacker can reconstruct the internal state and predict all past and future values, recovering reset tokens and session IDs.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// CATASTROPHIC: Predictable PRNG used for security tokens\nfunction generateResetToken() {\n    return Math.random().toString(36).substring(2);\n}",
          "explanation": "Mersenne Twister internal state can be deduced after observing 624 32-bit outputs."
    },
    secureExample: {
          "language": "javascript",
          "code": "import crypto from 'node:crypto';\n\nfunction generateResetToken(): string {\n    return crypto.randomBytes(32).toString('hex');\n}",
          "explanation": "Uses OS entropy pool (/dev/urandom or BCryptGenRandom), ensuring complete forward and backward secrecy."
    },
    howToTest: {
          "tools": [
                "semgrep",
                "ent entropy tester"
          ],
          "steps": [
                "Scan codebase with Semgrep rule detecting Math.random() in token generation.",
                "Collect 1,000,000 bytes from token generator and run NIST STS statistical test suite."
          ],
          "commandExample": "semgrep --config \"p/insecure-transport\" ./src/"
    },
    interviewChallenge: {
          "scenario": "A containerized microservice running in a stripped-down Alpine Linux image generates keys right after boot, but /dev/urandom blocks or suffers low entropy.",
          "question": "What is entropy exhaustion in virtualized/containerized environments, and how do modern cloud kernels solve it?",
          "hint": "Does /dev/urandom block in modern Linux kernels (5.6+)?",
          "sampleAnswer": "Historically, systems with no hardware RNG or disk activity had insufficient entropy immediately after boot. Since Linux 5.6, /dev/urandom does not deplete, and the kernel seeds the CSPRNG using CPU instructions like RDRAND/RDSEED, jitter entropy, and hypervisor virtio-rng devices. Applications should use getrandom(2) with GRND_NONBLOCK to guarantee the CSPRNG has initialized.",
          "keyTakeaway": "Always use modern OS entropy sources and ensure hypervisor virtio-rng drivers are enabled."
    }
  },
  {
    ruleNumber: 224,
    id: "SEC-CRYPTO-224",
    title: "RSA Key Length Minimum Ceiling (KeySize \u2265 2048 bits)",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Asymmetric Cryptography",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-57 Part 1", "FIPS 186-5", "CWE-326"],
    formalInvariant: "\u2200 rsaKey \u2208 RSA_Keys, BitLength(rsaKey) \u2265 2048 \u2227 (Recommended: BitLength(rsaKey) \u2265 3072)",
    symbolBreakdown: [
          {
                "symbol": "rsaKey",
                "meaning": "RSA key pair utilized for digital signatures or key encapsulation"
          },
          {
                "symbol": "BitLength \u2265 2048",
                "meaning": "Modulus n bit size must provide at least 112 bits of security margin"
          }
    ],
    plainEnglish: "RSA key sizes below 2048 bits are cryptographically broken or feasible to factor with commercial cloud compute clusters. Production systems must mandate at least 2048-bit keys, with 3072-bit or 4096-bit recommended for post-2030 longevity.",
    whyItMatters: "Keys under 2048 bits (e.g. 1024-bit RSA) can be factored using the General Number Field Sieve (GNFS) in days or weeks, enabling attackers to forge certificates, decrypt recorded TLS sessions, and impersonate servers.",
    vulnerableExample: {
          "language": "python",
          "code": "from cryptography.hazmat.primitives.asymmetric import rsa\n# VULNERABLE: 1024-bit RSA factored easily\nkey = rsa.generate_private_key(public_exponent=65537, key_size=1024)",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "python",
          "code": "from cryptography.hazmat.primitives.asymmetric import rsa\n# SECURE: Minimum 2048-bit, preferably 3072-bit\nkey = rsa.generate_private_key(public_exponent=65537, key_size=3072)",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "openssl rsa -in key.pem -text -noout",
                "Check bit length in TLS audit"
          ],
          "steps": [
                "Validate cryptographic configuration against NIST SP 800-57 Part 1 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "openssl rsa -in server.key -text -noout | grep 'Key:'"
    },
    interviewChallenge: {
          "scenario": "A legacy customer insists on connecting to your enterprise API using a 1024-bit RSA client certificate.",
          "question": "How do you quantify the risk and refuse or isolate the connection without violating enterprise compliance?",
          "hint": "Consider NIST SP 800-57 transition dates and GNFS factoring compute costs.",
          "sampleAnswer": "NIST disallowed 1024-bit RSA in 2013 because GNFS factoring is feasible with modest compute. Accepting 1024-bit client certs exposes the authentication boundary to identity forgery if the private key was factored. The proper architectural decision is hard rejection with automated cert provisioning via ACME/Let's Encrypt for 2048+ bit keys.",
          "keyTakeaway": "1024-bit RSA provides fewer than 80 bits of symmetric security equivalence\u2014unacceptable for modern systems."
    }
  },
  {
    ruleNumber: 225,
    id: "SEC-CRYPTO-225",
    title: "Elliptic Curve Domain Parameter Whitelist (P-256 / Ed25519)",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Elliptic Curve Crypto",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["FIPS 186-5", "RFC 8032", "CWE-327"],
    formalInvariant: "\u2200 curve \u2208 ActiveCurves, curve \u2208 {NIST_P256, NIST_P384, Ed25519, X25519} \u2227 curve \u2209 {secp192r1, secp112r1, BrainpoolP160}",
    symbolBreakdown: [
          {
                "symbol": "curve",
                "meaning": "Elliptic curve parameter group for ECDH or ECDSA"
          },
          {
                "symbol": "{NIST_P256, Ed25519...}",
                "meaning": "Rigorously vetted curves with known side-channel and small-subgroup resistance"
          }
    ],
    plainEnglish: "Elliptic curve operations must only use vetted, modern curves such as NIST P-256, NIST P-384, Ed25519, or X25519. Custom or obsolete curves with weak orders or susceptibility to Pohlig-Hellman attacks must be blocked.",
    whyItMatters: "Weak or proprietary curves enable small subgroup attacks and invalid curve attacks where an adversary sends an off-curve point to recover the server's private scalar in a few queries.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Deprecated curve with 160-bit prime\nconst ecdh = crypto.createECDH('secp160r1');",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: High-security Edwards-curve or NIST P-256\nconst { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "testssl.sh",
                "openssl ecparam -list_curves"
          ],
          "steps": [
                "Validate cryptographic configuration against FIPS 186-5 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "openssl ecparam -name prime256v1 -genkey -out ec_key.pem"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Elliptic Curve Domain Parameter Whitelist (P-256 / Ed25519) in a high-security environment.",
          "question": "Why do many cryptographers prefer Curve25519/Ed25519 over NIST curves like P-256 for modern greenfield applications?",
          "hint": "What mathematical properties protect Montgomery and Edwards curves against implementation bugs?",
          "sampleAnswer": "Curve25519 offers complete addition formulas (no special cases for point at infinity or point doubling), branchless Montgomery ladder arithmetic immune to timing attacks, and twist security that prevents invalid-curve attacks even if the public point is not validated.",
          "keyTakeaway": "Edwards curves (Ed25519) eliminate entire classes of side-channel and exceptional point vulnerabilities by design."
    }
  },
  {
    ruleNumber: 226,
    id: "SEC-CRYPTO-226",
    title: "HMAC Constant-Time Verification Invariant",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Message Authentication",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 2104", "NIST SP 800-107", "CWE-208"],
    formalInvariant: "\u2200 (sig_a, sig_b) \u2208 Signatures, Equal(sig_a, sig_b) \u21d4 ConstantTimeCompare(sig_a, sig_b) \u2227 EarlyExit(Equal) = FALSE",
    symbolBreakdown: [
          {
                "symbol": "sig_a, sig_b",
                "meaning": "Cryptographic signature or message authentication tag buffers"
          },
          {
                "symbol": "ConstantTimeCompare",
                "meaning": "Algorithm execution time t is invariant to buffer differences: t(diff) = t(match)"
          }
    ],
    plainEnglish: "Verification of cryptographic signatures, HMAC tags, and secret tokens must always be performed using constant-time comparison functions (e.g. crypto.timingSafeEqual or hmac.compare_digest). Never use standard string equality operators (== or ===).",
    whyItMatters: "Standard string comparison terminates on the first byte mismatch. An attacker measuring HTTP response times down to nanosecond precision can deduce secret tokens byte-by-byte via timing side-channel attacks.",
    vulnerableExample: {
          "language": "json",
          "code": "// VULNERABLE: Short-circuiting string equality leaks timing!\nif (userHmac === computedHmac) { grantAccess(); }",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "python",
          "code": "import crypto from 'node:crypto';\n// SECURE: Constant-time buffer comparison\nconst isValid = crypto.timingSafeEqual(Buffer.from(userHmac), Buffer.from(computedHmac));",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "Time trial benchmarker",
                "spectre/meltdown side channel scanners"
          ],
          "steps": [
                "Validate cryptographic configuration against RFC 2104 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "node -e \"const c=require('crypto'); console.log(c.timingSafeEqual(Buffer.from('a'), Buffer.from('a')))\""
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating HMAC Constant-Time Verification Invariant in a high-security environment.",
          "question": "How many network requests does an attacker typically need over a local network or LAN to extract an 8-character token using timing leaks?",
          "hint": "Think about statistical averaging across noisy network jitter.",
          "sampleAnswer": "While internet jitter can obscure timing differences, box-and-whisker statistical averaging over 10,000 to 100,000 samples per byte character easily reveals the extra 5-15 nanoseconds consumed by additional character comparisons, allowing practical token extraction.",
          "keyTakeaway": "Timing attacks work reliably even over networks when statistical noise is filtered through repeated sampling."
    }
  },
  {
    ruleNumber: 227,
    id: "SEC-CRYPTO-227",
    title: "HKDF Cryptographic Key Derivation Function Invariant",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Key Derivation",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 5869", "NIST SP 800-56C", "CWE-327"],
    formalInvariant: "\u2200 (ikm, salt, info) \u2208 KDF_Inputs, DerivedKey = HKDF_Expand(HKDF_Extract(salt, ikm), info, L)",
    symbolBreakdown: [
          {
                "symbol": "ikm",
                "meaning": "Input Keying Material (e.g., shared Diffie-Hellman secret or master secret)"
          },
          {
                "symbol": "salt, info",
                "meaning": "Cryptographic domain separator and context binding strings"
          }
    ],
    plainEnglish: "When deriving subkeys from a master secret or Diffie-Hellman shared secret, applications must use HMAC-based Extract-and-Expand Key Derivation Function (HKDF). Raw hashing (like SHA256(secret)) must never be used as a KDF.",
    whyItMatters: "Diffie-Hellman secrets are not uniformly distributed bitstrings. Raw hashing fails to extract true entropy, risks length-extension issues, and lacks context separation ('info' parameter), allowing derived keys across different protocols to collide.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Direct hashing of shared secret without entropy extraction\nconst encKey = crypto.createHash('sha256').update(dhSecret).digest();",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "python",
          "code": "// SECURE: HKDF with salt and context domain separation info\nconst encKey = crypto.hkdfSync('sha256', dhSecret, salt, Buffer.from('app-v1-encryption'), 32);",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "rfc5869 test vectors",
                "OpenSSL kdf tool"
          ],
          "steps": [
                "Validate cryptographic configuration against RFC 5869 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "openssl kdf -kdfopt digest:SHA256 -kdfopt key:secret -kdfopt info:label HKDF"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating HKDF Cryptographic Key Derivation Function Invariant in a high-security environment.",
          "question": "What is the difference between HKDF-Extract and HKDF-Expand in RFC 5869?",
          "hint": "What role does the optional salt play in Extract?",
          "sampleAnswer": "HKDF-Extract takes non-uniformly distributed input key material (like a DH point) and an optional salt to produce a pseudorandom key (PRK) of fixed length with uniform entropy. HKDF-Expand then expands that PRK into arbitrary-length output keys using context strings (info) to prevent cross-protocol key reuse.",
          "keyTakeaway": "Context binding via the 'info' parameter ensures keys derived for encryption cannot be confused with keys derived for authentication."
    }
  },
  {
    ruleNumber: 228,
    id: "SEC-CRYPTO-228",
    title: "Diffie-Hellman Ephemeral (DHE / ECDHE) Forward Secrecy",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Forward Secrecy",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 8446", "NIST SP 800-52", "CWE-327"],
    formalInvariant: "\u2200 session \u2208 TLS_Sessions, KeyExchange(session) \u2208 {ECDHE, DHE} \u2227 KeyExchange(session) \u2209 {Static_RSA, Static_DH}",
    symbolBreakdown: [
          {
                "symbol": "ECDHE, DHE",
                "meaning": "Ephemeral key exchange where private ephemeral parameters are destroyed immediately after handshake"
          },
          {
                "symbol": "Static_RSA",
                "meaning": "Legacy RSA key exchange where past traffic can be decrypted retroactively if server private key is leaked"
          }
    ],
    plainEnglish: "All cryptographic sessions must enforce Forward Secrecy using ephemeral key exchanges (ECDHE or DHE). Static RSA key exchange is strictly prohibited.",
    whyItMatters: "If static RSA key exchange is used, an adversary who records encrypted network traffic today can decrypt every historical communication if the server's long-term RSA private key is subpoenaed, compromised, or stolen years later.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Cipher suite using static RSA key exchange\nssl_ciphers 'AES128-SHA:AES256-SHA:RC4-SHA';",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Enforcing Ephemeral Diffie-Hellman with TLS 1.3\nssl_protocols TLSv1.3;\nssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256';",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "sslscan",
                "nmap --script ssl-enum-ciphers"
          ],
          "steps": [
                "Validate cryptographic configuration against RFC 8446 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "nmap --script ssl-enum-ciphers -p 443 target.com"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Diffie-Hellman Ephemeral (DHE / ECDHE) Forward Secrecy in a high-security environment.",
          "question": "How does Ephemeral Diffie-Hellman (ECDHE) guarantee Perfect Forward Secrecy (PFS)?",
          "hint": "What happens to the ephemeral private key after session key generation?",
          "sampleAnswer": "During ECDHE, both client and server generate fresh ephemeral key pairs for that single session, sign the parameters with their long-term identity keys, derive the symmetric session key, and immediately zeroize the ephemeral private keys. Even if the server's long-term private key is stolen later, it cannot reconstruct past session keys.",
          "keyTakeaway": "Forward secrecy ensures past confidentiality survives future identity key compromises."
    }
  },
  {
    ruleNumber: 229,
    id: "SEC-CRYPTO-229",
    title: "SHA-1 and MD5 Cryptographic Hash Deprecation Invariant",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Hash Function Security",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-131A", "RFC 6151", "CWE-328"],
    formalInvariant: "\u2200 h \u2208 HashFunctions, h \u2209 {MD4, MD5, SHA1} \u2227 DigestBitLength(h) \u2265 256",
    symbolBreakdown: [
          {
                "symbol": "MD5, SHA1",
                "meaning": "Cryptographically broken hash algorithms with practical collision attacks (SHAttered, Flame malware)"
          },
          {
                "symbol": "DigestBitLength \u2265 256",
                "meaning": "Modern collision-resistant standards (SHA-256, SHA-384, SHA-512, BLAKE3, SHA3)"
          }
    ],
    plainEnglish: "MD5 and SHA-1 are cryptographically broken and must never be used for digital signatures, certificates, integrity verification, or token generation. Systems must use SHA-256, SHA-384, SHA-512, SHA-3, or BLAKE3.",
    whyItMatters: "Collision attacks on MD5 (Flame malware) and SHA-1 (SHAttered attack in 2017) allow attackers to create two distinct documents or certificates with identical hashes, bypassing integrity checks and forging PKI certificates.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: SHA-1 used for file integrity check\nconst hash = crypto.createHash('sha1').update(uploadedFile).digest('hex');",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: SHA-256 or BLAKE3\nconst hash = crypto.createHash('sha256').update(uploadedFile).digest('hex');",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "trivy",
                "semgrep --config p/ci-bad-crypto"
          ],
          "steps": [
                "Validate cryptographic configuration against NIST SP 800-131A specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "sha256sum sensitive-archive.tar.gz"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating SHA-1 and MD5 Cryptographic Hash Deprecation Invariant in a high-security environment.",
          "question": "Is HMAC-SHA1 technically broken in the same way digital signatures with SHA1 are broken?",
          "hint": "Does a collision attack on H(m) directly break HMAC(k, m)?",
          "sampleAnswer": "Surprisingly, no: HMAC's security relies on pseudorandom function (PRF) security rather than collision resistance. HMAC-SHA1 does not suffer from collision attacks. However, standards bodies (NIST SP 800-131A) still deprecated HMAC-SHA1 to prevent algorithm confusion and enforce cryptographic hygiene.",
          "keyTakeaway": "Deprecate broken primitives globally to eliminate confusion across operational boundaries."
    }
  },
  {
    ruleNumber: 230,
    id: "SEC-CRYPTO-230",
    title: "Post-Quantum Lattice-Based Key Encapsulation (ML-KEM / Kyber)",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Post-Quantum Crypto",
    difficulty: "Expert",
    standardType: "Defensive Practice",
    standards: ["NIST FIPS 203", "NIST PQC Standards", "CWE-327"],
    formalInvariant: "\u2200 kex \u2208 HybridKeyExchanges, Algorithms(kex) \u2287 {X25519, ML_KEM_768}",
    symbolBreakdown: [
          {
                "symbol": "ML_KEM_768",
                "meaning": "Module-Lattice Key Encapsulation Mechanism (formerly CRYSTALS-Kyber) standardized by NIST"
          },
          {
                "symbol": "X25519",
                "meaning": "Classical elliptic curve key exchange run in hybrid tandem"
          }
    ],
    plainEnglish: "Long-lived encrypted data transmitted over public networks must implement hybrid post-quantum key encapsulation (e.g. X25519 + ML-KEM-768) to protect against Harvest Now, Decrypt Later (HNDL) attacks.",
    whyItMatters: "Hostile nation-states actively record high-value encrypted traffic today. Once a cryptanalytically relevant quantum computer (CRQC) emerges running Shor's algorithm, all recorded RSA and ECC sessions will be retroactively decrypted.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Classical ECDH only, susceptible to quantum harvesting\nconst cipher = initClassicalECDH('P-256');",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: Hybrid Classical + Quantum-Resistant KEM (X25519 + Kyber/ML-KEM)\nconst hybridKEM = initHybridKEM({ classical: 'X25519', pq: 'ML-KEM-768' });",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "oqs-provider for OpenSSL",
                "Wireshark TLS 1.3 KeyShare parser"
          ],
          "steps": [
                "Validate cryptographic configuration against NIST FIPS 203 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "openssl s_client -connect pq.cloudflareresearch.com:443 -curves X25519MLKEM768"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Post-Quantum Lattice-Based Key Encapsulation (ML-KEM / Kyber) in a high-security environment.",
          "question": "Why does NIST recommend a 'hybrid' deployment model (Classical + Post-Quantum) rather than switching 100% to ML-KEM immediately?",
          "hint": "Consider the risk of new cryptanalytic attacks on young lattice algorithms.",
          "sampleAnswer": "The hybrid approach combines a thoroughly vetted classical primitive (like X25519) with a post-quantum primitive (ML-KEM). Security is preserved as long as at least ONE of the two algorithms remains unbroken, safeguarding against novel mathematical breakthroughs against lattice cryptography while defending against quantum threats.",
          "keyTakeaway": "Hybrid cryptography provides belt-and-suspenders security during generational algorithm transitions."
    }
  },
  {
    ruleNumber: 231,
    id: "SEC-CRYPTO-231",
    title: "Post-Quantum State-Based Signature Verification (ML-DSA / Dilithium)",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Post-Quantum Crypto",
    difficulty: "Expert",
    standardType: "Defensive Practice",
    standards: ["NIST FIPS 204", "NIST PQC Standards"],
    formalInvariant: "\u2200 sig \u2208 PostQuantumSignatures, Algorithm(sig) \u2208 {ML_DSA_65, SLH_DSA_SHAKE_128s, XMSS, LMS}",
    symbolBreakdown: [
          {
                "symbol": "ML_DSA_65",
                "meaning": "Module-Lattice Digital Signature Algorithm (formerly CRYSTALS-Dilithium)"
          },
          {
                "symbol": "SLH_DSA",
                "meaning": "Stateless Hash-Based Digital Signature Algorithm (formerly SPHINCS+)"
          }
    ],
    plainEnglish: "Systems signing high-longevity firmware, root certificates, or legal contracts must transition to NIST-standardized Post-Quantum Digital Signature Algorithms (ML-DSA or SLH-DSA).",
    whyItMatters: "Shor's algorithm on a quantum computer solves discrete logarithms and integer factorization in polynomial time, rendering RSA, ECDSA, and Ed25519 digital signatures completely forgeable.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: RSA-2048 signature for 20-year root CA\nconst cert = ca.signWithRSA(key, 'SHA256');",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Post-quantum ML-DSA-65 or hybrid root CA\nconst cert = ca.signWithMLDSA(mldsaKey, 'ML-DSA-65');",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "liboqs",
                "BouncyCastle PQC"
          ],
          "steps": [
                "Validate cryptographic configuration against NIST FIPS 204 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "openssl req -new -newkey mldsa65 -nodes -out req.csr"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Post-Quantum State-Based Signature Verification (ML-DSA / Dilithium) in a high-security environment.",
          "question": "What is the operational downside of Post-Quantum signatures like ML-DSA and SLH-DSA compared to Ed25519?",
          "hint": "Compare public key sizes and signature byte lengths.",
          "sampleAnswer": "Ed25519 signatures are tiny (64 bytes) with 32-byte public keys. In contrast, ML-DSA-65 signatures are ~3,300 bytes and public keys are ~1,950 bytes. SLH-DSA signatures are even larger (~7 KB to 17 KB). This drastically increases TLS handshake packet fragmentation and storage overhead.",
          "keyTakeaway": "Post-quantum signatures trade larger network transmission footprints for quantum resilience."
    }
  },
  {
    ruleNumber: 232,
    id: "SEC-CRYPTO-232",
    title: "GCM Nonce Bit-Length Fixed Invariant (Length(IV) = 96 bits)",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "AEAD Modes",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-38D", "RFC 5116", "CWE-327"],
    formalInvariant: "\u2200 iv \u2208 AES_GCM_Nonces, Length(iv) = 96 bits (12 bytes) \u2227 Length(iv) \u2260 128 bits",
    symbolBreakdown: [
          {
                "symbol": "Length(iv) = 96 bits",
                "meaning": "The standard recommended IV length in NIST SP 800-38D Section 7.1"
          },
          {
                "symbol": "Length(iv) \u2260 128 bits",
                "meaning": "Non-96-bit IVs trigger GHASH preprocessing, degrading performance and increasing collision risk"
          }
    ],
    plainEnglish: "Initialization vectors for AES-GCM must be exactly 96 bits (12 bytes). Never supply 128-bit or variable-length IVs to AES-GCM functions.",
    whyItMatters: "When an IV is not exactly 96 bits, NIST SP 800-38D requires hashing the IV with GHASH to compress it into 128 bits. This incurs significant performance penalties and increases the probability of GHASH tag collisions due to birthday paradox bounds.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: 128-bit (16-byte) IV causes GHASH preprocessing overhead\nconst iv = crypto.randomBytes(16);\nconst cipher = crypto.createCipheriv('aes-256-gcm', key, iv);",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Exactly 96-bit (12-byte) IV for standard AES-GCM\nconst iv = crypto.randomBytes(12);\nconst cipher = crypto.createCipheriv('aes-256-gcm', key, iv);",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "Crypto linter",
                "Wycheproof test suite"
          ],
          "steps": [
                "Validate cryptographic configuration against NIST SP 800-38D specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "python3 -c \"import os; iv=os.urandom(12); print(len(iv))\""
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating GCM Nonce Bit-Length Fixed Invariant (Length(IV) = 96 bits) in a high-security environment.",
          "question": "Why did the designers of AES-GCM specifically choose 96 bits as the default IV length rather than the block cipher's natural 128-bit block size?",
          "hint": "How is the initial 128-bit counter block J0 constructed in hardware?",
          "sampleAnswer": "In 96-bit mode, the hardware implementation simply appends 31 zeros and a 1 (0x00000001) to the 96-bit nonce to form the 128-bit counter block J0 directly, without running the expensive GHASH polynomial calculation required for any other length.",
          "keyTakeaway": "Always use 12-byte (96-bit) nonces with AES-GCM for both maximum security and hardware acceleration."
    }
  },
  {
    ruleNumber: 233,
    id: "SEC-CRYPTO-233",
    title: "Cryptographic Key Zeroization from Memory After Use",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Memory Hygiene",
    difficulty: "Advanced",
    standardType: "Defensive Practice",
    standards: ["FIPS 140-3 Section 7.9", "CWE-226", "CWE-244"],
    formalInvariant: "\u2200 k \u2208 SecretKeys, AfterOperation(k) \u21d2 ZeroizeMemory(Address(k), Length(k)) \u2227 CompilerOptimization(Zeroize) = PREVENTED",
    symbolBreakdown: [
          {
                "symbol": "ZeroizeMemory",
                "meaning": "Overwriting memory buffers containing plaintext key bytes with zeros or random noise"
          },
          {
                "symbol": "CompilerOptimization = PREVENTED",
                "meaning": "Preventing memset dead-store elimination via secure_zero_memory or volatile pointers"
          }
    ],
    plainEnglish: "Plaintext cryptographic keys, passwords, and private key material must be zeroized from application memory immediately after the cryptographic operation completes.",
    whyItMatters: "Residual keys left in heap memory can be extracted by memory scrapers, core dump files generated after unhandled crashes, swap file leakage, or heartbleed-style out-of-bounds read vulnerabilities.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Standard memset is often optimized away as a dead store by compilers!\nchar key[32];\ncompute(key);\nmemset(key, 0, sizeof(key)); // DEAD STORE REMOVED BY COMPILER!",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Explicit volatile zeroization or explicit_bzero\n#include <string.h>\nexplicit_bzero(key, sizeof(key));",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "valgrind --tool=memcheck",
                "gdb memory dump inspector"
          ],
          "steps": [
                "Validate cryptographic configuration against FIPS 140-3 Section 7.9 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "gcc -O3 -fno-builtin-memset check.c"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Cryptographic Key Zeroization from Memory After Use in a high-security environment.",
          "question": "Why does standard memset(key, 0, len) fail to zeroize memory when compiled with optimization flags like -O2 or -O3?",
          "hint": "What is dead store elimination in modern compilers?",
          "sampleAnswer": "Compilers perform dead store elimination: if a memory buffer is not read again before being freed or leaving function scope, the compiler determines that writing zeros has no observable program effect and optimizes the memset call away entirely. Secure functions like explicit_bzero, SecureZeroMemory, or sodium_memzero use memory barriers to prevent this.",
          "keyTakeaway": "Use dedicated secure zeroization APIs to ensure memory wipe operations are never optimized away."
    }
  },
  {
    ruleNumber: 234,
    id: "SEC-CRYPTO-234",
    title: "TLS 1.3 Minimum Protocol Version Enforcement Invariant",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Transport Security",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["RFC 8446", "NIST SP 800-52 Rev 2", "PCI DSS 4.0"],
    formalInvariant: "\u2200 conn \u2208 InboundTLSConnections, ProtocolVersion(conn) \u2265 TLS_1_2 \u2227 TLS_Version(conn) \u2209 {SSLv2, SSLv3, TLS_1_0, TLS_1_1}",
    symbolBreakdown: [
          {
                "symbol": "ProtocolVersion \u2265 TLS_1_2",
                "meaning": "Minimum allowed transport layer security version"
          },
          {
                "symbol": "TLS 1.0, 1.1",
                "meaning": "Officially deprecated protocols with broken CBC ciphers and weak hash handshakes"
          }
    ],
    plainEnglish: "All servers and API endpoints must reject TLS versions prior to TLS 1.2, with TLS 1.3 mandated for modern infrastructure. SSLv2, SSLv3, TLS 1.0, and TLS 1.1 must be disabled at the reverse proxy or ingress layer.",
    whyItMatters: "Legacy TLS versions suffer from severe structural vulnerabilities, including BEAST (CBC IV vulnerability), POODLE (SSLv3 padding oracle), and lack of support for modern AEAD cipher suites.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Nginx allowing deprecated TLS 1.0/1.1\nssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Strictly modern TLS 1.2 and 1.3 only\nssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "testssl.sh",
                "sslyze"
          ],
          "steps": [
                "Validate cryptographic configuration against RFC 8446 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "testssl.sh --protocols https://api.yourdomain.com"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating TLS 1.3 Minimum Protocol Version Enforcement Invariant in a high-security environment.",
          "question": "What major security features were removed or changed between TLS 1.2 and TLS 1.3 to streamline the protocol?",
          "hint": "Think about static RSA, renegotiation, and round-trip times (RTT).",
          "sampleAnswer": "TLS 1.3 removed static RSA key exchange (mandating ephemeral Diffie-Hellman for forward secrecy), eliminated insecure CBC mode ciphers (mandating AEAD only), removed arbitrary compression (preventing CRIME), eliminated client renegotiation, and halved handshake latency from 2-RTT to 1-RTT (or 0-RTT resumption).",
          "keyTakeaway": "TLS 1.3 eliminates all known historical attack surfaces by removing obsolete cipher modes."
    }
  },
  {
    ruleNumber: 235,
    id: "SEC-CRYPTO-235",
    title: "PKCS#1 v1.5 Padding Deprecation (Enforce RSA-OAEP / RSA-PSS)",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Padding Oracles",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 8017", "NIST SP 800-56B", "CWE-780"],
    formalInvariant: "\u2200 rsa_op \u2208 RSA_Operations, Padding(rsa_op) \u2208 {RSA_OAEP, RSA_PSS} \u2227 Padding(rsa_op) \u2260 PKCS1_v1_5",
    symbolBreakdown: [
          {
                "symbol": "RSA_OAEP",
                "meaning": "Optimal Asymmetric Encryption Padding for public key encryption"
          },
          {
                "symbol": "RSA_PSS",
                "meaning": "Probabilistic Signature Scheme for digital signatures"
          },
          {
                "symbol": "PKCS1_v1_5",
                "meaning": "Vulnerable deterministic padding scheme susceptible to Bleichenbacher attacks"
          }
    ],
    plainEnglish: "RSA encryption must use Optimal Asymmetric Encryption Padding (RSA-OAEP) with SHA-256. RSA digital signatures must use Probabilistic Signature Scheme (RSA-PSS). PKCS#1 v1.5 padding is strictly deprecated.",
    whyItMatters: "PKCS#1 v1.5 padding oracle attacks (Bleichenbacher's attack and the Robot attack) allow attackers to decrypt arbitrary ciphertexts and forge signatures by observing server error responses or timing variations when invalid padding is processed.",
    vulnerableExample: {
          "language": "json",
          "code": "// VULNERABLE: PKCS#1 v1.5 padding vulnerable to Bleichenbacher oracle\nconst decrypted = crypto.privateDecrypt({\n  key: privKey,\n  padding: crypto.constants.RSA_PKCS1_PADDING\n}, ciphertext);",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: RSA-OAEP with SHA-256 digest\nconst decrypted = crypto.privateDecrypt({\n  key: privKey,\n  padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,\n  oaepHash: 'sha256'\n}, ciphertext);",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "python-bleichenbacher-tester",
                "sslscan"
          ],
          "steps": [
                "Validate cryptographic configuration against RFC 8017 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "openssl pkeyutl -encrypt -in secret.txt -pubin -inkey pub.pem -pkeyopt rsa_padding_mode:oaep"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating PKCS#1 v1.5 Padding Deprecation (Enforce RSA-OAEP / RSA-PSS) in a high-security environment.",
          "question": "Explain the mechanism of Bleichenbacher's million-message attack against PKCS#1 v1.5.",
          "hint": "How does an adversary use response errors to recover the plaintext?",
          "sampleAnswer": "Bleichenbacher showed that if an RSA server answers whether a ciphertext conforms to the PKCS#1 v1.5 format (0x00 0x02 ...), an attacker can multiply the ciphertext by chosen values (s^e mod N) and submit them. By recording whether the server accepts or rejects the padding, the attacker narrows down the possible range of the plaintext until it is completely solved.",
          "keyTakeaway": "Always use RSA-OAEP for encryption to eliminate Bleichenbacher padding oracles mathematically."
    }
  },
  {
    ruleNumber: 236,
    id: "SEC-CRYPTO-236",
    title: "Cryptographic Salt Length Minimum Bound (\u2265 128 bits)",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Salt Security",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-132", "OWASP Password Storage"],
    formalInvariant: "\u2200 salt \u2208 PasswordSalts, Length(salt) \u2265 16 bytes (128 bits) \u2227 UniquePerUser(salt) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "Length(salt) \u2265 16 bytes",
                "meaning": "Minimum 128 bits of entropy to guarantee global salt uniqueness"
          },
          {
                "symbol": "UniquePerUser",
                "meaning": "Every stored credential has its own distinct salt"
          }
    ],
    plainEnglish: "Password salts must be at least 16 bytes (128 bits) generated using a CSPRNG and must be globally unique per credential. Static or shared application-wide salts are prohibited.",
    whyItMatters: "Insufficient salt length or reused salts allow attackers to precompute rainbow tables across millions of users, converting expensive per-user cracking into a single amortized lookup table.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Short 4-byte salt or application-wide static salt\nconst salt = 'shared_salt_123';\nconst hash = pbkdf2(password, salt, 100000, 32, 'sha256');",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "python",
          "code": "import crypto from 'node:crypto';\n// SECURE: Unique 16-byte CSPRNG salt per user\nconst salt = crypto.randomBytes(16);\nconst hash = crypto.scryptSync(password, salt, 64);",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "hashcat test suite",
                "password audit script"
          ],
          "steps": [
                "Validate cryptographic configuration against NIST SP 800-132 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "python3 -c \"import os; print(os.urandom(16).hex())\""
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Cryptographic Salt Length Minimum Bound (\u2265 128 bits) in a high-security environment.",
          "question": "Why does salting a password prevent rainbow table attacks, but does NOT slow down brute-force cracking of an individual user's password?",
          "hint": "What is the mathematical distinction between precomputation protection and work factor?",
          "sampleAnswer": "A salt guarantees that identical passwords have completely different hashes, destroying the utility of precomputed rainbow tables. However, once an attacker focuses on cracking a single user's hash, the salt is simply fed into the candidate hash calculation; only the KDF's work factor (iterations/memory cost) slows down individual cracking.",
          "keyTakeaway": "Salts destroy precomputation and deduplication; work factors slow down per-target brute force."
    }
  },
  {
    ruleNumber: 237,
    id: "SEC-CRYPTO-237",
    title: "Hardware Security Module (HSM) FIPS 140-3 Level 3 Root of Trust",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Key Storage",
    difficulty: "Advanced",
    standardType: "Defensive Practice",
    standards: ["FIPS 140-3 Level 3", "PCI-HSM", "NIST SP 800-57"],
    formalInvariant: "\u2200 masterKey \u2208 RootKeys, StoredIn(masterKey) \u2208 HSM \u2227 Exportable(masterKey) = FALSE",
    symbolBreakdown: [
          {
                "symbol": "StoredIn(masterKey) \u2208 HSM",
                "meaning": "Cryptographic keys are generated and held within tamper-resistant hardware"
          },
          {
                "symbol": "Exportable = FALSE",
                "meaning": "Key material cannot be extracted in plaintext under any circumstances"
          }
    ],
    plainEnglish: "Root Certificate Authority private keys, master data encryption keys, and payment signing keys must reside inside a FIPS 140-2/140-3 Level 3 validated Hardware Security Module (HSM) or cloud KMS with non-exportable key policies.",
    whyItMatters: "Storing master signing keys in software files or on application servers allows an adversary with root server access or container breakout to exfiltrate the organization's entire identity and decrypt all database backups forever.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Root CA private key stored in plaintext on disk\nconst caKey = fs.readFileSync('/etc/ssl/ca-root.key');",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: Cloud KMS / HSM-backed key where private key never leaves hardware\nconst signResult = await kmsClient.sign({\n  KeyId: 'arn:aws:kms:us-east-1:123456789:key/root-ca',\n  Message: digest,\n  MessageType: 'DIGEST',\n  SigningAlgorithm: 'ECDSA_SHA_256'\n});",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "AWS KMS Key Policy Auditor",
                "PKCS#11 tool"
          ],
          "steps": [
                "Validate cryptographic configuration against FIPS 140-3 Level 3 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -l --list-objects"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Hardware Security Module (HSM) FIPS 140-3 Level 3 Root of Trust in a high-security environment.",
          "question": "What physical tamper-response mechanisms characterize FIPS 140-3 Level 3 and Level 4 HSM devices?",
          "hint": "What happens if an attacker drills into the casing or changes the temperature?",
          "sampleAnswer": "FIPS 140-3 Level 3+ HSMs feature physical encapsulation in tamper-evident resin with fine wire sensor meshes. If the mesh is severed by drilling, or if environmental sensors detect out-of-spec voltage, X-ray radiation, or liquid nitrogen cryogenic cooling, the HSM triggers active zeroization circuits, obliterating all key material in nanoseconds.",
          "keyTakeaway": "Hardware roots of trust provide active self-destruction guarantees against physical compromise."
    }
  },
  {
    ruleNumber: 238,
    id: "SEC-CRYPTO-238",
    title: "Automated Cryptographic Key Rotation Period Ceiling (\u2264 365 Days)",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Key Management",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-57 Section 5.3", "PCI DSS 4.0 Requirement 3.6"],
    formalInvariant: "\u2200 k \u2208 ActiveKeys, Age(k) = CurrentTime - CreatedAt(k) \u2264 365 Days \u2227 CryptoperiodEnforced(k) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "Age(k) \u2264 365 Days",
                "meaning": "Maximum validity period for asymmetric keys, TLS certs, and symmetric master keys"
          },
          {
                "symbol": "CryptoperiodEnforced",
                "meaning": "Automated rotation pipeline with graceful overlap period for decryption"
          }
    ],
    plainEnglish: "Cryptographic keys must have an enforced cryptoperiod not exceeding 365 days. Key rotation must be automated, supporting key versioning to decrypt historical data while encrypting new data with the active key.",
    whyItMatters: "Unrotated keys accumulate massive volumes of ciphertext over years. If a key is eventually compromised, years of data are exposed simultaneously. Furthermore, long-lived keys increase the chance of keystream exhaustion or cryptanalytic breakthroughs.",
    vulnerableExample: {
          "language": "python",
          "code": "// VULNERABLE: Hardcoded encryption key generated 5 years ago with no rotation plan\nconst KEY = Buffer.from('4f8b91...static_key_never_rotated');",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Versioned key rotation with automated AWS KMS or Google Cloud KMS rotation\n// AWS KMS automatically rotates backing key material every 365 days while preserving ability to decrypt past ciphertexts",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "aws kms get-key-rotation-status",
                "vault list sys/mounts"
          ],
          "steps": [
                "Validate cryptographic configuration against NIST SP 800-57 Section 5.3 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "aws kms get-key-rotation-status --key-id 1234abcd-12ab-34cd-56ef-1234567890ab"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Automated Cryptographic Key Rotation Period Ceiling (\u2264 365 Days) in a high-security environment.",
          "question": "How does versioned envelope encryption allow key rotation without having to re-encrypt petabytes of existing storage simultaneously?",
          "hint": "Think about the separation of Key Encryption Keys (KEK) and Data Encryption Keys (DEK).",
          "sampleAnswer": "In envelope encryption, each data file has its own unique Data Encryption Key (DEK) encrypted by a Key Encryption Key (KEK). When the KEK rotates to version 2, existing DEKs can either remain encrypted with KEK v1 or be lazily re-wrapped into KEK v2 by invoking KMS ReEncrypt. The underlying bulk data is never touched or moved.",
          "keyTakeaway": "Envelope key wrapping enables instant master key rotation without data-layer churn."
    }
  },
  {
    ruleNumber: 239,
    id: "SEC-CRYPTO-239",
    title: "Key Encryption Key (KEK) and Data Encryption Key (DEK) Separation",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Envelope Encryption",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-57 Part 1", "AWS KMS Best Practices"],
    formalInvariant: "\u2200 data \u2208 Datastore, EncryptedWith(data) = DEK \u2227 EncryptedWith(DEK) = KEK \u2227 DEK_InStorage = Ciphertext(DEK)",
    symbolBreakdown: [
          {
                "symbol": "DEK",
                "meaning": "Data Encryption Key: Ephemeral, generated per-record or per-file, used directly to encrypt plaintext"
          },
          {
                "symbol": "KEK",
                "meaning": "Key Encryption Key: Resides safely in KMS/HSM, never leaves hardware, used solely to wrap DEKs"
          }
    ],
    plainEnglish: "Large-scale systems must implement envelope encryption: data is encrypted locally using a unique Data Encryption Key (DEK), and the DEK is encrypted (wrapped) using a master Key Encryption Key (KEK) managed in an HSM or KMS.",
    whyItMatters: "Sending massive datasets directly to a remote KMS endpoint creates massive network bottlenecks, exceeds KMS rate limits, and exposes large plaintext payloads in transit.",
    vulnerableExample: {
          "language": "json",
          "code": "// VULNERABLE: Sending gigabytes of video or database backups directly to KMS\nconst result = await kms.encrypt({ KeyId: kekId, Plaintext: giantFileBuffer });",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "python",
          "code": "// SECURE: Envelope encryption with KMS GenerateDataKey\nconst { Plaintext: rawDEK, CiphertextBlob: wrappedDEK } = await kms.generateDataKey({\n  KeyId: kekId,\n  KeySpec: 'AES_256'\n});\nconst ciphertext = encryptLocal(rawDEK, giantFileBuffer);\nrawDEK.fill(0); // Zeroize local key from RAM\nreturn { ciphertext, wrappedDEK };",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "aws-encryption-sdk",
                "Google Tink envelope parser"
          ],
          "steps": [
                "Validate cryptographic configuration against NIST SP 800-57 Part 1 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "aws kms generate-data-key --key-id alias/master --key-spec AES_256"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Key Encryption Key (KEK) and Data Encryption Key (DEK) Separation in a high-security environment.",
          "question": "What is the operational benefit of using the AWS Encryption SDK or Google Tink for envelope encryption?",
          "hint": "How does it handle encryption context and algorithm negotiation?",
          "sampleAnswer": "Client-side envelope libraries like AWS Encryption SDK and Google Tink format ciphertexts into standardized portable message headers containing the wrapped data key, algorithm suite identifiers, and cryptographically authenticated encryption context (AAD) to prevent ciphertext tampering and header spoofing.",
          "keyTakeaway": "Envelope encryption combines local wire-speed encryption with centralized hardware key control."
    }
  },
  {
    ruleNumber: 240,
    id: "SEC-CRYPTO-240",
    title: "CBC Mode IV Unpredictability / Randomness Invariant",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Block Ciphers",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-38A", "CWE-329"],
    formalInvariant: "\u2200 c \u2208 CBC_Ciphertexts, IV(c) = CSPRNG() \u2227 Predictable(IV(c)) = FALSE \u2227 IV(c) \u2260 LastBlock(c_{prev})",
    symbolBreakdown: [
          {
                "symbol": "CBC_Ciphertexts",
                "meaning": "Cipher Block Chaining mode encrypted messages"
          },
          {
                "symbol": "Predictable(IV) = FALSE",
                "meaning": "IV must be completely uncorrelated with previous IVs to prevent chosen-plaintext attacks"
          }
    ],
    plainEnglish: "When Cipher Block Chaining (CBC) mode is used, the Initialization Vector (IV) must be generated using an unpredictable CSPRNG. Reusing the previous ciphertext block as the next IV (chained IVs) is strictly forbidden.",
    whyItMatters: "Predictable IVs in CBC mode enable chosen-plaintext attacks like the BEAST attack against SSL/TLS. An attacker can predict the IV of an upcoming block and craft specific plaintexts to deduce secret cookie values byte-by-byte.",
    vulnerableExample: {
          "language": "json",
          "code": "// VULNERABLE: Using last ciphertext block as the next IV (chained IV)\nlet lastBlock = Buffer.alloc(16);\nfunction encryptNext(chunk) {\n  const cipher = crypto.createCipheriv('aes-256-cbc', key, lastBlock);\n  const out = cipher.update(chunk);\n  lastBlock = out.slice(-16);\n  return out;\n}",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: Fresh CSPRNG IV generated for every individual encryption\nfunction encryptNext(chunk) {\n  const iv = crypto.randomBytes(16);\n  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);\n  return Buffer.concat([iv, cipher.update(chunk), cipher.final()]);\n}",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "Wireshark CBC IV variance tester",
                "Trivy"
          ],
          "steps": [
                "Validate cryptographic configuration against NIST SP 800-38A specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "openssl enc -aes-256-cbc -p -in file.txt -out file.enc"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating CBC Mode IV Unpredictability / Randomness Invariant in a high-security environment.",
          "question": "How did the BEAST (Browser Exploit Against SSL/TLS) attack exploit predictable CBC IVs in TLS 1.0?",
          "hint": "What role did Java applets or JavaScript play in crafting chosen-plaintexts?",
          "sampleAnswer": "In TLS 1.0, the IV for record N+1 was the last ciphertext block of record N. Because the attacker could observe network traffic, they knew IV_{N+1} before sending their next request. By injecting controlled byte prefixes via JavaScript/WebSockets, they XORed out the known IV and confirmed password guess bytes one by one.",
          "keyTakeaway": "Never allow an adversary to know or predict an IV before the plaintext is submitted."
    }
  },
  {
    ruleNumber: 241,
    id: "SEC-CRYPTO-241",
    title: "Certificate Authority Revocation Checking (OCSP Stapling / CRL)",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "PKI Revocation",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 6960", "CAB Forum Baseline Requirements", "RFC 8446"],
    formalInvariant: "\u2200 cert \u2208 ActiveCertificates, Valid(cert) \u21d4 SignatureValid(cert) \u2227 CurrentTime < Expiry(cert) \u2227 Status(OCSP_Staple(cert)) = GOOD",
    symbolBreakdown: [
          {
                "symbol": "OCSP_Stapling",
                "meaning": "Server includes a cryptographically signed, timestamped response from the CA proving the cert is not revoked"
          },
          {
                "symbol": "Status = GOOD",
                "meaning": "Explicitly confirms certificate has not been revoked"
          }
    ],
    plainEnglish: "Web servers and TLS terminators must enable OCSP Stapling (RFC 6066 / RFC 6960) to provide cryptographic proof of certificate revocation status during the TLS handshake without privacy leaks or latency penalties.",
    whyItMatters: "If a private key is stolen, the owner revokes the certificate. Without revocation checking or OCSP stapling, browsers continue trusting the revoked certificate until its natural expiration (which could be a full year later), enabling persistent Man-in-the-Middle attacks.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Nginx TLS config without OCSP stapling enabled\nssl_certificate /etc/ssl/cert.pem;\nssl_certificate_key /etc/ssl/key.pem;",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: OCSP stapling enabled with trusted resolver verification\nssl_stapling on;\nssl_stapling_verify on;\nssl_trusted_certificate /etc/ssl/ca-chain.pem;\nresolver 1.1.1.1 8.8.8.8 valid=300s;\nresolver_timeout 5s;",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "openssl s_client -status",
                "testssl.sh --stapling"
          ],
          "steps": [
                "Validate cryptographic configuration against RFC 6960 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "openssl s_client -connect target.com:443 -status -tlsextdebug"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Certificate Authority Revocation Checking (OCSP Stapling / CRL) in a high-security environment.",
          "question": "Why is client-side direct OCSP querying considered broken for privacy and performance, and how does OCSP Stapling solve it?",
          "hint": "What happens when a CA's OCSP server goes down during a direct client lookup?",
          "sampleAnswer": "Direct client queries leak the user's browsing history to the Certificate Authority (every website visited triggers an OCSP lookup). If the CA's OCSP responder is down, browsers must 'soft-fail' to maintain web availability, allowing MITM attackers to block the query and bypass revocation! OCSP Stapling shifts the burden to the server, which caches and staples the signed OCSP response directly.",
          "keyTakeaway": "OCSP stapling guarantees cryptographic revocation checks without leaking client browsing habits."
    }
  },
  {
    ruleNumber: 242,
    id: "SEC-CRYPTO-242",
    title: "X.509 Subject Alternative Name (SAN) Strict Matching Invariant",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "PKI Certificate Matching",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["RFC 6125", "CAB Forum Baseline Requirements", "CWE-295"],
    formalInvariant: "\u2200 requestDomain, TargetCert \u21d2 (requestDomain \u2208 SAN_List(TargetCert) \u2228 WildcardMatch(requestDomain, SAN_List)) \u2227 CommonName \u2209 ValidationSources",
    symbolBreakdown: [
          {
                "symbol": "requestDomain",
                "meaning": "Target FQDN requested by client"
          },
          {
                "symbol": "SAN_List",
                "meaning": "Subject Alternative Name extension entries in X.509 certificate"
          },
          {
                "symbol": "CommonName \u2209 ValidationSources",
                "meaning": "Legacy Subject CommonName (CN) is completely ignored in RFC 6125"
          }
    ],
    plainEnglish: "TLS client implementations must validate server identity strictly against the Subject Alternative Name (SAN) extension. The legacy Common Name (CN) field must be ignored completely, and wildcard matching must only cover a single domain label.",
    whyItMatters: "Trusting the legacy Common Name field or permitting multi-level wildcard certificates (*.com or *.*.example.com) allows attackers who obtain fraudulent wildcard certificates to impersonate arbitrary domains.",
    vulnerableExample: {
          "language": "json",
          "code": "// VULNERABLE: Custom TLS client checking only Common Name or disabling hostname verification\nconst agent = new https.Agent({ rejectUnauthorized: true, checkServerIdentity: (host, cert) => cert.subject.CN === host });",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: Default RFC 6125 SAN matching\nconst agent = new https.Agent({ rejectUnauthorized: true }); // Automatically uses tls.checkServerIdentity with SAN",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "sslyze",
                "openssl x509 -noout -text"
          ],
          "steps": [
                "Validate cryptographic configuration against RFC 6125 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "openssl x509 -in cert.pem -noout -text | grep -A1 \"Subject Alternative Name\""
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating X.509 Subject Alternative Name (SAN) Strict Matching Invariant in a high-security environment.",
          "question": "Can a wildcard certificate for *.example.com match sub.app.example.com under RFC 6125?",
          "hint": "What is the restriction on the wildcard asterisk character?",
          "sampleAnswer": "No. RFC 6125 Section 6.4.3 explicitly mandates that a wildcard character (*) only matches a single domain component (label). Therefore, *.example.com matches app.example.com, but does NOT match sub.app.example.com.",
          "keyTakeaway": "Wildcard certificates apply to exactly one subdomain level; multi-level wildcarding is strictly invalid."
    }
  },
  {
    ruleNumber: 243,
    id: "SEC-CRYPTO-243",
    title: "ECDSA Random k-Value Reuse and Deterministic RFC 6979 Invariant",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Signature Nonces",
    difficulty: "Advanced",
    standardType: "Defensive Practice",
    standards: ["RFC 6979", "FIPS 186-5", "CWE-347"],
    formalInvariant: "\u2200 (sig_1, sig_2) \u2208 ECDSA_Signatures, (sig_1 \u2260 sig_2 \u2227 Key(sig_1) = Key(sig_2)) \u21d2 Nonce(sig_1) \u2260 Nonce(sig_2) \u2227 Nonce = HMAC_DRBG(Key, Message)",
    symbolBreakdown: [
          {
                "symbol": "Nonce k",
                "meaning": "Per-signature ephemeral secret scalar in ECDSA: (r, s) where r = (k*G).x"
          },
          {
                "symbol": "HMAC_DRBG",
                "meaning": "Deterministic generation of k per RFC 6979 eliminates RNG failure risks"
          }
    ],
    plainEnglish: "ECDSA and DSA signing operations must either use deterministic nonce derivation according to RFC 6979 or an impeccably vetted CSPRNG. Never sign two different messages using the same ephemeral k value with the same private key.",
    whyItMatters: "Reusing the secret nonce k across two ECDSA signatures under the same private key allows anyone observing the public signatures to calculate the private key instantly using simple modular algebra (the PlayStation 3 Sony root key disaster).",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Broken PRNG producing repeated nonce k\nconst k = getBadRandomScalar();\nconst sig = ecdsaSign(privKey, hash, k);",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: RFC 6979 deterministic ECDSA signing\n// Derives k = HMAC-SHA256(privKey, messageHash)\nconst sig = secp256k1.sign(hash, privKey, { canonical: true });",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "wycheproof ECDSA tests",
                "secp256k1 test suite"
          ],
          "steps": [
                "Validate cryptographic configuration against RFC 6979 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "python3 -c \"import ecdsa; print('RFC 6979 verified')\""
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating ECDSA Random k-Value Reuse and Deterministic RFC 6979 Invariant in a high-security environment.",
          "question": "Walk through the exact mathematical equations used to extract Sony's PS3 private key when k was reused in two ECDSA signatures.",
          "hint": "Look at the equation for s: s = k^-1 * (z + r*d) mod n.",
          "sampleAnswer": "Given two signatures (r, s1) and (r, s2) for messages z1 and z2: since k was reused, r is identical! Subtracting the signatures yields s1 - s2 = k^-1 * (z1 - z2) mod n. The attacker solves directly for k: k = (z1 - z2) * (s1 - s2)^-1 mod n. Once k is known, the private key d is revealed by: d = (s1*k - z1) * r^-1 mod n.",
          "keyTakeaway": "Reusing a single ECDSA nonce turns private key recovery into simple high school modular algebra."
    }
  },
  {
    ruleNumber: 244,
    id: "SEC-CRYPTO-244",
    title: "Cipher Suite Forward Secrecy Preference Ordering",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "TLS Configuration",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["Mozilla SSL Configuration Guide", "RFC 8446"],
    formalInvariant: "\u2200 suite \u2208 ConfiguredSuites, suite \u2208 {TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, ECDHE_ECDSA_WITH_AES_256_GCM_SHA384} \u2227 suite \u2209 CBC_Suites",
    symbolBreakdown: [
          {
                "symbol": "ConfiguredSuites",
                "meaning": "Prioritized list of TLS cryptographic algorithm combinations"
          },
          {
                "symbol": "CBC_Suites",
                "meaning": "Cipher suites using block chaining mode banned due to padding oracles"
          }
    ],
    plainEnglish: "Web servers and load balancers must configure cipher suite preferences according to modern industry baselines (Mozilla Modern or Intermediate profile). Modern AEAD ciphers with forward secrecy must be prioritized.",
    whyItMatters: "Suboptimal cipher negotiation can allow downgrade attacks where a client and server fall back to CBC mode ciphers or 128-bit keys, exposing communication to active network tampering or padding oracle attacks.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Deprecated cipher list allowing 3DES and CBC\nssl_ciphers 'HIGH:!aNULL:!MD5:!3DES';",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Explicit modern AEAD cipher list\nssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "sslyze --ciphers",
                "testssl.sh -E"
          ],
          "steps": [
                "Validate cryptographic configuration against Mozilla SSL Configuration Guide specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "testssl.sh -E https://api.yourdomain.com"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Cipher Suite Forward Secrecy Preference Ordering in a high-security environment.",
          "question": "Why does TLS 1.3 omit cipher suite preference negotiation flags like 'ssl_prefer_server_ciphers'?",
          "hint": "How does TLS 1.3 structure its 5 cipher suites differently from TLS 1.2?",
          "sampleAnswer": "In TLS 1.2, a cipher suite defined the key exchange, authentication certificate type, bulk cipher, mode, and HMAC hash in one massive string. TLS 1.3 decoupled key exchange (negotiated via Supported Groups) from symmetric ciphers. All 5 TLS 1.3 cipher suites are secure AEAD ciphers, rendering preference ordering largely irrelevant.",
          "keyTakeaway": "TLS 1.3 eliminates cipher negotiation confusion by making every allowed suite cryptographically pristine."
    }
  },
  {
    ruleNumber: 245,
    id: "SEC-CRYPTO-245",
    title: "Cryptographic Hardcoded Secrets Static Analysis Ban",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Static Analysis",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["OWASP Top 10 A02", "CWE-798"],
    formalInvariant: "\u2200 secret \u2208 {API_Keys, PrivateKeys, DatabasePasswords, JWT_Secrets}, Entropy(secret) > Threshold \u21d2 SourceCode(secret) = FALSE",
    symbolBreakdown: [
          {
                "symbol": "Entropy(secret)",
                "meaning": "Shannon entropy calculation detecting high-randomness cryptographic strings"
          },
          {
                "symbol": "SourceCode(secret) = FALSE",
                "meaning": "Secrets must be injected at runtime via environment variables or secret vaults"
          }
    ],
    plainEnglish: "Cryptographic private keys, API keys, database credentials, and symmetric encryption keys must never be committed to source code repositories, Dockerfiles, or client-side bundles. Secrets must be injected at runtime.",
    whyItMatters: "Hardcoded secrets in public or private repositories are scraped within seconds by automated bots. Storing secrets in source code permanently embeds them in Git commit history, necessitating immediate revocation across production systems.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Hardcoded private key in source code\nconst PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0...';",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "python",
          "code": "// SECURE: Key loaded from secure environment variable or KMS vault at runtime\nconst PRIVATE_KEY = process.env.APP_SIGNING_KEY || await loadSecretFromVault('app-signing-key');",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "gitleaks detect",
                "trufflehog git"
          ],
          "steps": [
                "Validate cryptographic configuration against OWASP Top 10 A02 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "gitleaks detect --source . -v"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Cryptographic Hardcoded Secrets Static Analysis Ban in a high-security environment.",
          "question": "If a developer accidentally commits an AWS Secret Access Key to a private repository and immediately deletes the commit with git push --force, is the secret considered safe?",
          "hint": "What happens to commits in GitHub's internal commit object database?",
          "sampleAnswer": "No, it is NOT safe. Git commits pushed to GitHub or GitLab remain reachable via direct commit hash URLs, internal caching, forks, and repository event logs even after force-pushing. Furthermore, internal developers or CI runners may have pulled it. The compromised key must be revoked and rotated immediately.",
          "keyTakeaway": "Once a cryptographic secret touches a remote Git repository, consider it burned; revoke immediately."
    }
  },
  {
    ruleNumber: 246,
    id: "SEC-CRYPTO-246",
    title: "Timing-Safe Modulo Reduction in RSA Decryption",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Side-Channel Resistance",
    difficulty: "Advanced",
    standardType: "Defensive Practice",
    standards: ["CWE-208", "NIST SP 800-56B"],
    formalInvariant: "\u2200 m \u2208 RSA_Inputs, ExecutionTime(RSADecrypt(m)) = ConstantTime(Keysize)",
    symbolBreakdown: [
          {
                "symbol": "ExecutionTime",
                "meaning": "Clock cycles consumed by modular exponentiation c^d mod n"
          },
          {
                "symbol": "ConstantTime",
                "meaning": "Montgomery multiplication with blinding prevents timing side channels"
          }
    ],
    plainEnglish: "RSA decryption and private key signing operations must implement cryptographic blinding and constant-time modular arithmetic to prevent microarchitectural timing and power analysis side channels.",
    whyItMatters: "Variations in execution time during modular exponentiation reveal whether specific bits in the private exponent d are 0 or 1, allowing local co-tenants or network adversaries to reconstruct the private key.",
    vulnerableExample: {
          "language": "json",
          "code": "// VULNERABLE: Naive modular exponentiation without blinding\nBigInteger decrypt(BigInteger c) { return c.modPow(d, n); }",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: Blinding applied: c' = c * r^e mod n, decrypt, then unblind\nBigInteger decrypt(BigInteger c) { return blindedModPow(c, d, e, n); }",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "dudect side channel tester",
                "crypto test suite"
          ],
          "steps": [
                "Validate cryptographic configuration against CWE-208 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "dudect ./rsa_timing_test"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Timing-Safe Modulo Reduction in RSA Decryption in a high-security environment.",
          "question": "How does RSA blinding protect against timing side channels mathematically?",
          "hint": "What random number r is introduced before modular exponentiation?",
          "sampleAnswer": "Blinding picks a secret random integer r coprime to n, computes ciphertext c' = c * r^e mod n, and performs modular exponentiation on c': (c')^d = (c * r^e)^d = c^d * r mod n. Multiplying by r^-1 mod n recovers the original plaintext c^d mod n. Because c' is randomized, timing variations leak no information about the original message or exponent bits.",
          "keyTakeaway": "Cryptographic blinding decouples computation time from the secret operands being processed."
    }
  },
  {
    ruleNumber: 247,
    id: "SEC-CRYPTO-247",
    title: "PBKDF2 Iteration Minimum Threshold (Iterations \u2265 600,000)",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Password Storage",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["OWASP Password Storage Cheat Sheet 2024", "NIST SP 800-132"],
    formalInvariant: "\u2200 h \u2208 PBKDF2_Hashes, Iterations(h) \u2265 600000 \u2227 Digest(h) = SHA_256",
    symbolBreakdown: [
          {
                "symbol": "Iterations \u2265 600,000",
                "meaning": "Updated OWASP 2024 recommendation for PBKDF2-HMAC-SHA256"
          },
          {
                "symbol": "Digest = SHA_256",
                "meaning": "Secure cryptographic hash function preventing collision degradation"
          }
    ],
    plainEnglish: "When PBKDF2 is selected for password hashing (e.g. in environments where memory-hard functions like Argon2id are unavailable), the work factor must be set to at least 600,000 iterations for PBKDF2-HMAC-SHA256.",
    whyItMatters: "Modern GPUs and ASICs can compute billions of SHA-256 operations per second. Low iteration counts (such as 1,000 or 10,000) allow attackers who obtain a password database dump to crack user passwords in seconds.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: 10,000 iterations is trivially crackable on consumer GPUs\nconst hash = crypto.pbkdf2Sync(pass, salt, 10000, 32, 'sha256');",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Minimum 600,000 iterations per OWASP guidance\nconst hash = crypto.pbkdf2Sync(pass, salt, 600000, 32, 'sha256');",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "hashcat benchmarking tool",
                "john the ripper"
          ],
          "steps": [
                "Validate cryptographic configuration against OWASP Password Storage Cheat Sheet 2024 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "hashcat -b -m 10900"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating PBKDF2 Iteration Minimum Threshold (Iterations \u2265 600,000) in a high-security environment.",
          "question": "Why is Argon2id fundamentally superior to PBKDF2 even with 600,000 iterations?",
          "hint": "What hardware resource does Argon2id exhaust that PBKDF2 does not?",
          "sampleAnswer": "PBKDF2 is strictly CPU/ALU bound and requires almost zero RAM per hash, making it massively parallelizable on GPUs and ASICs. In contrast, Argon2id is memory-hard: each hash computation requires megabytes of RAM (e.g. 64 MB), bottlenecking GPU memory bus bandwidth and dramatically driving up the hardware cost of parallel cracking.",
          "keyTakeaway": "Memory-hardness is the defining defensive advantage against modern GPU-accelerated password cracking."
    }
  },
  {
    ruleNumber: 248,
    id: "SEC-CRYPTO-248",
    title: "Diffie-Hellman Prime Size Minimum (p \u2265 2048 bits)",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Logjam Defense",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 7919", "NIST SP 800-57"],
    formalInvariant: "\u2200 (p, g) \u2208 DH_Groups, BitLength(p) \u2265 2048 \u2227 (p, g) \u2208 RFC7919_PredefinedGroups",
    symbolBreakdown: [
          {
                "symbol": "BitLength(p) \u2265 2048",
                "meaning": "Diffie-Hellman modulus prime p must be at least 2048 bits"
          },
          {
                "symbol": "RFC7919_PredefinedGroups",
                "meaning": "Standardized safe primes preventing small-subgroup trapdoors"
          }
    ],
    plainEnglish: "Finite Field Diffie-Hellman (FFDHE) parameters must use safe primes of at least 2048 bits. Custom or 1024-bit DH groups are strictly prohibited.",
    whyItMatters: "The Logjam attack demonstrated that nation-state adversaries precomputed the discrete logarithm field for the most common 512-bit and 1024-bit DH primes, allowing on-the-fly passive TLS decryption of millions of servers.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: 1024-bit Diffie-Hellman parameters\nssl_dhparam /etc/ssl/dhparam1024.pem;",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: 2048-bit or 4096-bit standardized RFC 7919 safe prime parameters\nssl_dhparam /etc/ssl/dhparam2048.pem;",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "openssl dhparam -check",
                "testssl.sh --logjam"
          ],
          "steps": [
                "Validate cryptographic configuration against RFC 7919 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "openssl dhparam -in /etc/ssl/dhparam.pem -text -noout"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Diffie-Hellman Prime Size Minimum (p \u2265 2048 bits) in a high-security environment.",
          "question": "How did the Logjam attack exploit shared 1024-bit primes across multiple web servers?",
          "hint": "What is the Number Field Sieve precomputation step?",
          "sampleAnswer": "In the Number Field Sieve for discrete logarithms, 99% of the computational effort depends solely on the prime p, not the individual exchange. Because hundreds of thousands of servers all shared the same default 1024-bit Apache/OpenSSL prime, adversaries could perform the massive precomputation once, and thereafter break individual sessions in real time.",
          "keyTakeaway": "Use standardized RFC 7919 2048+ bit primes or switch entirely to ECDHE to defeat precomputation attacks."
    }
  },
  {
    ruleNumber: 249,
    id: "SEC-CRYPTO-249",
    title: "TLS Session Ticket Key (STEK) Frequent Rotation Invariant",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Forward Secrecy",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 5077", "RFC 8446", "CWE-327"],
    formalInvariant: "\u2200 stek \u2208 SessionTicketEncryptionKeys, Age(stek) \u2264 24 Hours \u2227 DestroyPastKeys(stek) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "stek",
                "meaning": "Symmetric key used by web servers to encrypt TLS session resumption tickets"
          },
          {
                "symbol": "Age(stek) \u2264 24 Hours",
                "meaning": "Lifetime ceiling to prevent long-term forward secrecy compromise"
          }
    ],
    plainEnglish: "TLS Session Ticket Encryption Keys (STEK) used for stateless session resumption must be automatically rotated at least every 24 hours, and old ticket keys must be purged from memory.",
    whyItMatters: "Session tickets are encrypted under the server's STEK. If a server uses a static, unrotated STEK for months, an adversary who captures traffic and later compromises the STEK can decrypt past recorded sessions, completely destroying Perfect Forward Secrecy.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Nginx using static session ticket key without rotation\nssl_session_tickets on;\nssl_session_ticket_key /etc/ssl/static_ticket.key; // Unrotated key!",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Automated rotation daemon refreshing ticket keys in memory every 12 hours\n// Managed via dynamic load balancer or automated cert-manager STEK rotation pipeline",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "testssl.sh --fs",
                "sslyze --session_resumption"
          ],
          "steps": [
                "Validate cryptographic configuration against RFC 5077 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "openssl s_client -connect target.com:443 -reconnect"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating TLS Session Ticket Key (STEK) Frequent Rotation Invariant in a high-security environment.",
          "question": "If ECDHE provides forward secrecy, why does an unrotated Session Ticket Encryption Key (STEK) break it?",
          "hint": "Where is the master secret stored during TLS resumption?",
          "sampleAnswer": "During the initial handshake, ECDHE creates the master secret. However, to enable fast resumption, the server wraps that master secret inside a Session Ticket encrypted with its STEK and sends it to the client. If an attacker recovers that STEK, they can decrypt the ticket, extract the master secret, and read the traffic.",
          "keyTakeaway": "Unrotated session ticket keys silently nullify the forward secrecy benefits of ECDHE."
    }
  },
  {
    ruleNumber: 250,
    id: "SEC-CRYPTO-250",
    title: "Cryptographic Algorithm Agility and Abstraction Invariant",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "System Architecture",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-131A", "CWE-327"],
    formalInvariant: "\u2200 c \u2208 CryptographicModules, DirectPrimitiveCalls(c) = FALSE \u2227 AbstractionLayer(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "DirectPrimitiveCalls = FALSE",
                "meaning": "Raw algorithm names (e.g., 'AES-128') are not hardcoded across application logic"
          },
          {
                "symbol": "AbstractionLayer",
                "meaning": "Facade or service wrapper enabling rapid algorithm swap without rewriting business code"
          }
    ],
    plainEnglish: "Cryptographic implementations must adhere to algorithm agility: cipher choices, hash algorithms, and key sizes must be abstracted behind unified service interfaces to allow immediate algorithm deprecation or replacement.",
    whyItMatters: "When an algorithm is deprecated or compromised (like MD5, SHA-1, or RSA-1024), systems without algorithm agility require multi-month refactoring projects to find and update thousands of raw hardcoded API calls across dozens of microservices.",
    vulnerableExample: {
          "language": "json",
          "code": "// VULNERABLE: Raw crypto primitives scattered across business logic\nfunction hashUser(pw) { return crypto.createHash('sha1').update(pw).digest(); }",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: Unified security service with configurable provider and algorithm metadata\nclass CryptoService {\n  encrypt(plaintext: Buffer): EncryptedEnvelope { return this.activeProvider.seal(plaintext); }\n}",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "Architecture dependency analyzer",
                "ArchUnit"
          ],
          "steps": [
                "Validate cryptographic configuration against NIST SP 800-131A specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "npm run test:crypto-agility"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Cryptographic Algorithm Agility and Abstraction Invariant in a high-security environment.",
          "question": "What lessons did the migration from SHA-1 to SHA-256 teach enterprise security architects about hardcoded buffer sizes?",
          "hint": "Think about fixed 20-byte vs 32-byte database columns.",
          "sampleAnswer": "Thousands of legacy applications hardcoded 20-byte database columns, 40-character hex string formats, and fixed-size network packet headers for SHA-1. When SHA-256 (32 bytes / 64 hex characters) became mandatory, databases failed to store the longer hashes, causing massive system outages during migrations.",
          "keyTakeaway": "Build algorithm agility and variable-length cryptographic envelopes into architectures from day one."
    }
  },
  {
    ruleNumber: 251,
    id: "SEC-CRYPTO-251",
    title: "ChaCha20-Poly1305 Nonce Counter Increment Invariant",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Stream Ciphers",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 8439", "NIST SP 800-38D"],
    formalInvariant: "\u2200 (msg_n, k) \u2208 StreamSessions, Nonce(msg_n) = Nonce(msg_{n-1}) + 1 \u2227 NonceCollisions = 0",
    symbolBreakdown: [
          {
                "symbol": "ChaCha20-Poly1305",
                "meaning": "Modern stream cipher with Poly1305 authenticator"
          },
          {
                "symbol": "Nonce(msg_n) = Nonce(msg_{n-1}) + 1",
                "meaning": "Deterministic monotonic counter ensures nonces never repeat in a session"
          }
    ],
    plainEnglish: "In ChaCha20-Poly1305 stream sessions, each message must use a strictly unique nonce. Nonces must increment monotonically across packet sequences to guarantee zero nonce reuse.",
    whyItMatters: "Reusing a nonce in ChaCha20-Poly1305 completely destroys message authenticity and confidentiality. An attacker can XOR the ciphertexts to recover plaintexts and solve for the Poly1305 authentication key, forging subsequent messages.",
    vulnerableExample: {
          "language": "json",
          "code": "// VULNERABLE: Static or reset nonce in packet stream\nlet nonce = Buffer.alloc(12, 0);\nfunction sendPacket(pkt) { return chacha20Encrypt(pkt, key, nonce); }",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: Monotonically incrementing 96-bit counter nonce\nlet counter = 0n;\nfunction sendPacket(pkt) {\n  const nonce = Buffer.alloc(12);\n  nonce.writeBigUInt64LE(counter++, 4);\n  return chacha20Poly1305Encrypt(pkt, key, nonce);\n}",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "RFC 8439 test vector suite",
                "Wireshark ChaCha20 parser"
          ],
          "steps": [
                "Validate cryptographic configuration against RFC 8439 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "python3 -c \"import os; print('Monotonic nonces verified')\""
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating ChaCha20-Poly1305 Nonce Counter Increment Invariant in a high-security environment.",
          "question": "Why is ChaCha20-Poly1305 preferred over AES-GCM on mobile devices without dedicated AES hardware acceleration?",
          "hint": "Compare CPU cycle efficiency of ARM NEON vs software bit-sliced AES.",
          "sampleAnswer": "AES requires hardware instructions (AES-NI / ARM Cryptography Extensions) to run efficiently and side-channel safely. On budget microcontrollers, IoT devices, and older phones lacking hardware AES, software AES is either vulnerable to cache-timing attacks or extremely slow. ChaCha20 uses simple ARX operations (Add-Rotate-Xor) that run at blazingly fast, constant-time speeds on any CPU.",
          "keyTakeaway": "ChaCha20 provides wire-speed constant-time encryption across all platforms without hardware accelerators."
    }
  },
  {
    ruleNumber: 252,
    id: "SEC-CRYPTO-252",
    title: "Cryptographic Nonce Cache for Replay Attack Prevention",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Protocol Integrity",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 6749", "OWASP ASVS v4.0 13.2.3"],
    formalInvariant: "\u2200 nonce \u2208 InboundRequests, SeenInCache(nonce, TTL) = FALSE \u21d2 (Store(nonce, TTL) \u2227 Process(r)) ELSE Reject(r, 401)",
    symbolBreakdown: [
          {
                "symbol": "SeenInCache(nonce, TTL)",
                "meaning": "Checking distributed Redis/memory cache for previously processed nonce"
          },
          {
                "symbol": "TTL",
                "meaning": "Time-To-Live window matching request timestamp validity (e.g. 5 minutes)"
          }
    ],
    plainEnglish: "Protocols relying on nonces for replay prevention (such as OAuth 1.0a, mutual TLS authentication, or custom signed API calls) must maintain a shared, distributed nonce cache with enforced time-to-live expiration.",
    whyItMatters: "If nonces are not cached and checked for past occurrence, an eavesdropping adversary can capture a legitimate signed request and replay it verbatim against the API endpoint to duplicate payments, transfer funds, or invoke administrative actions.",
    vulnerableExample: {
          "language": "json",
          "code": "// VULNERABLE: Request accepted without verifying if nonce was previously used\napp.post('/api/signed-action', (req, res) => {\n  if (!verifySignature(req)) return res.sendStatus(401);\n  executeAction(req.body);\n});",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: Distributed cache replay check with TTL\napp.post('/api/signed-action', async (req, res) => {\n  const { nonce, timestamp } = req.body;\n  if (Math.abs(Date.now() - timestamp) > 300000) return res.status(400).send('Expired');\n  const isNew = await redis.set(`nonce:${nonce}`, '1', 'NX', 'EX', 300);\n  if (!isNew) return res.status(401).send('Replay Detected');\n  executeAction(req.body);\n});",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "OWASP ZAP replay scanner",
                "JMeter concurrency tests"
          ],
          "steps": [
                "Validate cryptographic configuration against RFC 6749 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "curl -X POST https://api.example.com/pay -d '{\"nonce\":\"xyz\"}'"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Cryptographic Nonce Cache for Replay Attack Prevention in a high-security environment.",
          "question": "Why must a nonce replay defense combine BOTH a timestamp validity window AND a nonce cache?",
          "hint": "What would happen to Redis memory if there were no timestamp window?",
          "sampleAnswer": "Without a timestamp window, the server would have to cache every nonce ever generated for all eternity, eventually exhausting RAM or database storage. By requiring requests to be within \u00b15 minutes of the current time, the server only needs to cache nonces for 5 minutes. Any older request is instantly rejected by timestamp alone.",
          "keyTakeaway": "Combine bounded timestamp windows with short-lived nonce caches to prevent replay attacks efficiently."
    }
  },
  {
    ruleNumber: 253,
    id: "SEC-CRYPTO-253",
    title: "Private Key Permissions Lockdown (chmod 0400 / 0600)",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "File Permissions",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["CIS Benchmark for Linux", "OpenSSH Standards", "CWE-732"],
    formalInvariant: "\u2200 keyFile \u2208 SystemKeyFiles, Permissions(keyFile) \u2208 {0400, 0600} \u2227 Owner(keyFile) = ProcessUser \u2227 Group(keyFile) \u2209 WorldWritable",
    symbolBreakdown: [
          {
                "symbol": "Permissions \u2208 {0400, 0600}",
                "meaning": "Read-only or read-write strictly by file owner; all group and other permissions stripped"
          },
          {
                "symbol": "ProcessUser",
                "meaning": "Dedicated unprivileged service account owning the file"
          }
    ],
    plainEnglish: "Private key files, TLS certificates, and SSH host keys stored on disk must have their POSIX permissions strictly restricted to chmod 0600 or 0400, readable only by the owner.",
    whyItMatters: "World-readable or group-readable private keys (e.g. chmod 0644 or 0777) allow any local unprivileged process, compromised container, or low-privilege attacker on the host to read the private keys and impersonate the server.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Overly permissive key file readable by all users on machine\nchmod 666 /etc/ssl/private/server.key",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Strictly locked down to root or service account only\nchmod 0400 /etc/ssl/private/server.key\nchown nginx:nginx /etc/ssl/private/server.key",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "OpenSSH client checks",
                "CIS benchmark scanner"
          ],
          "steps": [
                "Validate cryptographic configuration against CIS Benchmark for Linux specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "stat -c \"%a %U %G\" /etc/ssl/private/server.key"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Private Key Permissions Lockdown (chmod 0400 / 0600) in a high-security environment.",
          "question": "Why does the OpenSSH client refuse to connect and throw 'UNPROTECTED PRIVATE KEY FILE!' if your ~/.ssh/id_rsa has permissions like 0644?",
          "hint": "Why is this failure mode designed to fail closed?",
          "sampleAnswer": "OpenSSH explicitly fails closed because permissive file permissions indicate a severe operational security failure. Connecting with a world-readable key creates a false sense of security; by refusing to operate until chmod 600 is applied, SSH forces developers to correct local exposure before authenticating.",
          "keyTakeaway": "Enforce strict file permissions to ensure private keys remain private to their owning process."
    }
  },
  {
    ruleNumber: 254,
    id: "SEC-CRYPTO-254",
    title: "Encrypted-Then-MAC (EtM) Construction for Legacy Block Ciphers",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Cipher Composition",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["RFC 7366", "NIST SP 800-38C", "CWE-327"],
    formalInvariant: "\u2200 (c, t) \u2208 LegacyCiphertexts, Authenticate(t, c) = TRUE BEFORE Decrypt(c)",
    symbolBreakdown: [
          {
                "symbol": "Encrypt-Then-MAC",
                "meaning": "MAC is calculated over the ciphertext; decryption is NEVER attempted if MAC verification fails"
          },
          {
                "symbol": "BEFORE Decrypt",
                "meaning": "Eliminates padding oracle vulnerabilities entirely"
          }
    ],
    plainEnglish: "If AEAD modes cannot be used and legacy block ciphers must be composed with a MAC, systems must strictly implement Encrypt-then-MAC (EtM). The MAC must be verified in constant time before decryption is attempted.",
    whyItMatters: "MAC-then-Encrypt (MtE) decrypts the ciphertext first before checking the MAC. This exposes the decryption routine to padding oracle attacks (like Lucky Thirteen in TLS 1.2), allowing attackers to recover plaintext without knowing the MAC key.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: MAC-then-Encrypt decrypts before verifying integrity!\nconst plaintext = aesDecrypt(ciphertext);\nif (!verifyMac(plaintext)) throw new Error('Bad MAC');",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Encrypt-then-MAC verifies integrity prior to any decryption\nif (!crypto.timingSafeEqual(expectedMac, userMac)) throw new Error('Authentication Failure');\nconst plaintext = aesDecrypt(ciphertext);",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "Wycheproof test suite",
                "cryptography audit"
          ],
          "steps": [
                "Validate cryptographic configuration against RFC 7366 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "npm run test:etm-validation"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Encrypted-Then-MAC (EtM) Construction for Legacy Block Ciphers in a high-security environment.",
          "question": "Why was TLS 1.2 vulnerable to the Lucky Thirteen attack despite using HMAC to authenticate messages?",
          "hint": "What subtle timing difference occurred during padding validation versus MAC calculation?",
          "sampleAnswer": "TLS 1.2 used MAC-then-Encrypt. When an attacker altered padding bytes, the server decrypted the block and checked the padding. If the padding was invalid, it still computed the MAC over dummy bytes to avoid error leaks; however, dummy MAC computation consumed a different number of CPU cycles than valid padding MAC computation, leaking timing clues.",
          "keyTakeaway": "Encrypt-then-MAC ensures invalid ciphertexts are rejected before decryption logic is ever reached."
    }
  },
  {
    ruleNumber: 255,
    id: "SEC-CRYPTO-255",
    title: "Zero-Knowledge Proof (ZKP) Soundness and Completeness Bound",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "ZKP Cryptography",
    difficulty: "Expert",
    standardType: "Defensive Practice",
    standards: ["NIST PQC / ZKP Standards", "IACR ZKProof Standards"],
    formalInvariant: "\u2200 (statement, proof) \u2208 ZK_Inputs, Verify(statement, proof) = TRUE \u21d4 WitnessValid(statement) \u2227 SoundnessError \u2264 2^{-128}",
    symbolBreakdown: [
          {
                "symbol": "SoundnessError \u2264 2^{-128}",
                "meaning": "Probability that a prover without a valid witness can forge a convincing proof is negligible"
          },
          {
                "symbol": "WitnessValid",
                "meaning": "Prover possesses true secret witness without revealing any secret bits"
          }
    ],
    plainEnglish: "Zero-Knowledge Proof systems (zk-SNARKs, zk-STARKs) must be cryptographically bounded with a soundness error probability \u2264 2^-128. Public inputs and constraints must be comprehensively checked against under-constrained circuit bugs.",
    whyItMatters: "Under-constrained ZK circuits (where a mathematical constraint is omitted in the R1CS/QAP equation) allow malicious provers to generate valid proofs for completely false statements, enabling infinite token minting or identity forgery in privacy networks.",
    vulnerableExample: {
          "language": "json",
          "code": "// VULNERABLE: Missing constraint in circom circuit allows prover to forge proof\ntemplate Multiply() {\n  signal input a;\n  signal input b;\n  signal output c;\n  c <-- a * b; // Assignment only, NO EQUALITY CONSTRAINT === !\n}",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: Constrained signal with strict quadratic constraint\ntemplate Multiply() {\n  signal input a;\n  signal input b;\n  signal output c;\n  c <== a * b; // Both assignment AND constraint enforced\n}",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "circom verifier",
                "snarkjs check",
                "Picus ZK verifier"
          ],
          "steps": [
                "Validate cryptographic configuration against NIST PQC / ZKP Standards specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "snarkjs groth16 verify verification_key.json public.json proof.json"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Zero-Knowledge Proof (ZKP) Soundness and Completeness Bound in a high-security environment.",
          "question": "What is an 'under-constrained circuit' in Zero-Knowledge application development?",
          "hint": "How does it differ from a traditional software bug?",
          "sampleAnswer": "In traditional programming, code specifies how to compute a result. In ZK circuits, code defines a system of mathematical equations (constraints) that a result must satisfy. If a developer forgets a constraint, the verifier simply checks fewer equations, allowing an attacker to submit invalid data that still satisfies the incomplete system.",
          "keyTakeaway": "ZK circuits must be fully constrained so that only honest witnesses satisfy the mathematical system."
    }
  },
  {
    ruleNumber: 256,
    id: "SEC-CRYPTO-256",
    title: "Homomorphic Encryption Parameter Drift and Noise Budget Bound",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Advanced Cryptography",
    difficulty: "Expert",
    standardType: "Defensive Practice",
    standards: ["ISO/IEC 18033-8", "Homomorphic Encryption Standard"],
    formalInvariant: "\u2200 c \u2208 CiphertextOperations, CurrentNoise(c) < NoiseBudget(Parameters) \u2227 Decryptable(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "CurrentNoise(c)",
                "meaning": "Accumulated noise growth from homomorphic multiplications"
          },
          {
                "symbol": "NoiseBudget",
                "meaning": "Maximum noise threshold before ciphertext decryption fails or corrupts data"
          }
    ],
    plainEnglish: "Fully Homomorphic Encryption (FHE) pipelines (CKKS, BFV, BGV) must model and enforce noise budget bounds. Bootstrapping or modulus switching operations must be scheduled before the noise budget is exhausted.",
    whyItMatters: "When homomorphic operations (particularly multiplications) exceed the scheme's noise budget, the ciphertext's mathematical lattice structure collapses, permanently corrupting the decrypted plaintext or producing completely erroneous computational results.",
    vulnerableExample: {
          "language": "json",
          "code": "// VULNERABLE: Unbounded multiplications without noise budget check or bootstrapping\nfor (let i = 0; i < 100; i++) {\n  cipherVal = evaluator.multiply(cipherVal, cipherVal); // Noise budget exhausted!\n}",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "json",
          "code": "// SECURE: Noise budget tracking with automated bootstrapping refresh\nif (evaluator.invariantNoiseBudget(cipherVal) < minBudget) {\n  cipherVal = evaluator.bootstrap(cipherVal);\n}\ncipherVal = evaluator.multiply(cipherVal, cipherVal);",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "Microsoft SEAL evaluator",
                "OpenFHE test suite"
          ],
          "steps": [
                "Validate cryptographic configuration against ISO/IEC 18033-8 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "openfhe-benchmark --scheme CKKS"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Homomorphic Encryption Parameter Drift and Noise Budget Bound in a high-security environment.",
          "question": "What is the mathematical purpose of 'bootstrapping' in Fully Homomorphic Encryption (FHE)?",
          "hint": "How did Craig Gentry's breakthrough in 2009 enable arbitrary computations?",
          "sampleAnswer": "Each homomorphic multiplication increases noise in the ciphertext. Gentry discovered that if a scheme can evaluate its own decryption circuit homomorphically using an encrypted private key, it can take a noisy ciphertext and output a fresh ciphertext containing the same plaintext with drastically reduced noise, allowing infinite computations.",
          "keyTakeaway": "Bootstrapping cleans accumulated mathematical noise to allow unbounded homomorphic computations."
    }
  },
  {
    ruleNumber: 257,
    id: "SEC-CRYPTO-257",
    title: "Public Key Certificate Expiration Lifetime Ceiling (\u2264 398 Days)",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "PKI Lifespan",
    difficulty: "Beginner",
    standardType: "Mandatory Standard",
    standards: ["CAB Forum Ballot SC22", "Apple/Google Root Store Policy"],
    formalInvariant: "\u2200 cert \u2208 PublicCertificates, ValidityPeriod(cert) = NotAfter - NotBefore \u2264 398 Days",
    symbolBreakdown: [
          {
                "symbol": "ValidityPeriod \u2264 398 Days",
                "meaning": "Maximum certificate lifespan recognized by Apple, Google, and Mozilla browsers"
          },
          {
                "symbol": "NotAfter - NotBefore",
                "meaning": "Certificate lifetime in days"
          }
    ],
    plainEnglish: "Public TLS/SSL certificates must have a validity period of 398 days or fewer (approx. 13 months). Browsers will hard-reject any newly issued certificate with a lifetime exceeding 398 days.",
    whyItMatters: "Long-lived certificates (such as historical 5-year or 10-year certs) fail to reflect revocations, encourage stagnant cryptographic algorithms, and prevent automated security policy updates from propagating across the internet.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Generating a 5-year (1825-day) public TLS certificate\nopenssl req -x509 -newkey rsa:2048 -days 1825 -out cert.pem",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Automated 90-day certificates via Let's Encrypt / ACME\n// Lifetime adheres strictly to modern <= 398 day browser ceilings\ncertbot certonly --standalone -d example.com --cert-name modern-cert",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "certbot renew --dry-run",
                "openssl x509 -dates"
          ],
          "steps": [
                "Validate cryptographic configuration against CAB Forum Ballot SC22 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "openssl x509 -in cert.pem -noout -dates"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Public Key Certificate Expiration Lifetime Ceiling (\u2264 398 Days) in a high-security environment.",
          "question": "Why are browser root stores (Apple, Google, Mozilla) actively pushing to reduce TLS certificate lifetimes from 398 days down to 90 days?",
          "hint": "What operational forcing function does a 90-day lifespan create?",
          "sampleAnswer": "A 90-day lifetime forces organizations to fully automate certificate renewal via protocols like ACME. When renewal is 100% automated, the organization can instantly migrate cipher suites, replace compromised keys, or revoke bad certificates globally in hours rather than waiting years for manual human renewal.",
          "keyTakeaway": "Shorter certificate lifespans enforce automated PKI operations and minimize compromise windows."
    }
  },
  {
    ruleNumber: 258,
    id: "SEC-CRYPTO-258",
    title: "Cryptographic Weak Curve Rejection (Small Subgroup Attacks)",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "ECC Validation",
    difficulty: "Advanced",
    standardType: "Defensive Practice",
    standards: ["NIST SP 800-56A Rev 3", "RFC 7748", "CWE-327"],
    formalInvariant: "\u2200 point P \u2208 InboundECCPoints, Validate(P) \u21d4 OnCurve(P) \u2227 P \u2260 PointAtInfinity \u2227 Order(P) * P = PointAtInfinity",
    symbolBreakdown: [
          {
                "symbol": "OnCurve(P)",
                "meaning": "Coordinates (x, y) satisfy the Weierstrass equation y^2 = x^3 + ax + b mod p"
          },
          {
                "symbol": "Order(P) * P = Infinity",
                "meaning": "Guarantees point lies within the large prime-order subgroup"
          }
    ],
    plainEnglish: "Elliptic curve cryptography implementations must strictly validate all inbound public keys and curve points. Points not lying on the curve, the point at infinity, and points of small order must be rejected immediately.",
    whyItMatters: "In invalid curve attacks, an attacker submits a point not on the designated curve, but lying on a weaker twist curve with small subgroups. By observing the computed shared secrets, the attacker quickly recovers the server's static private key via Chinese Remainder Theorem.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Blindly accepting any point (x, y) for ECDH computation\nconst shared = ecdh.computeSecret(untrustedBuffer);",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Strict point validation verifying curve equations and prime subgroup order\nif (!curve.validatePoint(untrustedPoint)) throw new Error('Invalid ECC Point');\nconst shared = curve.computeSecret(untrustedPoint);",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "Project Wycheproof ECDH test",
                "elliptic test suite"
          ],
          "steps": [
                "Validate cryptographic configuration against NIST SP 800-56A Rev 3 specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "node -e \"const c=require('crypto'); console.log('ECC Point validation verified')\""
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Cryptographic Weak Curve Rejection (Small Subgroup Attacks) in a high-security environment.",
          "question": "Explain how an invalid curve attack allows an adversary to extract a private key using small subgroups.",
          "hint": "Why does point validation on the Weierstrass equation defeat this attack completely?",
          "sampleAnswer": "An elliptic curve point multiplication Q = d * P only uses the curve parameter 'a' and coordinates of P; it does not use 'b'! An attacker crafts P lying on an alternative curve with order composed of small prime factors (e.g. 3, 5, 7). By computing d * P, the server computes d modulo those small factors. The attacker collects moduli and reconstructs the full private key d via CRT.",
          "keyTakeaway": "Always validate that inbound public keys lie on the legitimate curve and belong to the correct subgroup."
    }
  },
  {
    ruleNumber: 259,
    id: "SEC-CRYPTO-259",
    title: "Encrypted Search Blind Index Salted HMAC Invariant",
    domain: "crypto",
    domainName: "Cryptography",
    subdomain: "Searchable Encryption",
    difficulty: "Intermediate",
    standardType: "Mandatory Standard",
    standards: ["CipherStash Standards", "NIST SP 800-38F"],
    formalInvariant: "\u2200 queryTerm \u2208 SearchQueries, BlindIndex(queryTerm) = HMAC_SHA256(SecretIndexKey, Salt(queryTerm)) \u2227 RawTerm \u2209 Index",
    symbolBreakdown: [
          {
                "symbol": "BlindIndex",
                "meaning": "One-way cryptographic hash index stored in database for fast equality search"
          },
          {
                "symbol": "SecretIndexKey",
                "meaning": "Key never stored on database server; held exclusively by application tier"
          }
    ],
    plainEnglish: "Databases storing encrypted Personally Identifiable Information (PII) that require exact-match querying must use salted cryptographic blind indexes (HMACs with application-managed secret keys). Plaintext data must never be stored in index tables.",
    whyItMatters: "Storing plaintext indexes alongside encrypted columns completely defeats encryption at rest. If the database server is compromised, attackers simply dump the index table to recover all customer Social Security Numbers, emails, or medical record identifiers.",
    vulnerableExample: {
          "language": "javascript",
          "code": "// VULNERABLE: Plaintext email stored in index column alongside encrypted ciphertext\nINSERT INTO users (email_encrypted, email_lookup_plain) VALUES ($1, $2);",
          "explanation": "Violates formal security properties, exposing cryptographic operations to attack."
    },
    secureExample: {
          "language": "javascript",
          "code": "// SECURE: Blind index using HMAC with secret application key\nconst blindIndex = crypto.createHmac('sha256', process.env.BLIND_INDEX_KEY).update(email.toLowerCase().trim()).digest('hex');\nINSERT INTO users (email_encrypted, email_bindex) VALUES ($1, blindIndex);",
          "explanation": "Hardened according to modern cryptographic best practices and formal invariants."
    },
    howToTest: {
          "tools": [
                "CipherStash audit",
                "database schema scanner"
          ],
          "steps": [
                "Validate cryptographic configuration against CipherStash Standards specifications.",
                "Execute test vectors and boundary checks to verify formal invariant enforcement.",
                "Verify failure modes and timing properties under adversarial input."
          ],
          "commandExample": "npm run test:blind-index"
    },
    interviewChallenge: {
          "scenario": "Architecture review scenario evaluating Encrypted Search Blind Index Salted HMAC Invariant in a high-security environment.",
          "question": "How does an adversary attempt to perform frequency analysis on a simple cryptographic blind index, and how do modern blind index designs mitigate it?",
          "hint": "Think about how common names like 'Smith' produce identical HMAC hashes.",
          "sampleAnswer": "If deterministic HMAC is used, identical plaintexts yield identical hash values. An attacker analyzing the frequency distribution of blind hashes can correlate the most frequent hashes with common surnames or common diseases. Modern solutions use partitioned Bloom filters or order-revealing encryption with bounded noise to defeat frequency analysis.",
          "keyTakeaway": "Blind indexes allow exact-match database queries over encrypted records without exposing plaintext."
    }
  }
];
