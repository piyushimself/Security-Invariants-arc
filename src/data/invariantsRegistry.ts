import { DomainId, DomainMeta, LearningPath, SecurityInvariant } from '../types/invariants';
import { httpRules } from './domains/httpRules';
import { webRules } from './domains/webRules';
import { apiRules } from './domains/apiRules';
import { authRules } from './domains/authRules';
import { authzRules } from './domains/authzRules';
import { oauthRules } from './domains/oauthRules';
import { cryptoRules } from './domains/cryptoRules';
import { cloudRules } from './domains/cloudRules';
import { awsRules } from './domains/awsRules';
import { containerRules } from './domains/containerRules';
import { containerAdvancedRules } from './domains/containerAdvancedRules';
import { k8sRules } from './domains/k8sRules';
import { codingRules } from './domains/codingRules';
import { codeReviewAdvancedRules } from './domains/codeReviewAdvancedRules';
import { aiRules } from './domains/aiRules';
import { aiAdvancedRules } from './domains/aiAdvancedRules';
import { smartContractRules } from './domains/smartContractRules';
import { web3AdvancedRules } from './domains/web3AdvancedRules';
import { threatModelingRules } from './domains/threatModelingRules';
import { taxonomyExpandedRules } from './domains/taxonomyExpandedRules';
import {
  allSequentialRules,
  tier1FoundationsRules,
  tier2PractitionerRules,
  tier3AdvancedRules,
  tier4StaffFrontierRules
} from './sequentialCurriculum';

export {
  securityTopicsTaxonomy,
  getInvariantsForTopic
} from './taxonomyCategories';

export {
  allSequentialRules,
  tier1FoundationsRules,
  tier2PractitionerRules,
  tier3AdvancedRules,
  tier4StaffFrontierRules
};

export const allInvariants: SecurityInvariant[] = [
  ...httpRules,
  ...webRules,
  ...apiRules,
  ...authRules,
  ...authzRules,
  ...oauthRules,
  ...cryptoRules,
  ...cloudRules,
  ...awsRules,
  ...containerRules,
  ...containerAdvancedRules,
  ...k8sRules,
  ...codingRules,
  ...codeReviewAdvancedRules,
  ...aiRules,
  ...aiAdvancedRules,
  ...smartContractRules,
  ...web3AdvancedRules,
  ...threatModelingRules,
  ...taxonomyExpandedRules,
  ...allSequentialRules
];

const getDomainCount = (dom: DomainId): number => allInvariants.filter(r => r.domain === dom).length;

export const domainMetadata: Record<DomainId, DomainMeta> = {
  http: {
    id: 'http',
    name: 'HTTP Protocols',
    iconName: 'Globe',
    shortDescription: 'RFC 9110/9112 framing, request smuggling, caching, and connection invariants',
    primaryStandard: 'RFC 9112 / RFC 9110',
    count: getDomainCount('http'),
    colorScheme: {
      badge: 'bg-sky-500/10 text-sky-400 border-sky-500/20',
      border: 'border-sky-500/20',
      text: 'text-sky-400',
      bgSubtle: 'bg-sky-500/5'
    }
  },
  web: {
    id: 'web',
    name: 'Web Security',
    iconName: 'Shield',
    shortDescription: 'CSP, CORS, SOP, XSS mitigation, secure cookies, and DOM security',
    primaryStandard: 'W3C CSP / HTML Living Standard',
    count: getDomainCount('web'),
    colorScheme: {
      badge: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
      border: 'border-indigo-500/20',
      text: 'text-indigo-400',
      bgSubtle: 'bg-indigo-500/5'
    }
  },
  api: {
    id: 'api',
    name: 'API Security',
    iconName: 'Server',
    shortDescription: 'BOLA/IDOR, BFLA, mass assignment, GraphQL depth, and rate limiting',
    primaryStandard: 'OWASP API Security Top 10',
    count: getDomainCount('api'),
    colorScheme: {
      badge: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
      border: 'border-cyan-500/20',
      text: 'text-cyan-400',
      bgSubtle: 'bg-cyan-500/5'
    }
  },
  auth: {
    id: 'auth',
    name: 'Authentication',
    iconName: 'Key',
    shortDescription: 'Argon2id, timing-safe equality, session fixation, MFA step-up, and passkeys',
    primaryStandard: 'NIST SP 800-63B / FIDO2',
    count: getDomainCount('auth'),
    colorScheme: {
      badge: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      border: 'border-amber-500/20',
      text: 'text-amber-400',
      bgSubtle: 'bg-amber-500/5'
    }
  },
  authz: {
    id: 'authz',
    name: 'Authorization',
    iconName: 'Lock',
    shortDescription: 'Fail-closed default deny, multi-tenant isolation, ABAC, RBAC, and ReBAC',
    primaryStandard: 'NIST SP 800-53 / XACML',
    count: getDomainCount('authz'),
    colorScheme: {
      badge: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
      border: 'border-rose-500/20',
      text: 'text-rose-400',
      bgSubtle: 'bg-rose-500/5'
    }
  },
  oauth: {
    id: 'oauth',
    name: 'OAuth 2.0 & OIDC',
    iconName: 'Fingerprint',
    shortDescription: 'PKCE S256, redirect_uri exact matching, JWT alg none, and DPoP sender-constraining',
    primaryStandard: 'RFC 9700 / OpenID Connect Core',
    count: getDomainCount('oauth'),
    colorScheme: {
      badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      border: 'border-emerald-500/20',
      text: 'text-emerald-400',
      bgSubtle: 'bg-emerald-500/5'
    }
  },
  crypto: {
    id: 'crypto',
    name: 'Cryptography',
    iconName: 'Binary',
    shortDescription: 'AEAD (AES-GCM / ChaCha20), CSPRNG, constant-time compare, and post-quantum ML-KEM',
    primaryStandard: 'NIST SP 800-57 / FIPS 140-3',
    count: getDomainCount('crypto'),
    colorScheme: {
      badge: 'bg-violet-500/10 text-violet-400 border-violet-500/20',
      border: 'border-violet-500/20',
      text: 'text-violet-400',
      bgSubtle: 'bg-violet-500/5'
    }
  },
  cloud: {
    id: 'cloud',
    name: 'Cloud Security',
    iconName: 'Cloud',
    shortDescription: 'IMDSv2, S3 public access block, KMS envelope encryption, and audit logs',
    primaryStandard: 'CIS Cloud Benchmarks / NIST SP 800-53',
    count: getDomainCount('cloud'),
    colorScheme: {
      badge: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
      border: 'border-blue-500/20',
      text: 'text-blue-400',
      bgSubtle: 'bg-blue-500/5'
    }
  },
  aws: {
    id: 'aws',
    name: 'AWS Security',
    iconName: 'Cpu',
    shortDescription: 'IAM least privilege anti-wildcards, GuardDuty, Security Group lockdown, and SCPs',
    primaryStandard: 'CIS AWS Benchmark / Well-Architected',
    count: getDomainCount('aws'),
    colorScheme: {
      badge: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
      border: 'border-orange-500/20',
      text: 'text-orange-400',
      bgSubtle: 'bg-orange-500/5'
    }
  },
  containers: {
    id: 'containers',
    name: 'Containers',
    iconName: 'Box',
    shortDescription: 'Non-root execution, cap-drop=ALL, read-only root filesystems, and seccomp profiles',
    primaryStandard: 'CIS Docker Benchmark / NIST SP 800-190',
    count: getDomainCount('containers'),
    colorScheme: {
      badge: 'bg-teal-500/10 text-teal-400 border-teal-500/20',
      border: 'border-teal-500/20',
      text: 'text-teal-400',
      bgSubtle: 'bg-teal-500/5'
    }
  },
  k8s: {
    id: 'k8s',
    name: 'Kubernetes',
    iconName: 'Boxes',
    shortDescription: 'Cluster-admin bans, default-deny NetworkPolicies, Pod Security Standards, and KMS',
    primaryStandard: 'CIS Kubernetes Benchmark / PSS',
    count: getDomainCount('k8s'),
    colorScheme: {
      badge: 'bg-blue-600/10 text-blue-400 border-blue-600/20',
      border: 'border-blue-600/20',
      text: 'text-blue-400',
      bgSubtle: 'bg-blue-600/5'
    }
  },
  coding: {
    id: 'coding',
    name: 'Secure Coding',
    iconName: 'Code',
    shortDescription: 'Parameterized SQL, path canonicalization, deserialization bans, and ReDoS defense',
    primaryStandard: 'SEI CERT / CWE Top 25',
    count: getDomainCount('coding'),
    colorScheme: {
      badge: 'bg-green-500/10 text-green-400 border-green-500/20',
      border: 'border-green-500/20',
      text: 'text-green-400',
      bgSubtle: 'bg-green-500/5'
    }
  },
  ai: {
    id: 'ai',
    name: 'AI & LLM Security',
    iconName: 'Sparkles',
    shortDescription: 'Prompt injection delimiters, tool call authorization, RAG filtering, and token bounds',
    primaryStandard: 'OWASP Top 10 for LLMs / NIST AI RMF',
    count: getDomainCount('ai'),
    colorScheme: {
      badge: 'bg-fuchsia-500/10 text-fuchsia-400 border-fuchsia-500/20',
      border: 'border-fuchsia-500/20',
      text: 'text-fuchsia-400',
      bgSubtle: 'bg-fuchsia-500/5'
    }
  },
  smartcontracts: {
    id: 'smartcontracts',
    name: 'Smart Contract Security',
    iconName: 'Layers',
    shortDescription: 'Checks-Effects-Interactions, nonReentrant mutex, TWAP oracles, and EIP-712 replay defense',
    primaryStandard: 'SWC Registry / ConsenSys Best Practices',
    count: getDomainCount('smartcontracts'),
    colorScheme: {
      badge: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
      border: 'border-yellow-500/20',
      text: 'text-yellow-400',
      bgSubtle: 'bg-yellow-500/5'
    }
  },
  threatmodeling: {
    id: 'threatmodeling',
    name: 'Threat Modeling',
    iconName: 'Target',
    shortDescription: 'STRIDE, DREAD, PASTA, LINDDUN, trust boundary traversal, and attack tree minimal cut sets',
    primaryStandard: 'NIST SP 800-207 / STRIDE / PASTA',
    count: getDomainCount('threatmodeling'),
    colorScheme: {
      badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      border: 'border-emerald-500/20',
      text: 'text-emerald-400',
      bgSubtle: 'bg-emerald-500/5'
    }
  }
};

export const sectionLearningPaths: LearningPath[] = [
  {
    id: 'path-sec-01-http',
    sectionNumber: 1,
    title: 'Section 1: HTTP & Transport Security',
    tagline: 'RFC 9110 Framing, Request Smuggling, Desync & TLS 1.3 Strict Transport',
    description: 'Fundamental transport-layer invariants governing HTTP/1.1 framing, HTTP/2 multiplexing, TLS 1.3 cipher suite negotiation, and request desynchronization prevention.',
    targetRole: 'Network Security Engineers, Application Security Engineers, Edge/Proxy Architects',
    estimatedHours: 12,
    domainIds: ['http'],
    ruleIds: allInvariants.filter(r => r.domain === 'http').map(r => r.id),
    difficulty: 'Beginner',
    category: 'Domain-Curriculum',
    prerequisites: ['Basic TCP/IP fundamentals', 'HTTP request/response lifecycle'],
    keySkills: [
      'RFC 9112 Content-Length vs Transfer-Encoding Priority',
      'HTTP/2 Pseudo-Header Validation',
      'HSTS Preload & Strict-Transport-Security Enforcement',
      'TLS 1.3 Perfect Forward Secrecy & 0-RTT Anti-Replay'
    ],
    milestones: [
      { title: 'HTTP/1.1 Framing & Desync Defense', focus: 'CL.TE, TE.CL parsing & smuggling mitigation', rulesCount: 12 },
      { title: 'Transport Layer Security (TLS 1.3)', focus: 'Forward secrecy, cipher negotiation & ALPN', rulesCount: 12 },
      { title: 'HTTP/2 & Production Gateway Hardening', focus: 'Stream multiplexing, pseudo-headers & header compression', rulesCount: 12 }
    ],
    recommendedPace: '1–2 weeks (1 hr/day)',
    whyChooseThis: 'The foundational substrate of all web and API security; every web request begins here.',
    targetOutcome: 'Eliminate HTTP desynchronization and transport downgrades across reverse proxies and load balancers.'
  },
  {
    id: 'path-sec-02-web',
    sectionNumber: 2,
    title: 'Section 2: Web Security & Sandboxing',
    tagline: 'W3C CSP Level 3, Same-Origin Policy, PostMessage & Secure Cookie Architecture',
    description: 'Comprehensive browser boundary defenses. Master strict Content Security Policy nonces, CORS preflight validation, postMessage origin pinning, and partitioned cookie state.',
    targetRole: 'Frontend Security Engineers, Full-Stack Developers, Web AppSec Specialists',
    estimatedHours: 14,
    domainIds: ['web'],
    ruleIds: allInvariants.filter(r => r.domain === 'web').map(r => r.id),
    difficulty: 'Beginner',
    category: 'Domain-Curriculum',
    prerequisites: ['Section 1 or equivalent HTTP fundamentals', 'DOM and JavaScript familiarity'],
    keySkills: [
      'Content Security Policy Level 3 Strict Nonces',
      'Same-Origin Policy (SOP) & CORS Preflight Allowlisting',
      'PostMessage Origin Pinning & Trusted Types',
      'SameSite=Strict, Secure & Partitioned Cookie Sandboxing'
    ],
    milestones: [
      { title: 'Same-Origin Policy & CORS Defense', focus: 'Origin allowlists, credentials flag & preflight checks', rulesCount: 14 },
      { title: 'CSP3 & DOM Script Execution Control', focus: 'Strict hashes, nonces, frame-ancestors & Trusted Types', rulesCount: 14 },
      { title: 'State Isolation & Cookie Sandboxing', focus: 'SameSite=Strict, __Host- prefix & CHIPS partitioning', rulesCount: 12 }
    ],
    recommendedPace: '2 weeks (1 hr/day)',
    whyChooseThis: 'Neutralizes client-side XSS, CSRF, clickjacking, and cross-window origin leakage.',
    targetOutcome: 'Construct zero-trust browser execution environments with mathematically bounded script execution.'
  },
  {
    id: 'path-sec-03-api',
    sectionNumber: 3,
    title: 'Section 3: API & GraphQL Security',
    tagline: 'Broken Object-Level Auth (BOLA), Rate Limiting, OpenAPI & GraphQL AST Constraints',
    description: 'Invariants protecting REST, gRPC, and GraphQL APIs against unauthorized access, unbounded batching, resource exhaustion, and mass parameter assignment.',
    targetRole: 'Backend Security Engineers, API Platform Architects, Microservice Developers',
    estimatedHours: 14,
    domainIds: ['api'],
    ruleIds: allInvariants.filter(r => r.domain === 'api').map(r => r.id),
    difficulty: 'Intermediate',
    category: 'Domain-Curriculum',
    prerequisites: ['Basic REST/JSON APIs and database modeling'],
    keySkills: [
      'Cryptographic BOLA / IDOR Verification',
      'Distributed Token Bucket Rate Limiting',
      'GraphQL AST Depth, Breadth & Cost Limiting',
      'OpenAPI Schema Strict Parsing & Mass Assignment Guards'
    ],
    milestones: [
      { title: 'Object-Level Access & IDOR Elimination', focus: 'Cryptographic binding & tenant context validation', rulesCount: 12 },
      { title: 'Rate Limiting & Concurrency Control', focus: 'Distributed token buckets & endpoint quotas', rulesCount: 12 },
      { title: 'GraphQL AST & Schema Invariants', focus: 'Query depth caps, cyclic AST prevention & pagination bounds', rulesCount: 12 }
    ],
    recommendedPace: '2 weeks (1 hr/day)',
    whyChooseThis: 'BOLA and API resource exhaustion are the #1 vulnerability class in cloud-native microservices.',
    targetOutcome: 'Bulletproof microservice API gateways against unauthorized data extraction and volumetric exhaustion.'
  },
  {
    id: 'path-sec-04-auth',
    sectionNumber: 4,
    title: 'Section 4: Authentication & Credentials',
    tagline: 'NIST SP 800-63B, FIDO2/WebAuthn, Argon2id & Post-Auth Session Lifecycle',
    description: 'Cryptographically sound identity verification. Master memory-hard password hashing, phishing-resistant FIDO2/WebAuthn ceremonies, and post-authentication session regeneration.',
    targetRole: 'Identity Engineers, Security Software Engineers, AppSec Auditors',
    estimatedHours: 15,
    domainIds: ['auth'],
    ruleIds: allInvariants.filter(r => r.domain === 'auth').map(r => r.id),
    difficulty: 'Intermediate',
    category: 'Domain-Curriculum',
    prerequisites: ['Basic cryptographic hash knowledge', 'Web application architecture'],
    keySkills: [
      'Argon2id Memory-Hard Key Derivation',
      'FIDO2 / WebAuthn Origin Verification & Attestation',
      'Post-Authentication Session Regeneration & Invalidation',
      'Phishing-Resistant MFA & Passkey Invariants'
    ],
    milestones: [
      { title: 'Password Hashing & Secret Derivation', focus: 'Argon2id parameters, salt uniqueness & pepper separation', rulesCount: 13 },
      { title: 'FIDO2 / WebAuthn Hardware Authentication', focus: 'Cryptographic challenges, origin match & passkeys', rulesCount: 13 },
      { title: 'Session Lifecycle & Token Invalidation', focus: 'Session fixation defense, timeouts & global logout', rulesCount: 12 }
    ],
    recommendedPace: '2 weeks (1 hr/day)',
    whyChooseThis: 'Authentication is the perimeter of user trust; subtle session and credential bugs lead directly to account takeover.',
    targetOutcome: 'Implement NIST 800-63B compliant authentication resistant to credential stuffing, replay, and phishing.'
  },
  {
    id: 'path-sec-05-authz',
    sectionNumber: 5,
    title: 'Section 5: Authorization & Multi-Tenancy',
    tagline: 'NIST SP 800-162, Google Zanzibar ReBAC, Tenant Isolation & Fail-Closed Defaults',
    description: 'Provably correct authorization models. Learn how to architect Google Zanzibar-style relationship graphs (ReBAC), row-level multi-tenant partitioning, and attribute-based access control (ABAC).',
    targetRole: 'Staff Security Engineers, Principal Identity Architects, Platform Leads',
    estimatedHours: 15,
    domainIds: ['authz'],
    ruleIds: allInvariants.filter(r => r.domain === 'authz').map(r => r.id),
    difficulty: 'Intermediate',
    category: 'Domain-Curriculum',
    prerequisites: ['Section 4 Authentication or identity fundamentals'],
    keySkills: [
      'Zanzibar ReBAC Relationship Graph Evaluation',
      'Multi-Tenant Tenant-ID Parameterization & Row-Level Security',
      'NIST SP 800-162 ABAC Decision Enforcement',
      'Fail-Closed Default-Deny Authorization Gates'
    ],
    milestones: [
      { title: 'Multi-Tenant Data Partitioning', focus: 'Row-level security, tenant context injection & schema isolation', rulesCount: 12 },
      { title: 'Relationship-Based Access Control (ReBAC)', focus: 'Google Zanzibar tuple evaluation & transitive permissions', rulesCount: 12 },
      { title: 'ABAC & Centralized Policy Decision Points', focus: 'Open Policy Agent (OPA), fail-closed defaults & audit trails', rulesCount: 12 }
    ],
    recommendedPace: '2 weeks',
    whyChooseThis: 'Master the high-concurrency authorization patterns used by Google, Netflix, and Airbnb.',
    targetOutcome: 'Guarantee absolute multi-tenant tenant isolation with zero horizontal privilege escalations.'
  },
  {
    id: 'path-sec-06-oauth',
    sectionNumber: 6,
    title: 'Section 6: OAuth 2.0 & OIDC Flows',
    tagline: 'RFC 6749, RFC 7636 PKCE, RFC 8725 BCP, DPoP Sender-Constrained Tokens',
    description: 'Protocol-level rigor for delegated access and federated identity. Enforce Proof Key for Code Exchange (PKCE), state entropy, DPoP token binding, and OpenID Connect claim validation.',
    targetRole: 'Federation Architects, OAuth Specialists, API Security Engineers',
    estimatedHours: 15,
    domainIds: ['oauth'],
    ruleIds: allInvariants.filter(r => r.domain === 'oauth').map(r => r.id),
    difficulty: 'Advanced',
    category: 'Domain-Curriculum',
    prerequisites: ['Section 1 HTTP', 'Section 4 Authentication'],
    keySkills: [
      'RFC 7636 PKCE S256 Code Challenge Verification',
      'RFC 8725 Security Best Current Practice (BCP) Compliance',
      'RFC 9449 DPoP Sender-Constrained Proof of Possession',
      'OpenID Connect ID Token Signature & Audience Validation'
    ],
    milestones: [
      { title: 'Authorization Code Flow & PKCE', focus: 'Code challenge validation, state CSRF defense & redirect URI matching', rulesCount: 12 },
      { title: 'Token Issuance & Sender Constraints', focus: 'DPoP proof-of-possession, mTLS token binding & refresh rotation', rulesCount: 12 },
      { title: 'OIDC Federation & Claims Verification', focus: 'Signature checks, nonces, discovery endpoints & token introspection', rulesCount: 11 }
    ],
    recommendedPace: '2 weeks',
    whyChooseThis: 'OAuth and OIDC are notoriously misconfigured, resulting in token interception and silent account takeover.',
    targetOutcome: 'Architect airtight OAuth 2.0 and OIDC identity providers and clients conforming to RFC 8725.'
  },
  {
    id: 'path-sec-07-crypto',
    sectionNumber: 7,
    title: 'Section 7: Modern Cryptography',
    tagline: 'NIST SP 800-57, FIPS 140-3, AEAD Nonce Rigor, Constant-Time Primitives & Post-Quantum',
    description: 'Implementation cryptography free of theoretical and practical traps. Master AES-GCM nonce uniqueness, constant-time memory comparisons, HKDF key derivation, and NIST post-quantum (ML-KEM) migration.',
    targetRole: 'Cryptography Engineers, Systems Security Specialists, Security Architects',
    estimatedHours: 16,
    domainIds: ['crypto'],
    ruleIds: allInvariants.filter(r => r.domain === 'crypto').map(r => r.id),
    difficulty: 'Advanced',
    category: 'Domain-Curriculum',
    prerequisites: ['Basic number theory / discrete math intuition', 'Binary data manipulation'],
    keySkills: [
      'AES-256-GCM 96-Bit Nonce Uniqueness Invariants',
      'Constant-Time Timing-Attack Resistant Memory Comparisons',
      'RFC 5869 HKDF Extract-and-Expand Key Derivation',
      'FIPS 203 Post-Quantum ML-KEM Algorithm Readiness'
    ],
    milestones: [
      { title: 'AEAD Symmetric Ciphers & Nonce Rigor', focus: 'AES-GCM, ChaCha20-Poly1305 & authentication tags', rulesCount: 13 },
      { title: 'Constant-Time Math & Side-Channel Mitigation', focus: 'Cache-timing defenses & memory comparison primitives', rulesCount: 13 },
      { title: 'Asymmetric Cryptography & Post-Quantum ML-KEM', focus: 'Ed25519, HKDF hierarchies & post-quantum transitions', rulesCount: 12 }
    ],
    recommendedPace: '2–3 weeks',
    whyChooseThis: 'Cryptography is unforgiving: one single nonce reuse or non-constant-time branch destroys complete confidentiality.',
    targetOutcome: 'Implement secure cryptographic protocols with zero nonce reuse, timing side-channels, or key leakage.'
  },
  {
    id: 'path-sec-08-cloud',
    sectionNumber: 8,
    title: 'Section 8: Cloud Architecture & VPC',
    tagline: 'IMDSv2 Session Tokens, VPC Micro-Segmentation, Cloud KMS Envelope & Egress Filtering',
    description: 'Cloud infrastructure security across multi-cloud topologies. Enforce IMDSv2 token hops to defeat SSRF, automated VPC flow log auditing, and zero-trust perimeter network segmentation.',
    targetRole: 'Cloud Security Architects, Platform Engineers, Infrastructure Leads',
    estimatedHours: 14,
    domainIds: ['cloud'],
    ruleIds: allInvariants.filter(r => r.domain === 'cloud').map(r => r.id),
    difficulty: 'Intermediate',
    category: 'Domain-Curriculum',
    prerequisites: ['Networking fundamentals (CIDR, subnets, gateways)', 'Cloud compute basics'],
    keySkills: [
      'IMDSv2 Hop Limit = 1 SSRF Defense',
      'Zero-Trust VPC Micro-Segmentation & Flow Logging',
      'Cloud KMS Hardware Envelope Encryption',
      'Egress NAT Firewall Filtering & Private Endpoints'
    ],
    milestones: [
      { title: 'Instance Metadata & SSRF Containment', focus: 'IMDSv2 session tokens, PUT headers & hop limits', rulesCount: 12 },
      { title: 'VPC Micro-Segmentation & Flow Monitoring', focus: 'Private subnets, security groups & zero-trust boundaries', rulesCount: 12 },
      { title: 'KMS Key Management & Egress Control', focus: 'Envelope encryption, key rotation & egress filtering', rulesCount: 11 }
    ],
    recommendedPace: '2 weeks',
    whyChooseThis: 'Cloud infrastructure breaches stem overwhelmingly from misconfigured metadata and permissive network boundaries.',
    targetOutcome: 'Harden cloud virtual networks and compute instances to survive full perimeter SSRF attempts.'
  },
  {
    id: 'path-sec-09-aws',
    sectionNumber: 9,
    title: 'Section 9: AWS Identity & Infrastructure',
    tagline: 'AWS IAM Evaluation Logic, S3 Bucket Policies, KMS Key Policies & Organization SCPs',
    description: 'Master the formal mathematical evaluation order of AWS IAM policies: Explicit Deny precedence, Service Control Policies (SCPs), Permission Boundaries, and cross-account Confused Deputy defense.',
    targetRole: 'AWS Security Engineers, Cloud Engineers, DevSecOps Architects',
    estimatedHours: 15,
    domainIds: ['aws'],
    ruleIds: allInvariants.filter(r => r.domain === 'aws').map(r => r.id),
    difficulty: 'Advanced',
    category: 'Domain-Curriculum',
    prerequisites: ['Section 8 Cloud Architecture or active AWS experience'],
    keySkills: [
      'AWS IAM Explicit Deny Precedence Evaluation',
      'Cross-Account sts:AssumeRole ExternalId Protection',
      'S3 Block Public Access & KMS Server-Side Encryption',
      'AWS Organizations Multi-Account SCP Guardrails'
    ],
    milestones: [
      { title: 'IAM Policy Evaluation & SCP Guardrails', focus: 'Explicit deny, organization SCPs & boundary enforcement', rulesCount: 12 },
      { title: 'S3 Data Lake & Storage Hardening', focus: 'Block public access, bucket policies & KMS customer keys', rulesCount: 12 },
      { title: 'Cross-Account Delegation & Role Chains', focus: 'Confused deputy prevention, session policies & temporary tokens', rulesCount: 12 }
    ],
    recommendedPace: '2 weeks',
    whyChooseThis: 'AWS IAM is the definitive control plane of the cloud; mastering its evaluation model is essential for senior cloud roles.',
    targetOutcome: 'Design production AWS IAM architectures immune to privilege escalation and unauthorized cross-account pivoting.'
  },
  {
    id: 'path-sec-10-containers',
    sectionNumber: 10,
    title: 'Section 10: Container Runtime & Isolation',
    tagline: 'OCI Runtime Spec, Linux Namespaces, Cgroups v2, Seccomp-BPF & Rootless Execution',
    description: 'Deep Linux kernel container containment across 140 formal rules. Master user namespaces, cgroups v2 memory/PID bounds, seccomp system call filters, read-only root filesystems, and capability drops.',
    targetRole: 'Container Security Engineers, DevSecOps Leads, Systems Engineers, Cloud Security Leads',
    estimatedHours: 35,
    domainIds: ['containers'],
    ruleIds: allInvariants.filter(r => r.domain === 'containers').map(r => r.id),
    difficulty: 'Advanced',
    category: 'Domain-Curriculum',
    prerequisites: ['Linux operating system concepts (processes, kernel, syscalls)'],
    keySkills: [
      'Linux User, PID & Mount Namespace Separation',
      'Cgroups v2 Memory Limits & PID Exhaustion Clamps',
      'Seccomp-BPF Dangerous Syscall Filtering',
      'CAP_SYS_ADMIN Drop & Read-Only Root Filesystem Enforcements'
    ],
    milestones: [
      { title: 'Linux Namespaces & Process Isolation', focus: 'User, PID, mount namespaces & rootless containers', rulesCount: 47 },
      { title: 'Cgroups v2 & System Call Filtering', focus: 'Memory limits, CPU throttling & Seccomp-BPF filters', rulesCount: 47 },
      { title: 'Image Provenance & Production Hardening', focus: 'Read-only rootfs, drop ALL capabilities & Cosign signatures', rulesCount: 46 }
    ],
    recommendedPace: '4 weeks (1 hr/day)',
    whyChooseThis: 'The largest, most comprehensive container security curriculum available anywhere (140 verified invariants).',
    targetOutcome: 'Harden container runtimes so that even an unauthenticated remote code execution exploit cannot break into the host.'
  },
  {
    id: 'path-sec-11-k8s',
    sectionNumber: 11,
    title: 'Section 11: Kubernetes Orchestration',
    tagline: 'CIS Kubernetes Benchmark, Pod Security Standards (PSS), K8s RBAC & NetworkPolicies',
    description: 'Cluster-wide Kubernetes protection. Master the Pod Security Standard Restricted profile, default-deny NetworkPolicies, RBAC cluster role bounding, and API server control plane audit logging.',
    targetRole: 'Kubernetes Administrators, DevSecOps Engineers, Platform Security Architects',
    estimatedHours: 15,
    domainIds: ['k8s'],
    ruleIds: allInvariants.filter(r => r.domain === 'k8s').map(r => r.id),
    difficulty: 'Advanced',
    category: 'Domain-Curriculum',
    prerequisites: ['Section 10 Container Security or Kubernetes operator experience'],
    keySkills: [
      'Pod Security Standards (PSS) Restricted Profile',
      'Default-Deny Kubernetes Ingress & Egress NetworkPolicies',
      'Kubernetes RBAC ServiceAccount Privilege Minimization',
      'API Server Admission Webhooks & Audit Logging'
    ],
    milestones: [
      { title: 'Pod Security Standards & Workload Hardening', focus: 'PSS restricted profile, hostPath prevention & runAsNonRoot', rulesCount: 12 },
      { title: 'Kubernetes RBAC & Service Accounts', focus: 'ClusterRole binding elimination & automountServiceAccountToken=false', rulesCount: 12 },
      { title: 'Cluster Networking & Control Plane Defense', focus: 'Default-deny NetworkPolicies, mTLS service mesh & API server auditing', rulesCount: 12 }
    ],
    recommendedPace: '2 weeks',
    whyChooseThis: 'Kubernetes clusters without strict NetworkPolicies and PSS are vulnerable to single-pod lateral cluster takeover.',
    targetOutcome: 'Enforce cluster-wide admission controls and micro-segmentation that contain any compromised pod.'
  },
  {
    id: 'path-sec-12-coding',
    sectionNumber: 12,
    title: 'Section 12: Secure Coding & Code Review',
    tagline: 'OWASP Top 10, CWE Top 25, AST Taint Tracking, Deserialization & Memory Safety',
    description: '143 rigorous invariants for secure software development and code review. Eliminate SQLi, command injection, path traversal, prototype pollution, deserialization, and concurrency race conditions.',
    targetRole: 'Senior Software Engineers, Application Security Reviewers, Security Champions',
    estimatedHours: 35,
    domainIds: ['coding'],
    ruleIds: allInvariants.filter(r => r.domain === 'coding').map(r => r.id),
    difficulty: 'Intermediate',
    category: 'Domain-Curriculum',
    prerequisites: ['Programming proficiency in languages such as Python, Go, Java, C++, or TypeScript'],
    keySkills: [
      'Parameterized Database & Command Execution Axioms',
      'Safe Path Canonicalization & Traversal Prevention',
      'AST Taint Tracking & Automated SAST Policy Authoring',
      'Safe Serialization, Memory Bounds & ReDoS Elimination'
    ],
    milestones: [
      { title: 'Input Sanitization & Injection Defense', focus: 'SQLi, command injection, LDAP & XPath parameterization', rulesCount: 48 },
      { title: 'Memory Safety, Deserialization & ReDoS', focus: 'Path canonicalization, safe parsers & polynomial regex bounds', rulesCount: 48 },
      { title: 'Concurrency, Race Conditions & Cryptographic Validation', focus: 'TOCTOU elimination, prototype pollution & timing safety', rulesCount: 47 }
    ],
    recommendedPace: '4 weeks (1 hr/day)',
    whyChooseThis: 'The definitive handbook for staff-level secure code reviews—spot critical vulnerabilities at pull request time.',
    targetOutcome: 'Conduct high-velocity, high-precision code reviews with zero false-negatives on high-severity CWE categories.'
  },
  {
    id: 'path-sec-13-ai',
    sectionNumber: 13,
    title: 'Section 13: AI & Large Language Model Safety',
    tagline: 'OWASP LLM Top 10, NIST AI RMF, Prompt Injection Quarantine & Agentic Tool Bounds',
    description: '141 cutting-edge invariants for generative AI and autonomous agent systems. Learn dual-LLM supervisor containment, indirect prompt injection quarantines, RAG context taint tracking, and tool authorization envelopes.',
    targetRole: 'AI Security Engineers, LLM Platform Architects, Generative AI Developers',
    estimatedHours: 35,
    domainIds: ['ai'],
    ruleIds: allInvariants.filter(r => r.domain === 'ai').map(r => r.id),
    difficulty: 'Advanced',
    category: 'Domain-Curriculum',
    prerequisites: ['Basic LLM API experience (prompts, completions, tool calling)', 'Application Security fundamentals'],
    keySkills: [
      'Dual-LLM Supervisor Validation Pipelines',
      'Indirect Prompt Injection XML/JSON Envelope Quarantine',
      'Autonomous Agent Tool Authorization & Schema Bounding',
      'RAG Vector Context Provenance & Taint Tracking'
    ],
    milestones: [
      { title: 'LLM Boundary & Delimiter Invariants', focus: 'Prompt injection defense, XML delimiters & parser quarantine', rulesCount: 47 },
      { title: 'Agentic Tools & Autonomous Guardrails', focus: 'Tool call authorization, rate bounds & human-in-the-loop gates', rulesCount: 47 },
      { title: 'RAG Retrieval Protection & Model Integrity', focus: 'Document provenance, context taint tracking & embedding sanitization', rulesCount: 47 }
    ],
    recommendedPace: '4 weeks (1 hr/day)',
    whyChooseThis: 'The most requested specialization in modern security—architecting safe autonomous LLM systems for enterprise production.',
    targetOutcome: 'Deploy generative AI agents with provable mathematical containment against prompt injection and tool hijacking.'
  },
  {
    id: 'path-sec-14-smartcontracts',
    sectionNumber: 14,
    title: 'Section 14: Smart Contracts & Web3',
    tagline: 'SWC Registry, EVM Execution Semantics, Checks-Effects-Interactions & TWAP Oracles',
    description: '141 invariants for EVM smart contracts where bugs mean permanent loss of funds. Enforce Checks-Effects-Interactions (CEI), reentrancy mutexes, TWAP price oracles, and EIP-712 typed signature verification.',
    targetRole: 'Smart Contract Auditors, Web3 Security Engineers, DeFi Protocol Architects',
    estimatedHours: 35,
    domainIds: ['smartcontracts'],
    ruleIds: allInvariants.filter(r => r.domain === 'smartcontracts').map(r => r.id),
    difficulty: 'Expert',
    category: 'Domain-Curriculum',
    prerequisites: ['Solidity / EVM bytecode semantics', 'Applied cryptography fundamentals'],
    keySkills: [
      'Checks-Effects-Interactions (CEI) State Precedence',
      'TWAP Time-Weighted Oracle Flash Loan Defense',
      'EIP-712 Typed Data Domain Separators & Nonce Invalidation',
      'ERC-4626 Token Vault Inflation Attack Mitigation'
    ],
    milestones: [
      { title: 'EVM Execution & Reentrancy Defenses', focus: 'State mutation precedence, mutex locks & delegatecall bounds', rulesCount: 47 },
      { title: 'DeFi Economic Protocol Invariants', focus: 'TWAP oracles, slippage bounds, vaults & flash loan defense', rulesCount: 47 },
      { title: 'Cryptographic Signatures & Protocol Accounting', focus: 'EIP-712 domain separators, ECDSA normalization & rounding precision', rulesCount: 47 }
    ],
    recommendedPace: '4 weeks (1 hr/day)',
    whyChooseThis: 'Smart contract security commands elite industry compensation and demands the highest degree of formal verification.',
    targetOutcome: 'Audit complex multi-contract DeFi protocols and eliminate reentrancy, price manipulation, and accounting traps.'
  },
  {
    id: 'path-sec-15-threatmodeling',
    sectionNumber: 15,
    title: 'Section 15: Threat Modeling & Architecture',
    tagline: 'STRIDE, PASTA, Attack Trees, Trust Boundary Crossings & Quantitative Residual Risk',
    description: '105 architectural invariants for proactive threat modeling. Map trust boundaries, compute attack tree minimal cut sets, apply PASTA risk metrics, and eliminate systemic failure modes before code is deployed.',
    targetRole: 'Staff / Principal Security Architects, Systems Security Designers, CISOs',
    estimatedHours: 25,
    domainIds: ['threatmodeling'],
    ruleIds: allInvariants.filter(r => r.domain === 'threatmodeling').map(r => r.id),
    difficulty: 'Advanced',
    category: 'Domain-Curriculum',
    prerequisites: ['Broad software engineering and security architecture experience'],
    keySkills: [
      'STRIDE Trust Boundary Crossing Decomposition',
      'Attack Tree Minimal Cut Set Computation',
      'PASTA Risk-Centric Threat Modeling Scoring',
      'Systemic Fail-Closed Architectural Defaults'
    ],
    milestones: [
      { title: 'STRIDE & Trust Boundary Decomposition', focus: 'Process, data store, external entity & data flow mapping', rulesCount: 35 },
      { title: 'Quantitative Threat Modeling (PASTA / DREAD)', focus: 'Impact scoring, attack tree cut sets & blast radius', rulesCount: 35 },
      { title: 'Architectural Enforcement Controls', focus: 'Fail-closed defaults, isolation boundaries & auditability', rulesCount: 35 }
    ],
    recommendedPace: '3 weeks',
    whyChooseThis: 'The pinnacle capability of Staff and Principal Security Engineers—preventing vulnerabilities at design time.',
    targetOutcome: 'Lead enterprise-wide threat modeling sessions that uncover architectural flaws and establish resilient security baselines.'
  }
];

export const curatedLearningPaths: LearningPath[] = [
  {
    id: 'path-tier1-foundations',
    title: 'Tier 1: Web Protocols & Browser Sandboxing',
    tagline: 'Master HTTP/1.1 to HTTP/3, TLS 1.3, CSP3, and Browser Isolation',
    description: 'The essential bedrock of application security. Learn RFC 9110/9112 framing rules, strict SameSite cookies, Cross-Origin isolation, and script execution controls.',
    targetRole: 'Software Engineers, Associate AppSec, Junior PenTesters',
    estimatedHours: 14,
    domainIds: ['http', 'web'],
    ruleIds: allInvariants.filter(r => ['http', 'web'].includes(r.domain)).slice(0, 36).map(r => r.id),
    difficulty: 'Beginner',
    category: 'Foundational-Tier',
    prerequisites: ['Basic HTTP request/response flow', 'JavaScript & HTML understanding'],
    keySkills: ['Request Smuggling Defense', 'CSP Level 3 Nonce Configuration', 'CORS Origin Sandboxing', 'HSTS & TLS 1.3 Suites'],
    milestones: [
      { title: 'HTTP Protocol Framing', focus: 'CL.TE, TE.CL & chunked parsing', rulesCount: 36 },
      { title: 'Browser Defense-in-Depth', focus: 'CSP, CORS, Cookies & SRI', rulesCount: 40 }
    ],
    recommendedPace: '2 weeks (1 hr/day)',
    whyChooseThis: 'Mandatory entry point for all software engineers and application security candidates.',
    targetOutcome: 'Eliminate 95% of common web attack surfaces (XSS, CSRF, framing bugs, and transport degradation).'
  },
  {
    id: 'path-tier2-identity-access',
    title: 'Tier 2: Identity, Modern Auth & Fine-Grained Access Control',
    tagline: 'Zero-Trust Authentication, OAuth 2.0 PKCE, and Zanzibar ReBAC',
    description: 'Architect airtight identity boundaries. Covers NIST SP 800-63B credential storage, Argon2id, session lifecycle, OAuth 2.0 BCP (RFC 8725), OpenID Connect Core, and multi-tenant ReBAC.',
    targetRole: 'Identity Architects, Backend Security Engineers, API Developers',
    estimatedHours: 20,
    domainIds: ['auth', 'authz', 'oauth'],
    ruleIds: allInvariants.filter(r => ['auth', 'authz', 'oauth'].includes(r.domain)).slice(0, 36).map(r => r.id),
    difficulty: 'Intermediate',
    category: 'Foundational-Tier',
    prerequisites: ['Tier 1 Foundations or equivalent HTTP knowledge', 'Basic cryptographic hash intuition'],
    keySkills: ['PKCE & State Validation', 'Zanzibar ReBAC Modeling', 'Argon2id Memory Hardening', 'Multi-Tenant BOLA/IDOR Elimination'],
    milestones: [
      { title: 'Credential & Session Security', focus: 'NIST 800-63B & WebAuthn', rulesCount: 38 },
      { title: 'Fine-Grained Authorization', focus: 'RBAC, ABAC & Tenant isolation', rulesCount: 36 },
      { title: 'OAuth 2.0 & OIDC Federation', focus: 'PKCE, JWT validation & token binding', rulesCount: 35 }
    ],
    recommendedPace: '3 weeks (1 hr/day)',
    whyChooseThis: 'Identity and access control flaws (BOLA, Broken Auth) remain the #1 API and web attack vector worldwide.',
    targetOutcome: 'Design enterprise-grade single sign-on, API delegation, and multi-tenant authorization kernels.'
  },
  {
    id: 'path-tier3-cloud-containers',
    title: 'Tier 3: Cloud Architecture, Linux Containers & Kubernetes',
    tagline: 'Zero-Trust Infrastructure, Linux Namespaces, Seccomp & K8s Admission Control',
    description: 'Deep dive into infrastructure invariants from cloud metadata services (IMDSv2) and AWS IAM least-privilege evaluation to OCI container runtimes, non-root user enforcement, and Kubernetes Pod Security Standards.',
    targetRole: 'DevSecOps Engineers, Cloud Security Architects, Platform Leads',
    estimatedHours: 28,
    domainIds: ['cloud', 'aws', 'containers', 'k8s'],
    ruleIds: allInvariants.filter(r => ['cloud', 'aws', 'containers', 'k8s'].includes(r.domain)).slice(0, 40).map(r => r.id),
    difficulty: 'Intermediate',
    category: 'Foundational-Tier',
    prerequisites: ['Linux CLI fluency', 'Basic Docker/Container commands', 'Cloud VPC basics'],
    keySkills: ['Linux Namespaces & cgroups v2', 'IMDSv2 Hop-Limit Enforcement', 'Seccomp & AppArmor Profiles', 'Kubernetes NetworkPolicies & Admission Control'],
    milestones: [
      { title: 'Cloud & AWS IAM Hardening', focus: 'VPC segmentation, SCPs & KMS', rulesCount: 71 },
      { title: 'Container Isolation Invariants', focus: 'Capabilities, rootless & read-only fs', rulesCount: 140 },
      { title: 'Kubernetes Cluster Orchestration', focus: 'Admission webhooks, RBAC & PSS', rulesCount: 36 }
    ],
    recommendedPace: '4 weeks (1-1.5 hrs/day)',
    whyChooseThis: 'Essential for modern microservice architectures, cloud-native deployments, and containerized backends.',
    targetOutcome: 'Prevent container escapes, lateral cloud movement, SSRF-to-IAM pivots, and cluster privilege escalation.'
  },
  {
    id: 'path-tier4-secure-coding',
    title: 'Tier 4: Enterprise Secure Code Review & Static Analysis',
    tagline: 'Taint Analysis, Safe Deserialization, Memory Safety & ReDoS Neutralization',
    description: 'Master the code-level invariants that eliminate vulnerabilities at source. Rigorous AST checks for SQL injection, command injection, path canonicalization, unsafe deserialization, prototype pollution, and regular expression complexity.',
    targetRole: 'Senior Software Engineers, Code Review Leads, AppSec Reviewers',
    estimatedHours: 22,
    domainIds: ['coding', 'api'],
    ruleIds: allInvariants.filter(r => ['coding', 'api'].includes(r.domain)).slice(0, 40).map(r => r.id),
    difficulty: 'Intermediate',
    category: 'Foundational-Tier',
    prerequisites: ['Familiarity with multiple programming languages (Python, Go, Java, or TypeScript)', 'Data structures'],
    keySkills: ['Parameterized SQL Invariants', 'Safe Path Canonicalization', 'AST Deserialization Validation', 'ReDoS Polynomial Bounds'],
    milestones: [
      { title: 'Input Sanitization & Injection Defense', focus: 'SQLi, CMDi, Path Traversal', rulesCount: 70 },
      { title: 'Advanced Code Review Invariants', focus: 'Memory safety, prototypes, race conditions', rulesCount: 73 },
      { title: 'API Contract & Schema Constraints', focus: 'Mass assignment, pagination, GraphQL depth', rulesCount: 36 }
    ],
    recommendedPace: '3 weeks (1 hr/day)',
    whyChooseThis: 'Empowers you to spot high-severity vulnerabilities during PR reviews before code ever reaches production.',
    targetOutcome: 'Conduct staff-level secure code reviews with zero false-negatives on high-impact bug classes.'
  },
  {
    id: 'path-tier5-applied-crypto',
    title: 'Tier 5: Applied Cryptography & Key Management',
    tagline: 'AEAD Modes, Constant-Time Primitives, Key Hierarchies & Post-Quantum Prep',
    description: 'Theoretical and practical cryptographic engineering. Enforces AES-GCM nonce uniqueness, constant-time equality checks against timing attacks, HKDF key derivation, envelope encryption with KMS, and ML-KEM migration.',
    targetRole: 'Cryptography Engineers, Systems Security Specialists, Security Architects',
    estimatedHours: 20,
    domainIds: ['crypto', 'api'],
    ruleIds: allInvariants.filter(r => ['crypto', 'api'].includes(r.domain)).slice(0, 36).map(r => r.id),
    difficulty: 'Advanced',
    category: 'Specialized',
    prerequisites: ['Tier 1 & Tier 2 completion', 'Discrete math intuition'],
    keySkills: ['AEAD Nonce Invariants', 'Constant-Time Memory Comparisons', 'Envelope Encryption Architecture', 'KMS Key Rotation Automation'],
    milestones: [
      { title: 'Symmetric & Asymmetric Primitives', focus: 'AES-256-GCM, Ed25519, ML-KEM', rulesCount: 20 },
      { title: 'Key Lifecycle & Storage', focus: 'Hardware KMS, envelope encryption & derivation', rulesCount: 18 },
      { title: 'Cryptographic API Invariants', focus: 'mTLS, signed assertions & MAC validation', rulesCount: 36 }
    ],
    recommendedPace: '3 weeks',
    whyChooseThis: 'Cryptography is unforgiving: one subtle nonce reuse or timing leak destroys entire cryptosystems.',
    targetOutcome: 'Architect zero-knowledge and defense-in-depth cryptographic services free from implementation traps.'
  },
  {
    id: 'path-tier6-ai-llm-security',
    title: 'Tier 6: AI & Large Language Model System Safety',
    tagline: 'Prompt Injection Isolation, Autonomous Agent Guardrails & RAG Protection',
    description: 'Master the cutting edge of AI security. Learn mathematical and architectural invariants preventing direct and indirect prompt injection, tool-call privilege escalations, RAG data poisoning, and supervisor pipeline bypasses.',
    targetRole: 'AI Security Engineers, ML Platform Leads, LLM Application Developers',
    estimatedHours: 26,
    domainIds: ['ai', 'coding'],
    ruleIds: allInvariants.filter(r => ['ai', 'coding'].includes(r.domain)).slice(0, 40).map(r => r.id),
    difficulty: 'Advanced',
    category: 'Specialized',
    prerequisites: ['Basic LLM / API understanding', 'Application Security fundamentals'],
    keySkills: ['Dual-LLM Supervisor Validation', 'Indirect Prompt Injection Quarantine', 'Tool Authorization Envelopes', 'RAG Context Taint Isolation'],
    milestones: [
      { title: 'LLM Boundary & Delimiter Invariants', focus: 'Prompt injection & parser quarantine', rulesCount: 70 },
      { title: 'Agentic Tools & Autonomous Guardrails', focus: 'Tool call auth, rate bounds & human-in-the-loop', rulesCount: 71 },
      { title: 'Secure Integration Coding', focus: 'Safe JSON schemas & serialization', rulesCount: 50 }
    ],
    recommendedPace: '3 weeks (1.5 hrs/day)',
    whyChooseThis: 'AI & LLM security is the fastest-growing specialization in the global security industry today.',
    targetOutcome: 'Design enterprise-ready generative AI agents with mathematically verifiable containment boundaries.'
  },
  {
    id: 'path-tier7-web3-smart-contracts',
    title: 'Tier 7: Web3 & Smart Contract Security Audit',
    tagline: 'EVM Execution Semantics, CEI Patterns, Oracle Manipulation & Replay Defense',
    description: 'Immutability means code bugs are permanent financial losses. Master the SWC invariants: Checks-Effects-Interactions, reentrancy guards, TWAP price oracles, EIP-712 typed data signatures, and ERC-4626 vault inflation defense.',
    targetRole: 'Smart Contract Auditors, Protocol Security Engineers, DeFi Architects',
    estimatedHours: 28,
    domainIds: ['smartcontracts', 'crypto'],
    ruleIds: allInvariants.filter(r => ['smartcontracts', 'crypto'].includes(r.domain)).slice(0, 40).map(r => r.id),
    difficulty: 'Advanced',
    category: 'Specialized',
    prerequisites: ['Solidity / EVM concepts', 'Modern Cryptography intuition'],
    keySkills: ['Checks-Effects-Interactions (CEI)', 'TWAP Oracle Time-Weighted Moving Averages', 'EIP-712 Domain Separator Rigor', 'Flash Loan Resistant Settlement'],
    milestones: [
      { title: 'EVM Execution & Reentrancy', focus: 'Mutexes, state ordering & delegatecall', rulesCount: 70 },
      { title: 'DeFi & Economic Protocol Invariants', focus: 'Oracles, slippage, vaults & flash loans', rulesCount: 71 },
      { title: 'Cryptographic Signature Verification', focus: 'ECDSA malleability & EIP-712 replay', rulesCount: 38 }
    ],
    recommendedPace: '4 weeks',
    whyChooseThis: 'Smart contract audits require extreme formal rigor where a single state ordering mistake costs millions.',
    targetOutcome: 'Audit complex multi-contract DeFi protocols and pass top-tier Web3 security auditor benchmarks.'
  },
  {
    id: 'path-tier8-threat-modeling',
    title: 'Tier 8: Threat Modeling & Defensive System Architecture',
    tagline: 'STRIDE, PASTA, Attack Trees, Trust Boundary Crossings & Residual Risk',
    description: 'Elevate from vulnerability detection to architectural prevention. Systematically map trust boundaries, compute attack tree minimal cut sets, apply PASTA risk metrics, and eliminate single points of failure before code is written.',
    targetRole: 'Staff Security Architects, Principal Engineers, Head of Security',
    estimatedHours: 24,
    domainIds: ['threatmodeling', 'cloud', 'authz'],
    ruleIds: allInvariants.filter(r => ['threatmodeling', 'cloud', 'authz'].includes(r.domain)).slice(0, 40).map(r => r.id),
    difficulty: 'Advanced',
    category: 'Specialized',
    prerequisites: ['System design experience', 'Broad AppSec and Cloud knowledge'],
    keySkills: ['Attack Tree Minimal Cut Set Computation', 'STRIDE Threat Enumeration', 'Trust Boundary Invariant Enforcement', 'PASTA Risk-Centric Threat Modeling'],
    milestones: [
      { title: 'STRIDE & Trust Boundary Decomposition', focus: 'Process, data store & flow analysis', rulesCount: 50 },
      { title: 'Quantitative Threat Modeling (PASTA/DREAD)', focus: 'Impact scoring, cut sets & blast radius', rulesCount: 55 },
      { title: 'Architectural Enforcement Controls', focus: 'Fail-closed defaults & isolation boundaries', rulesCount: 71 }
    ],
    recommendedPace: '3 weeks',
    whyChooseThis: 'The defining skill of Staff and Principal Security Engineers—influencing architectural decisions at design time.',
    targetOutcome: 'Lead organization-wide threat modeling sessions that systematically uncover architectural flaws.'
  },
  {
    id: 'path-role-staff-appsec',
    title: 'Career Path: Staff Application Security Engineer',
    tagline: 'Comprehensive AppSec Mastery: Web, APIs, Auth, Code Review & Threat Modeling',
    description: 'The definitive curriculum for Staff AppSec leadership. Combines protocol mechanics, modern identity, secure coding, and threat modeling into an integrated defensive engineering program.',
    targetRole: 'Senior / Staff AppSec Engineers, Product Security Leads',
    estimatedHours: 45,
    domainIds: ['http', 'web', 'api', 'auth', 'authz', 'coding', 'threatmodeling'],
    ruleIds: allInvariants.filter(r => ['http', 'web', 'api', 'auth', 'authz', 'coding', 'threatmodeling'].includes(r.domain)).slice(0, 50).map(r => r.id),
    difficulty: 'Advanced',
    category: 'Career-Role',
    prerequisites: ['2+ years software engineering or AppSec experience'],
    keySkills: ['End-to-End Threat Modeling', 'Defensive API Gateway Architecture', 'Automated AST Rule Authoring', 'Zero-Trust Identity Federation'],
    milestones: [
      { title: 'Protocols & Browser Boundaries', focus: 'HTTP & Web security', rulesCount: 76 },
      { title: 'Authentication & Access Control', focus: 'Auth, Authz & APIs', rulesCount: 110 },
      { title: 'Code Review & Threat Modeling', focus: 'Secure coding & architectural design', rulesCount: 248 }
    ],
    recommendedPace: '6 weeks (1-2 hrs/day)',
    whyChooseThis: 'Directly aligns with Staff and Principal AppSec job descriptions at high-growth tech companies.',
    targetOutcome: 'Design enterprise secure development lifecycles and pass Staff AppSec technical system design interviews.'
  },
  {
    id: 'path-role-cloud-infra-sec',
    title: 'Career Path: Cloud & Platform Security Architect',
    tagline: 'AWS IAM, Multi-Cloud VPC, Linux Runtime Sandboxing & Kubernetes Hardening',
    description: 'Master infrastructure as code security, cloud least privilege, runtime container sandboxing with eBPF, and zero-trust Kubernetes cluster networking.',
    targetRole: 'Cloud Security Architects, Staff DevSecOps, Platform Security Leads',
    estimatedHours: 40,
    domainIds: ['cloud', 'aws', 'containers', 'k8s', 'threatmodeling'],
    ruleIds: allInvariants.filter(r => ['cloud', 'aws', 'containers', 'k8s', 'threatmodeling'].includes(r.domain)).slice(0, 50).map(r => r.id),
    difficulty: 'Advanced',
    category: 'Career-Role',
    prerequisites: ['AWS or GCP experience', 'Container & Kubernetes basics'],
    keySkills: ['IAM Least Privilege Evaluation', 'Linux Namespace & Seccomp Profiling', 'Kubernetes Admission Policy Enforcement', 'Multi-Cloud VPC Peering Isolation'],
    milestones: [
      { title: 'Cloud Control Plane & AWS IAM', focus: 'SCPs, IMDSv2, KMS envelopes', rulesCount: 71 },
      { title: 'Container Isolation & Hardening', focus: 'Non-root, read-only fs & Linux capabilities', rulesCount: 140 },
      { title: 'Cluster Orchestration & Threat Modeling', focus: 'Kubernetes PSS, NetworkPolicies & attack paths', rulesCount: 141 }
    ],
    recommendedPace: '5 weeks (1-2 hrs/day)',
    whyChooseThis: 'High-demand path for securing modern Kubernetes infrastructure and AWS multi-account estates.',
    targetOutcome: 'Design and enforce automated infrastructure security invariants across production Kubernetes clusters.'
  },
  {
    id: 'path-role-ai-security-lead',
    title: 'Career Path: AI & LLM Systems Security Lead',
    tagline: 'End-to-End AI Safety Architecture: Prompt Guardrails, Agent Tools & RAG Defense',
    description: 'Prepare for the emerging role of AI Security Lead. Build comprehensive defense systems across LLM prompt boundaries, multimodal inputs, vector database embeddings, and autonomous agent tool delegation.',
    targetRole: 'AI Security Architects, Lead AI Safety Engineers, CISO Staff Advisors',
    estimatedHours: 35,
    domainIds: ['ai', 'coding', 'api', 'threatmodeling'],
    ruleIds: allInvariants.filter(r => ['ai', 'coding', 'api', 'threatmodeling'].includes(r.domain)).slice(0, 50).map(r => r.id),
    difficulty: 'Advanced',
    category: 'Career-Role',
    prerequisites: ['Familiarity with generative AI pipelines & APIs', 'Application security basics'],
    keySkills: ['Dual-Model Evaluator Pipelines', 'Agent Tool Authorization Invariants', 'Vector DB Ingestion Filtering', 'AI Threat Modeling (STRIDE-AI / OWASP LLM)'],
    milestones: [
      { title: 'LLM Threat Modeling & Invariants', focus: 'STRIDE for AI & OWASP LLM 10', rulesCount: 105 },
      { title: 'AI Boundary Guardrails', focus: 'Injection quarantine & supervisor verification', rulesCount: 141 },
      { title: 'API Integration & Code Safety', focus: 'Schema limits, sanitization & authz', rulesCount: 179 }
    ],
    recommendedPace: '4 weeks (1-2 hrs/day)',
    whyChooseThis: 'Position yourself at the forefront of the AI security revolution with formal verification techniques.',
    targetOutcome: 'Establish company-wide AI security policies and certify enterprise LLM deployments.'
  },
  {
    id: 'path-role-crypto-identity',
    title: 'Career Path: Cryptography & Distributed Identity Architect',
    tagline: 'Zero Trust Protocols, Modern Ciphers, OAuth 2.0 PKCE & Zanzibar ReBAC',
    description: 'Specialized engineering track for identity architects and cryptographic protocol designers. Covers FIPS 140-3 standards, constant-time algorithms, OpenID Connect federation, and high-throughput ReBAC graph evaluation.',
    targetRole: 'Cryptography Engineers, Identity Architects, Security Principal Engineers',
    estimatedHours: 42,
    domainIds: ['crypto', 'auth', 'authz', 'oauth', 'api'],
    ruleIds: allInvariants.filter(r => ['crypto', 'auth', 'authz', 'oauth', 'api'].includes(r.domain)).slice(0, 50).map(r => r.id),
    difficulty: 'Expert',
    category: 'Career-Role',
    prerequisites: ['Solid mathematical background', 'Experience with identity protocols'],
    keySkills: ['Post-Quantum Algorithm Readiness (ML-KEM)', 'Timing-Safe Cryptographic Comparisons', 'OAuth 2.0 Security BCP (RFC 8725)', 'High-Performance ReBAC Zanzibar Evaluation'],
    milestones: [
      { title: 'Core Cryptographic Primitives', focus: 'AEAD, HKDF, ECC & constant-time math', rulesCount: 38 },
      { title: 'Authentication & Session Architecture', focus: 'WebAuthn, Argon2id & token binding', rulesCount: 73 },
      { title: 'Federation & Granular Access Control', focus: 'OAuth PKCE, ReBAC & API gateway invariants', rulesCount: 71 }
    ],
    recommendedPace: '5 weeks (1.5 hrs/day)',
    whyChooseThis: 'Deep technical specialization commanding high industry respect and critical architectural responsibility.',
    targetOutcome: 'Design enterprise zero-trust identity architectures that resist credential stuffing, replay, and cryptanalysis.'
  },
  {
    id: 'path-sprint-faang-interview',
    title: 'Interview Sprint: Tier-1 Tech AppSec Whiteboard Mastery',
    tagline: 'Top 60 High-Frequency Architectural Scenarios for Staff AppSec Interviews',
    description: 'Intensive 2-week interview prep program focusing on the most frequently asked system security scenarios: HTTP Smuggling, BOLA in microservices, OAuth state/PKCE bypasses, SSRF to IMDSv2, and ReBAC scale.',
    targetRole: 'Candidates interviewing for Senior / Staff AppSec & Systems Security Roles',
    estimatedHours: 16,
    domainIds: ['http', 'web', 'api', 'auth', 'authz', 'oauth', 'cloud', 'threatmodeling'],
    ruleIds: allInvariants.filter(r => ['http', 'web', 'api', 'auth', 'authz', 'oauth', 'cloud', 'threatmodeling'].includes(r.domain)).slice(0, 60).map(r => r.id),
    difficulty: 'Advanced',
    category: 'Interview-Sprint',
    prerequisites: ['Prior AppSec background, preparing for upcoming interview rounds'],
    keySkills: ['Whiteboard Formal Invariant Articulation', 'Instant Vulnerability Root-Cause Diagnosis', 'Staff-Level Spoken System Defense', 'Trade-off Justification on Production Scale'],
    milestones: [
      { title: 'Web & API Attack Scenarios', focus: 'Smuggling, CSP, CORS, BOLA', rulesCount: 30 },
      { title: 'Identity, Cloud & Architecture Scenarios', focus: 'OAuth PKCE, IMDSv2, ReBAC, Threat Modeling', rulesCount: 30 }
    ],
    recommendedPace: '2 weeks (1-2 hrs/day)',
    whyChooseThis: 'High-yield interview optimization: zero fluff, maximum scenario-to-model-answer practice.',
    targetOutcome: 'Speak with structured, senior-level precision in technical scenario, whiteboard, and system design interviews.'
  },
  {
    id: 'path-sprint-cloud-devsecops-interview',
    title: 'Interview Sprint: Cloud & DevSecOps Incident Scenarios',
    tagline: 'Top 50 Container, Kubernetes & AWS Infrastructure Interview Challenges',
    description: 'Targeted interview drill covering container breakout vectors, Kubernetes API server exposure, IAM privilege escalation chains, and production incident remediation.',
    targetRole: 'Candidates interviewing for Cloud Security, DevSecOps & Platform Security Roles',
    estimatedHours: 14,
    domainIds: ['cloud', 'aws', 'containers', 'k8s'],
    ruleIds: allInvariants.filter(r => ['cloud', 'aws', 'containers', 'k8s'].includes(r.domain)).slice(0, 50).map(r => r.id),
    difficulty: 'Advanced',
    category: 'Interview-Sprint',
    prerequisites: ['Cloud and container fundamentals'],
    keySkills: ['Container Escape Path Identification', 'IAM Escalation Graph Analysis', 'Kubernetes NetworkPolicy Enforcement', 'Cloud Breach Containment Strategy'],
    milestones: [
      { title: 'Container Isolation & Escape Traps', focus: 'Host paths, root user, capabilities', rulesCount: 25 },
      { title: 'Cloud & Kubernetes Blast Radius Defense', focus: 'IAM policies, metadata hops, PSS', rulesCount: 25 }
    ],
    recommendedPace: '2 weeks (1 hr/day)',
    whyChooseThis: 'Conquer live incident response and infrastructure design interview questions with confidence.',
    targetOutcome: 'Demonstrate deep Linux kernel, container runtime, and AWS security knowledge under interview pressure.'
  },
  {
    id: 'path-sprint-owasp-top10-deepdive',
    title: 'Interview Sprint: OWASP Top 10 & CWE Top 25 Elimination',
    tagline: 'Formal Mathematical Invariants for the World\'s Most Critical Vulnerabilities',
    description: 'Master the formal defensive theorem for every single OWASP Top 10 category (Broken Access Control, Cryptographic Failures, Injection, Insecure Design, etc.) with concrete verification code.',
    targetRole: 'Security Engineers, Software Developers, Security Champions',
    estimatedHours: 15,
    domainIds: ['coding', 'web', 'api', 'auth', 'authz'],
    ruleIds: allInvariants.filter(r => ['coding', 'web', 'api', 'auth', 'authz'].includes(r.domain)).slice(0, 50).map(r => r.id),
    difficulty: 'Intermediate',
    category: 'Interview-Sprint',
    prerequisites: ['General programming and web familiarity'],
    keySkills: ['OWASP Top 10 Invariant Mapping', 'CWE-25 Root Cause Elimination', 'AST-Based Automated Taint Rules', 'Secure Implementation Validation'],
    milestones: [
      { title: 'Injection & Access Control Axioms', focus: 'A01 Broken Access Control & A03 Injection', rulesCount: 35 },
      { title: 'Crypto, Config & Design Axioms', focus: 'A02 Crypto Failures & A04 Insecure Design', rulesCount: 35 }
    ],
    recommendedPace: '2 weeks',
    whyChooseThis: 'The benchmark standard every security engineer must know inside out.',
    targetOutcome: 'Explain and prevent every OWASP Top 10 vulnerability using formal invariants rather than band-aids.'
  },
  {
    id: 'path-full-1000-mastery',
    title: 'Grandmaster Track: Complete 1,036 Invariants Compendium',
    tagline: 'The Definitive Zero-Compromise Security Engineering Curriculum',
    description: 'Total formal mastery across all 15 security domains—from raw byte-level HTTP framing to eBPF Linux runtimes, AST taint analysis, AI supervisor containment, and zero-knowledge soundness.',
    targetRole: 'Principal Security Architects, CISOs, Lead Security Auditors',
    estimatedHours: 120,
    domainIds: [
      'http', 'web', 'api', 'auth', 'authz', 'oauth', 'crypto',
      'cloud', 'aws', 'containers', 'k8s', 'coding', 'ai', 'smartcontracts', 'threatmodeling'
    ],
    ruleIds: allInvariants.map(r => r.id),
    difficulty: 'Expert',
    category: 'Career-Role',
    prerequisites: ['Comprehensive software engineering & systems background'],
    keySkills: ['Omni-Domain Security Architecture', 'Formal Mathematical Invariant Proofs', 'Systemic Enterprise Defense-in-Depth', 'Zero-Day Vulnerability Mitigation'],
    milestones: [
      { title: 'Phase 1: Web & Identity Foundations (Sec 1-6)', focus: 'HTTP, Web, API, Auth, Authz, OAuth', rulesCount: 221 },
      { title: 'Phase 2: Cloud, Containers & Infra (Sec 7-11)', focus: 'Crypto, Cloud, AWS, Containers, K8s', rulesCount: 285 },
      { title: 'Phase 3: Code Review, AI & Web3 (Sec 12-15)', focus: 'Secure Coding, AI, Web3, Threat Modeling', rulesCount: 530 }
    ],
    recommendedPace: '12–16 weeks (1 hr/day)',
    whyChooseThis: 'For engineers who want absolute mastery across every facet of modern security.',
    targetOutcome: 'Achieve top 1% global security engineering expertise with verified invariant fluency.'
  },
  {
    id: 'path-sequential-foundations-to-staff',
    title: 'Zero-to-Staff Sequential Pathway (Steps 1–1036)',
    tagline: 'Deterministic Step-by-Step Cognitive Ladder: Basic Fundamentals to Staff Zero-Day Defenses',
    description: 'A structured, progressive cognitive roadmap designed to build intuitive mental models without cognitive overwhelm. Starts with syntax and framing fundamentals, scales through token and isolation defense, masters distributed cloud systems, and culminates in staff-level zero-day formal invariants.',
    targetRole: 'Engineers seeking a clear, linear, step-by-step security engineering learning path',
    estimatedHours: 90,
    domainIds: [
      'http', 'web', 'api', 'auth', 'authz', 'oauth', 'crypto',
      'cloud', 'aws', 'containers', 'k8s', 'coding', 'ai', 'smartcontracts', 'threatmodeling'
    ],
    ruleIds: allSequentialRules.map(r => r.id),
    difficulty: 'Intermediate',
    category: 'Foundational-Tier',
    prerequisites: ['Basic programming knowledge, eagerness to build solid security intuitions'],
    keySkills: ['Step-by-Step Security Reasoning', 'Foundational Protocol Mechanics', 'Distributed Boundary Enforcement', 'Staff Whiteboard Defense'],
    milestones: [
      { title: 'Tier 1: Foundations & Core Prerequisites (Steps 1–259)', focus: 'Syntactic gates, schema validation, HTTP framing, safe defaults', rulesCount: 259 },
      { title: 'Tier 2: Applied Defense & Architecture (Steps 260–518)', focus: 'Tokens, sessions, AST parameter binding, ReBAC, sandboxing', rulesCount: 259 },
      { title: 'Tier 3: Distributed Systems & Cloud Hardening (Steps 519–777)', focus: 'eBPF, mTLS, SPIFFE, PSS, IAM least-privilege, supply chain', rulesCount: 259 },
      { title: 'Tier 4: Staff Frontier & Zero-Day Invariants (Steps 778–1036)', focus: 'Parser differentials, prompt injection firewalls, formal proofs, micro-VMs', rulesCount: 259 }
    ],
    recommendedPace: '8–12 weeks (45 mins/day)',
    whyChooseThis: 'Provides the mind with an unambiguous sequence to follow from day one to staff mastery.',
    targetOutcome: 'Possess a systematic, unshakeable mental framework for evaluating any vulnerability or distributed architecture.'
  }
];

export const learningPaths: LearningPath[] = [
  ...sectionLearningPaths,
  ...curatedLearningPaths
];

export function getInvariantById(id: string): SecurityInvariant | undefined {
  return allInvariants.find(r => r.id.toLowerCase() === id.toLowerCase() || String(r.ruleNumber) === id);
}

export function searchInvariants(query: string, domain?: DomainId, difficulty?: string, standardType?: string): SecurityInvariant[] {
  const q = query.trim().toLowerCase();
  return allInvariants.filter(rule => {
    if (domain && rule.domain !== domain) return false;
    if (difficulty && difficulty !== 'All' && rule.difficulty !== difficulty) return false;
    if (standardType && standardType !== 'All' && rule.standardType !== standardType) return false;
    
    if (!q) return true;
    return (
      rule.id.toLowerCase().includes(q) ||
      String(rule.ruleNumber).includes(q) ||
      rule.title.toLowerCase().includes(q) ||
      rule.subdomain.toLowerCase().includes(q) ||
      rule.formalInvariant.toLowerCase().includes(q) ||
      rule.plainEnglish.toLowerCase().includes(q) ||
      rule.standards.some(s => s.toLowerCase().includes(q))
    );
  });
}
