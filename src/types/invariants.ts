export type DomainId =
  | 'http'
  | 'web'
  | 'api'
  | 'auth'
  | 'authz'
  | 'oauth'
  | 'crypto'
  | 'cloud'
  | 'aws'
  | 'containers'
  | 'k8s'
  | 'coding'
  | 'ai'
  | 'smartcontracts'
  | 'threatmodeling';

export type Difficulty = 'Beginner' | 'Intermediate' | 'Advanced' | 'Expert';

export type StandardType = 'Mandatory Standard' | 'Defense-in-Depth' | 'Defensive Practice';

export interface InvariantBreakdownItem {
  symbol: string;
  meaning: string;
}

export interface CodeExample {
  language: string;
  code: string;
  explanation: string;
}

export interface TestProcedure {
  tools: string[];
  steps: string[];
  commandExample: string;
}

export interface InterviewChallenge {
  scenario: string;
  question: string;
  hint: string;
  sampleAnswer: string;
  keyTakeaway: string;
}

export interface InteractiveSimulationConfig {
  type:
    | 'http_headers'
    | 'jwt'
    | 'cors'
    | 'prompt_injection'
    | 'reentrancy'
    | 'imds'
    | 'rate_limit'
    | 'sql_injection'
    | 'k8s_rbac'
    | 'generic';
  label: string;
  defaultInput: string;
  placeholder?: string;
  testFunctionDescription: string;
}

export interface SecurityInvariant {
  id: string; // e.g. "SEC-HTTP-001"
  ruleNumber: number; // 1 to 500+
  title: string;
  domain: DomainId;
  domainName: string;
  subdomain: string;
  difficulty: Difficulty;
  standardType: StandardType;
  standards: string[]; // ["RFC 9112 §6.3", "OWASP A05:2021", "CWE-444"]
  formalInvariant: string;
  symbolBreakdown: InvariantBreakdownItem[];
  plainEnglish: string;
  whyItMatters: string;
  vulnerableExample: CodeExample;
  secureExample: CodeExample;
  howToTest: TestProcedure;
  interviewChallenge: InterviewChallenge;
  simulation?: InteractiveSimulationConfig;
  topicId?: SecurityTopicId;
  isRareRule?: boolean;
  sequenceOrder?: number;
  tier?: string;
  tierLevel?: 1 | 2 | 3 | 4;
}

export type SecurityTopicId =
  | 'request_smuggling'
  | 'sql_injection'
  | 'command_code_injection'
  | 'xss'
  | 'csrf'
  | 'ssrf'
  | 'path_traversal'
  | 'deserialization_parsing'
  | 'redirects_cors_framing'
  | 'authentication'
  | 'sessions_tokens'
  | 'jwt'
  | 'authorization'
  | 'race_conditions'
  | 'crypto_basics'
  | 'secrets_supply_chain'
  | 'availability'
  | 'logging_errors'
  | 'smart_contracts_core'
  | 'http_proxy_cache'
  | 'browser_dom_csp'
  | 'oauth_oidc_sso'
  | 'apis_graphql_grpc'
  | 'cloud_iam_infra'
  | 'mobile_desktop_clients'
  | 'memory_safety_os'
  | 'advanced_crypto_pki'
  | 'supply_chain_cicd'
  | 'business_logic_payments'
  | 'llm_ai_agents'
  | 'defi_economic_security'
  | 'privacy_mail_ops'
  | 'ai_model_security'
  | 'containers_k8s'
  | 'secure_code_review'
  | 'threat_modeling'
  | 'web3_audit';

export type SecurityTopicSuite =
  | 'Application & Injection'
  | 'Identity, Auth & Tokens'
  | 'Systems, Concurrency & Crypto'
  | 'Cloud, Infrastructure & Ops'
  | 'AI & LLM System Safety'
  | 'Web3, Smart Contracts & DeFi';

export interface SecurityTopicMeta {
  id: SecurityTopicId;
  topicNumber: number; // 1 to 37
  name: string;
  tagline: string;
  description: string;
  primaryStandard: string;
  cwes: string[];
  rarityLevel: 'Common' | 'Advanced' | 'Rare & Subtle Zero-Day';
  suite: SecurityTopicSuite;
  iconName: string;
  domainId: DomainId;
}

export interface DomainMeta {
  id: DomainId;
  name: string;
  iconName: string;
  shortDescription: string;
  primaryStandard: string;
  count: number;
  colorScheme: {
    badge: string;
    border: string;
    text: string;
    bgSubtle: string;
  };
}

export interface UserProgress {
  bookmarkedIds: string[];
  masteredIds: string[];
  reviewedIds: string[];
  srsData: Record<
    string,
    {
      interval: number; // days
      repetition: number;
      easeFactor: number;
      nextDueDate: number; // timestamp
      lastReviewed: number; // timestamp
      consecutiveCorrect: number;
    }
  >;
  quizHistory: {
    id: string;
    date: number;
    totalQuestions: number;
    score: number;
    domainBreakdown: Record<string, number>;
  }[];
  notes: Record<string, string>;
  studyStreakDays: number;
  lastActiveDate: string; // YYYY-MM-DD
}

export interface LearningPath {
  id: string;
  title: string;
  tagline: string;
  description: string;
  targetRole: string;
  estimatedHours: number;
  domainIds: DomainId[];
  ruleIds: string[];
  difficulty: Difficulty;
  category: 'Domain-Curriculum' | 'Career-Role' | 'Specialized' | 'Interview-Sprint' | 'Foundational-Tier';
  sectionNumber?: number;
  prerequisites: string[];
  keySkills: string[];
  milestones: { title: string; focus: string; rulesCount: number }[];
  recommendedPace: string;
  whyChooseThis: string;
  targetOutcome: string;
}
