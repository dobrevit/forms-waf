// API Response types
export interface ApiResponse<T> {
  status?: 'ok'
  data?: T
  error?: string
}

// Auth types
export type UserRole = 'admin' | 'operator' | 'viewer'
export type AuthProvider = 'local' | 'oidc' | 'saml' | 'ldap'

export interface User {
  username: string
  role: UserRole
  vhost_scope: string[]  // ["*"] for global access, or specific vhost IDs
  auth_provider: AuthProvider
  display_name?: string
  email?: string
  must_change_password?: boolean
}

// Permission types
export interface RolePermissions {
  vhosts?: string[]
  endpoints?: string[]
  keywords?: string[]
  config?: string[]
  users?: string[]
  providers?: string[]
  logs?: string[]
  metrics?: string[]
  bulk?: string[]
  captcha?: string[]
  webhooks?: string[]
  geoip?: string[]
  reputation?: string[]
  timing?: string[]
  sync?: string[]
  status?: string[]
  hashes?: string[]
  whitelist?: string[]
}

export interface Role {
  id: string
  name: string
  description?: string
  permissions: RolePermissions
  scope: 'global' | 'vhost-scoped'
}

export interface LoginRequest {
  username: string
  password: string
}

export interface ChangePasswordRequest {
  current_password: string
  new_password: string
}

// Virtual Host types
export interface VhostWafConfig {
  enabled: boolean
  mode: 'monitoring' | 'blocking' | 'passthrough' | 'strict'
  debug_headers?: boolean  // Per-vhost debug header override (nil = inherit from global)
}

export interface VhostRouting {
  use_haproxy: boolean
  haproxy_backend?: string
  haproxy_upstream?: string      // Override global HAProxy HTTP endpoint
  haproxy_upstream_ssl?: string  // Override global HAProxy HTTPS endpoint
  upstream_ssl?: boolean         // Toggle: when true, use haproxy_upstream_ssl (overrides global)
  haproxy_ssl?: boolean          // @deprecated - use upstream_ssl instead
  upstream?: {
    servers: string[]
    health_check?: string
    timeout?: number
    ssl?: boolean                // Use HTTPS for direct upstream servers
  }
}

// Global routing configuration
export interface GlobalRouting {
  haproxy_upstream: string       // HAProxy HTTP endpoint address (e.g., "haproxy:8080")
  haproxy_upstream_ssl?: string  // HAProxy HTTPS endpoint address (e.g., "haproxy:8443")
  upstream_ssl?: boolean         // Toggle: when true, use haproxy_upstream_ssl instead of haproxy_upstream
  haproxy_timeout?: number       // Default timeout for HAProxy connections
}

export interface VhostThresholds {
  spam_score_block?: number
  spam_score_flag?: number
  ip_rate_limit?: number
}

export interface VhostKeywords {
  inherit_global: boolean
  additional_blocked?: string[]
  additional_flagged?: string[]
  excluded_blocked?: string[]  // Canonical: separate arrays for blocked/flagged exclusions
  excluded_flagged?: string[]
}

export interface VhostTimingConfig {
  enabled: boolean
  cookie_ttl?: number
  min_time_block?: number
  min_time_flag?: number
  score_no_cookie?: number
  score_too_fast?: number
  score_suspicious?: number
  start_paths?: string[]
  end_paths?: string[]
  path_match_mode?: 'exact' | 'prefix' | 'regex'
}

export interface VhostEndpoints {
  inherit_global: boolean
  overrides?: Record<string, unknown>
  custom?: unknown[]
}

export interface Vhost {
  id: string
  name: string
  description?: string
  enabled: boolean
  hostnames: string[]
  waf: VhostWafConfig
  routing: VhostRouting
  thresholds?: VhostThresholds
  keywords?: VhostKeywords
  endpoints?: VhostEndpoints
  timing?: VhostTimingConfig  // Per-vhost timing validation configuration
  behavioral?: VhostBehavioralConfig  // Per-vhost behavioral tracking configuration
  fingerprint_profiles?: FingerprintProfileAttachment  // Fingerprint profile configuration
  endpoint_count?: number  // Number of vhost-specific endpoints
}

// Endpoint types
export interface EndpointMatching {
  paths?: string[]
  path_prefix?: string
  path_regex?: string
  methods?: string[]
  content_types?: string[]
}

export interface EndpointThresholds {
  spam_score_block?: number
  spam_score_flag?: number
  ip_rate_limit?: number
  ip_daily_limit?: number
  hash_count_block?: number
  hash_unique_ips_block?: number
}

export interface EndpointKeywords {
  inherit_global: boolean
  blocked?: Record<string, unknown>  // Endpoint-specific blocked keywords
  flagged?: Record<string, unknown>  // Endpoint-specific flagged keywords
  additional_blocked?: string[]  // Legacy
  additional_flagged?: string[]  // Legacy
}

// Canonical field names:
//   fields.ignore (not ignore_fields)
//   fields.expected (not expected_fields)
//   fields.honeypot (array of field names)
//   fields.hash (object with enabled/fields)
export interface EndpointFields {
  required?: string[] | Record<string, unknown>
  max_length?: Record<string, number>
  ignore?: string[]  // Canonical: fields to ignore (CSRF tokens, etc.)
  expected?: string[]  // Expected fields - unexpected fields will trigger action
  honeypot?: string[]  // Canonical: honeypot field names (action/score in security)
  hash?: {  // Canonical: hash configuration
    enabled: boolean
    fields?: string[]  // Only hash these specific fields
  }
  unexpected_action?: 'flag' | 'block' | 'ignore' | 'filter'  // Action for unexpected fields
}

export interface EndpointRateLimiting {
  enabled: boolean
  requests_per_minute?: number
  requests_per_day?: number
}

export interface EndpointPatterns {
  inherit_global: boolean
  disabled?: Record<string, boolean>  // Canonical: disabled patterns
  custom?: Record<string, unknown>  // Canonical: custom patterns
}

export interface EndpointActions {
  on_flag?: 'tag' | 'log' | 'none'
  on_block?: 'reject' | 'tag' | 'log'
  log_level?: 'debug' | 'info' | 'warn' | 'error'
}

// Security settings (honeypot action/score, disposable email checks, etc.)
// Honeypot field NAMES are in fields.honeypot, but action/score are here
export interface EndpointSecurity {
  honeypot_action?: 'block' | 'flag'  // Action when honeypot triggered
  honeypot_score?: number  // Score to add if honeypot_action is 'flag'
  check_disposable_email?: boolean
  disposable_email_action?: 'flag' | 'block' | 'ignore'
  disposable_email_score?: number
  check_field_anomalies?: boolean  // Detect bot-like field patterns
}

export interface Endpoint {
  id: string
  name: string
  description?: string
  enabled: boolean
  mode: 'monitoring' | 'blocking' | 'passthrough' | 'strict'
  priority?: number
  vhost_id?: string | null  // null/empty = global endpoint
  matching: EndpointMatching
  thresholds?: EndpointThresholds
  keywords?: EndpointKeywords
  fields?: EndpointFields
  security?: EndpointSecurity  // Security settings (honeypot action, disposable email, etc.)
  rate_limiting?: EndpointRateLimiting
  patterns?: EndpointPatterns
  actions?: EndpointActions
  fingerprint_profiles?: FingerprintProfileAttachment  // Fingerprint profile configuration
}

// Config types
export interface Thresholds {
  spam_score_block: number
  spam_score_flag: number
  hash_count_block: number
  ip_rate_limit: number
  ip_daily_limit?: number
  hash_unique_ips_block?: number
}

// Status types
export interface WafStatus {
  status: string
  redis_connected: boolean
  blocked_keywords_count: number
  flagged_keywords_count: number
  blocked_hashes_count: number
  whitelisted_ips_count: number
  endpoints_count: number
  vhosts_count: number
}

// Match test types
export interface VhostMatchResult {
  vhost_id: string
  match_type: 'exact' | 'wildcard' | 'default'
  config?: Vhost
}

export interface EndpointMatchResult {
  endpoint_id: string
  match_type: 'exact' | 'prefix' | 'regex' | 'global'
  config?: Endpoint
}

export interface ContextResult {
  vhost: VhostMatchResult
  endpoint: EndpointMatchResult
  skip_waf: boolean
  reason?: string
  mode: string
}

// CAPTCHA types
export type CaptchaProviderType = 'turnstile' | 'recaptcha_v2' | 'recaptcha_v3' | 'hcaptcha'

export interface CaptchaProviderOptions {
  theme?: 'light' | 'dark' | 'auto'
  size?: 'normal' | 'compact'
  min_score?: number  // reCAPTCHA v3 only
  action?: string     // reCAPTCHA v3 only
}

export interface CaptchaProvider {
  id: string
  name: string
  type: CaptchaProviderType
  enabled: boolean
  priority: number
  site_key: string
  secret_key: string  // Will be "***" when fetched from API
  options?: CaptchaProviderOptions
  metadata?: {
    created_at?: string
    updated_at?: string
  }
}

export interface CaptchaGlobalConfig {
  enabled: boolean
  default_provider?: string | null
  trust_duration: number      // seconds (default: 86400 = 24h)
  challenge_ttl: number       // seconds (default: 600 = 10min)
  fallback_action: 'block' | 'allow' | 'monitor'
  cookie_name: string
  cookie_secure: boolean
  cookie_httponly: boolean
  cookie_samesite: 'Strict' | 'Lax' | 'None'
}

export interface CaptchaConfigResponse {
  config: CaptchaGlobalConfig
  defaults: CaptchaGlobalConfig
}

// Endpoint CAPTCHA configuration
export interface EndpointCaptchaConfig {
  enabled?: boolean
  provider?: string           // Override default provider
  trigger?: 'on_block' | 'on_flag' | 'always'
  spam_score_threshold?: number  // For 'on_flag' trigger
  trust_duration?: number     // Override global trust duration
  exempt_ips?: string[]       // IPs to skip CAPTCHA
}

// Extended Endpoint with CAPTCHA (inherits security from Endpoint)
export interface EndpointWithCaptcha extends Endpoint {
  captcha?: EndpointCaptchaConfig
}

// Behavioral tracking types
export interface BehavioralFlow {
  name: string
  start_paths: string[]
  start_methods?: string[]
  end_paths: string[]
  end_methods?: string[]
  path_match_mode?: 'exact' | 'prefix' | 'regex'
}

export interface BehavioralTracking {
  fill_duration?: boolean
  submission_counts?: boolean
  unique_ips?: boolean
  avg_spam_score?: boolean
}

export interface BehavioralBaselines {
  learning_period_days?: number
  min_samples?: number
}

export interface BehavioralAnomalyDetection {
  enabled?: boolean
  std_dev_threshold?: number
  action?: 'flag' | 'score'
  score_addition?: number
}

export interface VhostBehavioralConfig {
  enabled: boolean
  flows?: BehavioralFlow[]
  tracking?: BehavioralTracking
  baselines?: BehavioralBaselines
  anomaly_detection?: BehavioralAnomalyDetection
}

export interface BehavioralStats {
  bucket_id: string
  timestamp: number
  submissions: number
  allowed: number
  blocked: number
  monitored: number
  avg_spam_score: number
  duration_histogram: Record<string, number>
  unique_ips: number
}

export interface BehavioralBaseline {
  learning_complete: boolean
  hourly_avg_submissions?: number
  hourly_std_dev_submissions?: number
  hourly_p50_submissions?: number
  hourly_p90_submissions?: number
  hourly_p99_submissions?: number
  samples_used?: number
  samples_collected?: number
  min_samples_needed?: number
  learning_period_days?: number
  last_updated?: string
}

export interface BehavioralFlowSummary {
  name: string
  baseline_status: 'ready' | 'learning' | 'no_data'
  samples_collected: number
  last_hour?: {
    submissions: number
    blocked: number
    allowed: number
    unique_ips: number
    avg_spam_score: number
  }
}

export interface BehavioralVhostSummary {
  vhost_id: string
  flows: BehavioralFlowSummary[]
}

export interface BehavioralVhostItem {
  vhost_id: string
  vhost_name?: string
  enabled: boolean
  flows_count: number
  last_activity?: string
}

// Fingerprint Profile types
export type FingerprintProfileAction = 'allow' | 'block' | 'flag' | 'ignore'
export type FingerprintConditionType = 'present' | 'absent' | 'matches' | 'not_matches'
export type FingerprintMatchMode = 'all' | 'any'
export type FingerprintNoMatchAction = 'use_default' | 'flag' | 'allow'

export interface FingerprintHeaderCondition {
  header: string
  condition: FingerprintConditionType
  pattern?: string  // Required for 'matches' and 'not_matches'
}

export interface FingerprintMatching {
  conditions: FingerprintHeaderCondition[]
  match_mode: FingerprintMatchMode
}

export interface FingerprintHeaders {
  headers: string[]
  normalize?: boolean
  max_length?: number
  include_field_names?: boolean
}

export interface FingerprintRateLimiting {
  enabled?: boolean
  fingerprint_rate_limit?: number
}

export interface FingerprintProfile {
  id: string
  name: string
  description?: string
  enabled: boolean
  builtin: boolean
  priority: number
  matching: FingerprintMatching
  fingerprint_headers: FingerprintHeaders
  action: FingerprintProfileAction
  score?: number
  rate_limiting?: FingerprintRateLimiting
}

export interface FingerprintProfileAttachment {
  enabled: boolean
  profiles?: string[]  // Profile IDs, null = use all global profiles
  no_match_action?: FingerprintNoMatchAction
  no_match_score?: number
}

export interface FingerprintProfileTestRequest {
  headers: Record<string, string>
  profiles?: string[]  // Profile IDs to test against, null = all
  form_fields?: Record<string, string>
  no_match_config?: {
    no_match_action?: FingerprintNoMatchAction
    no_match_score?: number
  }
}

export interface FingerprintProfileTestResult {
  matched_profiles: {
    id: string
    name: string
    priority: number
    action: FingerprintProfileAction
    score?: number
  }[]
  result: {
    blocked: boolean
    ignored: boolean
    total_score: number
    flags: string[]
    fingerprint_profile_id?: string
    fingerprint_rate_limit?: number
    fingerprint?: string
  }
}

// Extend Vhost and Endpoint to include fingerprint profile attachment
export interface VhostFingerprintConfig extends FingerprintProfileAttachment {}

export interface EndpointFingerprintConfig extends FingerprintProfileAttachment {}
