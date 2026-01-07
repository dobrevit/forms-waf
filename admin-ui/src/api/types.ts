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
  fingerprint_profiles?: string[]
  defense_profiles?: string[]
  attack_signatures?: string[]
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
  defense_profiles?: DefenseProfileAttachment  // Multi-profile defense configuration
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
  defense_profiles?: DefenseProfileAttachment  // Multi-profile defense configuration
  defense_lines?: DefenseLineAttachment[]  // Additional defense lines (run after base profile)
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

// ============================================================================
// Defense Profile Types
// ============================================================================

// Node types in defense profile graph
export type DefenseNodeType = 'start' | 'defense' | 'operator' | 'action' | 'observation'

// Observation mechanism types (non-blocking, side-effect only)
export type ObservationType = 'field_learner'

// Defense mechanism types
export type DefenseType =
  | 'ip_allowlist'
  | 'geoip'
  | 'ip_reputation'
  | 'timing_token'
  | 'behavioral'
  | 'honeypot'
  | 'keyword_filter'
  | 'content_hash'
  | 'expected_fields'
  | 'pattern_scan'
  | 'disposable_email'
  | 'field_anomalies'
  | 'fingerprint'
  | 'header_consistency'
  | 'rate_limiter'

// Operator types
export type OperatorType = 'sum' | 'threshold_branch' | 'and' | 'or' | 'max' | 'min'

// Action types
export type ActionType = 'allow' | 'block' | 'tarpit' | 'captcha' | 'flag' | 'monitor'

// Node position for visual editor
export interface NodePosition {
  x: number
  y: number
}

// Threshold range for threshold_branch operator
export interface ThresholdRange {
  min: number
  max?: number | null
  output: string
}

// Base node interface
export interface DefenseProfileNode {
  id: string
  type: DefenseNodeType
  position?: NodePosition
  outputs?: Record<string, string>
  config?: Record<string, unknown>
}

// Defense node
export interface DefenseNode extends DefenseProfileNode {
  type: 'defense'
  defense: DefenseType
}

// Operator node
export interface OperatorNode extends DefenseProfileNode {
  type: 'operator'
  operator: OperatorType
  inputs?: string[]
}

// Action node
export interface ActionNode extends DefenseProfileNode {
  type: 'action'
  action: ActionType
}

// Start node
export interface StartNode extends DefenseProfileNode {
  type: 'start'
}

// Observation node (non-blocking, side-effect only - e.g., field learning)
export interface ObservationNode extends DefenseProfileNode {
  type: 'observation'
  observation: ObservationType
}

// Union type for all nodes
export type GraphNode = StartNode | DefenseNode | OperatorNode | ActionNode | ObservationNode

// Profile graph
export interface DefenseProfileGraph {
  nodes: GraphNode[]
}

// Profile settings
export interface DefenseProfileSettings {
  default_action?: ActionType
  max_execution_time_ms?: number
}

// Attack signature attachment item (for attaching signatures to profiles)
export interface AttackSignatureAttachmentItem {
  signature_id: string
  priority?: number  // Order of application (lower = first)
  enabled?: boolean  // Override signature's enabled state
}

// Merge mode for combining signature patterns
export type SignatureMergeMode = 'UNION' | 'FIRST_MATCH'

// Attack signature attachment configuration (attached to defense profile)
export interface AttackSignatureAttachment {
  items: AttackSignatureAttachmentItem[]
  merge_mode: SignatureMergeMode
}

// Main defense profile interface
export interface DefenseProfile {
  id: string
  name: string
  description?: string
  enabled: boolean
  builtin: boolean
  priority: number
  extends?: string | null
  graph: DefenseProfileGraph
  settings?: DefenseProfileSettings
  attack_signatures?: AttackSignatureAttachment  // Attached attack signatures
}

// Defense metadata for UI
export interface DefenseMetadata {
  name: string
  description: string
  outputs: string[]
  output_types: Record<string, string>
  config_schema?: Record<string, unknown>
  score_range?: { min: number; max: number }
}

// Operator metadata for UI
export interface OperatorMetadata {
  name: string
  description: string
  input_type: string
  output_type: string
  config_schema?: Record<string, unknown>
}

// Action metadata for UI
export interface ActionMetadata {
  name: string
  description: string
  terminal: boolean
  config_schema?: Record<string, unknown>
}

// Simulation result
export interface DefenseProfileSimulationResult {
  action: ActionType
  score: number
  flags: string[]
  details: Record<string, unknown>
  block_reason?: string
  allow_reason?: string
  tarpit_delay?: number
  execution_time_ms: number
  nodes_executed: number
}

// Validation result
export interface DefenseProfileValidationResult {
  valid: boolean
  errors: string[]
}

// Profile attachment item (single profile within multi-profile config)
export interface DefenseProfileAttachmentItem {
  id: string
  priority?: number  // Execution order (lower = first)
  weight?: number    // For weighted score aggregation (0-1)
}

// Aggregation strategies for binary decisions
export type DefenseAggregation = 'OR' | 'AND' | 'MAJORITY'

// Score aggregation strategies
export type DefenseScoreAggregation = 'SUM' | 'MAX' | 'WEIGHTED_AVG'

// Multi-profile attachment for vhost/endpoint
export interface DefenseProfileAttachment {
  enabled: boolean
  profiles: DefenseProfileAttachmentItem[]
  aggregation: DefenseAggregation
  score_aggregation: DefenseScoreAggregation
  short_circuit?: boolean  // Stop on first block (optimization)
}

// ============================================================================
// Attack Signature Types
// ============================================================================

// Signature section for IP Allowlist defense
export interface IPAllowlistSignature {
  allowed_cidrs?: string[]
  allowed_ips?: string[]
}

// Signature section for GeoIP defense
export interface GeoIPSignature {
  blocked_countries?: string[]
  flagged_countries?: { country: string; score: number }[]
  blocked_regions?: string[]
  flagged_regions?: { region: string; score: number }[]
}

// Signature section for IP Reputation defense
export interface IPReputationSignature {
  blocked_cidrs?: string[]
  flagged_cidrs?: { cidr: string; score: number }[]
  min_reputation_score?: number
  blocked_asns?: string[]
}

// Signature section for Timing Token defense
export interface TimingTokenSignature {
  min_time_ms?: number
  max_time_ms?: number
  require_token?: boolean
}

// Signature section for Behavioral defense
export interface BehavioralSignature {
  min_interaction_score?: number
  require_mouse_movement?: boolean
  require_keyboard_input?: boolean
  min_time_on_page_ms?: number
  max_time_on_page_ms?: number
  require_scroll?: boolean
}

// Signature section for Honeypot defense
export interface HoneypotSignature {
  field_names?: string[]
  blocked_if_filled?: boolean
  score_if_filled?: number
}

// Signature section for Keyword Filter defense
export interface KeywordFilterSignature {
  blocked_keywords?: string[]
  flagged_keywords?: { keyword: string; score: number }[]
  blocked_patterns?: string[]
  flagged_patterns?: { pattern: string; score: number }[]
  case_sensitive?: boolean
}

// Signature section for Content Hash defense
export interface ContentHashSignature {
  blocked_hashes?: string[]
  blocked_fuzzy_hashes?: string[]
  flagged_hashes?: { hash: string; score: number }[]
}

// Signature section for Expected Fields defense
export interface ExpectedFieldsSignature {
  required_fields?: string[]
  forbidden_fields?: string[]
  optional_fields?: string[]
  max_extra_fields?: number
}

// Signature section for Pattern Scan defense
export interface PatternScanSignature {
  blocked_patterns?: string[]
  flagged_patterns?: { pattern: string; score: number }[]
  scan_fields?: string[]
  multiline?: boolean
}

// Signature section for Disposable Email defense
export interface DisposableEmailSignature {
  blocked_domains?: string[]
  allowed_domains?: string[]
  blocked_patterns?: string[]
  flagged_domains?: { domain: string; score: number }[]
}

// Field rule for Field Anomalies defense
export interface FieldRule {
  field: string
  min_length?: number
  max_length?: number
  pattern?: string
  forbidden_pattern?: string
  score_on_violation?: number
}

// Signature section for Field Anomalies defense
export interface FieldAnomaliesSignature {
  field_rules?: FieldRule[]
  max_field_length?: number
  max_total_size?: number
}

// Signature section for Fingerprint defense
export interface FingerprintSignature {
  blocked_user_agents?: string[]
  flagged_user_agents?: { pattern: string; score: number }[]
  required_fingerprint_fields?: string[]
  blocked_fingerprints?: string[]
  flagged_fingerprints?: { hash: string; score: number }[]
}

// Header rule for Header Consistency defense
export interface HeaderRule {
  header: string
  pattern?: string
  forbidden_pattern?: string
  score_on_violation?: number
}

// Signature section for Header Consistency defense
export interface HeaderConsistencySignature {
  required_headers?: string[]
  forbidden_headers?: string[]
  header_rules?: HeaderRule[]
}

// Signature section for Rate Limiter defense
export interface RateLimiterSignature {
  requests_per_second?: number
  requests_per_minute?: number
  requests_per_hour?: number
  burst_limit?: number
  by_field?: string
}

// All signature sections combined (1:1 mapping with DefenseType)
export interface AttackSignatures {
  ip_allowlist?: IPAllowlistSignature
  geoip?: GeoIPSignature
  ip_reputation?: IPReputationSignature
  timing_token?: TimingTokenSignature
  behavioral?: BehavioralSignature
  honeypot?: HoneypotSignature
  keyword_filter?: KeywordFilterSignature
  content_hash?: ContentHashSignature
  expected_fields?: ExpectedFieldsSignature
  pattern_scan?: PatternScanSignature
  disposable_email?: DisposableEmailSignature
  field_anomalies?: FieldAnomaliesSignature
  fingerprint?: FingerprintSignature
  header_consistency?: HeaderConsistencySignature
  rate_limiter?: RateLimiterSignature
}

// Threshold overrides when signature is active
export interface AttackSignatureThresholds {
  spam_score_block?: number
  spam_score_flag?: number
}

// Signature match statistics
export interface AttackSignatureStats {
  total_matches: number
  last_match_at?: string
  matches_by_type?: Record<string, number>
}

// Main Attack Signature entity
export interface AttackSignature {
  id: string
  name: string
  description?: string
  enabled: boolean
  builtin?: boolean
  builtin_version?: number
  priority?: number

  // Signature patterns for each defense type
  signatures: AttackSignatures

  // Threshold overrides
  thresholds?: AttackSignatureThresholds

  // Metadata
  tags?: string[]
  expires_at?: string

  // Analytics (populated when include_stats=true)
  stats?: AttackSignatureStats

  // Timestamps
  created_at?: string
  updated_at?: string
  created_by?: string
}

// ============================================================================
// Defense Line Types (Endpoint configuration)
// ============================================================================

// Defense line attachment for endpoints
export interface DefenseLineAttachment {
  profile_id: string              // Defense Profile ID for this line
  signature_ids?: string[]        // Attack Signature IDs (in priority order)
  enabled?: boolean               // Enable/disable this line
  inline_signatures?: AttackSignatures  // Optional inline signature overrides
}

// Extended Endpoint with Defense Lines
export interface EndpointWithDefenseLines extends Endpoint {
  defense_lines?: DefenseLineAttachment[]
}

// ============================================================================
// Attack Signature API Response Types
// ============================================================================

export interface AttackSignatureListResponse {
  signatures: AttackSignature[]
}

export interface AttackSignatureResponse {
  signature: AttackSignature
}

export interface AttackSignatureCreateResponse {
  created: boolean
  signature: AttackSignature
}

export interface AttackSignatureUpdateResponse {
  updated: boolean
  signature: AttackSignature
}

export interface AttackSignatureDeleteResponse {
  deleted: boolean
  id: string
}

export interface AttackSignatureCloneResponse {
  cloned: boolean
  signature: AttackSignature
}

export interface AttackSignatureEnableResponse {
  enabled: boolean
  signature: AttackSignature
}

export interface AttackSignatureDisableResponse {
  disabled: boolean
  signature: AttackSignature
}

export interface AttackSignatureStatsResponse {
  stats: AttackSignatureStats
}

export interface AttackSignatureBuiltinsResponse {
  builtin_ids: string[]
}

export interface AttackSignatureResetBuiltinsResponse {
  reset: boolean
  count: number
}

export interface AttackSignatureTagsResponse {
  tags: { tag: string; count: number }[]  // Array of tag objects
}

export interface AttackSignatureExportResponse {
  signatures: AttackSignature[]
  exported_at: string
  count: number
}

export interface AttackSignatureImportResponse {
  imported: number
  errors: string[]
  total: number
}

export interface AttackSignatureValidateResponse {
  valid: boolean
  errors: string[]
}

export interface AttackSignatureTestMatch {
  type: string
  pattern_type: string
  pattern: string
  matched_value: string
  action: 'block' | 'flag'
  score?: number
}

export interface AttackSignatureTestResult {
  signature_id: string
  signature_name: string
  matches: AttackSignatureTestMatch[]
  total_score: number
  would_block: boolean
}

export interface AttackSignatureTestResponse {
  test: AttackSignatureTestResult
  sample_provided: Record<string, string>
}

export interface AttackSignatureStatsSummary {
  total_signatures: number
  enabled_count: number
  disabled_count: number
  builtin_count: number
  custom_count: number
  total_matches: number
  matches_by_type: Record<string, number>
}

export interface AttackSignatureStatsSummaryResponse {
  summary: AttackSignatureStatsSummary
}

// ============================================================================
// Backup and Restore Types
// ============================================================================

// Entity types available for backup
export interface BackupEntityInfo {
  id: string
  name: string
  has_builtins: boolean
  sensitive: boolean
}

// Backup metadata
export interface BackupMetadata {
  version: string
  created_at: string
  entity_counts: Record<string, number>
  include_builtins: boolean
  include_users: boolean
}

// Backup data structure
export interface BackupData {
  vhosts?: Vhost[]
  endpoints?: Endpoint[]
  defense_profiles?: DefenseProfile[]
  attack_signatures?: AttackSignature[]
  fingerprint_profiles?: FingerprintProfile[]
  captcha_providers?: CaptchaProvider[]
  auth_providers?: Record<string, unknown>[]
  users?: Partial<User>[]
  roles?: Role[]
  keywords?: {
    blocked?: string[]
    flagged?: string[]
  }
  hashes?: {
    blocked?: string[]
  }
  whitelist?: {
    ips?: string[]
  }
  config?: {
    geoip?: Record<string, unknown>
    timing_token?: Record<string, unknown>
    routing?: GlobalRouting
    thresholds?: Thresholds
    webhooks?: Record<string, unknown>
    captcha?: CaptchaGlobalConfig
    reputation?: Record<string, unknown>
  }
}

// Full backup structure
export interface Backup {
  metadata: BackupMetadata
  data: BackupData
  checksum?: string
}

// Validation result
export interface BackupValidationResult {
  valid: boolean
  errors: string[]
  warnings: string[]
  summary: Record<string, number | string>
  conflicts?: Record<string, string[]>
}

// Import mode
export type BackupImportMode = 'merge' | 'replace' | 'update'

// Import request
export interface BackupImportRequest {
  backup: Backup
  mode: BackupImportMode
  include_users?: boolean
}

// Import result details
export interface BackupImportResultDetails {
  imported: Record<string, number>
  skipped: Record<string, number>
  updated: Record<string, number>
  errors: Record<string, string[]>
}

// Import response
export interface BackupImportResponse {
  success: boolean
  mode: BackupImportMode
  results: BackupImportResultDetails
}

// Export options
export interface BackupExportOptions {
  include_users?: boolean
  include_builtins?: boolean
  entities?: string[]  // Filter to specific entity types
}

// API Responses
export interface BackupEntitiesResponse {
  entities: BackupEntityInfo[]
}

export interface BackupExportResponse extends Backup {}

export interface BackupValidateResponse extends BackupValidationResult {}
