import type { ApiResponse, GlobalRouting } from './types'

const API_BASE = '/api'

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
    this.name = 'ApiError'
  }
}

async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE}${endpoint}`

  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    credentials: 'include',
  })

  if (response.status === 401) {
    // Session expired - don't redirect here, let AuthContext handle it
    // Redirecting here causes infinite loop on login page
    throw new ApiError(401, 'Session expired')
  }

  const data = await response.json()

  if (!response.ok) {
    throw new ApiError(response.status, data.error || 'An error occurred')
  }

  return data
}

// Auth API
export const authApi = {
  login: (username: string, password: string) =>
    request<ApiResponse<{ user: { username: string; must_change_password: boolean } }>>(
      '/auth/login',
      {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      }
    ),

  logout: () =>
    request<ApiResponse<null>>('/auth/logout', { method: 'POST' }),

  verify: () =>
    request<ApiResponse<{ user: { username: string; must_change_password: boolean } }>>(
      '/auth/verify'
    ),

  changePassword: (currentPassword: string, newPassword: string) =>
    request<ApiResponse<null>>('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    }),
}

// User Management API
import type { User, UserRole } from './types'

export interface CreateUserRequest {
  username: string
  password: string
  role: UserRole
  vhost_scope?: string[]
  display_name?: string
  email?: string
}

export interface UpdateUserRequest {
  role?: UserRole
  vhost_scope?: string[]
  display_name?: string
  email?: string
}

export const usersApi = {
  list: () =>
    request<{ users: User[] }>('/users'),

  get: (username: string) =>
    request<{ user: User }>(`/users/${encodeURIComponent(username)}`),

  create: (data: CreateUserRequest) =>
    request<{ created: boolean; user: User }>('/users', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (username: string, data: UpdateUserRequest) =>
    request<{ updated: boolean; user: User }>(`/users/${encodeURIComponent(username)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  delete: (username: string) =>
    request<{ deleted: boolean; username: string }>(`/users/${encodeURIComponent(username)}`, {
      method: 'DELETE',
    }),

  resetPassword: (username: string, newPassword: string) =>
    request<{ reset: boolean; username: string }>(`/users/${encodeURIComponent(username)}/reset-password`, {
      method: 'POST',
      body: JSON.stringify({ new_password: newPassword }),
    }),
}

// Auth Providers API
export interface AuthProviderPublic {
  id: string
  name: string
  type: 'oidc' | 'ldap' | 'saml'
  icon?: string
}

export interface OIDCConfig {
  issuer?: string
  discovery?: string
  client_id: string
  client_secret?: string
  scopes?: string[]
  ssl_verify?: boolean
  use_pkce?: boolean
}

export interface LDAPConfig {
  host: string
  port?: number
  use_ssl?: boolean
  ssl_verify?: boolean
  timeout?: number
  base_dn: string
  user_base_dn?: string
  user_dn_template?: string
  user_filter?: string
  group_base_dn?: string
  group_filter?: string
  group_attribute?: string
  bind_dn?: string
  bind_password?: string
}

export interface RoleMapping {
  group: string
  role: 'admin' | 'operator' | 'viewer'
  vhosts?: string[]
  priority?: number
}

export interface RoleMappingConfig {
  default_role: 'admin' | 'operator' | 'viewer'
  default_vhosts?: string[]
  claim_name?: string
  sync_on_login?: boolean
  mappings?: RoleMapping[]
}

export interface AuthProviderConfig {
  id: string
  name: string
  type: 'oidc' | 'ldap' | 'saml'
  enabled: boolean
  priority?: number
  icon?: string
  oidc?: OIDCConfig
  ldap?: LDAPConfig
  role_mapping?: RoleMappingConfig
  created_at?: string
  updated_at?: string
}

export const authProvidersApi = {
  // Public endpoint - list available providers for login
  listPublic: () =>
    request<{ providers: AuthProviderPublic[]; local_auth_enabled: boolean }>('/auth/providers'),

  // Admin endpoints
  list: () =>
    request<{ providers: AuthProviderConfig[] }>('/auth/providers/config'),

  get: (id: string) =>
    request<{ provider: AuthProviderConfig }>(`/auth/providers/config/${encodeURIComponent(id)}`),

  create: (data: Omit<AuthProviderConfig, 'created_at' | 'updated_at'>) =>
    request<{ created: boolean; provider: AuthProviderConfig }>('/auth/providers/config', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (id: string, data: Partial<AuthProviderConfig>) =>
    request<{ updated: boolean; provider: AuthProviderConfig }>(`/auth/providers/config/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  delete: (id: string) =>
    request<{ deleted: boolean; provider_id: string }>(`/auth/providers/config/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  test: (id: string) =>
    request<{ success: boolean; message: string; issuer?: string }>(`/auth/providers/config/${encodeURIComponent(id)}/test`, {
      method: 'POST',
    }),

  enable: (id: string) =>
    request<{ enabled: boolean; provider_id: string }>(`/auth/providers/config/${encodeURIComponent(id)}/enable`, {
      method: 'POST',
    }),

  disable: (id: string) =>
    request<{ disabled: boolean; provider_id: string }>(`/auth/providers/config/${encodeURIComponent(id)}/disable`, {
      method: 'POST',
    }),

  // Get SSO login URL (for OIDC redirect flow)
  getSSOUrl: (type: 'oidc' | 'saml', providerId: string) =>
    `/api/auth/sso/${type}/${encodeURIComponent(providerId)}`,

  // LDAP authentication (takes username/password directly)
  authenticateLdap: (providerId: string, username: string, password: string) =>
    request<{ authenticated: boolean; user: { username: string; role: string; vhost_scope: string[] } }>(
      `/auth/sso/ldap/${encodeURIComponent(providerId)}`,
      {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      }
    ),
}

// Status API
export const statusApi = {
  get: () => request<ApiResponse<unknown>>('/status'),
}

// Vhost Timing Configuration
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

export interface VhostTimingResponse {
  vhost_id: string
  timing: VhostTimingConfig
  resolved_timing: VhostTimingConfig
  cookie_name: string | null
}

// Vhosts API
export const vhostsApi = {
  list: () => request<ApiResponse<{ vhosts: unknown[] }>>('/vhosts'),

  get: (id: string) => request<ApiResponse<unknown>>(`/vhosts/${id}`),

  create: (data: unknown) =>
    request<ApiResponse<unknown>>('/vhosts', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (id: string, data: unknown) =>
    request<ApiResponse<unknown>>(`/vhosts/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  delete: (id: string) =>
    request<ApiResponse<null>>(`/vhosts/${id}`, { method: 'DELETE' }),

  enable: (id: string) =>
    request<ApiResponse<null>>(`/vhosts/${id}/enable`, { method: 'POST' }),

  disable: (id: string) =>
    request<ApiResponse<null>>(`/vhosts/${id}/disable`, { method: 'POST' }),

  match: (host: string) =>
    request<ApiResponse<unknown>>(`/vhosts/match?host=${encodeURIComponent(host)}`),

  context: (host: string, path: string, method: string = 'POST') =>
    request<ApiResponse<unknown>>(
      `/vhosts/context?host=${encodeURIComponent(host)}&path=${encodeURIComponent(path)}&method=${method}`
    ),

  // Timing configuration per vhost
  getTiming: (id: string) =>
    request<VhostTimingResponse>(`/vhosts/${id}/timing`),

  updateTiming: (id: string, data: VhostTimingConfig) =>
    request<{ updated: boolean; vhost_id: string; timing: VhostTimingConfig }>(`/vhosts/${id}/timing`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  deleteTiming: (id: string) =>
    request<{ deleted: boolean; vhost_id: string }>(`/vhosts/${id}/timing`, {
      method: 'DELETE',
    }),
}

// Endpoints API
export const endpointsApi = {
  list: (vhostId?: string) => {
    const params = vhostId ? `?vhost_id=${encodeURIComponent(vhostId)}` : ''
    return request<ApiResponse<{ endpoints: unknown[]; global_count?: number }>>(`/endpoints${params}`)
  },

  get: (id: string) => request<ApiResponse<unknown>>(`/endpoints/${id}`),

  create: (data: unknown) =>
    request<ApiResponse<unknown>>('/endpoints', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (id: string, data: unknown) =>
    request<ApiResponse<unknown>>(`/endpoints/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  delete: (id: string) =>
    request<ApiResponse<null>>(`/endpoints/${id}`, { method: 'DELETE' }),

  enable: (id: string) =>
    request<ApiResponse<null>>(`/endpoints/${id}/enable`, { method: 'POST' }),

  disable: (id: string) =>
    request<ApiResponse<null>>(`/endpoints/${id}/disable`, { method: 'POST' }),

  match: (path: string, method: string = 'POST') =>
    request<ApiResponse<unknown>>(
      `/endpoints/match?path=${encodeURIComponent(path)}&method=${method}`
    ),
}

// Keywords API
export const keywordsApi = {
  getBlocked: () =>
    request<ApiResponse<{ keywords: string[] }>>('/keywords/blocked'),

  addBlocked: (keyword: string) =>
    request<ApiResponse<null>>('/keywords/blocked', {
      method: 'POST',
      body: JSON.stringify({ keyword }),
    }),

  removeBlocked: (keyword: string) =>
    request<ApiResponse<null>>('/keywords/blocked', {
      method: 'DELETE',
      body: JSON.stringify({ keyword }),
    }),

  editBlocked: (oldKeyword: string, newKeyword: string) =>
    request<ApiResponse<{ updated: boolean; old_keyword: string; new_keyword: string }>>('/keywords/blocked', {
      method: 'PUT',
      body: JSON.stringify({ old_keyword: oldKeyword, new_keyword: newKeyword }),
    }),

  getFlagged: () =>
    request<ApiResponse<{ keywords: string[] }>>('/keywords/flagged'),

  addFlagged: (keyword: string, score: number) =>
    request<ApiResponse<null>>('/keywords/flagged', {
      method: 'POST',
      body: JSON.stringify({ keyword, score }),
    }),

  removeFlagged: (keyword: string) =>
    request<ApiResponse<null>>('/keywords/flagged', {
      method: 'DELETE',
      body: JSON.stringify({ keyword }),
    }),

  editFlagged: (oldKeyword: string, newKeyword?: string, newScore?: number) =>
    request<ApiResponse<{ updated: boolean; old_keyword: string; new_keyword: string }>>('/keywords/flagged', {
      method: 'PUT',
      body: JSON.stringify({ old_keyword: oldKeyword, new_keyword: newKeyword, new_score: newScore }),
    }),
}

// Config API
export const configApi = {
  getThresholds: () =>
    request<ApiResponse<Record<string, number>>>('/config/thresholds'),

  setThreshold: (name: string, value: number) =>
    request<ApiResponse<null>>('/config/thresholds', {
      method: 'POST',
      body: JSON.stringify({ name, value }),
    }),

  getRouting: () =>
    request<{ routing: GlobalRouting; defaults: GlobalRouting }>('/config/routing'),

  updateRouting: (data: Partial<GlobalRouting>) =>
    request<ApiResponse<null>>('/config/routing', {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  // IP Allow List (backend endpoint still uses /whitelist for compatibility)
  getAllowedIps: () =>
    request<ApiResponse<{ ips: string[] }>>('/whitelist/ips'),

  addAllowedIp: (ip: string) =>
    request<ApiResponse<null>>('/whitelist/ips', {
      method: 'POST',
      body: JSON.stringify({ ip }),
    }),

  removeAllowedIp: (ip: string) =>
    request<ApiResponse<null>>('/whitelist/ips', {
      method: 'DELETE',
      body: JSON.stringify({ ip }),
    }),
}

// Sync API
export const syncApi = {
  force: () => request<ApiResponse<null>>('/sync', { method: 'POST' }),
}

// Metrics API
export interface GlobalMetrics {
  total_requests: number
  blocked_requests: number
  monitored_requests: number
  allowed_requests: number
  skipped_requests: number
  form_submissions: number
  validation_errors: number
  instance_count: number
  last_updated?: string  // Optional: may be undefined if timestamp key doesn't exist
}

export interface MetricsSummary {
  total_requests: number
  blocked_requests: number
  monitored_requests: number
  allowed_requests: number
  skipped_requests: number
  form_submissions: number
  validation_errors: number
  by_vhost: Record<string, { total: number; blocked: number; monitored: number; allowed: number }>
  by_endpoint: Record<string, { total: number; blocked: number; monitored: number; allowed: number }>
  // Global cluster-wide metrics (optional, only available in multi-instance deployments)
  global?: GlobalMetrics
}

export const metricsApi = {
  get: () => request<MetricsSummary>('/metrics'),
  reset: () => request<{ success: boolean; message: string }>('/metrics/reset', { method: 'POST' }),
}

// Learning API - Field learning data
export interface LearnedField {
  name: string
  type: string
  count: number
  first_seen?: number
  last_seen?: number
  endpoints?: string[]  // Only for vhost-level
}

export interface LearnedFieldsResponse {
  endpoint_id?: string
  vhost_id?: string
  fields: LearnedField[]
  count: number
  learning_stats: {
    batch_count: number
    cache_available: boolean
  }
}

export const learningApi = {
  // Endpoint learning
  getEndpointFields: (endpointId: string) =>
    request<LearnedFieldsResponse>(`/endpoints/learned-fields?endpoint_id=${encodeURIComponent(endpointId)}`),

  clearEndpointFields: (endpointId: string) =>
    request<{ cleared: boolean; endpoint_id: string }>(`/endpoints/learned-fields?endpoint_id=${encodeURIComponent(endpointId)}`, {
      method: 'DELETE',
    }),

  // Vhost learning
  getVhostFields: (vhostId: string) =>
    request<LearnedFieldsResponse>(`/vhosts/learned-fields?vhost_id=${encodeURIComponent(vhostId)}`),

  clearVhostFields: (vhostId: string) =>
    request<{ cleared: boolean; vhost_id: string }>(`/vhosts/learned-fields?vhost_id=${encodeURIComponent(vhostId)}`, {
      method: 'DELETE',
    }),

  // Stats
  getStats: () =>
    request<{ stats: { batch_count: number; cache_available: boolean } }>('/learning/stats'),
}

// CAPTCHA API - Provider and configuration management
import type {
  CaptchaProvider,
  CaptchaGlobalConfig,
  CaptchaConfigResponse,
} from './types'

export interface CaptchaProviderTestResult {
  provider_id: string
  success: boolean
  message: string
}

// Webhooks API - Notification management
export interface WebhookConfig {
  enabled: boolean
  url?: string
  urls?: string[]
  events: string[]
  batch_size: number
  batch_interval: number
  headers?: Record<string, string>
  ssl_verify?: boolean
}

export interface WebhookStats {
  queue_size: number
  last_flush: number
  max_queue_size: number
}

export const webhooksApi = {
  getConfig: () =>
    request<{ config: WebhookConfig; defaults: WebhookConfig }>('/webhooks/config'),

  updateConfig: (data: Partial<WebhookConfig>) =>
    request<{ updated: boolean; config: WebhookConfig }>('/webhooks/config', {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  test: () =>
    request<{ success: boolean; message: string; response_code?: number }>('/webhooks/test', {
      method: 'POST',
    }),

  getStats: () =>
    request<{ stats: WebhookStats }>('/webhooks/stats'),
}

// Bulk Operations API - Import/Export
export interface BulkExportData {
  keywords?: string[]
  ips?: string[]
  hashes?: string[]
  exported_at?: string
}

export const bulkApi = {
  // Export
  exportKeywords: () =>
    request<{ keywords: string[]; count: number }>('/bulk/export/keywords'),

  exportIps: () =>
    request<{ ips: string[]; count: number }>('/bulk/export/ips'),

  exportHashes: () =>
    request<{ hashes: string[]; count: number }>('/bulk/export/hashes'),

  exportAll: () =>
    request<BulkExportData>('/bulk/export/all'),

  // Import
  importKeywords: (keywords: string[], merge: boolean = true) =>
    request<{ imported: number; skipped: number; total: number }>('/bulk/import/keywords', {
      method: 'POST',
      body: JSON.stringify({ keywords, merge }),
    }),

  importIps: (ips: string[], merge: boolean = true) =>
    request<{ imported: number; skipped: number; invalid: number; total: number }>('/bulk/import/ips', {
      method: 'POST',
      body: JSON.stringify({ ips, merge }),
    }),

  importHashes: (hashes: string[], merge: boolean = true) =>
    request<{ imported: number; skipped: number; invalid: number; total: number }>('/bulk/import/hashes', {
      method: 'POST',
      body: JSON.stringify({ hashes, merge }),
    }),

  // Clear
  clearKeywords: (confirm: boolean = false) =>
    request<{ cleared: boolean; count: number }>(`/bulk/clear/keywords?confirm=${confirm}`, {
      method: 'DELETE',
    }),
}

// GeoIP API
export interface GeoIPStatus {
  enabled: boolean
  mmdb_available: boolean
  country_db_loaded: boolean
  asn_db_loaded: boolean
  country_db_path: string
  asn_db_path: string
  datacenter_asns_count: number
}

export interface GeoIPConfig {
  enabled: boolean
  country_db_path?: string
  asn_db_path?: string
  default_action?: 'allow' | 'block' | 'flag'
  blocked_countries?: string[]
  allowed_countries?: string[]
  flagged_countries?: string[]
  flagged_country_score?: number
  blocked_asns?: number[]
  flagged_asns?: number[]
  flagged_asn_score?: number
  block_datacenters?: boolean
  flag_datacenters?: boolean
  datacenter_score?: number
}

export interface GeoIPLookupResult {
  ip: string
  country?: { country_code: string; country_name: string } | null
  asn?: { asn: number; org: string } | null
  is_datacenter: boolean
  datacenter_provider?: string | null
}

export const geoipApi = {
  getStatus: () =>
    request<GeoIPStatus>('/geoip/status'),

  getConfig: () =>
    request<GeoIPConfig>('/geoip/config'),

  updateConfig: (data: Partial<GeoIPConfig>) =>
    request<{ success: boolean; config: GeoIPConfig }>('/geoip/config', {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  reload: () =>
    request<{ success: boolean; status: GeoIPStatus }>('/geoip/reload', {
      method: 'POST',
    }),

  lookup: (ip: string) =>
    request<GeoIPLookupResult | { available: false; message: string }>(`/geoip/lookup?ip=${encodeURIComponent(ip)}`),
}

// IP Reputation API
export interface IPReputationStatus {
  enabled: boolean
  providers: {
    local_blocklist: boolean
    abuseipdb: boolean
    webhook: boolean
  }
  blocklist_count: number
  block_score: number
  flag_score: number
}

export interface IPReputationConfig {
  enabled: boolean
  cache_ttl?: number
  cache_negative_ttl?: number
  abuseipdb?: {
    enabled: boolean
    api_key?: string
    min_confidence?: number
    max_age_days?: number
    score_multiplier?: number
  }
  local_blocklist?: {
    enabled: boolean
    redis_key?: string
  }
  webhook?: {
    enabled: boolean
    url?: string
    timeout?: number
    headers?: Record<string, string>
  }
  block_score?: number
  flag_score?: number
  flag_score_addition?: number
}

export interface IPReputationCheckResult {
  ip: string
  result: {
    score: number
    blocked: boolean
    reason?: string
    flags: string[]
    details?: Record<string, unknown>
  }
}

export const reputationApi = {
  getStatus: () =>
    request<IPReputationStatus>('/reputation/status'),

  getConfig: () =>
    request<IPReputationConfig>('/reputation/config'),

  updateConfig: (data: Partial<IPReputationConfig>) =>
    request<{ success: boolean; config: IPReputationConfig }>('/reputation/config', {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  checkIP: (ip: string) =>
    request<IPReputationCheckResult | { available: false; message: string }>(`/reputation/check?ip=${encodeURIComponent(ip)}`),

  getBlocklist: () =>
    request<{ blocked_ips: string[] }>('/reputation/blocklist'),

  addToBlocklist: (ip: string, reason?: string) =>
    request<{ success: boolean; ip: string; reason?: string }>('/reputation/blocklist', {
      method: 'POST',
      body: JSON.stringify({ ip, reason }),
    }),

  removeFromBlocklist: (ip: string) =>
    request<{ success: boolean; ip: string }>('/reputation/blocklist', {
      method: 'DELETE',
      body: JSON.stringify({ ip }),
    }),

  clearCache: (ip: string) =>
    request<{ success: boolean; ip: string; message: string }>('/reputation/cache', {
      method: 'DELETE',
      body: JSON.stringify({ ip }),
    }),
}

// Timing Token API
export interface TimingTokenConfig {
  enabled: boolean
  cookie_name?: string
  cookie_ttl?: number
  encryption_key?: string
  min_time_block?: number
  min_time_flag?: number
  score_no_cookie?: number
  score_too_fast?: number
  score_suspicious?: number
}

export interface TimingVhostItem {
  vhost_id: string
  name?: string
  hostnames?: string[]
  timing: VhostTimingConfig
  cookie_name: string
}

export const timingApi = {
  getStatus: () =>
    request<{ enabled: boolean; config: TimingTokenConfig }>('/timing/status'),

  getConfig: () =>
    request<TimingTokenConfig>('/timing/config'),

  updateConfig: (data: Partial<TimingTokenConfig>) =>
    request<{ success: boolean; config: TimingTokenConfig }>('/timing/config', {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  // List all vhosts with timing enabled
  listVhosts: () =>
    request<{ vhosts: TimingVhostItem[]; total: number }>('/timing/vhosts'),
}

export const captchaApi = {
  // Provider CRUD
  listProviders: () =>
    request<{ providers: CaptchaProvider[] }>('/captcha/providers'),

  getProvider: (id: string) =>
    request<{ provider: CaptchaProvider }>(`/captcha/providers/${id}`),

  createProvider: (data: Omit<CaptchaProvider, 'id' | 'metadata'>) =>
    request<{ created: boolean; provider: CaptchaProvider }>('/captcha/providers', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  updateProvider: (id: string, data: Partial<CaptchaProvider>) =>
    request<{ updated: boolean; provider: CaptchaProvider }>(`/captcha/providers/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  deleteProvider: (id: string) =>
    request<{ deleted: boolean; provider_id: string }>(`/captcha/providers/${id}`, {
      method: 'DELETE',
    }),

  // Provider actions
  enableProvider: (id: string) =>
    request<{ enabled: boolean; provider_id: string }>(`/captcha/providers/${id}/enable`, {
      method: 'POST',
    }),

  disableProvider: (id: string) =>
    request<{ disabled: boolean; provider_id: string }>(`/captcha/providers/${id}/disable`, {
      method: 'POST',
    }),

  testProvider: (id: string) =>
    request<CaptchaProviderTestResult>(`/captcha/providers/${id}/test`, {
      method: 'POST',
    }),

  // Global configuration
  getConfig: () =>
    request<CaptchaConfigResponse>('/captcha/config'),

  updateConfig: (data: Partial<CaptchaGlobalConfig>) =>
    request<{ updated: boolean; fields: string[] }>('/captcha/config', {
      method: 'PUT',
      body: JSON.stringify(data),
    }),
}

// Behavioral Tracking API
import type {
  BehavioralStats,
  BehavioralBaseline,
  BehavioralFlow,
  BehavioralVhostSummary,
} from './types'

export interface BehavioralVhostItem {
  vhost_id: string
  name?: string
  hostnames?: string[]
  flows: string[]
  tracking?: {
    fill_duration?: boolean
    submission_counts?: boolean
    unique_ips?: boolean
    avg_spam_score?: boolean
  }
  anomaly_detection?: {
    enabled?: boolean
    std_dev_threshold?: number
    action?: 'flag' | 'score'
    score_addition?: number
  }
}

export const behavioralApi = {
  // Get stats for a specific flow
  getStats: (vhostId: string, flowName: string, bucketType: 'hour' | 'day' | 'week' | 'month' | 'year' = 'hour', count: number = 24) =>
    request<{
      vhost_id: string
      flow_name: string
      bucket_type: string
      count: number
      stats: BehavioralStats[]
    }>(`/behavioral/stats?vhost_id=${encodeURIComponent(vhostId)}&flow_name=${encodeURIComponent(flowName)}&bucket_type=${bucketType}&count=${count}`),

  // Get baseline data for a flow
  getBaseline: (vhostId: string, flowName: string) =>
    request<{
      vhost_id: string
      flow_name: string
      baseline: BehavioralBaseline | null
      status: 'ready' | 'learning' | 'no_data'
      message?: string
    }>(`/behavioral/baseline?vhost_id=${encodeURIComponent(vhostId)}&flow_name=${encodeURIComponent(flowName)}`),

  // Force baseline recalculation
  recalculateBaseline: (vhostId: string, flowName?: string) => {
    const params = flowName
      ? `?vhost_id=${encodeURIComponent(vhostId)}&flow_name=${encodeURIComponent(flowName)}`
      : `?vhost_id=${encodeURIComponent(vhostId)}`
    return request<{
      vhost_id: string
      flow_name: string
      results: Record<string, { success: boolean; error?: string }>
    }>(`/behavioral/recalculate${params}`, { method: 'POST' })
  },

  // Get all flows for a vhost
  getFlows: (vhostId: string) =>
    request<{
      vhost_id: string
      flows: string[]
      configs: Record<string, BehavioralFlow>
    }>(`/behavioral/flows?vhost_id=${encodeURIComponent(vhostId)}`),

  // List all vhosts with behavioral tracking enabled
  listVhosts: () =>
    request<{ vhosts: BehavioralVhostItem[]; total: number }>('/behavioral/vhosts'),

  // Get summary of behavioral tracking status
  getSummary: (vhostId?: string) => {
    const params = vhostId ? `?vhost_id=${encodeURIComponent(vhostId)}` : ''
    return request<{
      total_tracked_vhosts: number
      vhosts: BehavioralVhostSummary[]
    }>(`/behavioral/summary${params}`)
  },
}

// Cluster types
export interface ClusterInstance {
  instance_id: string
  started_at: number
  last_heartbeat: number
  status: 'active' | 'drifted' | 'down' | 'unknown'
  worker_count: number
}

export interface ClusterStatus {
  cluster_healthy: boolean
  instance_count: number
  active_instances: number
  drifted_instances: number
  leader: {
    instance_id: string
    since: number
  } | null
}

export interface ClusterConfig {
  instance_id: string
  heartbeat_interval: number
  heartbeat_ttl: number
  leader_ttl: number
  drift_threshold: number
  stale_threshold: number
}

export interface ClusterThisInstance {
  instance_id: string
  is_leader: boolean
  worker_id: number
  worker_count: number
  config: {
    heartbeat_interval: number
    leader_ttl: number
    drift_threshold: number
    stale_threshold: number
  }
}

export const clusterApi = {
  // Get cluster health status
  getStatus: () =>
    request<ClusterStatus>('/cluster/status'),

  // List all registered instances
  getInstances: () =>
    request<{
      instances: ClusterInstance[]
      total: number
      current_leader: string | null
    }>('/cluster/instances'),

  // Get current leader info
  getLeader: () =>
    request<{
      leader: string | null
      this_instance: {
        id: string
        is_leader: boolean
      }
    }>('/cluster/leader'),

  // Get coordinator configuration
  getConfig: () =>
    request<ClusterConfig>('/cluster/config'),

  // Get info about this instance
  getThis: () =>
    request<ClusterThisInstance>('/cluster/this'),
}

// Fingerprint Profiles API
import type {
  FingerprintProfile,
  FingerprintProfileTestRequest,
  FingerprintProfileTestResult,
  DefenseProfile,
  DefenseMetadata,
  OperatorMetadata,
  ActionMetadata,
  DefenseProfileSimulationResult,
  DefenseProfileValidationResult,
  AttackSignature,
  AttackSignatureListResponse,
  AttackSignatureResponse,
  AttackSignatureCreateResponse,
  AttackSignatureUpdateResponse,
  AttackSignatureDeleteResponse,
  AttackSignatureCloneResponse,
  AttackSignatureEnableResponse,
  AttackSignatureDisableResponse,
  AttackSignatureStatsResponse,
  AttackSignatureTestResponse,
  AttackSignatureBuiltinsResponse,
  AttackSignatureResetBuiltinsResponse,
  AttackSignatureTagsResponse,
  AttackSignatureExportResponse,
  AttackSignatureImportResponse,
  AttackSignatureValidateResponse,
  AttackSignatureStatsSummaryResponse,
} from './types'

export const fingerprintProfilesApi = {
  // List all profiles
  list: () =>
    request<{ profiles: FingerprintProfile[] }>('/fingerprint-profiles'),

  // Get a single profile
  get: (id: string) =>
    request<{ profile: FingerprintProfile }>(`/fingerprint-profiles/${encodeURIComponent(id)}`),

  // Create a custom profile
  create: (data: Omit<FingerprintProfile, 'builtin'>) =>
    request<{ created: boolean; profile: FingerprintProfile }>('/fingerprint-profiles', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Update a profile
  update: (id: string, data: Partial<FingerprintProfile>) =>
    request<{ updated: boolean; profile: FingerprintProfile }>(`/fingerprint-profiles/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  // Delete a custom profile (built-in profiles cannot be deleted)
  delete: (id: string) =>
    request<{ deleted: boolean; id: string }>(`/fingerprint-profiles/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  // Test profile matching
  test: (data: FingerprintProfileTestRequest) =>
    request<FingerprintProfileTestResult>('/fingerprint-profiles/test', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Reset built-in profiles to defaults
  resetBuiltin: () =>
    request<{ reset: boolean; count: number }>('/fingerprint-profiles/reset-builtin', {
      method: 'POST',
    }),
}

// Defense Profiles API
export const defenseProfilesApi = {
  // List all profiles
  list: () =>
    request<{ profiles: DefenseProfile[] }>('/defense-profiles'),

  // Get a single profile
  get: (id: string) =>
    request<{ profile: DefenseProfile }>(`/defense-profiles/${encodeURIComponent(id)}`),

  // Get profile with inheritance resolved
  getResolved: (id: string) =>
    request<{ profile: DefenseProfile }>(`/defense-profiles/${encodeURIComponent(id)}/resolved`),

  // Create a profile
  create: (data: Omit<DefenseProfile, 'builtin'>) =>
    request<{ created: boolean; profile: DefenseProfile }>('/defense-profiles', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Update a profile
  update: (id: string, data: Partial<DefenseProfile>) =>
    request<{ updated: boolean; profile: DefenseProfile }>(`/defense-profiles/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  // Delete a profile (built-in profiles cannot be deleted)
  delete: (id: string) =>
    request<{ deleted: boolean; id: string }>(`/defense-profiles/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  // Clone a profile
  clone: (sourceId: string, newId: string, newName?: string) =>
    request<{ cloned: boolean; profile: DefenseProfile }>(`/defense-profiles/${encodeURIComponent(sourceId)}/clone`, {
      method: 'POST',
      body: JSON.stringify({ id: newId, name: newName }),
    }),

  // Enable/disable a profile
  enable: (id: string) =>
    request<{ enabled: boolean; profile: DefenseProfile }>(`/defense-profiles/${encodeURIComponent(id)}/enable`, {
      method: 'POST',
    }),

  disable: (id: string) =>
    request<{ disabled: boolean; profile: DefenseProfile }>(`/defense-profiles/${encodeURIComponent(id)}/disable`, {
      method: 'POST',
    }),

  // Get built-in profile IDs
  getBuiltins: () =>
    request<{ builtin_ids: string[] }>('/defense-profiles/builtins'),

  // Validate a profile graph
  validate: (profile: Partial<DefenseProfile>) =>
    request<DefenseProfileValidationResult>('/defense-profiles/validate', {
      method: 'POST',
      body: JSON.stringify(profile),
    }),

  // Simulate request through a profile
  simulate: (profileId: string, requestData: {
    form_data?: Record<string, unknown>
    client_ip?: string
    host?: string
    path?: string
    method?: string
    headers?: Record<string, string>
  }) =>
    request<{ valid: boolean; simulation?: DefenseProfileSimulationResult; errors?: string[] }>('/defense-profiles/simulate', {
      method: 'POST',
      body: JSON.stringify({ profile_id: profileId, ...requestData }),
    }),

  // Get metadata for UI
  getMetadata: () =>
    request<{
      defenses: Record<string, DefenseMetadata>
      operators: Record<string, OperatorMetadata>
      actions: Record<string, ActionMetadata>
    }>('/defense-profiles/metadata'),

  // Reset built-in profiles to defaults
  resetBuiltins: () =>
    request<{ reset: boolean; count: number }>('/defense-profiles/reset-builtins', {
      method: 'POST',
    }),
}

// Attack Signatures API
export interface AttackSignatureListOptions {
  tag?: string
  active?: boolean
  enabled?: boolean
  include_stats?: boolean
}

export const attackSignaturesApi = {
  // List all signatures
  list: (options?: AttackSignatureListOptions) => {
    const params = new URLSearchParams()
    if (options?.tag) params.append('tag', options.tag)
    if (options?.active !== undefined) params.append('active', String(options.active))
    if (options?.enabled !== undefined) params.append('enabled', String(options.enabled))
    if (options?.include_stats !== undefined) params.append('include_stats', String(options.include_stats))
    const query = params.toString()
    return request<AttackSignatureListResponse>(`/attack-signatures${query ? `?${query}` : ''}`)
  },

  // Get a single signature
  get: (id: string) =>
    request<AttackSignatureResponse>(`/attack-signatures/${encodeURIComponent(id)}`),

  // Create a signature
  create: (data: Omit<AttackSignature, 'builtin' | 'builtin_version' | 'stats' | 'created_at' | 'updated_at'>) =>
    request<AttackSignatureCreateResponse>('/attack-signatures', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Update a signature
  update: (id: string, data: Partial<AttackSignature>) =>
    request<AttackSignatureUpdateResponse>(`/attack-signatures/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  // Delete a signature (built-in signatures cannot be deleted)
  delete: (id: string) =>
    request<AttackSignatureDeleteResponse>(`/attack-signatures/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  // Clone a signature
  clone: (sourceId: string, newId: string, newName?: string) =>
    request<AttackSignatureCloneResponse>(`/attack-signatures/${encodeURIComponent(sourceId)}/clone`, {
      method: 'POST',
      body: JSON.stringify({ id: newId, name: newName }),
    }),

  // Enable/disable a signature
  enable: (id: string) =>
    request<AttackSignatureEnableResponse>(`/attack-signatures/${encodeURIComponent(id)}/enable`, {
      method: 'POST',
    }),

  disable: (id: string) =>
    request<AttackSignatureDisableResponse>(`/attack-signatures/${encodeURIComponent(id)}/disable`, {
      method: 'POST',
    }),

  // Get signature statistics
  getStats: (id: string) =>
    request<AttackSignatureStatsResponse>(`/attack-signatures/${encodeURIComponent(id)}/stats`),

  // Test signature against sample data
  test: (id: string, sample: {
    user_agent?: string
    content?: string
    username?: string
    password?: string
  }) =>
    request<AttackSignatureTestResponse>(`/attack-signatures/${encodeURIComponent(id)}/test`, {
      method: 'POST',
      body: JSON.stringify({ sample }),
    }),

  // Get overall stats summary
  getStatsSummary: () =>
    request<AttackSignatureStatsSummaryResponse>('/attack-signatures/stats/summary'),

  // Get built-in signature IDs
  getBuiltins: () =>
    request<AttackSignatureBuiltinsResponse>('/attack-signatures/builtins'),

  // Reset built-in signatures to defaults
  resetBuiltins: () =>
    request<AttackSignatureResetBuiltinsResponse>('/attack-signatures/reset-builtins', {
      method: 'POST',
    }),

  // Get all tags with counts
  getTags: () =>
    request<AttackSignatureTagsResponse>('/attack-signatures/tags'),

  // Export signatures
  export: (ids?: string[]) => {
    const params = ids?.length ? `?ids=${ids.join(',')}` : ''
    return request<AttackSignatureExportResponse>(`/attack-signatures/export${params}`)
  },

  // Import signatures
  import: (signatures: AttackSignature[], options?: { overwrite?: boolean; skip_existing?: boolean }) =>
    request<AttackSignatureImportResponse>('/attack-signatures/import', {
      method: 'POST',
      body: JSON.stringify({ signatures, ...options }),
    }),

  // Validate a signature
  validate: (signature: Partial<AttackSignature>) =>
    request<AttackSignatureValidateResponse>('/attack-signatures/validate', {
      method: 'POST',
      body: JSON.stringify(signature),
    }),
}

// Backup and Restore API
import type {
  Backup,
  BackupEntityInfo,
  BackupExportOptions,
  BackupImportMode,
  BackupImportResponse,
  BackupValidationResult,
} from './types'

export const backupApi = {
  // Get available entity types
  getEntities: () =>
    request<{ entities: BackupEntityInfo[] }>('/backup/entities'),

  // Export configuration
  export: (options?: BackupExportOptions) => {
    const params = new URLSearchParams()
    if (options?.include_users !== undefined) params.append('include_users', String(options.include_users))
    if (options?.include_builtins !== undefined) params.append('include_builtins', String(options.include_builtins))
    if (options?.entities?.length) params.append('entities', options.entities.join(','))
    const query = params.toString()
    return request<Backup>(`/backup/export${query ? `?${query}` : ''}`)
  },

  // Validate backup file
  validate: (backup: Backup) =>
    request<BackupValidationResult>('/backup/validate', {
      method: 'POST',
      body: JSON.stringify(backup),
    }),

  // Import configuration
  import: (backup: Backup, mode: BackupImportMode = 'merge', includeUsers: boolean = true) =>
    request<BackupImportResponse>('/backup/import', {
      method: 'POST',
      body: JSON.stringify({
        backup,
        mode,
        include_users: includeUsers,
      }),
    }),

  // Download backup as file (helper)
  downloadExport: async (options?: BackupExportOptions) => {
    const backup = await backupApi.export(options)
    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `waf-backup-${new Date().toISOString().slice(0, 19).replace(/[:-]/g, '')}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    return backup
  },
}
