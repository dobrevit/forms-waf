import type { ApiResponse } from './types'

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

// Status API
export const statusApi = {
  get: () => request<ApiResponse<unknown>>('/status'),
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
    request<{ routing: { haproxy_upstream: string; haproxy_timeout?: number }; defaults: { haproxy_upstream: string; haproxy_timeout: number } }>('/config/routing'),

  updateRouting: (data: { haproxy_upstream?: string; haproxy_timeout?: number }) =>
    request<ApiResponse<null>>('/config/routing', {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  getWhitelistedIps: () =>
    request<ApiResponse<{ ips: string[] }>>('/whitelist/ips'),

  addWhitelistedIp: (ip: string) =>
    request<ApiResponse<null>>('/whitelist/ips', {
      method: 'POST',
      body: JSON.stringify({ ip }),
    }),

  removeWhitelistedIp: (ip: string) =>
    request<ApiResponse<null>>('/whitelist/ips', {
      method: 'DELETE',
      body: JSON.stringify({ ip }),
    }),
}

// Sync API
export const syncApi = {
  force: () => request<ApiResponse<null>>('/sync', { method: 'POST' }),
}
