import { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react'
import { authApi } from '@/api/client'
import type { User, UserRole, RolePermissions } from '@/api/types'

// Default role permissions (should match backend rbac.lua)
const DEFAULT_PERMISSIONS: Record<UserRole, RolePermissions> = {
  admin: {
    vhosts: ['create', 'read', 'update', 'delete', 'enable', 'disable'],
    endpoints: ['create', 'read', 'update', 'delete', 'enable', 'disable'],
    keywords: ['create', 'read', 'update', 'delete'],
    config: ['read', 'update'],
    users: ['create', 'read', 'update', 'delete'],
    providers: ['create', 'read', 'update', 'delete'],
    logs: ['read'],
    metrics: ['read', 'reset'],
    bulk: ['import', 'export', 'clear'],
    captcha: ['create', 'read', 'update', 'delete', 'enable', 'disable', 'test'],
    webhooks: ['read', 'update', 'test'],
    geoip: ['read', 'update', 'reload'],
    reputation: ['read', 'update'],
    timing: ['read', 'update'],
    sync: ['execute'],
    status: ['read'],
    hashes: ['read', 'create'],
    whitelist: ['read', 'create'],
  },
  operator: {
    vhosts: ['read', 'update', 'enable', 'disable'],
    endpoints: ['create', 'read', 'update', 'delete', 'enable', 'disable'],
    keywords: ['create', 'read', 'update', 'delete'],
    config: ['read'],
    logs: ['read'],
    metrics: ['read'],
    bulk: ['import', 'export'],
    captcha: ['read'],
    webhooks: ['read'],
    geoip: ['read'],
    reputation: ['read'],
    timing: ['read'],
    status: ['read'],
    hashes: ['read', 'create'],
    whitelist: ['read'],
  },
  viewer: {
    vhosts: ['read'],
    endpoints: ['read'],
    keywords: ['read'],
    config: ['read'],
    logs: ['read'],
    metrics: ['read'],
    captcha: ['read'],
    webhooks: ['read'],
    geoip: ['read'],
    reputation: ['read'],
    timing: ['read'],
    status: ['read'],
    hashes: ['read'],
    whitelist: ['read'],
  },
}

interface AuthContextType {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>
  // Permission helpers
  hasPermission: (resource: keyof RolePermissions, action: string) => boolean
  hasVhostAccess: (vhostId: string) => boolean
  permissions: RolePermissions
  isAdmin: boolean
  isOperator: boolean
  isViewer: boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const verifySession = useCallback(async () => {
    try {
      const response = await authApi.verify()
      if (response.data?.user) {
        setUser(response.data.user as User)
      }
    } catch {
      setUser(null)
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    verifySession()
  }, [verifySession])

  const login = async (username: string, password: string) => {
    const response = await authApi.login(username, password)
    if (response.data?.user) {
      setUser(response.data.user as User)
    }
  }

  const logout = async () => {
    await authApi.logout()
    setUser(null)
  }

  const changePassword = async (currentPassword: string, newPassword: string) => {
    await authApi.changePassword(currentPassword, newPassword)
    if (user) {
      setUser({ ...user, must_change_password: false })
    }
  }

  // Get permissions for current user's role
  const permissions = useMemo((): RolePermissions => {
    if (!user?.role) return {}
    return DEFAULT_PERMISSIONS[user.role] || {}
  }, [user?.role])

  // Check if user has a specific permission
  const hasPermission = useCallback(
    (resource: keyof RolePermissions, action: string): boolean => {
      if (!user?.role) return false
      const resourcePerms = permissions[resource]
      if (!resourcePerms) return false
      return resourcePerms.includes(action)
    },
    [user?.role, permissions]
  )

  // Check if user has access to a specific vhost
  const hasVhostAccess = useCallback(
    (vhostId: string): boolean => {
      if (!user?.vhost_scope) return false
      // Global access
      if (user.vhost_scope.includes('*')) return true
      // Specific vhost access
      return user.vhost_scope.includes(vhostId)
    },
    [user?.vhost_scope]
  )

  // Role convenience helpers
  const isAdmin = user?.role === 'admin'
  const isOperator = user?.role === 'operator'
  const isViewer = user?.role === 'viewer'

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout,
        changePassword,
        hasPermission,
        hasVhostAccess,
        permissions,
        isAdmin,
        isOperator,
        isViewer,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
