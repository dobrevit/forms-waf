import { useMemo } from 'react'
import { useAuth } from '@/context/AuthContext'

/**
 * Hook for checking user permissions in components.
 *
 * Usage:
 * ```tsx
 * function VhostList() {
 *   const { canCreateVhost, canEditVhost, canDeleteVhost, isReadOnly } = usePermissions()
 *
 *   return (
 *     <>
 *       {canCreateVhost && <Button>Create Vhost</Button>}
 *       {vhosts.map(vhost => (
 *         <>
 *           {canEditVhost(vhost.id) && <EditButton />}
 *           {canDeleteVhost(vhost.id) && <DeleteButton />}
 *         </>
 *       ))}
 *     </>
 *   )
 * }
 * ```
 */
export function usePermissions() {
  const { hasPermission, hasVhostAccess, isAdmin, isOperator, isViewer, user } = useAuth()

  return useMemo(() => ({
    // Role checks
    isAdmin,
    isOperator,
    isViewer,
    isReadOnly: isViewer,

    // Vhost permissions
    canCreateVhost: hasPermission('vhosts', 'create'),
    canEditVhost: (vhostId: string) =>
      hasPermission('vhosts', 'update') && hasVhostAccess(vhostId),
    canDeleteVhost: (vhostId: string) =>
      hasPermission('vhosts', 'delete') && hasVhostAccess(vhostId),
    canEnableVhost: (vhostId: string) =>
      hasPermission('vhosts', 'enable') && hasVhostAccess(vhostId),
    canDisableVhost: (vhostId: string) =>
      hasPermission('vhosts', 'disable') && hasVhostAccess(vhostId),
    canViewVhost: (vhostId: string) =>
      hasPermission('vhosts', 'read') && hasVhostAccess(vhostId),

    // Endpoint permissions
    canCreateEndpoint: hasPermission('endpoints', 'create'),
    canEditEndpoint: (vhostId?: string | null) => {
      if (!hasPermission('endpoints', 'update')) return false
      // Global endpoints or if user has access to the vhost
      if (!vhostId) return true
      return hasVhostAccess(vhostId)
    },
    canDeleteEndpoint: (vhostId?: string | null) => {
      if (!hasPermission('endpoints', 'delete')) return false
      if (!vhostId) return true
      return hasVhostAccess(vhostId)
    },
    canEnableEndpoint: (vhostId?: string | null) => {
      if (!hasPermission('endpoints', 'enable')) return false
      if (!vhostId) return true
      return hasVhostAccess(vhostId)
    },
    canDisableEndpoint: (vhostId?: string | null) => {
      if (!hasPermission('endpoints', 'disable')) return false
      if (!vhostId) return true
      return hasVhostAccess(vhostId)
    },

    // Keyword permissions
    canCreateKeyword: hasPermission('keywords', 'create'),
    canEditKeyword: hasPermission('keywords', 'update'),
    canDeleteKeyword: hasPermission('keywords', 'delete'),

    // Config permissions
    canEditConfig: hasPermission('config', 'update'),

    // User management permissions (admin only)
    canManageUsers: hasPermission('users', 'create'),
    canViewUsers: hasPermission('users', 'read'),

    // Provider management permissions (admin only)
    canManageProviders: hasPermission('providers', 'create'),
    canViewProviders: hasPermission('providers', 'read'),

    // Metrics permissions
    canResetMetrics: hasPermission('metrics', 'reset'),

    // Bulk operations
    canBulkImport: hasPermission('bulk', 'import'),
    canBulkExport: hasPermission('bulk', 'export'),
    canBulkClear: hasPermission('bulk', 'clear'),

    // CAPTCHA permissions
    canManageCaptcha: hasPermission('captcha', 'create'),
    canTestCaptcha: hasPermission('captcha', 'test'),

    // Webhook permissions
    canEditWebhooks: hasPermission('webhooks', 'update'),
    canTestWebhooks: hasPermission('webhooks', 'test'),

    // Sync permission
    canSync: hasPermission('sync', 'execute'),

    // Whitelist/Hashes
    canAddToWhitelist: hasPermission('whitelist', 'create'),
    canAddBlockedHash: hasPermission('hashes', 'create'),

    // Fingerprint profiles
    canCreateFingerprintProfile: hasPermission('fingerprint_profiles', 'create'),
    canEditFingerprintProfile: hasPermission('fingerprint_profiles', 'update'),
    canDeleteFingerprintProfile: hasPermission('fingerprint_profiles', 'delete'),
    canTestFingerprintProfile: hasPermission('fingerprint_profiles', 'test'),
    canResetFingerprintProfiles: hasPermission('fingerprint_profiles', 'reset'),

    // Defense profiles
    canCreateDefenseProfile: hasPermission('defense_profiles', 'create'),
    canEditDefenseProfile: hasPermission('defense_profiles', 'update'),
    canDeleteDefenseProfile: hasPermission('defense_profiles', 'delete'),
    canResetDefenseProfiles: hasPermission('defense_profiles', 'reset'),
    canSimulateDefenseProfile: hasPermission('defense_profiles', 'read'),

    // Attack signatures
    canCreateAttackSignature: hasPermission('attack_signatures', 'create'),
    canEditAttackSignature: hasPermission('attack_signatures', 'update'),
    canDeleteAttackSignature: hasPermission('attack_signatures', 'delete'),
    canResetAttackSignatures: hasPermission('attack_signatures', 'reset'),

    // Vhost scope helpers
    hasVhostAccess,
    vhostScope: user?.vhost_scope || [],
    hasGlobalAccess: user?.vhost_scope?.includes('*') ?? false,

    // Generic permission check
    hasPermission,
  }), [hasPermission, hasVhostAccess, isAdmin, isOperator, isViewer, user?.vhost_scope])
}

export default usePermissions
