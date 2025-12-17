import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { authProvidersApi, type AuthProviderConfig, type OIDCConfig, type LDAPConfig, type RoleMappingConfig, type RoleMapping } from '@/api/client'
import { usePermissions } from '@/hooks/usePermissions'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs'
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useToast } from '@/components/ui/use-toast'
import { Plus, Search, Pencil, Trash2, KeyRound, Shield, Play, CheckCircle, XCircle, Loader2 } from 'lucide-react'

// Helper to ensure arrays are always arrays (backend may return {} for empty)
function ensureArray<T>(value: T[] | Record<string, never> | undefined): T[] {
  if (!value) return []
  if (Array.isArray(value)) return value
  return []
}

// Specific helper for mappings for backward compat
function ensureMappingsArray(mappings: RoleMapping[] | Record<string, never> | undefined): RoleMapping[] {
  return ensureArray(mappings)
}

type ProviderType = 'oidc' | 'ldap' | 'saml'

interface ProviderFormData {
  id: string
  name: string
  type: ProviderType
  enabled: boolean
  priority: number
  icon: string
  oidc: OIDCConfig
  ldap: LDAPConfig
  role_mapping: RoleMappingConfig
}

const emptyOIDCConfig: OIDCConfig = {
  issuer: '',
  discovery: '',
  client_id: '',
  client_secret: '',
  scopes: ['openid', 'profile', 'email'],
  ssl_verify: true,
  use_pkce: true,
}

const emptyLDAPConfig: LDAPConfig = {
  host: '',
  port: 389,
  use_ssl: false,
  ssl_verify: true,
  timeout: 5000,
  base_dn: '',
  user_base_dn: '',
  user_dn_template: '',
  user_filter: '(uid={username})',
  group_base_dn: '',
  group_filter: '(member={user_dn})',
  group_attribute: 'cn',
  bind_dn: '',
  bind_password: '',
}

const emptyRoleMapping: RoleMappingConfig = {
  default_role: 'viewer',
  default_vhosts: ['*'],
  claim_name: 'groups',
  sync_on_login: true,
  mappings: [],
}

const emptyFormData: ProviderFormData = {
  id: '',
  name: '',
  type: 'oidc',
  enabled: true,
  priority: 100,
  icon: '',
  oidc: emptyOIDCConfig,
  ldap: emptyLDAPConfig,
  role_mapping: emptyRoleMapping,
}

export function AuthProviders() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { canManageProviders, canViewProviders } = usePermissions()
  const [search, setSearch] = useState('')
  const [deleteProviderId, setDeleteProviderId] = useState<string | null>(null)
  const [editingProvider, setEditingProvider] = useState<AuthProviderConfig | null>(null)
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [formData, setFormData] = useState<ProviderFormData>(emptyFormData)
  const [testingProvider, setTestingProvider] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['auth-providers'],
    queryFn: authProvidersApi.list,
    enabled: canViewProviders,
  })

  const createMutation = useMutation({
    mutationFn: authProvidersApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auth-providers'] })
      setIsCreateOpen(false)
      setFormData(emptyFormData)
      toast({ title: 'Provider created successfully' })
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to create provider',
        variant: 'destructive',
      })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<AuthProviderConfig> }) =>
      authProvidersApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auth-providers'] })
      toast({ title: 'Provider updated' })
      setEditingProvider(null)
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to update provider',
        variant: 'destructive',
      })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: authProvidersApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auth-providers'] })
      toast({ title: 'Provider deleted' })
      setDeleteProviderId(null)
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to delete provider',
        variant: 'destructive',
      })
    },
  })

  const enableMutation = useMutation({
    mutationFn: authProvidersApi.enable,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auth-providers'] })
      toast({ title: 'Provider enabled' })
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to enable provider',
        variant: 'destructive',
      })
    },
  })

  const disableMutation = useMutation({
    mutationFn: authProvidersApi.disable,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auth-providers'] })
      toast({ title: 'Provider disabled' })
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to disable provider',
        variant: 'destructive',
      })
    },
  })

  const testMutation = useMutation({
    mutationFn: authProvidersApi.test,
    onSuccess: (result) => {
      setTestResult(result)
      setTestingProvider(null)
    },
    onError: (error) => {
      setTestResult({
        success: false,
        message: error instanceof Error ? error.message : 'Test failed',
      })
      setTestingProvider(null)
    },
  })

  const providers = ensureArray(data?.providers)
  const filteredProviders = useMemo(() => {
    return providers.filter((p) => {
      return (
        p.id.toLowerCase().includes(search.toLowerCase()) ||
        p.name.toLowerCase().includes(search.toLowerCase())
      )
    })
  }, [providers, search])

  const getTypeBadgeVariant = (type: ProviderType) => {
    switch (type) {
      case 'oidc':
        return 'default'
      case 'ldap':
        return 'secondary'
      case 'saml':
        return 'outline'
      default:
        return 'outline'
    }
  }

  const getTypeIcon = (type: ProviderType) => {
    switch (type) {
      case 'oidc':
        return <KeyRound className="h-3 w-3 mr-1" />
      case 'saml':
        return <Shield className="h-3 w-3 mr-1" />
      case 'ldap':
        return <KeyRound className="h-3 w-3 mr-1" />
      default:
        return null
    }
  }

  const handleCreate = () => {
    const providerData: Omit<AuthProviderConfig, 'created_at' | 'updated_at'> = {
      id: formData.id,
      name: formData.name,
      type: formData.type,
      enabled: formData.enabled,
      priority: formData.priority,
      icon: formData.icon || undefined,
      role_mapping: formData.role_mapping,
    }

    if (formData.type === 'oidc' || formData.type === 'saml') {
      providerData.oidc = {
        ...formData.oidc,
        scopes: formData.oidc.scopes?.length ? formData.oidc.scopes : undefined,
      }
    }

    if (formData.type === 'ldap') {
      providerData.ldap = formData.ldap
    }

    createMutation.mutate(providerData)
  }

  const handleUpdate = () => {
    if (!editingProvider) return

    const updateData: Partial<AuthProviderConfig> = {
      name: formData.name,
      enabled: formData.enabled,
      priority: formData.priority,
      icon: formData.icon || undefined,
      role_mapping: formData.role_mapping,
    }

    if (formData.type === 'oidc' || formData.type === 'saml') {
      updateData.oidc = formData.oidc
    }

    if (formData.type === 'ldap') {
      updateData.ldap = formData.ldap
    }

    updateMutation.mutate({ id: editingProvider.id, data: updateData })
  }

  const openEditDialog = (provider: AuthProviderConfig) => {
    setEditingProvider(provider)
    const roleMapping = provider.role_mapping || emptyRoleMapping
    setFormData({
      id: provider.id,
      name: provider.name,
      type: provider.type,
      enabled: provider.enabled,
      priority: provider.priority || 100,
      icon: provider.icon || '',
      oidc: provider.oidc || emptyOIDCConfig,
      ldap: provider.ldap || emptyLDAPConfig,
      role_mapping: {
        ...roleMapping,
        mappings: ensureMappingsArray(roleMapping.mappings),
      },
    })
  }

  const handleTest = (providerId: string) => {
    setTestingProvider(providerId)
    setTestResult(null)
    testMutation.mutate(providerId)
  }

  const handleToggleEnabled = (provider: AuthProviderConfig) => {
    if (provider.enabled) {
      disableMutation.mutate(provider.id)
    } else {
      enableMutation.mutate(provider.id)
    }
  }

  const addRoleMapping = () => {
    setFormData({
      ...formData,
      role_mapping: {
        ...formData.role_mapping,
        mappings: [
          ...ensureMappingsArray(formData.role_mapping.mappings),
          { group: '', role: 'viewer', vhosts: ['*'], priority: 100 },
        ],
      },
    })
  }

  const updateRoleMapping = (index: number, mapping: RoleMapping) => {
    const mappings = [...ensureMappingsArray(formData.role_mapping.mappings)]
    mappings[index] = mapping
    setFormData({
      ...formData,
      role_mapping: { ...formData.role_mapping, mappings },
    })
  }

  const removeRoleMapping = (index: number) => {
    const mappings = [...ensureMappingsArray(formData.role_mapping.mappings)]
    mappings.splice(index, 1)
    setFormData({
      ...formData,
      role_mapping: { ...formData.role_mapping, mappings },
    })
  }

  if (!canViewProviders) {
    return (
      <div className="flex items-center justify-center h-96">
        <p className="text-muted-foreground">You don't have permission to view auth providers.</p>
      </div>
    )
  }

  const renderProviderForm = (isEdit: boolean) => (
    <Tabs defaultValue="general" className="w-full">
      <TabsList className="grid w-full grid-cols-3">
        <TabsTrigger value="general">General</TabsTrigger>
        <TabsTrigger value="config">
          {formData.type === 'ldap' ? 'LDAP Config' : 'OIDC Config'}
        </TabsTrigger>
        <TabsTrigger value="roles">Role Mapping</TabsTrigger>
      </TabsList>

      <TabsContent value="general" className="space-y-4 mt-4">
        <div className="grid gap-2">
          <Label htmlFor="id">Provider ID</Label>
          <Input
            id="id"
            value={formData.id}
            onChange={(e) => setFormData({ ...formData, id: e.target.value })}
            placeholder="e.g., corporate-sso"
            disabled={isEdit}
          />
          <p className="text-xs text-muted-foreground">
            Unique identifier (letters, numbers, hyphens, underscores)
          </p>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="name">Display Name</Label>
          <Input
            id="name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            placeholder="e.g., Corporate SSO"
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="type">Provider Type</Label>
          <Select
            value={formData.type}
            onValueChange={(value: ProviderType) => setFormData({ ...formData, type: value })}
            disabled={isEdit}
          >
            <SelectTrigger>
              <SelectValue placeholder="Select type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="oidc">OIDC - OpenID Connect</SelectItem>
              <SelectItem value="ldap">LDAP - Directory Service</SelectItem>
              <SelectItem value="saml">SAML - via OIDC Bridge</SelectItem>
            </SelectContent>
          </Select>
          {formData.type === 'saml' && (
            <p className="text-xs text-muted-foreground">
              SAML uses an OIDC bridge (Keycloak/Dex). Configure OIDC settings for the bridge.
            </p>
          )}
        </div>
        <div className="grid gap-2">
          <Label htmlFor="priority">Priority</Label>
          <Input
            id="priority"
            type="number"
            value={formData.priority}
            onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 100 })}
          />
          <p className="text-xs text-muted-foreground">
            Lower numbers appear first on login page
          </p>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="icon">Icon URL (optional)</Label>
          <Input
            id="icon"
            value={formData.icon}
            onChange={(e) => setFormData({ ...formData, icon: e.target.value })}
            placeholder="https://example.com/icon.svg"
          />
        </div>
        <div className="flex items-center gap-2">
          <Switch
            id="enabled"
            checked={formData.enabled}
            onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
          />
          <Label htmlFor="enabled">Enabled</Label>
        </div>
      </TabsContent>

      <TabsContent value="config" className="space-y-4 mt-4">
        {(formData.type === 'oidc' || formData.type === 'saml') && (
          <>
            <div className="grid gap-2">
              <Label htmlFor="discovery">Discovery URL</Label>
              <Input
                id="discovery"
                value={formData.oidc.discovery || ''}
                onChange={(e) => setFormData({
                  ...formData,
                  oidc: { ...formData.oidc, discovery: e.target.value }
                })}
                placeholder="https://idp.example.com/.well-known/openid-configuration"
              />
              <p className="text-xs text-muted-foreground">
                Or specify issuer URL below
              </p>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="issuer">Issuer URL</Label>
              <Input
                id="issuer"
                value={formData.oidc.issuer || ''}
                onChange={(e) => setFormData({
                  ...formData,
                  oidc: { ...formData.oidc, issuer: e.target.value }
                })}
                placeholder="https://idp.example.com"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="client_id">Client ID</Label>
              <Input
                id="client_id"
                value={formData.oidc.client_id}
                onChange={(e) => setFormData({
                  ...formData,
                  oidc: { ...formData.oidc, client_id: e.target.value }
                })}
                placeholder="waf-admin"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="client_secret">Client Secret</Label>
              <Input
                id="client_secret"
                type="password"
                value={formData.oidc.client_secret || ''}
                onChange={(e) => setFormData({
                  ...formData,
                  oidc: { ...formData.oidc, client_secret: e.target.value }
                })}
                placeholder={isEdit ? '***masked*** (leave empty to keep)' : 'Enter client secret'}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="scopes">Scopes</Label>
              <Input
                id="scopes"
                value={(formData.oidc.scopes || []).join(' ')}
                onChange={(e) => setFormData({
                  ...formData,
                  oidc: { ...formData.oidc, scopes: e.target.value.split(' ').filter(Boolean) }
                })}
                placeholder="openid profile email groups"
              />
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Switch
                  id="ssl_verify"
                  checked={formData.oidc.ssl_verify !== false}
                  onCheckedChange={(checked) => setFormData({
                    ...formData,
                    oidc: { ...formData.oidc, ssl_verify: checked }
                  })}
                />
                <Label htmlFor="ssl_verify">Verify SSL</Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch
                  id="use_pkce"
                  checked={formData.oidc.use_pkce !== false}
                  onCheckedChange={(checked) => setFormData({
                    ...formData,
                    oidc: { ...formData.oidc, use_pkce: checked }
                  })}
                />
                <Label htmlFor="use_pkce">Use PKCE</Label>
              </div>
            </div>
          </>
        )}

        {formData.type === 'ldap' && (
          <>
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="ldap_host">Host</Label>
                <Input
                  id="ldap_host"
                  value={formData.ldap.host}
                  onChange={(e) => setFormData({
                    ...formData,
                    ldap: { ...formData.ldap, host: e.target.value }
                  })}
                  placeholder="ldap.example.com"
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="ldap_port">Port</Label>
                <Input
                  id="ldap_port"
                  type="number"
                  value={formData.ldap.port || 389}
                  onChange={(e) => setFormData({
                    ...formData,
                    ldap: { ...formData.ldap, port: parseInt(e.target.value) || 389 }
                  })}
                />
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Switch
                  id="ldap_ssl"
                  checked={formData.ldap.use_ssl || false}
                  onCheckedChange={(checked) => setFormData({
                    ...formData,
                    ldap: { ...formData.ldap, use_ssl: checked, port: checked ? 636 : 389 }
                  })}
                />
                <Label htmlFor="ldap_ssl">Use SSL (LDAPS)</Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch
                  id="ldap_ssl_verify"
                  checked={formData.ldap.ssl_verify !== false}
                  onCheckedChange={(checked) => setFormData({
                    ...formData,
                    ldap: { ...formData.ldap, ssl_verify: checked }
                  })}
                />
                <Label htmlFor="ldap_ssl_verify">Verify SSL</Label>
              </div>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="base_dn">Base DN</Label>
              <Input
                id="base_dn"
                value={formData.ldap.base_dn}
                onChange={(e) => setFormData({
                  ...formData,
                  ldap: { ...formData.ldap, base_dn: e.target.value }
                })}
                placeholder="dc=example,dc=com"
              />
            </div>

            <Accordion type="single" collapsible className="w-full">
              <AccordionItem value="bind">
                <AccordionTrigger>Service Account (optional)</AccordionTrigger>
                <AccordionContent className="space-y-4 pt-4">
                  <div className="grid gap-2">
                    <Label htmlFor="bind_dn">Bind DN</Label>
                    <Input
                      id="bind_dn"
                      value={formData.ldap.bind_dn || ''}
                      onChange={(e) => setFormData({
                        ...formData,
                        ldap: { ...formData.ldap, bind_dn: e.target.value }
                      })}
                      placeholder="cn=service,dc=example,dc=com"
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="bind_password">Bind Password</Label>
                    <Input
                      id="bind_password"
                      type="password"
                      value={formData.ldap.bind_password || ''}
                      onChange={(e) => setFormData({
                        ...formData,
                        ldap: { ...formData.ldap, bind_password: e.target.value }
                      })}
                      placeholder={isEdit ? '***masked***' : 'Enter password'}
                    />
                  </div>
                </AccordionContent>
              </AccordionItem>
              <AccordionItem value="user">
                <AccordionTrigger>User Search</AccordionTrigger>
                <AccordionContent className="space-y-4 pt-4">
                  <div className="grid gap-2">
                    <Label htmlFor="user_base_dn">User Base DN</Label>
                    <Input
                      id="user_base_dn"
                      value={formData.ldap.user_base_dn || ''}
                      onChange={(e) => setFormData({
                        ...formData,
                        ldap: { ...formData.ldap, user_base_dn: e.target.value }
                      })}
                      placeholder="ou=users,dc=example,dc=com"
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="user_filter">User Filter</Label>
                    <Input
                      id="user_filter"
                      value={formData.ldap.user_filter || ''}
                      onChange={(e) => setFormData({
                        ...formData,
                        ldap: { ...formData.ldap, user_filter: e.target.value }
                      })}
                      placeholder="(uid={username})"
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="user_dn_template">User DN Template</Label>
                    <Input
                      id="user_dn_template"
                      value={formData.ldap.user_dn_template || ''}
                      onChange={(e) => setFormData({
                        ...formData,
                        ldap: { ...formData.ldap, user_dn_template: e.target.value }
                      })}
                      placeholder="uid={username},ou=users,dc=example,dc=com"
                    />
                  </div>
                </AccordionContent>
              </AccordionItem>
              <AccordionItem value="group">
                <AccordionTrigger>Group Search</AccordionTrigger>
                <AccordionContent className="space-y-4 pt-4">
                  <div className="grid gap-2">
                    <Label htmlFor="group_base_dn">Group Base DN</Label>
                    <Input
                      id="group_base_dn"
                      value={formData.ldap.group_base_dn || ''}
                      onChange={(e) => setFormData({
                        ...formData,
                        ldap: { ...formData.ldap, group_base_dn: e.target.value }
                      })}
                      placeholder="ou=groups,dc=example,dc=com"
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="group_filter">Group Filter</Label>
                    <Input
                      id="group_filter"
                      value={formData.ldap.group_filter || ''}
                      onChange={(e) => setFormData({
                        ...formData,
                        ldap: { ...formData.ldap, group_filter: e.target.value }
                      })}
                      placeholder="(member={user_dn})"
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="group_attribute">Group Attribute</Label>
                    <Input
                      id="group_attribute"
                      value={formData.ldap.group_attribute || 'cn'}
                      onChange={(e) => setFormData({
                        ...formData,
                        ldap: { ...formData.ldap, group_attribute: e.target.value }
                      })}
                      placeholder="cn"
                    />
                  </div>
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </>
        )}
      </TabsContent>

      <TabsContent value="roles" className="space-y-4 mt-4">
        <div className="grid gap-2">
          <Label htmlFor="default_role">Default Role</Label>
          <Select
            value={formData.role_mapping.default_role}
            onValueChange={(value: 'admin' | 'operator' | 'viewer') => setFormData({
              ...formData,
              role_mapping: { ...formData.role_mapping, default_role: value }
            })}
          >
            <SelectTrigger>
              <SelectValue placeholder="Select default role" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="admin">Admin</SelectItem>
              <SelectItem value="operator">Operator</SelectItem>
              <SelectItem value="viewer">Viewer</SelectItem>
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            Role assigned when no group mappings match
          </p>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="default_vhosts">Default Vhost Scope</Label>
          <Input
            id="default_vhosts"
            value={(formData.role_mapping.default_vhosts || ['*']).join(', ')}
            onChange={(e) => setFormData({
              ...formData,
              role_mapping: {
                ...formData.role_mapping,
                default_vhosts: e.target.value.split(',').map(s => s.trim()).filter(Boolean)
              }
            })}
            placeholder="* for all, or comma-separated vhost IDs"
          />
        </div>
        {(formData.type === 'oidc' || formData.type === 'saml') && (
          <div className="grid gap-2">
            <Label htmlFor="claim_name">Groups Claim Name</Label>
            <Input
              id="claim_name"
              value={formData.role_mapping.claim_name || 'groups'}
              onChange={(e) => setFormData({
                ...formData,
                role_mapping: { ...formData.role_mapping, claim_name: e.target.value }
              })}
              placeholder="groups"
            />
          </div>
        )}
        <div className="flex items-center gap-2">
          <Switch
            id="sync_on_login"
            checked={formData.role_mapping.sync_on_login !== false}
            onCheckedChange={(checked) => setFormData({
              ...formData,
              role_mapping: { ...formData.role_mapping, sync_on_login: checked }
            })}
          />
          <Label htmlFor="sync_on_login">Sync role on every login</Label>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <Label>Group to Role Mappings</Label>
            <Button type="button" variant="outline" size="sm" onClick={addRoleMapping}>
              <Plus className="h-4 w-4 mr-1" /> Add Mapping
            </Button>
          </div>
          {ensureMappingsArray(formData.role_mapping.mappings).map((mapping, index) => (
            <Card key={index}>
              <CardContent className="pt-4">
                <div className="grid gap-3">
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <Label>Group Name/Pattern</Label>
                      <Input
                        value={mapping.group}
                        onChange={(e) => updateRoleMapping(index, { ...mapping, group: e.target.value })}
                        placeholder="WAF-Admins"
                      />
                    </div>
                    <div>
                      <Label>Role</Label>
                      <Select
                        value={mapping.role}
                        onValueChange={(value: 'admin' | 'operator' | 'viewer') =>
                          updateRoleMapping(index, { ...mapping, role: value })
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="admin">Admin</SelectItem>
                          <SelectItem value="operator">Operator</SelectItem>
                          <SelectItem value="viewer">Viewer</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <Label>Vhosts</Label>
                      <Input
                        value={(mapping.vhosts || ['*']).join(', ')}
                        onChange={(e) => updateRoleMapping(index, {
                          ...mapping,
                          vhosts: e.target.value.split(',').map(s => s.trim()).filter(Boolean)
                        })}
                        placeholder="* for all"
                      />
                    </div>
                    <div className="flex items-end">
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        onClick={() => removeRoleMapping(index)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
          {ensureMappingsArray(formData.role_mapping.mappings).length === 0 && (
            <p className="text-sm text-muted-foreground text-center py-4">
              No group mappings configured. All users will get the default role.
            </p>
          )}
        </div>
      </TabsContent>
    </Tabs>
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Authentication Providers</h2>
          <p className="text-muted-foreground">
            Configure SSO providers for admin authentication
          </p>
        </div>
        {canManageProviders && (
          <Button onClick={() => setIsCreateOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Add Provider
          </Button>
        )}
      </div>

      {/* Search */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search providers..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10"
          />
        </div>
      </div>

      {/* Table */}
      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Provider</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Priority</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : filteredProviders.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center">
                  No providers configured
                </TableCell>
              </TableRow>
            ) : (
              filteredProviders.map((provider) => (
                <TableRow key={provider.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {provider.icon ? (
                        <img src={provider.icon} alt="" className="h-5 w-5" />
                      ) : (
                        <KeyRound className="h-4 w-4 text-muted-foreground" />
                      )}
                      <div>
                        <p className="font-medium">{provider.name}</p>
                        <p className="text-xs text-muted-foreground">{provider.id}</p>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={getTypeBadgeVariant(provider.type)}>
                      {getTypeIcon(provider.type)}
                      {provider.type.toUpperCase()}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={provider.enabled}
                        onCheckedChange={() => handleToggleEnabled(provider)}
                        disabled={!canManageProviders}
                      />
                      <span className="text-sm">
                        {provider.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>{provider.priority || 100}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleTest(provider.id)}
                        disabled={testingProvider === provider.id}
                        title="Test connection"
                      >
                        {testingProvider === provider.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Play className="h-4 w-4" />
                        )}
                      </Button>
                      {canManageProviders && (
                        <>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => openEditDialog(provider)}
                            title="Edit provider"
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => setDeleteProviderId(provider.id)}
                            title="Delete provider"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>

      {/* Create Provider Dialog */}
      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent className="sm:max-w-[700px] max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add Authentication Provider</DialogTitle>
            <DialogDescription>
              Configure a new SSO provider for admin authentication
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            {renderProviderForm(false)}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleCreate}
              disabled={!formData.id || !formData.name || createMutation.isPending}
            >
              {createMutation.isPending ? 'Creating...' : 'Create Provider'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Provider Dialog */}
      <Dialog open={!!editingProvider} onOpenChange={() => setEditingProvider(null)}>
        <DialogContent className="sm:max-w-[700px] max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit Provider</DialogTitle>
            <DialogDescription>
              Update settings for {editingProvider?.name}
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            {renderProviderForm(true)}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingProvider(null)}>
              Cancel
            </Button>
            <Button onClick={handleUpdate} disabled={updateMutation.isPending}>
              {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteProviderId} onOpenChange={() => setDeleteProviderId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Provider</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this provider? Users who authenticated via this
              provider will no longer be able to log in using it.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteProviderId && deleteMutation.mutate(deleteProviderId)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Test Result Dialog */}
      <Dialog open={!!testResult} onOpenChange={() => setTestResult(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {testResult?.success ? (
                <>
                  <CheckCircle className="h-5 w-5 text-green-500" />
                  Connection Successful
                </>
              ) : (
                <>
                  <XCircle className="h-5 w-5 text-destructive" />
                  Connection Failed
                </>
              )}
            </DialogTitle>
          </DialogHeader>
          <div className="py-4">
            <p className={testResult?.success ? 'text-green-600' : 'text-destructive'}>
              {testResult?.message}
            </p>
          </div>
          <DialogFooter>
            <Button onClick={() => setTestResult(null)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

export default AuthProviders
