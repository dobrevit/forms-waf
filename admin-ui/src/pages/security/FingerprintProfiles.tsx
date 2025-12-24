import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fingerprintProfilesApi } from '@/api/client'
import type {
  FingerprintProfile,
  FingerprintProfileAction,
  FingerprintConditionType,
  FingerprintMatchMode,
  FingerprintHeaderCondition,
} from '@/api/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useToast } from '@/components/ui/use-toast'
import {
  Plus,
  Pencil,
  Trash2,
  Fingerprint,
  RotateCcw,
  Loader2,
  CheckCircle,
  X,
  Copy,
} from 'lucide-react'

const ACTION_OPTIONS: { value: FingerprintProfileAction; label: string; description: string }[] = [
  { value: 'allow', label: 'Allow', description: 'Normal tracking, no score added' },
  { value: 'flag', label: 'Flag', description: 'Add score to spam detection' },
  { value: 'block', label: 'Block', description: 'Reject request immediately' },
  { value: 'ignore', label: 'Ignore', description: 'Skip fingerprint tracking' },
]

const CONDITION_OPTIONS: { value: FingerprintConditionType; label: string }[] = [
  { value: 'present', label: 'Present' },
  { value: 'absent', label: 'Absent' },
  { value: 'matches', label: 'Matches regex' },
  { value: 'not_matches', label: 'Does not match regex' },
]

const COMMON_HEADERS = [
  'User-Agent',
  'Accept-Language',
  'Accept-Encoding',
  'Accept',
  'Sec-Fetch-Site',
  'Sec-Fetch-Mode',
  'Sec-Fetch-Dest',
  'Sec-Ch-Ua',
  'Sec-Ch-Ua-Mobile',
  'Sec-Ch-Ua-Platform',
  'Referer',
  'Origin',
  'X-Requested-With',
]

const defaultProfile: Omit<FingerprintProfile, 'id' | 'builtin'> = {
  name: '',
  description: '',
  enabled: true,
  priority: 500,
  matching: {
    conditions: [],
    match_mode: 'all',
  },
  fingerprint_headers: {
    headers: ['User-Agent', 'Accept-Language', 'Accept-Encoding'],
    normalize: true,
    max_length: 100,
  },
  action: 'allow',
  score: 0,
  rate_limiting: {
    enabled: true,
  },
}

export function FingerprintProfiles() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [editingProfile, setEditingProfile] = useState<FingerprintProfile | null>(null)
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [deleteProfile, setDeleteProfile] = useState<FingerprintProfile | null>(null)
  const [formData, setFormData] = useState<Omit<FingerprintProfile, 'id' | 'builtin'>>(defaultProfile)
  const [activeTab, setActiveTab] = useState<'all' | 'builtin' | 'custom'>('all')

  const { data, isLoading } = useQuery({
    queryKey: ['fingerprint-profiles'],
    queryFn: fingerprintProfilesApi.list,
  })

  const createMutation = useMutation({
    mutationFn: fingerprintProfilesApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fingerprint-profiles'] })
      toast({ title: 'Profile created successfully' })
      setIsCreateOpen(false)
      setFormData(defaultProfile)
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to create profile',
        variant: 'destructive',
      })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<FingerprintProfile> }) =>
      fingerprintProfilesApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fingerprint-profiles'] })
      toast({ title: 'Profile updated successfully' })
      setEditingProfile(null)
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to update profile',
        variant: 'destructive',
      })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: fingerprintProfilesApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fingerprint-profiles'] })
      toast({ title: 'Profile deleted' })
      setDeleteProfile(null)
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to delete profile',
        variant: 'destructive',
      })
    },
  })

  const resetBuiltinMutation = useMutation({
    mutationFn: fingerprintProfilesApi.resetBuiltin,
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['fingerprint-profiles'] })
      toast({ title: `Reset ${result.count} built-in profiles to defaults` })
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to reset profiles',
        variant: 'destructive',
      })
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      fingerprintProfilesApi.update(id, { enabled }),
    onSuccess: (_, { enabled }) => {
      queryClient.invalidateQueries({ queryKey: ['fingerprint-profiles'] })
      toast({ title: `Profile ${enabled ? 'enabled' : 'disabled'}` })
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to toggle profile',
        variant: 'destructive',
      })
    },
  })

  const profiles = data?.profiles || []
  const filteredProfiles = profiles.filter((p) => {
    if (activeTab === 'builtin') return p.builtin
    if (activeTab === 'custom') return !p.builtin
    return true
  })

  const handleCreateOpen = () => {
    setFormData(defaultProfile)
    setIsCreateOpen(true)
  }

  const handleClone = (profile: FingerprintProfile) => {
    setFormData({
      name: `${profile.name} (copy)`,
      description: profile.description,
      enabled: true,
      priority: profile.priority + 10,
      matching: { ...profile.matching },
      fingerprint_headers: { ...profile.fingerprint_headers },
      action: profile.action,
      score: profile.score,
      rate_limiting: profile.rate_limiting ? { ...profile.rate_limiting } : undefined,
    })
    setIsCreateOpen(true)
  }

  const handleEditOpen = (profile: FingerprintProfile) => {
    setFormData({
      name: profile.name,
      description: profile.description,
      enabled: profile.enabled,
      priority: profile.priority,
      matching: { ...profile.matching },
      fingerprint_headers: { ...profile.fingerprint_headers },
      action: profile.action,
      score: profile.score,
      rate_limiting: profile.rate_limiting ? { ...profile.rate_limiting } : undefined,
    })
    setEditingProfile(profile)
  }

  const addCondition = () => {
    setFormData({
      ...formData,
      matching: {
        ...formData.matching,
        conditions: [
          ...formData.matching.conditions,
          { header: 'User-Agent', condition: 'present' },
        ],
      },
    })
  }

  const updateCondition = (index: number, updates: Partial<FingerprintHeaderCondition>) => {
    const newConditions = [...formData.matching.conditions]
    newConditions[index] = { ...newConditions[index], ...updates }
    setFormData({
      ...formData,
      matching: { ...formData.matching, conditions: newConditions },
    })
  }

  const removeCondition = (index: number) => {
    setFormData({
      ...formData,
      matching: {
        ...formData.matching,
        conditions: formData.matching.conditions.filter((_, i) => i !== index),
      },
    })
  }

  // Helper to ensure headers is always an array (Lua cjson encodes empty arrays as {})
  const getHeadersArray = () => {
    const h = formData.fingerprint_headers.headers
    return Array.isArray(h) ? h : []
  }

  const toggleFingerprintHeader = (header: string) => {
    const headers = getHeadersArray()
    const newHeaders = headers.includes(header)
      ? headers.filter((h) => h !== header)
      : [...headers, header]
    setFormData({
      ...formData,
      fingerprint_headers: { ...formData.fingerprint_headers, headers: newHeaders },
    })
  }

  const getActionBadge = (action: FingerprintProfileAction) => {
    switch (action) {
      case 'allow':
        return <Badge className="bg-green-100 text-green-800">Allow</Badge>
      case 'flag':
        return <Badge className="bg-yellow-100 text-yellow-800">Flag</Badge>
      case 'block':
        return <Badge className="bg-red-100 text-red-800">Block</Badge>
      case 'ignore':
        return <Badge variant="secondary">Ignore</Badge>
    }
  }

  const renderProfileForm = (isEdit: boolean) => (
    <div className="space-y-6 max-h-[60vh] overflow-y-auto pr-2">
      {/* Basic Info */}
      <div className="space-y-4">
        <h4 className="font-medium">Basic Information</h4>

        {!isEdit && (
          <div className="space-y-2">
            <Label htmlFor="id">Profile ID</Label>
            <Input
              id="id"
              placeholder="e.g., my-custom-profile"
              value={(formData as FingerprintProfile).id || ''}
              onChange={(e) =>
                setFormData({ ...formData, id: e.target.value } as typeof formData)
              }
            />
            <p className="text-sm text-muted-foreground">
              Alphanumeric, hyphens and underscores only
            </p>
          </div>
        )}

        <div className="space-y-2">
          <Label htmlFor="name">Name</Label>
          <Input
            id="name"
            placeholder="e.g., Custom Bot Detector"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="description">Description</Label>
          <Textarea
            id="description"
            placeholder="Describe what this profile detects..."
            value={formData.description || ''}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label htmlFor="priority">Priority</Label>
            <Input
              id="priority"
              type="number"
              min="1"
              max="1000"
              value={formData.priority}
              onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 500 })}
            />
            <p className="text-sm text-muted-foreground">Lower = matched first</p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="action">Action</Label>
            <Select
              value={formData.action}
              onValueChange={(value: FingerprintProfileAction) =>
                setFormData({ ...formData, action: value })
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ACTION_OPTIONS.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>
                    {opt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {formData.action === 'flag' && (
          <div className="space-y-2">
            <Label htmlFor="score">Score to Add</Label>
            <Input
              id="score"
              type="number"
              min="0"
              max="100"
              value={formData.score || 0}
              onChange={(e) => setFormData({ ...formData, score: parseInt(e.target.value) || 0 })}
            />
          </div>
        )}

        <div className="flex items-center space-x-2">
          <Switch
            id="enabled"
            checked={formData.enabled}
            onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
          />
          <Label htmlFor="enabled">Enabled</Label>
        </div>
      </div>

      {/* Matching Conditions */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h4 className="font-medium">Matching Conditions</h4>
          <Button variant="outline" size="sm" onClick={addCondition}>
            <Plus className="h-4 w-4 mr-1" />
            Add Condition
          </Button>
        </div>

        <div className="space-y-2">
          <Label>Match Mode</Label>
          <Select
            value={formData.matching.match_mode}
            onValueChange={(value: FingerprintMatchMode) =>
              setFormData({
                ...formData,
                matching: { ...formData.matching, match_mode: value },
              })
            }
          >
            <SelectTrigger className="w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All (AND)</SelectItem>
              <SelectItem value="any">Any (OR)</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {formData.matching.conditions.length === 0 ? (
          <p className="text-sm text-muted-foreground">No conditions - profile matches all requests</p>
        ) : (
          <div className="space-y-2">
            {formData.matching.conditions.map((condition, index) => (
              <div key={index} className="flex items-center gap-2 p-2 border rounded">
                <Input
                  placeholder="Header name"
                  value={condition.header}
                  onChange={(e) => updateCondition(index, { header: e.target.value })}
                  className="w-40"
                  list="common-headers"
                />
                <datalist id="common-headers">
                  {COMMON_HEADERS.map((h) => (
                    <option key={h} value={h} />
                  ))}
                </datalist>

                <Select
                  value={condition.condition}
                  onValueChange={(value: FingerprintConditionType) =>
                    updateCondition(index, { condition: value })
                  }
                >
                  <SelectTrigger className="w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CONDITION_OPTIONS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>
                        {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>

                {(condition.condition === 'matches' || condition.condition === 'not_matches') && (
                  <Input
                    placeholder="Regex pattern"
                    value={condition.pattern || ''}
                    onChange={(e) => updateCondition(index, { pattern: e.target.value })}
                    className="flex-1"
                  />
                )}

                <Button variant="ghost" size="icon" onClick={() => removeCondition(index)}>
                  <X className="h-4 w-4" />
                </Button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Fingerprint Headers */}
      <div className="space-y-4">
        <h4 className="font-medium">Fingerprint Headers</h4>
        <p className="text-sm text-muted-foreground">
          Select which headers to include in the fingerprint hash
        </p>

        <div className="flex flex-wrap gap-2">
          {COMMON_HEADERS.map((header) => (
            <Badge
              key={header}
              variant={getHeadersArray().includes(header) ? 'default' : 'outline'}
              className="cursor-pointer"
              onClick={() => toggleFingerprintHeader(header)}
            >
              {header}
            </Badge>
          ))}
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="flex items-center space-x-2">
            <Switch
              id="normalize"
              checked={formData.fingerprint_headers.normalize !== false}
              onCheckedChange={(checked) =>
                setFormData({
                  ...formData,
                  fingerprint_headers: { ...formData.fingerprint_headers, normalize: checked },
                })
              }
            />
            <Label htmlFor="normalize">Normalize values</Label>
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="max_length">Max header value length</Label>
          <Input
            id="max_length"
            type="number"
            min="10"
            max="500"
            value={formData.fingerprint_headers.max_length || 100}
            onChange={(e) =>
              setFormData({
                ...formData,
                fingerprint_headers: {
                  ...formData.fingerprint_headers,
                  max_length: parseInt(e.target.value) || 100,
                },
              })
            }
            className="w-24"
          />
        </div>
      </div>

      {/* Rate Limiting Override */}
      <div className="space-y-4">
        <h4 className="font-medium">Rate Limiting</h4>

        <div className="flex items-center space-x-2">
          <Switch
            id="rate_limiting_enabled"
            checked={formData.rate_limiting?.enabled !== false}
            onCheckedChange={(checked) =>
              setFormData({
                ...formData,
                rate_limiting: { ...formData.rate_limiting, enabled: checked },
              })
            }
          />
          <Label htmlFor="rate_limiting_enabled">Enable rate limiting for this profile</Label>
        </div>

        <div className="space-y-2">
          <Label htmlFor="fingerprint_rate_limit">Fingerprint rate limit (per minute)</Label>
          <Input
            id="fingerprint_rate_limit"
            type="number"
            min="1"
            max="1000"
            placeholder="Use default"
            value={formData.rate_limiting?.fingerprint_rate_limit || ''}
            onChange={(e) =>
              setFormData({
                ...formData,
                rate_limiting: {
                  ...formData.rate_limiting,
                  fingerprint_rate_limit: e.target.value ? parseInt(e.target.value) : undefined,
                },
              })
            }
            className="w-32"
          />
          <p className="text-sm text-muted-foreground">Leave empty to use the global threshold</p>
        </div>
      </div>
    </div>
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Fingerprint Profiles</h2>
          <p className="text-muted-foreground">
            Detect client types and configure fingerprint generation
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => resetBuiltinMutation.mutate()}>
            <RotateCcw className="mr-2 h-4 w-4" />
            Reset Built-in
          </Button>
          <Button onClick={handleCreateOpen}>
            <Plus className="mr-2 h-4 w-4" />
            Create Profile
          </Button>
        </div>
      </div>

      <Card className="border-blue-200 bg-blue-50">
        <CardContent className="flex items-center gap-4 py-4">
          <Fingerprint className="h-5 w-5 text-blue-500" />
          <div>
            <p className="font-medium text-blue-800">Client Fingerprinting</p>
            <p className="text-sm text-blue-600">
              Profiles detect client types (browsers, bots, scripts) based on HTTP headers.
              The first matching profile determines which headers are used for fingerprint generation.
            </p>
          </div>
        </CardContent>
      </Card>

      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as typeof activeTab)}>
        <TabsList>
          <TabsTrigger value="all">All ({profiles.length})</TabsTrigger>
          <TabsTrigger value="builtin">
            Built-in ({profiles.filter((p) => p.builtin).length})
          </TabsTrigger>
          <TabsTrigger value="custom">
            Custom ({profiles.filter((p) => !p.builtin).length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value={activeTab} className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Profiles</CardTitle>
              <CardDescription>
                Profiles are matched in priority order (lower = higher priority).
                First match determines fingerprint generation.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Priority</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Conditions</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {isLoading ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center">
                        Loading...
                      </TableCell>
                    </TableRow>
                  ) : filteredProfiles.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center">
                        No profiles found
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredProfiles.map((profile) => (
                      <TableRow key={profile.id}>
                        <TableCell>
                          <div className="font-medium">
                            {profile.name}
                            {profile.builtin && (
                              <Badge variant="outline" className="ml-2 text-xs">
                                Built-in
                              </Badge>
                            )}
                          </div>
                          <div className="text-sm text-muted-foreground">{profile.id}</div>
                          {profile.description && (
                            <div className="text-xs text-muted-foreground mt-1">
                              {profile.description}
                            </div>
                          )}
                        </TableCell>
                        <TableCell>{profile.priority}</TableCell>
                        <TableCell>
                          {getActionBadge(profile.action)}
                          {profile.action === 'flag' && profile.score && (
                            <span className="text-sm text-muted-foreground ml-1">
                              +{profile.score}
                            </span>
                          )}
                        </TableCell>
                        <TableCell>
                          <span className="text-sm">
                            {profile.matching.conditions.length} condition
                            {profile.matching.conditions.length !== 1 ? 's' : ''}
                            {profile.matching.conditions.length > 0 && (
                              <span className="text-muted-foreground ml-1">
                                ({profile.matching.match_mode})
                              </span>
                            )}
                          </span>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Switch
                              checked={profile.enabled}
                              onCheckedChange={(checked) =>
                                toggleMutation.mutate({ id: profile.id, enabled: checked })
                              }
                            />
                            {profile.enabled ? (
                              <Badge className="bg-green-100 text-green-800">Enabled</Badge>
                            ) : (
                              <Badge variant="secondary">Disabled</Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1">
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleClone(profile)}
                              title="Clone"
                            >
                              <Copy className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleEditOpen(profile)}
                              title="Edit"
                            >
                              <Pencil className="h-4 w-4" />
                            </Button>
                            {!profile.builtin && (
                              <Button
                                variant="ghost"
                                size="icon"
                                onClick={() => setDeleteProfile(profile)}
                                title="Delete"
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Create Dialog */}
      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Create Fingerprint Profile</DialogTitle>
            <DialogDescription>
              Configure a new profile for client detection and fingerprinting
            </DialogDescription>
          </DialogHeader>
          {renderProfileForm(false)}
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMutation.mutate(formData as FingerprintProfile)}
              disabled={
                !formData.name ||
                !(formData as FingerprintProfile).id ||
                createMutation.isPending
              }
            >
              {createMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <CheckCircle className="mr-2 h-4 w-4" />
              )}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={!!editingProfile} onOpenChange={() => setEditingProfile(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Edit Fingerprint Profile</DialogTitle>
            <DialogDescription>
              Update the profile configuration
              {editingProfile?.builtin && (
                <span className="text-yellow-600 ml-2">
                  (Built-in profile - changes will be preserved until reset)
                </span>
              )}
            </DialogDescription>
          </DialogHeader>
          {renderProfileForm(true)}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingProfile(null)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (editingProfile) {
                  updateMutation.mutate({ id: editingProfile.id, data: formData })
                }
              }}
              disabled={!formData.name || updateMutation.isPending}
            >
              {updateMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <CheckCircle className="mr-2 h-4 w-4" />
              )}
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteProfile} onOpenChange={() => setDeleteProfile(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Profile</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{deleteProfile?.name}"?
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteProfile && deleteMutation.mutate(deleteProfile.id)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
