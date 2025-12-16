import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { captchaApi } from '@/api/client'
import type { CaptchaProvider, CaptchaProviderType } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
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
import { useToast } from '@/components/ui/use-toast'
import {
  Plus,
  Pencil,
  Trash2,
  Shield,
  TestTube,
  Loader2,
  CheckCircle,
  XCircle,
} from 'lucide-react'

const PROVIDER_TYPES: { value: CaptchaProviderType; label: string; description: string }[] = [
  { value: 'turnstile', label: 'Cloudflare Turnstile', description: 'Privacy-focused, free tier available' },
  { value: 'recaptcha_v2', label: 'Google reCAPTCHA v2', description: 'Checkbox challenge' },
  { value: 'recaptcha_v3', label: 'Google reCAPTCHA v3', description: 'Invisible, score-based' },
  { value: 'hcaptcha', label: 'hCaptcha', description: 'Privacy-respecting alternative' },
]

const defaultProvider: Omit<CaptchaProvider, 'id' | 'metadata'> = {
  name: '',
  type: 'turnstile',
  enabled: true,
  priority: 100,
  site_key: '',
  secret_key: '',
  options: {
    theme: 'auto',
    size: 'normal',
  },
}

export function CaptchaProviders() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [editingProvider, setEditingProvider] = useState<CaptchaProvider | null>(null)
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [deleteProvider, setDeleteProvider] = useState<CaptchaProvider | null>(null)
  const [testingId, setTestingId] = useState<string | null>(null)
  const [formData, setFormData] = useState<Omit<CaptchaProvider, 'id' | 'metadata'>>(defaultProvider)

  const { data, isLoading } = useQuery({
    queryKey: ['captcha', 'providers'],
    queryFn: captchaApi.listProviders,
  })

  const createMutation = useMutation({
    mutationFn: captchaApi.createProvider,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['captcha', 'providers'] })
      toast({ title: 'Provider created successfully' })
      setIsCreateOpen(false)
      setFormData(defaultProvider)
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
    mutationFn: ({ id, data }: { id: string; data: Partial<CaptchaProvider> }) =>
      captchaApi.updateProvider(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['captcha', 'providers'] })
      toast({ title: 'Provider updated successfully' })
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
    mutationFn: captchaApi.deleteProvider,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['captcha', 'providers'] })
      toast({ title: 'Provider deleted' })
      setDeleteProvider(null)
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to delete provider',
        variant: 'destructive',
      })
    },
  })

  const testMutation = useMutation({
    mutationFn: captchaApi.testProvider,
    onSuccess: (result) => {
      setTestingId(null)
      toast({
        title: result.success ? 'Connection successful' : 'Connection failed',
        description: result.message,
        variant: result.success ? 'default' : 'destructive',
      })
    },
    onError: (error) => {
      setTestingId(null)
      toast({
        title: 'Test failed',
        description: error instanceof Error ? error.message : 'Failed to test provider',
        variant: 'destructive',
      })
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      enabled ? captchaApi.enableProvider(id) : captchaApi.disableProvider(id),
    onSuccess: (_, { enabled }) => {
      queryClient.invalidateQueries({ queryKey: ['captcha', 'providers'] })
      toast({ title: `Provider ${enabled ? 'enabled' : 'disabled'}` })
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to toggle provider',
        variant: 'destructive',
      })
    },
  })

  const providers = data?.providers || []

  const handleCreateOpen = () => {
    setFormData(defaultProvider)
    setIsCreateOpen(true)
  }

  const handleEditOpen = (provider: CaptchaProvider) => {
    setFormData({
      name: provider.name,
      type: provider.type,
      enabled: provider.enabled,
      priority: provider.priority,
      site_key: provider.site_key,
      secret_key: '', // Don't pre-fill secret
      options: provider.options || { theme: 'auto', size: 'normal' },
    })
    setEditingProvider(provider)
  }

  const handleTest = (id: string) => {
    setTestingId(id)
    testMutation.mutate(id)
  }

  const getProviderTypeLabel = (type: CaptchaProviderType) => {
    return PROVIDER_TYPES.find((t) => t.value === type)?.label || type
  }

  const renderProviderForm = (isEdit: boolean) => (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="name">Provider Name</Label>
        <Input
          id="name"
          placeholder="e.g., Production Turnstile"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="type">Provider Type</Label>
        <Select
          value={formData.type}
          onValueChange={(value: CaptchaProviderType) =>
            setFormData({ ...formData, type: value })
          }
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PROVIDER_TYPES.map((type) => (
              <SelectItem key={type.value} value={type.value}>
                <div>
                  <span className="font-medium">{type.label}</span>
                  <span className="text-muted-foreground text-sm ml-2">
                    - {type.description}
                  </span>
                </div>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <Label htmlFor="site_key">Site Key</Label>
        <Input
          id="site_key"
          placeholder="Enter your site key"
          value={formData.site_key}
          onChange={(e) => setFormData({ ...formData, site_key: e.target.value })}
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="secret_key">
          Secret Key {isEdit && <span className="text-muted-foreground">(leave blank to keep existing)</span>}
        </Label>
        <Input
          id="secret_key"
          type="password"
          placeholder={isEdit ? '••••••••' : 'Enter your secret key'}
          value={formData.secret_key}
          onChange={(e) => setFormData({ ...formData, secret_key: e.target.value })}
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="priority">Priority</Label>
        <Input
          id="priority"
          type="number"
          min="1"
          max="1000"
          value={formData.priority}
          onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 100 })}
        />
        <p className="text-sm text-muted-foreground">
          Lower numbers = higher priority. Used when selecting default provider.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label htmlFor="theme">Theme</Label>
          <Select
            value={formData.options?.theme || 'auto'}
            onValueChange={(value) =>
              setFormData({
                ...formData,
                options: { ...formData.options, theme: value as 'light' | 'dark' | 'auto' },
              })
            }
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="auto">Auto</SelectItem>
              <SelectItem value="light">Light</SelectItem>
              <SelectItem value="dark">Dark</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-2">
          <Label htmlFor="size">Size</Label>
          <Select
            value={formData.options?.size || 'normal'}
            onValueChange={(value) =>
              setFormData({
                ...formData,
                options: { ...formData.options, size: value as 'normal' | 'compact' },
              })
            }
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="normal">Normal</SelectItem>
              <SelectItem value="compact">Compact</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {formData.type === 'recaptcha_v3' && (
        <>
          <div className="space-y-2">
            <Label htmlFor="min_score">Minimum Score (0-1)</Label>
            <Input
              id="min_score"
              type="number"
              min="0"
              max="1"
              step="0.1"
              value={formData.options?.min_score || 0.5}
              onChange={(e) =>
                setFormData({
                  ...formData,
                  options: { ...formData.options, min_score: parseFloat(e.target.value) || 0.5 },
                })
              }
            />
            <p className="text-sm text-muted-foreground">
              Requests with scores below this threshold will fail verification
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="action">Action Name</Label>
            <Input
              id="action"
              placeholder="submit"
              value={formData.options?.action || 'submit'}
              onChange={(e) =>
                setFormData({
                  ...formData,
                  options: { ...formData.options, action: e.target.value },
                })
              }
            />
          </div>
        </>
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
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">CAPTCHA Providers</h2>
          <p className="text-muted-foreground">
            Configure CAPTCHA services for bot protection
          </p>
        </div>
        <Button onClick={handleCreateOpen}>
          <Plus className="mr-2 h-4 w-4" />
          Add Provider
        </Button>
      </div>

      <Card className="border-blue-200 bg-blue-50">
        <CardContent className="flex items-center gap-4 py-4">
          <Shield className="h-5 w-5 text-blue-500" />
          <div>
            <p className="font-medium text-blue-800">CAPTCHA Challenge</p>
            <p className="text-sm text-blue-600">
              Instead of blocking suspicious requests, challenge users with CAPTCHA verification.
              Users who pass receive a trust token for future requests.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Providers Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Configured Providers</CardTitle>
          <CardDescription>
            Add multiple providers for redundancy. The highest priority enabled provider is used by default.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Priority</TableHead>
                <TableHead>Status</TableHead>
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
              ) : providers.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center">
                    No providers configured. Add one to enable CAPTCHA challenges.
                  </TableCell>
                </TableRow>
              ) : (
                providers.map((provider) => (
                  <TableRow key={provider.id}>
                    <TableCell>
                      <div className="font-medium">{provider.name}</div>
                      <div className="text-sm text-muted-foreground">{provider.id}</div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{getProviderTypeLabel(provider.type)}</Badge>
                    </TableCell>
                    <TableCell>{provider.priority}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Switch
                          checked={provider.enabled}
                          onCheckedChange={(checked) =>
                            toggleMutation.mutate({ id: provider.id, enabled: checked })
                          }
                        />
                        {provider.enabled ? (
                          <Badge className="bg-green-100 text-green-800">Enabled</Badge>
                        ) : (
                          <Badge variant="secondary">Disabled</Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => handleTest(provider.id)}
                          disabled={testingId === provider.id}
                        >
                          {testingId === provider.id ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            <TestTube className="h-4 w-4" />
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => handleEditOpen(provider)}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => setDeleteProvider(provider)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Create Dialog */}
      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Add CAPTCHA Provider</DialogTitle>
            <DialogDescription>
              Configure a new CAPTCHA provider for bot protection
            </DialogDescription>
          </DialogHeader>
          {renderProviderForm(false)}
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMutation.mutate(formData)}
              disabled={!formData.name || !formData.site_key || !formData.secret_key || createMutation.isPending}
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
      <Dialog open={!!editingProvider} onOpenChange={() => setEditingProvider(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Edit CAPTCHA Provider</DialogTitle>
            <DialogDescription>
              Update the provider configuration
            </DialogDescription>
          </DialogHeader>
          {renderProviderForm(true)}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingProvider(null)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (editingProvider) {
                  const updateData: Partial<CaptchaProvider> = { ...formData }
                  // Only include secret_key if it was changed
                  if (!formData.secret_key) {
                    delete updateData.secret_key
                  }
                  updateMutation.mutate({ id: editingProvider.id, data: updateData })
                }
              }}
              disabled={!formData.name || !formData.site_key || updateMutation.isPending}
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
      <AlertDialog open={!!deleteProvider} onOpenChange={() => setDeleteProvider(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Provider</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{deleteProvider?.name}"?
              Any endpoints using this provider will fall back to the default.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteProvider && deleteMutation.mutate(deleteProvider.id)}
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
