import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { captchaApi } from '@/api/client'
import type { CaptchaGlobalConfig, CaptchaProvider } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
  Shield,
  Save,
  Loader2,
  Clock,
  Cookie,
  AlertTriangle,
  Settings,
} from 'lucide-react'

const DURATION_PRESETS = [
  { value: 3600, label: '1 hour' },
  { value: 21600, label: '6 hours' },
  { value: 86400, label: '24 hours' },
  { value: 604800, label: '7 days' },
]

const formatDuration = (seconds: number): string => {
  if (seconds < 60) return `${seconds} seconds`
  if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours`
  return `${Math.floor(seconds / 86400)} days`
}

export function CaptchaSettings() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [formData, setFormData] = useState<Partial<CaptchaGlobalConfig>>({})
  const [isDirty, setIsDirty] = useState(false)

  const { data: configData, isLoading: configLoading } = useQuery({
    queryKey: ['captcha', 'config'],
    queryFn: captchaApi.getConfig,
  })

  const { data: providersData } = useQuery({
    queryKey: ['captcha', 'providers'],
    queryFn: captchaApi.listProviders,
  })

  const updateMutation = useMutation({
    mutationFn: captchaApi.updateConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['captcha', 'config'] })
      toast({ title: 'Settings saved successfully' })
      setIsDirty(false)
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to save settings',
        variant: 'destructive',
      })
    },
  })

  // Initialize form data when config loads
  useEffect(() => {
    if (configData?.config) {
      setFormData(configData.config)
    }
  }, [configData])

  const handleChange = <K extends keyof CaptchaGlobalConfig>(
    key: K,
    value: CaptchaGlobalConfig[K]
  ) => {
    setFormData((prev) => ({ ...prev, [key]: value }))
    setIsDirty(true)
  }

  const handleSave = () => {
    updateMutation.mutate(formData)
  }

  const providers = providersData?.providers || []
  const enabledProviders = providers.filter((p) => p.enabled)
  const config = configData?.config
  const defaults = configData?.defaults

  if (configLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">CAPTCHA Settings</h2>
          <p className="text-muted-foreground">
            Global CAPTCHA configuration and behavior
          </p>
        </div>
        <Button onClick={handleSave} disabled={!isDirty || updateMutation.isPending}>
          {updateMutation.isPending ? (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          ) : (
            <Save className="mr-2 h-4 w-4" />
          )}
          Save Changes
        </Button>
      </div>

      {/* Status Card */}
      <Card className={formData.enabled ? 'border-green-200 bg-green-50' : 'border-yellow-200 bg-yellow-50'}>
        <CardContent className="flex items-center justify-between py-4">
          <div className="flex items-center gap-4">
            <Shield className={`h-5 w-5 ${formData.enabled ? 'text-green-500' : 'text-yellow-500'}`} />
            <div>
              <p className={`font-medium ${formData.enabled ? 'text-green-800' : 'text-yellow-800'}`}>
                CAPTCHA Protection is {formData.enabled ? 'Enabled' : 'Disabled'}
              </p>
              <p className={`text-sm ${formData.enabled ? 'text-green-600' : 'text-yellow-600'}`}>
                {formData.enabled
                  ? 'Suspicious requests will be challenged instead of blocked'
                  : 'Enable to challenge suspicious requests with CAPTCHA'}
              </p>
            </div>
          </div>
          <Switch
            checked={formData.enabled ?? false}
            onCheckedChange={(checked) => handleChange('enabled', checked)}
          />
        </CardContent>
      </Card>

      {enabledProviders.length === 0 && formData.enabled && (
        <Card className="border-orange-200 bg-orange-50">
          <CardContent className="flex items-center gap-4 py-4">
            <AlertTriangle className="h-5 w-5 text-orange-500" />
            <div>
              <p className="font-medium text-orange-800">No Providers Enabled</p>
              <p className="text-sm text-orange-600">
                CAPTCHA is enabled but no providers are configured. Add and enable a provider first.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-6 md:grid-cols-2">
        {/* Provider Selection */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Settings className="h-5 w-5" />
              Default Provider
            </CardTitle>
            <CardDescription>
              Select which CAPTCHA provider to use by default
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Provider</Label>
              <Select
                value={formData.default_provider || 'auto'}
                onValueChange={(value) =>
                  handleChange('default_provider', value === 'auto' ? null : value)
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select provider" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="auto">
                    <div className="flex items-center gap-2">
                      <span>Auto (highest priority enabled)</span>
                      <Badge variant="secondary">Recommended</Badge>
                    </div>
                  </SelectItem>
                  {providers.map((provider) => (
                    <SelectItem key={provider.id} value={provider.id}>
                      <div className="flex items-center gap-2">
                        <span>{provider.name}</span>
                        {!provider.enabled && (
                          <Badge variant="outline" className="text-orange-600">
                            Disabled
                          </Badge>
                        )}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-sm text-muted-foreground">
                {enabledProviders.length} of {providers.length} providers enabled
              </p>
            </div>

            <div className="space-y-2">
              <Label>Fallback Action</Label>
              <Select
                value={formData.fallback_action || 'block'}
                onValueChange={(value: 'block' | 'allow' | 'monitor') =>
                  handleChange('fallback_action', value)
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="block">Block request</SelectItem>
                  <SelectItem value="allow">Allow through</SelectItem>
                  <SelectItem value="monitor">Log only</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-sm text-muted-foreground">
                Action when CAPTCHA provider is unreachable
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Trust Duration */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Clock className="h-5 w-5" />
              Trust Duration
            </CardTitle>
            <CardDescription>
              How long users bypass CAPTCHA after solving
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Trust Duration</Label>
              <Select
                value={String(formData.trust_duration || 86400)}
                onValueChange={(value) => handleChange('trust_duration', parseInt(value))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {DURATION_PRESETS.map((preset) => (
                    <SelectItem key={preset.value} value={String(preset.value)}>
                      {preset.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-sm text-muted-foreground">
                Users who pass CAPTCHA can bypass checks for this duration
              </p>
            </div>

            <div className="space-y-2">
              <Label>Challenge TTL</Label>
              <div className="flex items-center gap-2">
                <Input
                  type="number"
                  min="60"
                  max="3600"
                  value={formData.challenge_ttl || 600}
                  onChange={(e) => handleChange('challenge_ttl', parseInt(e.target.value) || 600)}
                  className="w-32"
                />
                <span className="text-sm text-muted-foreground">seconds</span>
              </div>
              <p className="text-sm text-muted-foreground">
                How long users have to complete the challenge ({formatDuration(formData.challenge_ttl || 600)})
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Cookie Settings */}
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Cookie className="h-5 w-5" />
              Cookie Settings
            </CardTitle>
            <CardDescription>
              Configure trust token cookie behavior
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
              <div className="space-y-2">
                <Label>Cookie Name</Label>
                <Input
                  value={formData.cookie_name || 'waf_trust'}
                  onChange={(e) => handleChange('cookie_name', e.target.value)}
                  placeholder="waf_trust"
                />
              </div>

              <div className="space-y-2">
                <Label>SameSite</Label>
                <Select
                  value={formData.cookie_samesite || 'Strict'}
                  onValueChange={(value: 'Strict' | 'Lax' | 'None') =>
                    handleChange('cookie_samesite', value)
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="Strict">Strict (recommended)</SelectItem>
                    <SelectItem value="Lax">Lax</SelectItem>
                    <SelectItem value="None">None</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-center space-x-2 pt-8">
                <Switch
                  id="secure"
                  checked={formData.cookie_secure ?? true}
                  onCheckedChange={(checked) => handleChange('cookie_secure', checked)}
                />
                <Label htmlFor="secure">Secure (HTTPS only)</Label>
              </div>

              <div className="flex items-center space-x-2 pt-8">
                <Switch
                  id="httponly"
                  checked={formData.cookie_httponly ?? true}
                  onCheckedChange={(checked) => handleChange('cookie_httponly', checked)}
                />
                <Label htmlFor="httponly">HttpOnly</Label>
              </div>
            </div>

            <div className="mt-4 p-4 bg-muted rounded-lg">
              <p className="text-sm font-medium mb-2">Cookie Preview</p>
              <code className="text-xs text-muted-foreground">
                {formData.cookie_name || 'waf_trust'}=&lt;token&gt;; Path=/; Max-Age=
                {formData.trust_duration || 86400}
                {formData.cookie_secure && '; Secure'}
                {formData.cookie_httponly && '; HttpOnly'}
                {formData.cookie_samesite && `; SameSite=${formData.cookie_samesite}`}
              </code>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Defaults Reference */}
      {defaults && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Default Values</CardTitle>
            <CardDescription>
              Reference values used when settings are not explicitly configured
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-3 lg:grid-cols-5 text-sm">
              <div>
                <span className="text-muted-foreground">Trust Duration:</span>{' '}
                <span className="font-medium">{formatDuration(defaults.trust_duration)}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Challenge TTL:</span>{' '}
                <span className="font-medium">{formatDuration(defaults.challenge_ttl)}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Fallback:</span>{' '}
                <span className="font-medium capitalize">{defaults.fallback_action}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Cookie Name:</span>{' '}
                <span className="font-medium">{defaults.cookie_name}</span>
              </div>
              <div>
                <span className="text-muted-foreground">SameSite:</span>{' '}
                <span className="font-medium">{defaults.cookie_samesite}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
