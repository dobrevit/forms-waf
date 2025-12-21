import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Info, ShieldCheck } from 'lucide-react'
import type { CaptchaTabProps } from './types'

export function CaptchaTab({ formData, setFormData, captchaProviders, globalCaptchaConfig }: CaptchaTabProps) {
  const enabledCaptchaProviders = captchaProviders.filter(p => p.enabled)

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5" />
          CAPTCHA Settings
        </CardTitle>
        <CardDescription>
          Challenge suspicious requests with CAPTCHA instead of blocking them outright
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {!globalCaptchaConfig?.enabled && (
          <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4">
            <div className="flex items-start gap-3">
              <Info className="h-5 w-5 text-yellow-600 mt-0.5" />
              <div>
                <p className="font-medium text-yellow-800">CAPTCHA is Disabled Globally</p>
                <p className="text-sm text-yellow-700 mt-1">
                  CAPTCHA protection is currently disabled at the global level. Enable it in CAPTCHA Settings
                  to use per-endpoint CAPTCHA configuration.
                </p>
              </div>
            </div>
          </div>
        )}

        {enabledCaptchaProviders.length === 0 && (
          <div className="rounded-lg border border-orange-200 bg-orange-50 p-4">
            <div className="flex items-start gap-3">
              <Info className="h-5 w-5 text-orange-500 mt-0.5" />
              <div>
                <p className="font-medium text-orange-800">No CAPTCHA Providers Configured</p>
                <p className="text-sm text-orange-700 mt-1">
                  Add and enable a CAPTCHA provider in CAPTCHA Providers before configuring per-endpoint CAPTCHA.
                </p>
              </div>
            </div>
          </div>
        )}

        <div className="flex items-center space-x-2">
          <Switch
            id="captcha_enabled"
            checked={(formData as any).captcha?.enabled === true}
            onCheckedChange={(checked) =>
              setFormData({
                ...formData,
                captcha: { ...(formData as any).captcha, enabled: checked },
              } as any)
            }
          />
          <Label htmlFor="captcha_enabled">Enable CAPTCHA for this endpoint</Label>
        </div>

        {(formData as any).captcha?.enabled && (
          <div className="space-y-6 pl-6 border-l-2 border-blue-200">
            <div className="space-y-2">
              <Label>Provider</Label>
              <Select
                value={(formData as any).captcha?.provider || '_default'}
                onValueChange={(value) =>
                  setFormData({
                    ...formData,
                    captcha: {
                      ...(formData as any).captcha,
                      provider: value === '_default' ? undefined : value,
                    },
                  } as any)
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="_default">
                    Use global default
                    {globalCaptchaConfig?.default_provider &&
                      ` (${captchaProviders.find(p => p.id === globalCaptchaConfig.default_provider)?.name || 'auto'})`}
                  </SelectItem>
                  {captchaProviders.map((provider) => (
                    <SelectItem key={provider.id} value={provider.id} disabled={!provider.enabled}>
                      {provider.name} ({provider.type})
                      {!provider.enabled && ' [Disabled]'}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Trigger Mode</Label>
              <Select
                value={(formData as any).captcha?.trigger || 'on_block'}
                onValueChange={(value) =>
                  setFormData({
                    ...formData,
                    captcha: {
                      ...(formData as any).captcha,
                      trigger: value as 'on_block' | 'on_flag' | 'always',
                    },
                  } as any)
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="on_block">On Block - Challenge when request would be blocked</SelectItem>
                  <SelectItem value="on_flag">On Flag - Challenge when spam score exceeds threshold</SelectItem>
                  <SelectItem value="always">Always - Challenge all requests to this endpoint</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {(formData as any).captcha?.trigger === 'on_flag' && (
              <div className="space-y-2">
                <Label>Spam Score Threshold</Label>
                <Input
                  type="number"
                  min="0"
                  max="100"
                  value={(formData as any).captcha?.spam_score_threshold || 50}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      captcha: {
                        ...(formData as any).captcha,
                        spam_score_threshold: parseInt(e.target.value) || 50,
                      },
                    } as any)
                  }
                  className="w-32"
                />
                <p className="text-sm text-muted-foreground">
                  Challenge requests with spam score at or above this value
                </p>
              </div>
            )}

            <div className="space-y-2">
              <Label>Trust Duration Override (seconds)</Label>
              <div className="flex items-center gap-2">
                <Input
                  type="number"
                  min="0"
                  placeholder={String(globalCaptchaConfig?.trust_duration || 86400)}
                  value={(formData as any).captcha?.trust_duration || ''}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      captcha: {
                        ...(formData as any).captcha,
                        trust_duration: e.target.value ? parseInt(e.target.value) : undefined,
                      },
                    } as any)
                  }
                  className="w-40"
                />
                <span className="text-sm text-muted-foreground">
                  Leave empty to use global default ({((globalCaptchaConfig?.trust_duration || 86400) / 3600).toFixed(0)}h)
                </span>
              </div>
            </div>

            <div className="space-y-2">
              <Label>Exempt IPs</Label>
              <p className="text-sm text-muted-foreground">
                IP addresses that bypass CAPTCHA for this endpoint (one per line)
              </p>
              <textarea
                className="flex min-h-[80px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                placeholder="10.0.0.0/8&#10;192.168.1.0/24"
                value={((formData as any).captcha?.exempt_ips || []).join('\n')}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    captcha: {
                      ...(formData as any).captcha,
                      exempt_ips: e.target.value.split('\n').filter(ip => ip.trim()),
                    },
                  } as any)
                }
              />
            </div>
          </div>
        )}

        <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
          <div className="flex items-start gap-3">
            <Info className="h-5 w-5 text-blue-500 mt-0.5" />
            <div>
              <p className="font-medium text-blue-800">How CAPTCHA Works</p>
              <p className="text-sm text-blue-700 mt-1">
                When enabled, suspicious requests will be presented with a CAPTCHA challenge instead of
                being blocked. Users who complete the challenge receive a trust token that allows them
                to bypass CAPTCHA for subsequent requests during the trust duration period.
              </p>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
