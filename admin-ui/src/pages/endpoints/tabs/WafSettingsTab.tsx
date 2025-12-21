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
import { Info } from 'lucide-react'
import type { WafSettingsTabProps } from './types'

export function WafSettingsTab({ formData, setFormData, globalThresholds }: WafSettingsTabProps) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Thresholds</CardTitle>
          <CardDescription>
            Override global thresholds for this endpoint. Leave empty to inherit global values.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Info banner showing inherited values */}
          <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
            <div className="flex items-start gap-3">
              <Info className="h-5 w-5 text-blue-500 mt-0.5" />
              <div className="space-y-1">
                <p className="font-medium text-blue-800">Global Thresholds (inherited when not overridden)</p>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-1 text-sm text-blue-700">
                  <span>Block Score: <strong>{globalThresholds.spam_score_block}</strong></span>
                  <span>Flag Score: <strong>{globalThresholds.spam_score_flag}</strong></span>
                  <span>IP Rate: <strong>{globalThresholds.ip_rate_limit}/min</strong></span>
                  <span>IP Daily: <strong>{globalThresholds.ip_daily_limit}</strong></span>
                  <span>Hash Block: <strong>{globalThresholds.hash_count_block}</strong></span>
                  <span>Hash IPs: <strong>{globalThresholds.hash_unique_ips_block}</strong></span>
                </div>
              </div>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="spam_score_block">Spam Score Block Threshold</Label>
              <Input
                id="spam_score_block"
                type="number"
                value={formData.thresholds?.spam_score_block ?? ''}
                placeholder={String(globalThresholds.spam_score_block)}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    thresholds: {
                      ...formData.thresholds,
                      spam_score_block: e.target.value ? parseInt(e.target.value) : undefined,
                    },
                  })
                }
              />
              <p className="text-xs text-muted-foreground">Reject submissions scoring above this</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="spam_score_flag">Spam Score Flag Threshold</Label>
              <Input
                id="spam_score_flag"
                type="number"
                value={formData.thresholds?.spam_score_flag ?? ''}
                placeholder={String(globalThresholds.spam_score_flag)}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    thresholds: {
                      ...formData.thresholds,
                      spam_score_flag: e.target.value ? parseInt(e.target.value) : undefined,
                    },
                  })
                }
              />
              <p className="text-xs text-muted-foreground">Tag submissions scoring above this</p>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="hash_count_block">Hash Count Block</Label>
              <Input
                id="hash_count_block"
                type="number"
                value={formData.thresholds?.hash_count_block ?? ''}
                placeholder={String(globalThresholds.hash_count_block)}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    thresholds: {
                      ...formData.thresholds,
                      hash_count_block: e.target.value ? parseInt(e.target.value) : undefined,
                    },
                  })
                }
              />
              <p className="text-xs text-muted-foreground">Block after this many identical submissions</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="hash_unique_ips_block">Hash Unique IPs Block</Label>
              <Input
                id="hash_unique_ips_block"
                type="number"
                value={formData.thresholds?.hash_unique_ips_block ?? ''}
                placeholder={String(globalThresholds.hash_unique_ips_block)}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    thresholds: {
                      ...formData.thresholds,
                      hash_unique_ips_block: e.target.value ? parseInt(e.target.value) : undefined,
                    },
                  })
                }
              />
              <p className="text-xs text-muted-foreground">Block hash if seen from this many unique IPs</p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Keywords</CardTitle>
          <CardDescription>Configure keyword inheritance and overrides</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center space-x-2">
            <Switch
              id="inherit_global_keywords"
              checked={formData.keywords?.inherit_global !== false}
              onCheckedChange={(checked) =>
                setFormData({
                  ...formData,
                  keywords: { ...formData.keywords, inherit_global: checked },
                })
              }
            />
            <Label htmlFor="inherit_global_keywords">Inherit Global Keywords</Label>
          </div>
          <p className="text-sm text-muted-foreground">
            When enabled, this endpoint will use the globally defined blocked and flagged keywords
            in addition to any endpoint-specific keywords.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Actions</CardTitle>
          <CardDescription>Configure how the WAF responds to threats</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-3">
            <div className="space-y-2">
              <Label htmlFor="on_block">On Block</Label>
              <Select
                value={formData.actions?.on_block || 'reject'}
                onValueChange={(value) =>
                  setFormData({
                    ...formData,
                    actions: { ...formData.actions, on_block: value as 'reject' | 'tag' | 'log' },
                  })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="reject">Reject Request</SelectItem>
                  <SelectItem value="tag">Tag Only</SelectItem>
                  <SelectItem value="log">Log Only</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="on_flag">On Flag</Label>
              <Select
                value={formData.actions?.on_flag || 'tag'}
                onValueChange={(value) =>
                  setFormData({
                    ...formData,
                    actions: { ...formData.actions, on_flag: value as 'tag' | 'log' | 'none' },
                  })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="tag">Tag Request</SelectItem>
                  <SelectItem value="log">Log Only</SelectItem>
                  <SelectItem value="none">No Action</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="log_level">Log Level</Label>
              <Select
                value={formData.actions?.log_level || 'info'}
                onValueChange={(value) =>
                  setFormData({
                    ...formData,
                    actions: { ...formData.actions, log_level: value as 'debug' | 'info' | 'warn' | 'error' },
                  })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="debug">Debug</SelectItem>
                  <SelectItem value="info">Info</SelectItem>
                  <SelectItem value="warn">Warn</SelectItem>
                  <SelectItem value="error">Error</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
