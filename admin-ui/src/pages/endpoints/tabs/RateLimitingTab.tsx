import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Info } from 'lucide-react'
import type { RateLimitingTabProps } from './types'

export function RateLimitingTab({ formData, setFormData }: RateLimitingTabProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Rate Limiting</CardTitle>
        <CardDescription>
          Control the rate of requests allowed to this endpoint
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
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
          <Label htmlFor="rate_limiting_enabled">Enable Rate Limiting</Label>
        </div>

        {formData.rate_limiting?.enabled !== false && (
          <div className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="requests_per_minute">Requests per Minute</Label>
                <Input
                  id="requests_per_minute"
                  type="number"
                  value={formData.rate_limiting?.requests_per_minute ?? 30}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      rate_limiting: {
                        ...formData.rate_limiting,
                        enabled: formData.rate_limiting?.enabled !== false,
                        requests_per_minute: parseInt(e.target.value) || 30,
                      },
                    })
                  }
                  min={1}
                  max={1000}
                />
                <p className="text-xs text-muted-foreground">
                  Maximum requests allowed per IP per minute
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="requests_per_day">Requests per Day</Label>
                <Input
                  id="requests_per_day"
                  type="number"
                  value={formData.rate_limiting?.requests_per_day ?? 500}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      rate_limiting: {
                        ...formData.rate_limiting,
                        enabled: formData.rate_limiting?.enabled !== false,
                        requests_per_day: parseInt(e.target.value) || 500,
                      },
                    })
                  }
                  min={1}
                  max={100000}
                />
                <p className="text-xs text-muted-foreground">
                  Maximum requests allowed per IP per day
                </p>
              </div>
            </div>

            <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4">
              <div className="flex items-start gap-3">
                <Info className="h-5 w-5 text-yellow-600 mt-0.5" />
                <div>
                  <p className="font-medium text-yellow-800">Rate Limiting Behavior</p>
                  <p className="text-sm text-yellow-700 mt-1">
                    When rate limits are exceeded, requests will be rejected with a 429 Too Many Requests response.
                    Limits are tracked per IP address. The minute limit resets every minute, while the daily limit resets at midnight UTC.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
