import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useToast } from '@/components/ui/use-toast'
import { Loader2, Clock, Save, Info } from 'lucide-react'
import { timingApi, type TimingTokenConfig } from '@/api/client'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert'

export default function TimingConfig() {
  const { toast } = useToast()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [config, setConfig] = useState<TimingTokenConfig>({
    enabled: false,
    cookie_name: '_waf_timing',
    cookie_ttl: 3600,
    min_time_seconds: 2,
    suspicious_time_seconds: 5,
    no_cookie_score: 30,
    too_fast_score: 40,
    suspicious_score: 20,
  })

  useEffect(() => {
    loadConfig()
  }, [])

  const loadConfig = async () => {
    try {
      const data = await timingApi.getConfig()
      setConfig(prev => ({ ...prev, ...data }))
    } catch (error) {
      toast({
        title: 'Error loading configuration',
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive',
      })
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      await timingApi.updateConfig(config)
      toast({
        title: 'Configuration saved',
        description: 'Timing token settings have been updated.',
      })
    } catch (error) {
      toast({
        title: 'Error saving configuration',
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive',
      })
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Form Timing Detection</h1>
        <p className="text-muted-foreground">
          Detect bot submissions by measuring time between form load and submission
        </p>
      </div>

      <Alert>
        <Info className="h-4 w-4" />
        <AlertTitle>How it works</AlertTitle>
        <AlertDescription>
          When a user loads a page with a form, the WAF sets an encrypted cookie with the current timestamp.
          On form submission, the WAF validates this cookie and checks how long the user spent on the form.
          Bots typically submit forms instantly, while humans take time to fill them out.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Timing Token Settings
          </CardTitle>
          <CardDescription>
            Configure form timing detection thresholds and scores
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Enable/Disable */}
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Enable Timing Detection</Label>
              <p className="text-sm text-muted-foreground">
                Set cookies on page load and validate on form submission
              </p>
            </div>
            <Switch
              checked={config.enabled}
              onCheckedChange={(checked) => setConfig({ ...config, enabled: checked })}
            />
          </div>

          <div className="border-t pt-4 space-y-4">
            <h4 className="font-medium">Cookie Settings</h4>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="cookie_name">Cookie Name</Label>
                <Input
                  id="cookie_name"
                  value={config.cookie_name || '_waf_timing'}
                  onChange={(e) => setConfig({ ...config, cookie_name: e.target.value })}
                  placeholder="_waf_timing"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="cookie_ttl">Cookie TTL (seconds)</Label>
                <Input
                  id="cookie_ttl"
                  type="number"
                  value={config.cookie_ttl || 3600}
                  onChange={(e) => setConfig({ ...config, cookie_ttl: parseInt(e.target.value) || 3600 })}
                />
                <p className="text-xs text-muted-foreground">How long the cookie is valid</p>
              </div>
            </div>
          </div>

          <div className="border-t pt-4 space-y-4">
            <h4 className="font-medium">Time Thresholds</h4>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="min_time">Minimum Time (seconds)</Label>
                <Input
                  id="min_time"
                  type="number"
                  value={config.min_time_seconds || 2}
                  onChange={(e) => setConfig({ ...config, min_time_seconds: parseInt(e.target.value) || 2 })}
                />
                <p className="text-xs text-muted-foreground">
                  Submissions faster than this are flagged as "too fast"
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="suspicious_time">Suspicious Time (seconds)</Label>
                <Input
                  id="suspicious_time"
                  type="number"
                  value={config.suspicious_time_seconds || 5}
                  onChange={(e) => setConfig({ ...config, suspicious_time_seconds: parseInt(e.target.value) || 5 })}
                />
                <p className="text-xs text-muted-foreground">
                  Submissions between min and this are "suspicious"
                </p>
              </div>
            </div>
          </div>

          <div className="border-t pt-4 space-y-4">
            <h4 className="font-medium">Score Additions</h4>
            <p className="text-sm text-muted-foreground">
              Score points added to spam score based on timing behavior
            </p>

            <div className="grid grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label htmlFor="too_fast_score">Too Fast Score</Label>
                <Input
                  id="too_fast_score"
                  type="number"
                  value={config.too_fast_score || 40}
                  onChange={(e) => setConfig({ ...config, too_fast_score: parseInt(e.target.value) || 40 })}
                />
                <p className="text-xs text-muted-foreground">
                  Added when submission is faster than minimum time
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="suspicious_score">Suspicious Score</Label>
                <Input
                  id="suspicious_score"
                  type="number"
                  value={config.suspicious_score || 20}
                  onChange={(e) => setConfig({ ...config, suspicious_score: parseInt(e.target.value) || 20 })}
                />
                <p className="text-xs text-muted-foreground">
                  Added when submission is in suspicious range
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="no_cookie_score">No Cookie Score</Label>
                <Input
                  id="no_cookie_score"
                  type="number"
                  value={config.no_cookie_score || 30}
                  onChange={(e) => setConfig({ ...config, no_cookie_score: parseInt(e.target.value) || 30 })}
                />
                <p className="text-xs text-muted-foreground">
                  Added when timing cookie is missing (direct POST)
                </p>
              </div>
            </div>
          </div>

          <div className="flex justify-end pt-4 border-t">
            <Button onClick={handleSave} disabled={saving}>
              {saving ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Saving...
                </>
              ) : (
                <>
                  <Save className="h-4 w-4 mr-2" />
                  Save Configuration
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
