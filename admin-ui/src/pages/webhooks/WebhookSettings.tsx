import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { webhooksApi, WebhookConfig } from '@/api/client'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useToast } from '@/components/ui/use-toast'
import { Bell, Save, TestTube, Plus, X, Info, CheckCircle, XCircle } from 'lucide-react'

const AVAILABLE_EVENTS = [
  { id: 'request_blocked', label: 'Request Blocked', description: 'When a request is blocked by the WAF' },
  { id: 'rate_limit_triggered', label: 'Rate Limit Triggered', description: 'When rate limiting blocks a request' },
  { id: 'high_spam_score', label: 'High Spam Score', description: 'When spam score exceeds threshold' },
  { id: 'captcha_triggered', label: 'CAPTCHA Triggered', description: 'When CAPTCHA challenge is presented' },
  { id: 'honeypot_triggered', label: 'Honeypot Triggered', description: 'When a honeypot field is filled' },
  { id: 'disposable_email', label: 'Disposable Email', description: 'When disposable email is detected' },
  { id: 'fingerprint_flood', label: 'Fingerprint Flood', description: 'When coordinated attack detected' },
]

export function WebhookSettings() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const [formData, setFormData] = useState<Partial<WebhookConfig>>({
    enabled: false,
    url: '',
    urls: [],
    events: [],
    batch_size: 10,
    batch_interval: 60,
    headers: {},
    ssl_verify: true,
  })
  const [newUrl, setNewUrl] = useState('')
  const [newHeaderKey, setNewHeaderKey] = useState('')
  const [newHeaderValue, setNewHeaderValue] = useState('')
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['webhooks', 'config'],
    queryFn: webhooksApi.getConfig,
  })

  const { data: statsData } = useQuery({
    queryKey: ['webhooks', 'stats'],
    queryFn: webhooksApi.getStats,
    refetchInterval: 10000,
  })

  useEffect(() => {
    if (data?.config) {
      setFormData({
        ...data.config,
        urls: data.config.urls || (data.config.url ? [data.config.url] : []),
        headers: data.config.headers || {},
      })
    }
  }, [data])

  const saveMutation = useMutation({
    mutationFn: webhooksApi.updateConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
      toast({ title: 'Webhook settings saved' })
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to save',
        variant: 'destructive',
      })
    },
  })

  const testMutation = useMutation({
    mutationFn: webhooksApi.test,
    onSuccess: (result) => {
      setTestResult(result)
      if (result.success) {
        toast({ title: 'Webhook test successful' })
      } else {
        toast({
          title: 'Webhook test failed',
          description: result.message,
          variant: 'destructive',
        })
      }
    },
    onError: (error) => {
      setTestResult({ success: false, message: error instanceof Error ? error.message : 'Test failed' })
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to test webhook',
        variant: 'destructive',
      })
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    saveMutation.mutate(formData)
  }

  const addUrl = () => {
    if (newUrl && !formData.urls?.includes(newUrl)) {
      setFormData({
        ...formData,
        urls: [...(formData.urls || []), newUrl],
      })
      setNewUrl('')
    }
  }

  const removeUrl = (url: string) => {
    setFormData({
      ...formData,
      urls: formData.urls?.filter((u) => u !== url),
    })
  }

  const addHeader = () => {
    if (newHeaderKey && newHeaderValue) {
      setFormData({
        ...formData,
        headers: {
          ...formData.headers,
          [newHeaderKey]: newHeaderValue,
        },
      })
      setNewHeaderKey('')
      setNewHeaderValue('')
    }
  }

  const removeHeader = (key: string) => {
    const { [key]: _, ...rest } = formData.headers || {}
    setFormData({
      ...formData,
      headers: rest,
    })
  }

  const toggleEvent = (eventId: string) => {
    const events = formData.events || []
    if (events.includes(eventId)) {
      setFormData({
        ...formData,
        events: events.filter((e) => e !== eventId),
      })
    } else {
      setFormData({
        ...formData,
        events: [...events, eventId],
      })
    }
  }

  const selectAllEvents = () => {
    setFormData({
      ...formData,
      events: AVAILABLE_EVENTS.map((e) => e.id),
    })
  }

  if (isLoading) {
    return <div className="flex items-center justify-center h-64">Loading...</div>
  }

  const stats = statsData?.stats

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Bell className="h-8 w-8 text-primary" />
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Webhook Notifications</h2>
          <p className="text-muted-foreground">
            Configure webhooks to receive real-time notifications about security events
          </p>
        </div>
      </div>

      {stats && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Queue Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-6 text-sm">
              <div>
                <span className="text-muted-foreground">Queue Size:</span>{' '}
                <span className="font-medium">{stats.queue_size} / {stats.max_queue_size}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Last Flush:</span>{' '}
                <span className="font-medium">
                  {stats.last_flush > 0
                    ? new Date(stats.last_flush * 1000).toLocaleTimeString()
                    : 'Never'}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <form onSubmit={handleSubmit}>
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>General Settings</CardTitle>
              <CardDescription>Enable webhooks and configure delivery options</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center space-x-2">
                <Switch
                  id="enabled"
                  checked={formData.enabled}
                  onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
                />
                <Label htmlFor="enabled">Enable Webhooks</Label>
              </div>

              {formData.enabled && (
                <>
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="batch_size">Batch Size</Label>
                      <Input
                        id="batch_size"
                        type="number"
                        min="1"
                        max="100"
                        value={formData.batch_size || 10}
                        onChange={(e) =>
                          setFormData({ ...formData, batch_size: parseInt(e.target.value) || 10 })
                        }
                      />
                      <p className="text-xs text-muted-foreground">
                        Send webhook when this many events are queued
                      </p>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="batch_interval">Batch Interval (seconds)</Label>
                      <Input
                        id="batch_interval"
                        type="number"
                        min="10"
                        max="3600"
                        value={formData.batch_interval || 60}
                        onChange={(e) =>
                          setFormData({ ...formData, batch_interval: parseInt(e.target.value) || 60 })
                        }
                      />
                      <p className="text-xs text-muted-foreground">
                        Maximum time to wait before sending queued events
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <Switch
                      id="ssl_verify"
                      checked={formData.ssl_verify !== false}
                      onCheckedChange={(checked) => setFormData({ ...formData, ssl_verify: checked })}
                    />
                    <Label htmlFor="ssl_verify">Verify SSL Certificates</Label>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          {formData.enabled && (
            <>
              <Card>
                <CardHeader>
                  <CardTitle>Webhook URLs</CardTitle>
                  <CardDescription>
                    Add one or more URLs to receive webhook notifications
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex gap-2">
                    <Input
                      value={newUrl}
                      onChange={(e) => setNewUrl(e.target.value)}
                      placeholder="https://example.com/webhook"
                      className="flex-1"
                      onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addUrl())}
                    />
                    <Button type="button" onClick={addUrl}>
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>

                  {(formData.urls?.length || 0) > 0 ? (
                    <div className="space-y-2">
                      {formData.urls?.map((url) => (
                        <div
                          key={url}
                          className="flex items-center justify-between rounded-md bg-secondary px-3 py-2 text-sm"
                        >
                          <code className="truncate flex-1">{url}</code>
                          <button
                            type="button"
                            onClick={() => removeUrl(url)}
                            className="ml-2 hover:text-destructive"
                          >
                            <X className="h-4 w-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground italic">
                      No webhook URLs configured
                    </p>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle>Event Types</CardTitle>
                      <CardDescription>
                        Select which events should trigger webhook notifications
                      </CardDescription>
                    </div>
                    <Button type="button" variant="outline" size="sm" onClick={selectAllEvents}>
                      Select All
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-4 md:grid-cols-2">
                    {AVAILABLE_EVENTS.map((event) => (
                      <div
                        key={event.id}
                        className={`flex items-start space-x-3 rounded-lg border p-4 cursor-pointer transition-colors ${
                          formData.events?.includes(event.id)
                            ? 'border-primary bg-primary/5'
                            : 'hover:bg-muted/50'
                        }`}
                        onClick={() => toggleEvent(event.id)}
                      >
                        <Switch
                          checked={formData.events?.includes(event.id)}
                          onCheckedChange={() => toggleEvent(event.id)}
                        />
                        <div>
                          <Label className="font-medium cursor-pointer">{event.label}</Label>
                          <p className="text-xs text-muted-foreground mt-1">{event.description}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Custom Headers</CardTitle>
                  <CardDescription>
                    Add custom headers to webhook requests (e.g., Authorization)
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex gap-2">
                    <Input
                      value={newHeaderKey}
                      onChange={(e) => setNewHeaderKey(e.target.value)}
                      placeholder="Header name"
                      className="flex-1"
                    />
                    <Input
                      value={newHeaderValue}
                      onChange={(e) => setNewHeaderValue(e.target.value)}
                      placeholder="Header value"
                      className="flex-1"
                      type="password"
                    />
                    <Button type="button" onClick={addHeader}>
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>

                  {Object.keys(formData.headers || {}).length > 0 ? (
                    <div className="space-y-2">
                      {Object.entries(formData.headers || {}).map(([key, value]) => (
                        <div
                          key={key}
                          className="flex items-center justify-between rounded-md bg-secondary px-3 py-2 text-sm"
                        >
                          <div>
                            <span className="font-medium">{key}:</span>{' '}
                            <span className="text-muted-foreground">{'*'.repeat(8)}</span>
                          </div>
                          <button
                            type="button"
                            onClick={() => removeHeader(key)}
                            className="ml-2 hover:text-destructive"
                          >
                            <X className="h-4 w-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground italic">No custom headers</p>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Test Webhook</CardTitle>
                  <CardDescription>
                    Send a test event to verify your webhook configuration
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
                    <div className="flex items-start gap-3">
                      <Info className="h-5 w-5 text-blue-500 mt-0.5" />
                      <div>
                        <p className="font-medium text-blue-800">Webhook Payload Format</p>
                        <p className="text-sm text-blue-700 mt-1">
                          Events are sent as JSON with the following structure:
                        </p>
                        <pre className="text-xs bg-blue-100 p-2 rounded mt-2 overflow-x-auto">
{`{
  "source": "forms-waf",
  "batch_id": "1234567890-1234",
  "event_count": 1,
  "events": [{
    "event": "request_blocked",
    "timestamp": 1234567890,
    "data": {
      "client_ip": "1.2.3.4",
      "host": "example.com",
      "path": "/contact",
      "reason": "spam_score_exceeded",
      "spam_score": 95
    }
  }]
}`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => testMutation.mutate()}
                      disabled={testMutation.isPending || (formData.urls?.length || 0) === 0}
                    >
                      <TestTube className="mr-2 h-4 w-4" />
                      {testMutation.isPending ? 'Testing...' : 'Send Test Event'}
                    </Button>

                    {testResult && (
                      <div
                        className={`flex items-center gap-2 text-sm ${
                          testResult.success ? 'text-green-600' : 'text-red-600'
                        }`}
                      >
                        {testResult.success ? (
                          <CheckCircle className="h-4 w-4" />
                        ) : (
                          <XCircle className="h-4 w-4" />
                        )}
                        {testResult.message}
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </>
          )}

          <div className="flex justify-end">
            <Button type="submit" disabled={saveMutation.isPending}>
              <Save className="mr-2 h-4 w-4" />
              {saveMutation.isPending ? 'Saving...' : 'Save Settings'}
            </Button>
          </div>
        </div>
      </form>
    </div>
  )
}
