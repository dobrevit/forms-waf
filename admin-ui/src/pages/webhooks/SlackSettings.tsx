import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { slackApi } from '@/api/client'
import type { SlackConfig, SlackAttackStream } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useToast } from '@/components/ui/use-toast'
import { Slack, Save, TestTube, Plus, X, Info, CheckCircle, XCircle, Shield, Clock, AlertTriangle } from 'lucide-react'
import { Slider } from '@/components/ui/slider'

const AVAILABLE_EVENTS = [
  { id: 'request_blocked', label: 'Request Blocked', description: 'When a request is blocked by the WAF' },
  { id: 'rate_limit_triggered', label: 'Rate Limit Triggered', description: 'When rate limiting blocks a request' },
  { id: 'high_spam_score', label: 'High Spam Score', description: 'When spam score exceeds threshold' },
  { id: 'captcha_triggered', label: 'CAPTCHA Triggered', description: 'When CAPTCHA challenge is presented' },
  { id: 'honeypot_triggered', label: 'Honeypot Triggered', description: 'When a honeypot field is filled' },
  { id: 'disposable_email', label: 'Disposable Email', description: 'When disposable email is detected' },
  { id: 'fingerprint_flood', label: 'Fingerprint Flood', description: 'When coordinated attack detected' },
]

export function SlackSettings() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const [formData, setFormData] = useState<Partial<SlackConfig>>({
    enabled: false,
    webhook_url: '',
    channel: '',
    update_interval: 300,
    resolution_threshold: 600,
    events: [],
    mention_users: [],
    mention_on_high_severity: false,
    severity_thresholds: {
      high_event_count: 100,
      high_event_rate: 10,
    },
  })
  const [newMentionUser, setNewMentionUser] = useState('')
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['slack', 'config'],
    queryFn: slackApi.getConfig,
  })

  const { data: statsData } = useQuery({
    queryKey: ['slack', 'stats'],
    queryFn: slackApi.getStats,
    refetchInterval: 10000,
  })

  const { data: attacksData } = useQuery({
    queryKey: ['slack', 'attacks'],
    queryFn: slackApi.getAttacks,
    refetchInterval: 30000,
  })

  useEffect(() => {
    if (data?.config) {
      setFormData({
        ...data.config,
        mention_users: data.config.mention_users || [],
        severity_thresholds: data.config.severity_thresholds || {
          high_event_count: 100,
          high_event_rate: 10,
        },
      })
    }
  }, [data])

  const saveMutation = useMutation({
    mutationFn: slackApi.updateConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['slack'] })
      toast({ title: 'Slack settings saved' })
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
    mutationFn: slackApi.test,
    onSuccess: (result) => {
      setTestResult(result)
      if (result.success) {
        toast({ title: 'Slack test notification sent' })
      } else {
        toast({
          title: 'Slack test failed',
          description: result.message || result.error,
          variant: 'destructive',
        })
      }
    },
    onError: (error) => {
      setTestResult({ success: false, message: error instanceof Error ? error.message : 'Test failed' })
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to test Slack notification',
        variant: 'destructive',
      })
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    saveMutation.mutate(formData)
  }

  const addMentionUser = () => {
    if (newMentionUser && !formData.mention_users?.includes(newMentionUser)) {
      // Validate format: should be U followed by alphanumeric
      if (!/^U[A-Z0-9]+$/.test(newMentionUser.toUpperCase())) {
        toast({
          title: 'Invalid User ID',
          description: 'Slack user ID should match format U[A-Z0-9]+ (e.g., U123ABC456)',
          variant: 'destructive',
        })
        return
      }
      setFormData({
        ...formData,
        mention_users: [...(formData.mention_users || []), newMentionUser.toUpperCase()],
      })
      setNewMentionUser('')
    }
  }

  const removeMentionUser = (userId: string) => {
    setFormData({
      ...formData,
      mention_users: formData.mention_users?.filter((u) => u !== userId),
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

  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${seconds} seconds`
    const minutes = Math.floor(seconds / 60)
    return `${minutes} minute${minutes > 1 ? 's' : ''}`
  }

  const formatTimestamp = (ts: number) => {
    return new Date(ts * 1000).toLocaleString()
  }

  if (isLoading) {
    return <div className="flex items-center justify-center h-64">Loading...</div>
  }

  const stats = statsData?.stats
  const attacks = attacksData?.attacks || []

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Slack className="h-8 w-8 text-primary" />
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Slack Notifications</h2>
          <p className="text-muted-foreground">
            Receive formatted attack notifications in Slack with deduplication
          </p>
        </div>
      </div>

      {stats && (
        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Notifications Sent</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.total_notifications_sent}</div>
              <p className="text-xs text-muted-foreground">Total</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Attacks Today</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.attacks_detected_today}</div>
              <p className="text-xs text-muted-foreground">Detected</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Resolved Today</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.attacks_resolved_today}</div>
              <p className="text-xs text-muted-foreground">Attacks</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Active Attacks</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-orange-600">{stats.active_attacks_count}</div>
              <p className="text-xs text-muted-foreground">Ongoing</p>
            </CardContent>
          </Card>
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>General Settings</CardTitle>
              <CardDescription>Enable Slack notifications and configure the webhook</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center space-x-2">
                <Switch
                  id="enabled"
                  checked={formData.enabled}
                  onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
                />
                <Label htmlFor="enabled">Enable Slack Notifications</Label>
              </div>

              {formData.enabled && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="webhook_url">Slack Webhook URL</Label>
                    <Input
                      id="webhook_url"
                      type="url"
                      value={formData.webhook_url || ''}
                      onChange={(e) => setFormData({ ...formData, webhook_url: e.target.value })}
                      placeholder="https://hooks.slack.com/services/T.../B.../xxx"
                    />
                    <p className="text-xs text-muted-foreground">
                      Create an incoming webhook at{' '}
                      <a
                        href="https://api.slack.com/messaging/webhooks"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-primary hover:underline"
                      >
                        Slack API
                      </a>
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="channel">Channel Override (Optional)</Label>
                    <Input
                      id="channel"
                      value={formData.channel || ''}
                      onChange={(e) => setFormData({ ...formData, channel: e.target.value })}
                      placeholder="#security-alerts"
                    />
                    <p className="text-xs text-muted-foreground">
                      Only works with legacy webhooks or Slack Apps. Modern webhooks use a fixed channel.
                    </p>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          {formData.enabled && (
            <>
              <Card>
                <CardHeader>
                  <CardTitle>Notification Timing</CardTitle>
                  <CardDescription>
                    Control how often notifications are sent during ongoing attacks
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <Label>Update Interval</Label>
                      <span className="text-sm font-medium">
                        {formatDuration(formData.update_interval || 300)}
                      </span>
                    </div>
                    <Slider
                      value={[formData.update_interval || 300]}
                      onValueChange={([value]) => setFormData({ ...formData, update_interval: value })}
                      min={60}
                      max={1800}
                      step={60}
                      className="w-full"
                    />
                    <p className="text-xs text-muted-foreground">
                      How often to send &quot;Ongoing Attack&quot; updates while an attack continues
                    </p>
                  </div>

                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <Label>Resolution Threshold</Label>
                      <span className="text-sm font-medium">
                        {formatDuration(formData.resolution_threshold || 600)}
                      </span>
                    </div>
                    <Slider
                      value={[formData.resolution_threshold || 600]}
                      onValueChange={([value]) => setFormData({ ...formData, resolution_threshold: value })}
                      min={120}
                      max={3600}
                      step={60}
                      className="w-full"
                    />
                    <p className="text-xs text-muted-foreground">
                      Time with no new events before an attack is considered resolved
                    </p>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle>Event Types</CardTitle>
                      <CardDescription>
                        Select which events should trigger Slack notifications
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
                  <CardTitle>Mentions &amp; Severity</CardTitle>
                  <CardDescription>
                    Configure @mentions for high-severity attacks
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="flex items-center space-x-2">
                    <Switch
                      id="mention_on_high_severity"
                      checked={formData.mention_on_high_severity}
                      onCheckedChange={(checked) =>
                        setFormData({ ...formData, mention_on_high_severity: checked })
                      }
                    />
                    <Label htmlFor="mention_on_high_severity">
                      @mention users for high-severity attacks
                    </Label>
                  </div>

                  {formData.mention_on_high_severity && (
                    <>
                      <div className="space-y-4">
                        <Label>Slack User IDs to @mention</Label>
                        <div className="flex gap-2">
                          <Input
                            value={newMentionUser}
                            onChange={(e) => setNewMentionUser(e.target.value)}
                            placeholder="U123ABC456"
                            className="flex-1"
                            onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addMentionUser())}
                          />
                          <Button type="button" onClick={addMentionUser}>
                            <Plus className="h-4 w-4" />
                          </Button>
                        </div>
                        <p className="text-xs text-muted-foreground">
                          Find user IDs in Slack user profiles (click profile &gt; More &gt; Copy member ID)
                        </p>

                        {(formData.mention_users?.length || 0) > 0 ? (
                          <div className="flex flex-wrap gap-2">
                            {formData.mention_users?.map((userId) => (
                              <div
                                key={userId}
                                className="flex items-center gap-1 rounded-md bg-secondary px-3 py-1 text-sm"
                              >
                                <code>@{userId}</code>
                                <button
                                  type="button"
                                  onClick={() => removeMentionUser(userId)}
                                  className="ml-1 hover:text-destructive"
                                >
                                  <X className="h-3 w-3" />
                                </button>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-sm text-muted-foreground italic">
                            No users configured for mentions
                          </p>
                        )}
                      </div>

                      <div className="grid gap-4 md:grid-cols-2">
                        <div className="space-y-2">
                          <Label htmlFor="high_event_count">High Severity: Event Count</Label>
                          <Input
                            id="high_event_count"
                            type="number"
                            min="1"
                            value={formData.severity_thresholds?.high_event_count || 100}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                severity_thresholds: {
                                  ...formData.severity_thresholds!,
                                  high_event_count: parseInt(e.target.value) || 100,
                                },
                              })
                            }
                          />
                          <p className="text-xs text-muted-foreground">
                            Attack is high severity when events exceed this count
                          </p>
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="high_event_rate">High Severity: Event Rate</Label>
                          <Input
                            id="high_event_rate"
                            type="number"
                            min="1"
                            value={formData.severity_thresholds?.high_event_rate || 10}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                severity_thresholds: {
                                  ...formData.severity_thresholds!,
                                  high_event_rate: parseInt(e.target.value) || 10,
                                },
                              })
                            }
                          />
                          <p className="text-xs text-muted-foreground">
                            Attack is high severity when rate exceeds events/minute
                          </p>
                        </div>
                      </div>
                    </>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Test Notification</CardTitle>
                  <CardDescription>
                    Send a test notification to verify your Slack configuration
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
                    <div className="flex items-start gap-3">
                      <Info className="h-5 w-5 text-blue-500 mt-0.5" />
                      <div>
                        <p className="font-medium text-blue-800">Message Format</p>
                        <p className="text-sm text-blue-700 mt-1">
                          Slack messages include colored attachments with structured fields:
                        </p>
                        <ul className="text-sm text-blue-700 mt-2 list-disc list-inside">
                          <li><span className="text-red-600 font-medium">Red</span> - New attack detected</li>
                          <li><span className="text-yellow-600 font-medium">Yellow</span> - Ongoing attack update</li>
                          <li><span className="text-green-600 font-medium">Green</span> - Attack resolved</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => testMutation.mutate()}
                      disabled={testMutation.isPending || !formData.webhook_url}
                    >
                      <TestTube className="mr-2 h-4 w-4" />
                      {testMutation.isPending ? 'Sending...' : 'Send Test Notification'}
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

              {attacks.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <AlertTriangle className="h-5 w-5 text-orange-500" />
                      Active Attack Streams
                    </CardTitle>
                    <CardDescription>
                      Currently tracked attacks with deduplication
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {attacks.map((attack: SlackAttackStream) => (
                        <div
                          key={attack.attack_key}
                          className="rounded-lg border p-4 space-y-2"
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <Shield className="h-4 w-4 text-red-500" />
                              <span className="font-medium">{attack.attack_type}</span>
                            </div>
                            <span
                              className={`px-2 py-1 rounded text-xs font-medium ${
                                attack.status === 'active'
                                  ? 'bg-orange-100 text-orange-800'
                                  : 'bg-green-100 text-green-800'
                              }`}
                            >
                              {attack.status}
                            </span>
                          </div>
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                            <div>
                              <span className="text-muted-foreground">Target:</span>{' '}
                              <span className="font-medium">
                                {attack.target_vhost}
                                {attack.target_endpoint}
                              </span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Source:</span>{' '}
                              <span className="font-medium">{attack.source_ip_prefix}</span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Events:</span>{' '}
                              <span className="font-medium">{attack.event_count}</span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Notifications:</span>{' '}
                              <span className="font-medium">{attack.notification_count}</span>
                            </div>
                          </div>
                          <div className="flex items-center gap-4 text-xs text-muted-foreground">
                            <div className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              Started: {formatTimestamp(attack.first_seen)}
                            </div>
                            <div>
                              Last seen: {formatTimestamp(attack.last_seen)}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
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
