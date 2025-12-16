import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/components/ui/use-toast'
import { Loader2, Shield, Save, Search, X, Plus, Trash2, AlertTriangle, CheckCircle } from 'lucide-react'
import { reputationApi, type IPReputationConfig, type IPReputationStatus, type IPReputationCheckResult } from '@/api/client'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

export default function ReputationConfig() {
  const { toast } = useToast()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [status, setStatus] = useState<IPReputationStatus | null>(null)
  const [config, setConfig] = useState<IPReputationConfig>({
    enabled: false,
    cache_ttl: 86400,
    cache_negative_ttl: 3600,
    abuseipdb: {
      enabled: false,
      min_confidence: 25,
      max_age_days: 90,
      score_multiplier: 0.5,
    },
    local_blocklist: {
      enabled: true,
    },
    webhook: {
      enabled: false,
      timeout: 2000,
    },
    block_score: 80,
    flag_score: 50,
    flag_score_addition: 30,
  })

  // Blocklist state
  const [blocklist, setBlocklist] = useState<string[]>([])
  const [newBlockedIP, setNewBlockedIP] = useState('')
  const [blocklistLoading, setBlocklistLoading] = useState(false)

  // IP Check state
  const [checkIP, setCheckIP] = useState('')
  const [checkResult, setCheckResult] = useState<IPReputationCheckResult | null>(null)
  const [checkLoading, setCheckLoading] = useState(false)

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      const [statusData, configData, blocklistData] = await Promise.all([
        reputationApi.getStatus(),
        reputationApi.getConfig(),
        reputationApi.getBlocklist(),
      ])
      setStatus(statusData)
      setConfig(prev => ({ ...prev, ...configData }))
      setBlocklist(blocklistData.blocked_ips || [])
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
      await reputationApi.updateConfig(config)
      toast({
        title: 'Configuration saved',
        description: 'IP reputation settings have been updated.',
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

  const handleAddToBlocklist = async () => {
    if (!newBlockedIP.trim()) return
    setBlocklistLoading(true)
    try {
      await reputationApi.addToBlocklist(newBlockedIP.trim())
      setBlocklist([...blocklist, newBlockedIP.trim()])
      setNewBlockedIP('')
      toast({ title: 'IP added to blocklist' })
    } catch (error) {
      toast({
        title: 'Failed to add IP',
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive',
      })
    } finally {
      setBlocklistLoading(false)
    }
  }

  const handleRemoveFromBlocklist = async (ip: string) => {
    try {
      await reputationApi.removeFromBlocklist(ip)
      setBlocklist(blocklist.filter(i => i !== ip))
      toast({ title: 'IP removed from blocklist' })
    } catch (error) {
      toast({
        title: 'Failed to remove IP',
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive',
      })
    }
  }

  const handleCheckIP = async () => {
    if (!checkIP.trim()) return
    setCheckLoading(true)
    setCheckResult(null)
    try {
      const result = await reputationApi.checkIP(checkIP.trim())
      if ('available' in result && result.available === false) {
        toast({
          title: 'IP Reputation not available',
          description: result.message,
          variant: 'destructive',
        })
      } else {
        setCheckResult(result as IPReputationCheckResult)
      }
    } catch (error) {
      toast({
        title: 'Check failed',
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive',
      })
    } finally {
      setCheckLoading(false)
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
        <h1 className="text-2xl font-bold">IP Reputation</h1>
        <p className="text-muted-foreground">
          Block or flag requests based on IP reputation data from multiple sources
        </p>
      </div>

      {/* Status */}
      {status && (
        <Alert>
          <Shield className="h-4 w-4" />
          <AlertTitle>Provider Status</AlertTitle>
          <AlertDescription className="flex flex-wrap gap-4">
            <div className="flex items-center gap-2">
              {status.providers.local_blocklist ? (
                <CheckCircle className="h-4 w-4 text-green-500" />
              ) : (
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
              )}
              Local Blocklist ({status.blocklist_count} IPs)
            </div>
            <div className="flex items-center gap-2">
              {status.providers.abuseipdb ? (
                <CheckCircle className="h-4 w-4 text-green-500" />
              ) : (
                <AlertTriangle className="h-4 w-4 text-muted-foreground" />
              )}
              AbuseIPDB {status.providers.abuseipdb ? 'Configured' : 'Not configured'}
            </div>
            <div className="flex items-center gap-2">
              {status.providers.webhook ? (
                <CheckCircle className="h-4 w-4 text-green-500" />
              ) : (
                <AlertTriangle className="h-4 w-4 text-muted-foreground" />
              )}
              Webhook {status.providers.webhook ? 'Configured' : 'Not configured'}
            </div>
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            IP Reputation Settings
          </CardTitle>
          <CardDescription>
            Configure reputation checking providers and thresholds
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Enable/Disable */}
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Enable IP Reputation</Label>
              <p className="text-sm text-muted-foreground">
                Check incoming IPs against reputation sources
              </p>
            </div>
            <Switch
              checked={config.enabled}
              onCheckedChange={(checked) => setConfig({ ...config, enabled: checked })}
            />
          </div>

          <Tabs defaultValue="providers" className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="providers">Providers</TabsTrigger>
              <TabsTrigger value="thresholds">Thresholds</TabsTrigger>
              <TabsTrigger value="blocklist">Local Blocklist</TabsTrigger>
            </TabsList>

            <TabsContent value="providers" className="space-y-6 pt-4">
              {/* Local Blocklist Provider */}
              <div className="space-y-4 p-4 border rounded-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-medium">Local Blocklist</h4>
                    <p className="text-sm text-muted-foreground">Redis-based IP blocklist (always available)</p>
                  </div>
                  <Switch
                    checked={config.local_blocklist?.enabled ?? true}
                    onCheckedChange={(checked) => setConfig({
                      ...config,
                      local_blocklist: { ...config.local_blocklist, enabled: checked }
                    })}
                  />
                </div>
              </div>

              {/* AbuseIPDB Provider */}
              <div className="space-y-4 p-4 border rounded-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-medium">AbuseIPDB</h4>
                    <p className="text-sm text-muted-foreground">External IP reputation API (requires API key)</p>
                  </div>
                  <Switch
                    checked={config.abuseipdb?.enabled ?? false}
                    onCheckedChange={(checked) => setConfig({
                      ...config,
                      abuseipdb: { ...config.abuseipdb, enabled: checked }
                    })}
                  />
                </div>

                {config.abuseipdb?.enabled && (
                  <div className="space-y-4 pt-2">
                    <div className="space-y-2">
                      <Label>API Key</Label>
                      <Input
                        type="password"
                        placeholder="Enter AbuseIPDB API key"
                        value={config.abuseipdb?.api_key || ''}
                        onChange={(e) => setConfig({
                          ...config,
                          abuseipdb: { ...config.abuseipdb, api_key: e.target.value }
                        })}
                      />
                      <p className="text-xs text-muted-foreground">
                        Get your API key from <a href="https://www.abuseipdb.com/api" target="_blank" rel="noopener" className="underline">abuseipdb.com/api</a>
                      </p>
                    </div>
                    <div className="grid grid-cols-3 gap-4">
                      <div className="space-y-2">
                        <Label>Min Confidence</Label>
                        <Input
                          type="number"
                          value={config.abuseipdb?.min_confidence || 25}
                          onChange={(e) => setConfig({
                            ...config,
                            abuseipdb: { ...config.abuseipdb, min_confidence: parseInt(e.target.value) || 25 }
                          })}
                        />
                        <p className="text-xs text-muted-foreground">0-100</p>
                      </div>
                      <div className="space-y-2">
                        <Label>Max Age (days)</Label>
                        <Input
                          type="number"
                          value={config.abuseipdb?.max_age_days || 90}
                          onChange={(e) => setConfig({
                            ...config,
                            abuseipdb: { ...config.abuseipdb, max_age_days: parseInt(e.target.value) || 90 }
                          })}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Score Multiplier</Label>
                        <Input
                          type="number"
                          step="0.1"
                          value={config.abuseipdb?.score_multiplier || 0.5}
                          onChange={(e) => setConfig({
                            ...config,
                            abuseipdb: { ...config.abuseipdb, score_multiplier: parseFloat(e.target.value) || 0.5 }
                          })}
                        />
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Custom Webhook Provider */}
              <div className="space-y-4 p-4 border rounded-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-medium">Custom Webhook</h4>
                    <p className="text-sm text-muted-foreground">Query your own reputation service</p>
                  </div>
                  <Switch
                    checked={config.webhook?.enabled ?? false}
                    onCheckedChange={(checked) => setConfig({
                      ...config,
                      webhook: { ...config.webhook, enabled: checked }
                    })}
                  />
                </div>

                {config.webhook?.enabled && (
                  <div className="space-y-4 pt-2">
                    <div className="space-y-2">
                      <Label>Webhook URL</Label>
                      <Input
                        placeholder="https://your-service.com/check-ip"
                        value={config.webhook?.url || ''}
                        onChange={(e) => setConfig({
                          ...config,
                          webhook: { ...config.webhook, url: e.target.value }
                        })}
                      />
                      <p className="text-xs text-muted-foreground">
                        IP will be appended as ?ip=x.x.x.x. Expects JSON response with score (0-100) and optional blocked (boolean)
                      </p>
                    </div>
                    <div className="space-y-2">
                      <Label>Timeout (ms)</Label>
                      <Input
                        type="number"
                        value={config.webhook?.timeout || 2000}
                        onChange={(e) => setConfig({
                          ...config,
                          webhook: { ...config.webhook, timeout: parseInt(e.target.value) || 2000 }
                        })}
                        className="w-32"
                      />
                    </div>
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="thresholds" className="space-y-4 pt-4">
              <div className="grid grid-cols-2 gap-6">
                <div className="space-y-4">
                  <h4 className="font-medium">Score Thresholds</h4>

                  <div className="space-y-2">
                    <Label>Block Score</Label>
                    <Input
                      type="number"
                      value={config.block_score || 80}
                      onChange={(e) => setConfig({ ...config, block_score: parseInt(e.target.value) || 80 })}
                    />
                    <p className="text-xs text-muted-foreground">
                      Block request if reputation score &gt;= this value
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label>Flag Score</Label>
                    <Input
                      type="number"
                      value={config.flag_score || 50}
                      onChange={(e) => setConfig({ ...config, flag_score: parseInt(e.target.value) || 50 })}
                    />
                    <p className="text-xs text-muted-foreground">
                      Add to spam score if reputation &gt;= this (but less than block)
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label>Flag Score Addition</Label>
                    <Input
                      type="number"
                      value={config.flag_score_addition || 30}
                      onChange={(e) => setConfig({ ...config, flag_score_addition: parseInt(e.target.value) || 30 })}
                    />
                    <p className="text-xs text-muted-foreground">
                      Points added to spam score when flagged
                    </p>
                  </div>
                </div>

                <div className="space-y-4">
                  <h4 className="font-medium">Cache Settings</h4>

                  <div className="space-y-2">
                    <Label>Cache TTL (seconds)</Label>
                    <Input
                      type="number"
                      value={config.cache_ttl || 86400}
                      onChange={(e) => setConfig({ ...config, cache_ttl: parseInt(e.target.value) || 86400 })}
                    />
                    <p className="text-xs text-muted-foreground">
                      How long to cache "bad" reputation results (default: 24h)
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label>Negative Cache TTL (seconds)</Label>
                    <Input
                      type="number"
                      value={config.cache_negative_ttl || 3600}
                      onChange={(e) => setConfig({ ...config, cache_negative_ttl: parseInt(e.target.value) || 3600 })}
                    />
                    <p className="text-xs text-muted-foreground">
                      How long to cache "clean" reputation results (default: 1h)
                    </p>
                  </div>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="blocklist" className="space-y-4 pt-4">
              <div className="flex gap-2">
                <Input
                  placeholder="Enter IP address to block"
                  value={newBlockedIP}
                  onChange={(e) => setNewBlockedIP(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleAddToBlocklist()}
                />
                <Button onClick={handleAddToBlocklist} disabled={blocklistLoading || !newBlockedIP.trim()}>
                  {blocklistLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
                </Button>
              </div>

              <div className="border rounded-lg">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>IP Address</TableHead>
                      <TableHead className="w-24">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {blocklist.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={2} className="text-center text-muted-foreground">
                          No IPs in local blocklist
                        </TableCell>
                      </TableRow>
                    ) : (
                      blocklist.map(ip => (
                        <TableRow key={ip}>
                          <TableCell className="font-mono">{ip}</TableCell>
                          <TableCell>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleRemoveFromBlocklist(ip)}
                            >
                              <Trash2 className="h-4 w-4 text-destructive" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </TabsContent>
          </Tabs>

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

      {/* IP Check Tool */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Search className="h-5 w-5" />
            Check IP Reputation
          </CardTitle>
          <CardDescription>
            Test reputation lookup for any IP address
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Input
              placeholder="Enter IP address (e.g., 1.2.3.4)"
              value={checkIP}
              onChange={(e) => setCheckIP(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCheckIP()}
            />
            <Button onClick={handleCheckIP} disabled={checkLoading || !checkIP.trim()}>
              {checkLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            </Button>
          </div>

          {checkResult && (
            <div className="bg-muted p-4 rounded-lg space-y-3">
              <div className="flex items-center gap-4">
                <div>
                  <span className="text-sm text-muted-foreground">IP:</span>
                  <span className="ml-2 font-mono">{checkResult.ip}</span>
                </div>
                <div>
                  <span className="text-sm text-muted-foreground">Score:</span>
                  <span className="ml-2 font-bold">{checkResult.result.score}</span>
                </div>
                <div>
                  {checkResult.result.blocked ? (
                    <Badge variant="destructive">BLOCKED</Badge>
                  ) : checkResult.result.score >= (config.flag_score || 50) ? (
                    <Badge variant="outline" className="bg-yellow-50 text-yellow-800 border-yellow-300">FLAGGED</Badge>
                  ) : (
                    <Badge variant="outline" className="bg-green-50 text-green-800 border-green-300">CLEAN</Badge>
                  )}
                </div>
              </div>

              {checkResult.result.flags.length > 0 && (
                <div>
                  <span className="text-sm text-muted-foreground">Flags:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {checkResult.result.flags.map((flag, i) => (
                      <Badge key={i} variant="secondary">{flag}</Badge>
                    ))}
                  </div>
                </div>
              )}

              {checkResult.result.reason && (
                <div>
                  <span className="text-sm text-muted-foreground">Reason:</span>
                  <span className="ml-2">{checkResult.result.reason}</span>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
