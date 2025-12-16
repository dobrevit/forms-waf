import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/components/ui/use-toast'
import { Loader2, Globe, Save, Search, X, AlertTriangle, CheckCircle, Database } from 'lucide-react'
import { geoipApi, type GeoIPConfig, type GeoIPStatus, type GeoIPLookupResult } from '@/api/client'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'

export default function GeoIPConfig() {
  const { toast } = useToast()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [status, setStatus] = useState<GeoIPStatus | null>(null)
  const [config, setConfig] = useState<GeoIPConfig>({
    enabled: false,
    blocked_countries: [],
    allowed_countries: [],
    flagged_countries: [],
    flagged_country_score: 15,
    blocked_asns: [],
    flagged_asns: [],
    flagged_asn_score: 20,
    block_datacenters: false,
    flag_datacenters: true,
    datacenter_score: 25,
  })

  // IP Lookup state
  const [lookupIP, setLookupIP] = useState('')
  const [lookupResult, setLookupResult] = useState<GeoIPLookupResult | null>(null)
  const [lookupLoading, setLookupLoading] = useState(false)

  // New item inputs
  const [newBlockedCountry, setNewBlockedCountry] = useState('')
  const [newAllowedCountry, setNewAllowedCountry] = useState('')
  const [newFlaggedCountry, setNewFlaggedCountry] = useState('')
  const [newBlockedASN, setNewBlockedASN] = useState('')
  const [newFlaggedASN, setNewFlaggedASN] = useState('')

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      const [statusData, configData] = await Promise.all([
        geoipApi.getStatus(),
        geoipApi.getConfig(),
      ])
      setStatus(statusData)
      setConfig(prev => ({ ...prev, ...configData }))
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
      await geoipApi.updateConfig(config)
      toast({
        title: 'Configuration saved',
        description: 'GeoIP settings have been updated.',
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

  const handleLookup = async () => {
    if (!lookupIP.trim()) return
    setLookupLoading(true)
    setLookupResult(null)
    try {
      const result = await geoipApi.lookup(lookupIP.trim())
      if ('available' in result && result.available === false) {
        toast({
          title: 'GeoIP not available',
          description: result.message,
          variant: 'destructive',
        })
      } else {
        setLookupResult(result as GeoIPLookupResult)
      }
    } catch (error) {
      toast({
        title: 'Lookup failed',
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive',
      })
    } finally {
      setLookupLoading(false)
    }
  }

  const addItem = (field: 'blocked_countries' | 'allowed_countries' | 'flagged_countries', value: string) => {
    const normalized = value.toUpperCase().trim()
    if (!normalized || normalized.length !== 2) {
      toast({ title: 'Invalid country code', description: 'Please enter a 2-letter ISO country code', variant: 'destructive' })
      return
    }
    const current = config[field] || []
    if (!current.includes(normalized)) {
      setConfig({ ...config, [field]: [...current, normalized] })
    }
  }

  const addASN = (field: 'blocked_asns' | 'flagged_asns', value: string) => {
    const num = parseInt(value.trim())
    if (isNaN(num) || num <= 0) {
      toast({ title: 'Invalid ASN', description: 'Please enter a valid ASN number', variant: 'destructive' })
      return
    }
    const current = config[field] || []
    if (!current.includes(num)) {
      setConfig({ ...config, [field]: [...current, num] })
    }
  }

  const removeItem = (field: 'blocked_countries' | 'allowed_countries' | 'flagged_countries', value: string) => {
    setConfig({ ...config, [field]: (config[field] || []).filter(v => v !== value) })
  }

  const removeASN = (field: 'blocked_asns' | 'flagged_asns', value: number) => {
    setConfig({ ...config, [field]: (config[field] || []).filter(v => v !== value) })
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
        <h1 className="text-2xl font-bold">GeoIP Restrictions</h1>
        <p className="text-muted-foreground">
          Block or flag requests based on geographic location and network provider
        </p>
      </div>

      {/* Status Alert */}
      {status && (
        <Alert variant={status.country_db_loaded || status.asn_db_loaded ? 'default' : 'destructive'}>
          <Database className="h-4 w-4" />
          <AlertTitle>Database Status</AlertTitle>
          <AlertDescription className="flex flex-col gap-1">
            <div className="flex items-center gap-2">
              {status.country_db_loaded ? (
                <CheckCircle className="h-4 w-4 text-green-500" />
              ) : (
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
              )}
              Country Database: {status.country_db_loaded ? 'Loaded' : 'Not available'}
            </div>
            <div className="flex items-center gap-2">
              {status.asn_db_loaded ? (
                <CheckCircle className="h-4 w-4 text-green-500" />
              ) : (
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
              )}
              ASN Database: {status.asn_db_loaded ? 'Loaded' : 'Not available'}
            </div>
            {!status.mmdb_available && (
              <p className="text-sm mt-2">
                MaxMind database library not available. Mount GeoLite2 databases to enable this feature.
              </p>
            )}
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5" />
            GeoIP Settings
          </CardTitle>
          <CardDescription>
            Configure country and ASN-based restrictions
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Enable/Disable */}
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Enable GeoIP Restrictions</Label>
              <p className="text-sm text-muted-foreground">
                Check incoming requests against geographic data
              </p>
            </div>
            <Switch
              checked={config.enabled}
              onCheckedChange={(checked) => setConfig({ ...config, enabled: checked })}
            />
          </div>

          <Tabs defaultValue="countries" className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="countries">Countries</TabsTrigger>
              <TabsTrigger value="asns">ASNs</TabsTrigger>
              <TabsTrigger value="datacenters">Datacenters</TabsTrigger>
            </TabsList>

            <TabsContent value="countries" className="space-y-4 pt-4">
              {/* Blocked Countries */}
              <div className="space-y-2">
                <Label>Blocked Countries (ISO codes)</Label>
                <p className="text-xs text-muted-foreground">Requests from these countries will be blocked</p>
                <div className="flex gap-2">
                  <Input
                    placeholder="e.g., RU"
                    value={newBlockedCountry}
                    onChange={(e) => setNewBlockedCountry(e.target.value.toUpperCase())}
                    maxLength={2}
                    className="w-24"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        addItem('blocked_countries', newBlockedCountry)
                        setNewBlockedCountry('')
                      }
                    }}
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      addItem('blocked_countries', newBlockedCountry)
                      setNewBlockedCountry('')
                    }}
                  >
                    Add
                  </Button>
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {(config.blocked_countries || []).map(cc => (
                    <Badge key={cc} variant="destructive" className="gap-1">
                      {cc}
                      <X className="h-3 w-3 cursor-pointer" onClick={() => removeItem('blocked_countries', cc)} />
                    </Badge>
                  ))}
                  {(config.blocked_countries || []).length === 0 && (
                    <span className="text-sm text-muted-foreground">No blocked countries</span>
                  )}
                </div>
              </div>

              {/* Allowed Countries (whitelist mode) */}
              <div className="space-y-2 border-t pt-4">
                <Label>Allowed Countries (whitelist mode)</Label>
                <p className="text-xs text-muted-foreground">
                  If set, ONLY these countries are allowed (overrides blocked list)
                </p>
                <div className="flex gap-2">
                  <Input
                    placeholder="e.g., US"
                    value={newAllowedCountry}
                    onChange={(e) => setNewAllowedCountry(e.target.value.toUpperCase())}
                    maxLength={2}
                    className="w-24"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        addItem('allowed_countries', newAllowedCountry)
                        setNewAllowedCountry('')
                      }
                    }}
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      addItem('allowed_countries', newAllowedCountry)
                      setNewAllowedCountry('')
                    }}
                  >
                    Add
                  </Button>
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {(config.allowed_countries || []).map(cc => (
                    <Badge key={cc} variant="secondary" className="gap-1 bg-green-100 text-green-800">
                      {cc}
                      <X className="h-3 w-3 cursor-pointer" onClick={() => removeItem('allowed_countries', cc)} />
                    </Badge>
                  ))}
                  {(config.allowed_countries || []).length === 0 && (
                    <span className="text-sm text-muted-foreground">Whitelist disabled (all countries allowed unless blocked)</span>
                  )}
                </div>
              </div>

              {/* Flagged Countries */}
              <div className="space-y-2 border-t pt-4">
                <Label>Flagged Countries</Label>
                <p className="text-xs text-muted-foreground">
                  Requests from these countries add to spam score but aren't blocked
                </p>
                <div className="flex gap-2">
                  <Input
                    placeholder="e.g., CN"
                    value={newFlaggedCountry}
                    onChange={(e) => setNewFlaggedCountry(e.target.value.toUpperCase())}
                    maxLength={2}
                    className="w-24"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        addItem('flagged_countries', newFlaggedCountry)
                        setNewFlaggedCountry('')
                      }
                    }}
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      addItem('flagged_countries', newFlaggedCountry)
                      setNewFlaggedCountry('')
                    }}
                  >
                    Add
                  </Button>
                  <Input
                    type="number"
                    value={config.flagged_country_score || 15}
                    onChange={(e) => setConfig({ ...config, flagged_country_score: parseInt(e.target.value) || 15 })}
                    className="w-24"
                  />
                  <span className="text-sm text-muted-foreground self-center">score</span>
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {(config.flagged_countries || []).map(cc => (
                    <Badge key={cc} variant="outline" className="gap-1 bg-yellow-50 text-yellow-800 border-yellow-300">
                      {cc}
                      <X className="h-3 w-3 cursor-pointer" onClick={() => removeItem('flagged_countries', cc)} />
                    </Badge>
                  ))}
                  {(config.flagged_countries || []).length === 0 && (
                    <span className="text-sm text-muted-foreground">No flagged countries</span>
                  )}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="asns" className="space-y-4 pt-4">
              {/* Blocked ASNs */}
              <div className="space-y-2">
                <Label>Blocked ASNs</Label>
                <p className="text-xs text-muted-foreground">Block requests from specific Autonomous System Numbers</p>
                <div className="flex gap-2">
                  <Input
                    placeholder="e.g., 12345"
                    value={newBlockedASN}
                    onChange={(e) => setNewBlockedASN(e.target.value)}
                    type="number"
                    className="w-32"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        addASN('blocked_asns', newBlockedASN)
                        setNewBlockedASN('')
                      }
                    }}
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      addASN('blocked_asns', newBlockedASN)
                      setNewBlockedASN('')
                    }}
                  >
                    Add
                  </Button>
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {(config.blocked_asns || []).map(asn => (
                    <Badge key={asn} variant="destructive" className="gap-1">
                      AS{asn}
                      <X className="h-3 w-3 cursor-pointer" onClick={() => removeASN('blocked_asns', asn)} />
                    </Badge>
                  ))}
                  {(config.blocked_asns || []).length === 0 && (
                    <span className="text-sm text-muted-foreground">No blocked ASNs</span>
                  )}
                </div>
              </div>

              {/* Flagged ASNs */}
              <div className="space-y-2 border-t pt-4">
                <Label>Flagged ASNs</Label>
                <p className="text-xs text-muted-foreground">
                  Requests from these ASNs add to spam score
                </p>
                <div className="flex gap-2">
                  <Input
                    placeholder="e.g., 67890"
                    value={newFlaggedASN}
                    onChange={(e) => setNewFlaggedASN(e.target.value)}
                    type="number"
                    className="w-32"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        addASN('flagged_asns', newFlaggedASN)
                        setNewFlaggedASN('')
                      }
                    }}
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      addASN('flagged_asns', newFlaggedASN)
                      setNewFlaggedASN('')
                    }}
                  >
                    Add
                  </Button>
                  <Input
                    type="number"
                    value={config.flagged_asn_score || 20}
                    onChange={(e) => setConfig({ ...config, flagged_asn_score: parseInt(e.target.value) || 20 })}
                    className="w-24"
                  />
                  <span className="text-sm text-muted-foreground self-center">score</span>
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {(config.flagged_asns || []).map(asn => (
                    <Badge key={asn} variant="outline" className="gap-1 bg-yellow-50 text-yellow-800 border-yellow-300">
                      AS{asn}
                      <X className="h-3 w-3 cursor-pointer" onClick={() => removeASN('flagged_asns', asn)} />
                    </Badge>
                  ))}
                  {(config.flagged_asns || []).length === 0 && (
                    <span className="text-sm text-muted-foreground">No flagged ASNs</span>
                  )}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="datacenters" className="space-y-4 pt-4">
              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>Datacenter Detection</AlertTitle>
                <AlertDescription>
                  The WAF includes a built-in list of known datacenter/hosting/VPN ASNs
                  (AWS, Google Cloud, Azure, DigitalOcean, etc.). You can block or flag
                  requests originating from these networks.
                </AlertDescription>
              </Alert>

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Block Datacenter IPs</Label>
                  <p className="text-sm text-muted-foreground">
                    Block all requests from known datacenter/hosting providers
                  </p>
                </div>
                <Switch
                  checked={config.block_datacenters || false}
                  onCheckedChange={(checked) => setConfig({ ...config, block_datacenters: checked })}
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Flag Datacenter IPs</Label>
                  <p className="text-sm text-muted-foreground">
                    Add score when request comes from datacenter (not blocked)
                  </p>
                </div>
                <Switch
                  checked={config.flag_datacenters ?? true}
                  onCheckedChange={(checked) => setConfig({ ...config, flag_datacenters: checked })}
                />
              </div>

              <div className="space-y-2">
                <Label>Datacenter Flag Score</Label>
                <Input
                  type="number"
                  value={config.datacenter_score || 25}
                  onChange={(e) => setConfig({ ...config, datacenter_score: parseInt(e.target.value) || 25 })}
                  className="w-24"
                />
                <p className="text-xs text-muted-foreground">
                  Score added when request is from a known datacenter
                </p>
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

      {/* IP Lookup Tool */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Search className="h-5 w-5" />
            IP Lookup
          </CardTitle>
          <CardDescription>
            Test GeoIP lookup for any IP address
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Input
              placeholder="Enter IP address (e.g., 8.8.8.8)"
              value={lookupIP}
              onChange={(e) => setLookupIP(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
            />
            <Button onClick={handleLookup} disabled={lookupLoading || !lookupIP.trim()}>
              {lookupLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            </Button>
          </div>

          {lookupResult && (
            <div className="bg-muted p-4 rounded-lg space-y-2">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-sm text-muted-foreground">IP:</span>
                  <span className="ml-2 font-mono">{lookupResult.ip}</span>
                </div>
                <div>
                  <span className="text-sm text-muted-foreground">Country:</span>
                  <span className="ml-2">
                    {lookupResult.country?.country_code || 'Unknown'}
                    {lookupResult.country?.country_name && ` (${lookupResult.country.country_name})`}
                  </span>
                </div>
                <div>
                  <span className="text-sm text-muted-foreground">ASN:</span>
                  <span className="ml-2">
                    {lookupResult.asn?.asn ? `AS${lookupResult.asn.asn}` : 'Unknown'}
                  </span>
                </div>
                <div>
                  <span className="text-sm text-muted-foreground">Organization:</span>
                  <span className="ml-2">{lookupResult.asn?.org || 'Unknown'}</span>
                </div>
                <div className="col-span-2">
                  <span className="text-sm text-muted-foreground">Datacenter:</span>
                  <span className="ml-2">
                    {lookupResult.is_datacenter ? (
                      <Badge variant="destructive">
                        Yes {lookupResult.datacenter_provider && `(${lookupResult.datacenter_provider})`}
                      </Badge>
                    ) : (
                      <Badge variant="outline">No</Badge>
                    )}
                  </span>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
