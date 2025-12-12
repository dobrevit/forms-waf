import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { vhostsApi, configApi } from '@/api/client'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useToast } from '@/components/ui/use-toast'
import { ArrowLeft, Save, Plus, X, Server } from 'lucide-react'
import type { Vhost } from '@/api/types'

const defaultVhost: Partial<Vhost> = {
  enabled: true,
  hostnames: [],
  waf: {
    enabled: true,
    mode: 'monitoring',
  },
  routing: {
    use_haproxy: true,
    haproxy_backend: '',
    upstream: {
      servers: [],
      timeout: 30,
    },
  },
  thresholds: {
    spam_score_block: 80,
    spam_score_flag: 50,
  },
  keywords: {
    inherit_global: true,
    additional_blocked: [],
    additional_flagged: [],
    exclusions: [],
  },
}

export function VhostForm() {
  const { id } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const isNew = !id

  const [formData, setFormData] = useState<Partial<Vhost>>(defaultVhost)
  const [newHostname, setNewHostname] = useState('')
  const [newUpstreamServer, setNewUpstreamServer] = useState('')
  const [newBlockedKeyword, setNewBlockedKeyword] = useState('')
  const [newFlaggedKeyword, setNewFlaggedKeyword] = useState('')
  const [newExclusion, setNewExclusion] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['vhost', id],
    queryFn: () => vhostsApi.get(id!),
    enabled: !!id,
  })

  // Fetch global routing config for placeholder/defaults
  const { data: globalRoutingData } = useQuery({
    queryKey: ['config', 'routing'],
    queryFn: configApi.getRouting,
  })
  const globalRouting = globalRoutingData?.routing || globalRoutingData?.defaults || { haproxy_upstream: 'haproxy:80' }

  useEffect(() => {
    // API returns vhost directly (not wrapped in .data)
    const vhost = (data as { vhost?: Vhost } | undefined)?.vhost || data as Vhost | undefined
    if (vhost && typeof vhost === 'object' && 'id' in vhost) {
      // Ensure arrays are proper arrays (Lua cjson may encode empty arrays as objects)
      const normalized: Partial<Vhost> = {
        ...vhost,
        hostnames: Array.isArray(vhost.hostnames) ? vhost.hostnames : [],
        routing: vhost.routing ? {
          ...vhost.routing,
          upstream: vhost.routing.upstream ? {
            ...vhost.routing.upstream,
            servers: Array.isArray(vhost.routing.upstream.servers) ? vhost.routing.upstream.servers : [],
          } : { servers: [], timeout: 30 },
        } : defaultVhost.routing,
        keywords: vhost.keywords ? {
          ...vhost.keywords,
          additional_blocked: Array.isArray(vhost.keywords.additional_blocked) ? vhost.keywords.additional_blocked : [],
          additional_flagged: Array.isArray(vhost.keywords.additional_flagged) ? vhost.keywords.additional_flagged : [],
          exclusions: Array.isArray(vhost.keywords.exclusions) ? vhost.keywords.exclusions : [],
        } : defaultVhost.keywords,
      }
      setFormData(normalized)
    }
  }, [data])

  const saveMutation = useMutation({
    mutationFn: (data: Partial<Vhost>) =>
      isNew ? vhostsApi.create(data) : vhostsApi.update(id!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vhosts'] })
      toast({ title: isNew ? 'Virtual host created' : 'Virtual host updated' })
      navigate('/vhosts')
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to save',
        variant: 'destructive',
      })
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    // Clean up routing config before saving:
    // - Remove haproxy_upstream if empty or matches global (don't persist redundant data)
    // - Remove empty haproxy_backend
    const cleanedFormData = { ...formData }
    if (cleanedFormData.routing) {
      const routing = { ...cleanedFormData.routing }

      // Strip haproxy_upstream if empty or matches global
      if (!routing.haproxy_upstream || routing.haproxy_upstream === globalRouting.haproxy_upstream) {
        delete routing.haproxy_upstream
      }

      // Strip empty haproxy_backend
      if (!routing.haproxy_backend) {
        delete routing.haproxy_backend
      }

      cleanedFormData.routing = routing
    }

    saveMutation.mutate(cleanedFormData)
  }

  const addHostname = () => {
    if (newHostname && !formData.hostnames?.includes(newHostname)) {
      setFormData({
        ...formData,
        hostnames: [...(formData.hostnames || []), newHostname],
      })
      setNewHostname('')
    }
  }

  const removeHostname = (hostname: string) => {
    setFormData({
      ...formData,
      hostnames: formData.hostnames?.filter((h) => h !== hostname),
    })
  }

  const addUpstreamServer = () => {
    if (newUpstreamServer && !formData.routing?.upstream?.servers?.includes(newUpstreamServer)) {
      setFormData({
        ...formData,
        routing: {
          ...formData.routing,
          use_haproxy: formData.routing?.use_haproxy ?? false,
          upstream: {
            ...formData.routing?.upstream,
            servers: [...(formData.routing?.upstream?.servers || []), newUpstreamServer],
          },
        },
      })
      setNewUpstreamServer('')
    }
  }

  const removeUpstreamServer = (server: string) => {
    setFormData({
      ...formData,
      routing: {
        ...formData.routing,
        use_haproxy: formData.routing?.use_haproxy ?? false,
        upstream: {
          ...formData.routing?.upstream,
          servers: formData.routing?.upstream?.servers?.filter((s) => s !== server) || [],
        },
      },
    })
  }

  const addKeyword = (type: 'blocked' | 'flagged' | 'exclusions') => {
    const value = type === 'blocked' ? newBlockedKeyword : type === 'flagged' ? newFlaggedKeyword : newExclusion
    const setter = type === 'blocked' ? setNewBlockedKeyword : type === 'flagged' ? setNewFlaggedKeyword : setNewExclusion
    const key = type === 'blocked' ? 'additional_blocked' : type === 'flagged' ? 'additional_flagged' : 'exclusions'

    if (value && !formData.keywords?.[key]?.includes(value)) {
      setFormData({
        ...formData,
        keywords: {
          ...formData.keywords,
          inherit_global: formData.keywords?.inherit_global ?? true,
          [key]: [...(formData.keywords?.[key] || []), value],
        },
      })
      setter('')
    }
  }

  const removeKeyword = (type: 'additional_blocked' | 'additional_flagged' | 'exclusions', keyword: string) => {
    setFormData({
      ...formData,
      keywords: {
        ...formData.keywords,
        inherit_global: formData.keywords?.inherit_global ?? true,
        [type]: formData.keywords?.[type]?.filter((k) => k !== keyword),
      },
    })
  }

  if (!isNew && isLoading) {
    return <div>Loading...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={() => navigate('/vhosts')}>
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div>
          <h2 className="text-3xl font-bold tracking-tight">
            {isNew ? 'New Virtual Host' : 'Edit Virtual Host'}
          </h2>
          <p className="text-muted-foreground">
            {isNew ? 'Create a new virtual host configuration' : `Editing ${formData.name || formData.id}`}
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit}>
        <Tabs defaultValue="general" className="space-y-4">
          <TabsList>
            <TabsTrigger value="general">General</TabsTrigger>
            <TabsTrigger value="routing">Routing</TabsTrigger>
            <TabsTrigger value="waf">WAF Settings</TabsTrigger>
            <TabsTrigger value="keywords">Keywords</TabsTrigger>
          </TabsList>

          <TabsContent value="general">
            <Card>
              <CardHeader>
                <CardTitle>General Settings</CardTitle>
                <CardDescription>Basic virtual host configuration</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="id">ID</Label>
                    <Input
                      id="id"
                      value={formData.id || ''}
                      onChange={(e) => setFormData({ ...formData, id: e.target.value })}
                      disabled={!isNew}
                      placeholder="my-vhost"
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="name">Name</Label>
                    <Input
                      id="name"
                      value={formData.name || ''}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      placeholder="My Virtual Host"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="description">Description</Label>
                  <Input
                    id="description"
                    value={formData.description || ''}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    placeholder="Description of this virtual host"
                  />
                </div>

                <div className="flex items-center space-x-2">
                  <Switch
                    id="enabled"
                    checked={formData.enabled}
                    onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
                  />
                  <Label htmlFor="enabled">Enabled</Label>
                </div>

                <div className="space-y-2">
                  <Label>Hostnames</Label>
                  <div className="flex gap-2">
                    <Input
                      value={newHostname}
                      onChange={(e) => setNewHostname(e.target.value)}
                      placeholder="example.com or *.example.com"
                      onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addHostname())}
                    />
                    <Button type="button" onClick={addHostname}>
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {(Array.isArray(formData.hostnames) ? formData.hostnames : []).map((hostname) => (
                      <div
                        key={hostname}
                        className="flex items-center gap-1 rounded-md bg-secondary px-2 py-1 text-sm"
                      >
                        {hostname}
                        <button
                          type="button"
                          onClick={() => removeHostname(hostname)}
                          className="ml-1 hover:text-destructive"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="routing">
            <Card>
              <CardHeader>
                <CardTitle>Routing Configuration</CardTitle>
                <CardDescription>How traffic should be routed</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center space-x-2">
                  <Switch
                    id="use_haproxy"
                    checked={formData.routing?.use_haproxy}
                    onCheckedChange={(checked) =>
                      setFormData({
                        ...formData,
                        routing: { ...formData.routing, use_haproxy: checked },
                      })
                    }
                  />
                  <Label htmlFor="use_haproxy">Use HAProxy</Label>
                </div>

                {formData.routing?.use_haproxy ? (
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="haproxy_backend">HAProxy Backend</Label>
                      <Input
                        id="haproxy_backend"
                        value={formData.routing?.haproxy_backend || ''}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            routing: { ...formData.routing, use_haproxy: true, haproxy_backend: e.target.value },
                          })
                        }
                        placeholder="default_backend"
                      />
                      <p className="text-xs text-muted-foreground">
                        Name of the HAProxy backend to route traffic to
                      </p>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="haproxy_upstream">HAProxy Upstream (Override)</Label>
                      <Input
                        id="haproxy_upstream"
                        value={formData.routing?.haproxy_upstream || ''}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            routing: { ...formData.routing, use_haproxy: true, haproxy_upstream: e.target.value },
                          })
                        }
                        placeholder={globalRouting.haproxy_upstream}
                      />
                      <p className="text-xs text-muted-foreground">
                        Override global HAProxy address. Leave empty to use global: <code className="bg-muted px-1 rounded">{globalRouting.haproxy_upstream}</code>
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label>Upstream Servers</Label>
                      <div className="flex gap-2">
                        <Input
                          value={newUpstreamServer}
                          onChange={(e) => setNewUpstreamServer(e.target.value)}
                          placeholder="http://backend:8080 or 10.0.0.1:8080"
                          onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addUpstreamServer())}
                        />
                        <Button type="button" onClick={addUpstreamServer}>
                          <Plus className="h-4 w-4" />
                        </Button>
                      </div>
                      <div className="flex flex-wrap gap-2 mt-2">
                        {(formData.routing?.upstream?.servers || []).map((server) => (
                          <div
                            key={server}
                            className="flex items-center gap-1 rounded-md bg-secondary px-2 py-1 text-sm"
                          >
                            <Server className="h-3 w-3 text-muted-foreground" />
                            {server}
                            <button
                              type="button"
                              onClick={() => removeUpstreamServer(server)}
                              className="ml-1 hover:text-destructive"
                            >
                              <X className="h-3 w-3" />
                            </button>
                          </div>
                        ))}
                      </div>
                      {(formData.routing?.upstream?.servers || []).length === 0 && (
                        <p className="text-sm text-muted-foreground">
                          No upstream servers configured. Add at least one server for direct routing.
                        </p>
                      )}
                    </div>

                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="space-y-2">
                        <Label htmlFor="upstream_timeout">Timeout (seconds)</Label>
                        <Input
                          id="upstream_timeout"
                          type="number"
                          value={formData.routing?.upstream?.timeout || 30}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              routing: {
                                ...formData.routing,
                                use_haproxy: false,
                                upstream: {
                                  ...formData.routing?.upstream,
                                  servers: formData.routing?.upstream?.servers || [],
                                  timeout: parseInt(e.target.value) || 30,
                                },
                              },
                            })
                          }
                        />
                        <p className="text-xs text-muted-foreground">
                          Connection timeout for upstream requests
                        </p>
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="health_check">Health Check Path</Label>
                        <Input
                          id="health_check"
                          value={formData.routing?.upstream?.health_check || ''}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              routing: {
                                ...formData.routing,
                                use_haproxy: false,
                                upstream: {
                                  ...formData.routing?.upstream,
                                  servers: formData.routing?.upstream?.servers || [],
                                  health_check: e.target.value,
                                },
                              },
                            })
                          }
                          placeholder="/health"
                        />
                        <p className="text-xs text-muted-foreground">
                          Optional path for health checks (e.g., /health)
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="waf">
            <Card>
              <CardHeader>
                <CardTitle>WAF Settings</CardTitle>
                <CardDescription>Configure WAF behavior for this host</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center space-x-2">
                  <Switch
                    id="waf_enabled"
                    checked={formData.waf?.enabled}
                    onCheckedChange={(checked) =>
                      setFormData({
                        ...formData,
                        waf: { ...formData.waf, enabled: checked, mode: formData.waf?.mode || 'monitoring' },
                      })
                    }
                  />
                  <Label htmlFor="waf_enabled">WAF Enabled</Label>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="mode">Mode</Label>
                  <Select
                    value={formData.waf?.mode || 'monitoring'}
                    onValueChange={(value) =>
                      setFormData({
                        ...formData,
                        waf: { ...formData.waf, enabled: formData.waf?.enabled ?? true, mode: value as Vhost['waf']['mode'] },
                      })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="monitoring">Monitoring (log only)</SelectItem>
                      <SelectItem value="blocking">Blocking (active protection)</SelectItem>
                      <SelectItem value="passthrough">Passthrough (skip WAF)</SelectItem>
                      <SelectItem value="strict">Strict (enhanced protection)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="spam_score_block">Block Threshold</Label>
                    <Input
                      id="spam_score_block"
                      type="number"
                      value={formData.thresholds?.spam_score_block || 80}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          thresholds: {
                            ...formData.thresholds,
                            spam_score_block: parseInt(e.target.value),
                          },
                        })
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="spam_score_flag">Flag Threshold</Label>
                    <Input
                      id="spam_score_flag"
                      type="number"
                      value={formData.thresholds?.spam_score_flag || 50}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          thresholds: {
                            ...formData.thresholds,
                            spam_score_flag: parseInt(e.target.value),
                          },
                        })
                      }
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="keywords">
            <Card>
              <CardHeader>
                <CardTitle>Keyword Configuration</CardTitle>
                <CardDescription>Override global keyword settings for this host</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex items-center space-x-2">
                  <Switch
                    id="inherit_global"
                    checked={formData.keywords?.inherit_global}
                    onCheckedChange={(checked) =>
                      setFormData({
                        ...formData,
                        keywords: { ...formData.keywords, inherit_global: checked },
                      })
                    }
                  />
                  <Label htmlFor="inherit_global">Inherit Global Keywords</Label>
                </div>

                <div className="space-y-2">
                  <Label>Additional Blocked Keywords</Label>
                  <div className="flex gap-2">
                    <Input
                      value={newBlockedKeyword}
                      onChange={(e) => setNewBlockedKeyword(e.target.value)}
                      placeholder="keyword"
                      onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addKeyword('blocked'))}
                    />
                    <Button type="button" onClick={() => addKeyword('blocked')}>
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {(Array.isArray(formData.keywords?.additional_blocked) ? formData.keywords.additional_blocked : []).map((kw) => (
                      <div
                        key={kw}
                        className="flex items-center gap-1 rounded-md bg-red-100 px-2 py-1 text-sm text-red-800"
                      >
                        {kw}
                        <button
                          type="button"
                          onClick={() => removeKeyword('additional_blocked', kw)}
                          className="ml-1 hover:text-red-600"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Additional Flagged Keywords</Label>
                  <div className="flex gap-2">
                    <Input
                      value={newFlaggedKeyword}
                      onChange={(e) => setNewFlaggedKeyword(e.target.value)}
                      placeholder="keyword:score"
                      onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addKeyword('flagged'))}
                    />
                    <Button type="button" onClick={() => addKeyword('flagged')}>
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {(Array.isArray(formData.keywords?.additional_flagged) ? formData.keywords.additional_flagged : []).map((kw) => (
                      <div
                        key={kw}
                        className="flex items-center gap-1 rounded-md bg-yellow-100 px-2 py-1 text-sm text-yellow-800"
                      >
                        {kw}
                        <button
                          type="button"
                          onClick={() => removeKeyword('additional_flagged', kw)}
                          className="ml-1 hover:text-yellow-600"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Keyword Exclusions</Label>
                  <div className="flex gap-2">
                    <Input
                      value={newExclusion}
                      onChange={(e) => setNewExclusion(e.target.value)}
                      placeholder="keyword to exclude"
                      onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addKeyword('exclusions'))}
                    />
                    <Button type="button" onClick={() => addKeyword('exclusions')}>
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {(Array.isArray(formData.keywords?.exclusions) ? formData.keywords.exclusions : []).map((kw) => (
                      <div
                        key={kw}
                        className="flex items-center gap-1 rounded-md bg-gray-100 px-2 py-1 text-sm"
                      >
                        {kw}
                        <button
                          type="button"
                          onClick={() => removeKeyword('exclusions', kw)}
                          className="ml-1 hover:text-gray-600"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        <div className="flex justify-end gap-4 mt-6">
          <Button type="button" variant="outline" onClick={() => navigate('/vhosts')}>
            Cancel
          </Button>
          <Button type="submit" disabled={saveMutation.isPending}>
            <Save className="mr-2 h-4 w-4" />
            {saveMutation.isPending ? 'Saving...' : 'Save'}
          </Button>
        </div>
      </form>
    </div>
  )
}
