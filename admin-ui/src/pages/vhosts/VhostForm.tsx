import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { vhostsApi, configApi, learningApi, LearnedField, VhostTimingConfig } from '@/api/client'
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
import { ArrowLeft, Save, Plus, X, Server, BookOpen, Trash2, Info, Check, Timer } from 'lucide-react'
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
  timing: {
    enabled: false,
    cookie_ttl: 3600,
    min_time_block: 2,
    min_time_flag: 5,
    score_no_cookie: 30,
    score_too_fast: 40,
    score_suspicious: 20,
    start_paths: [],
    end_paths: [],
    path_match_mode: 'exact',
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
  const [newStartPath, setNewStartPath] = useState('')
  const [newEndPath, setNewEndPath] = useState('')
  const [shouldNavigate, setShouldNavigate] = useState(true)

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

  // Fetch learned fields for existing vhosts
  const { data: learnedFieldsData, isLoading: learnedFieldsLoading, refetch: refetchLearnedFields } = useQuery({
    queryKey: ['vhost-learned-fields', id],
    queryFn: () => learningApi.getVhostFields(id!),
    enabled: !!id,
  })

  // Extract learned fields from response (ensure array - Lua cjson may encode empty arrays as objects)
  const learnedFields: LearnedField[] = Array.isArray(learnedFieldsData?.fields) ? learnedFieldsData.fields : []
  const learningStats = learnedFieldsData?.learning_stats

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
        timing: vhost.timing ? {
          ...vhost.timing,
          start_paths: Array.isArray(vhost.timing.start_paths) ? vhost.timing.start_paths : [],
          end_paths: Array.isArray(vhost.timing.end_paths) ? vhost.timing.end_paths : [],
        } : defaultVhost.timing,
      }
      setFormData(normalized)
    }
  }, [data])

  const saveMutation = useMutation({
    mutationFn: (data: Partial<Vhost>) =>
      isNew ? vhostsApi.create(data) : vhostsApi.update(id!, data),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['vhosts'] })
      queryClient.invalidateQueries({ queryKey: ['vhost', id] })
      toast({ title: isNew ? 'Virtual host created' : 'Virtual host updated' })
      if (shouldNavigate) {
        navigate('/vhosts')
      } else {
        // If this was a new vhost, navigate to the edit page for the newly created one
        if (isNew && response?.vhost?.id) {
          navigate(`/vhosts/${response.vhost.id}`, { replace: true })
        }
      }
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to save',
        variant: 'destructive',
      })
    },
  })

  const clearLearningMutation = useMutation({
    mutationFn: () => learningApi.clearVhostFields(id!),
    onSuccess: () => {
      refetchLearnedFields()
      toast({ title: 'Learning data cleared for this vhost' })
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to clear learning data',
        variant: 'destructive',
      })
    },
  })

  const getCleanedFormData = () => {
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
    return cleanedFormData
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setShouldNavigate(true)
    saveMutation.mutate(getCleanedFormData())
  }

  const handleApply = () => {
    setShouldNavigate(false)
    saveMutation.mutate(getCleanedFormData())
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

  const addTimingPath = (type: 'start_paths' | 'end_paths') => {
    const value = type === 'start_paths' ? newStartPath : newEndPath
    const setter = type === 'start_paths' ? setNewStartPath : setNewEndPath
    const currentPaths = formData.timing?.[type] || []

    if (value && !currentPaths.includes(value)) {
      setFormData({
        ...formData,
        timing: {
          ...formData.timing,
          enabled: formData.timing?.enabled ?? false,
          [type]: [...currentPaths, value],
        },
      })
      setter('')
    }
  }

  const removeTimingPath = (type: 'start_paths' | 'end_paths', path: string) => {
    setFormData({
      ...formData,
      timing: {
        ...formData.timing,
        enabled: formData.timing?.enabled ?? false,
        [type]: (formData.timing?.[type] || []).filter((p) => p !== path),
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
            <TabsTrigger value="timing" className="flex items-center gap-1">
              <Timer className="h-3 w-3" />
              Timing
            </TabsTrigger>
            {!isNew && (
              <TabsTrigger value="learned-fields" className="flex items-center gap-1">
                <BookOpen className="h-3 w-3" />
                Learned Fields
                {learnedFields.length > 0 && (
                  <span className="ml-1 rounded-full bg-blue-100 px-2 py-0.5 text-xs text-blue-700">
                    {learnedFields.length}
                  </span>
                )}
              </TabsTrigger>
            )}
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

                    <div className="flex items-center justify-between rounded-lg border p-3">
                      <div className="space-y-0.5">
                        <Label htmlFor="haproxy_ssl">Use HTTPS for HAProxy</Label>
                        <p className="text-xs text-muted-foreground">
                          Connect to HAProxy using HTTPS. Leave unchecked to inherit from global config.
                        </p>
                      </div>
                      <Switch
                        id="haproxy_ssl"
                        checked={formData.routing?.haproxy_ssl ?? false}
                        onCheckedChange={(checked) =>
                          setFormData({
                            ...formData,
                            routing: { ...formData.routing, use_haproxy: true, haproxy_ssl: checked },
                          })
                        }
                      />
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

                    <div className="flex items-center justify-between rounded-lg border p-3">
                      <div className="space-y-0.5">
                        <Label htmlFor="upstream_ssl">Use HTTPS for Upstreams</Label>
                        <p className="text-xs text-muted-foreground">
                          Connect to upstream servers using HTTPS. Leave unchecked to inherit from global config.
                        </p>
                      </div>
                      <Switch
                        id="upstream_ssl"
                        checked={formData.routing?.upstream?.ssl ?? false}
                        onCheckedChange={(checked) =>
                          setFormData({
                            ...formData,
                            routing: {
                              ...formData.routing,
                              use_haproxy: false,
                              upstream: {
                                ...formData.routing?.upstream,
                                servers: formData.routing?.upstream?.servers || [],
                                ssl: checked,
                              },
                            },
                          })
                        }
                      />
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

          <TabsContent value="timing">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Timer className="h-5 w-5" />
                  Timing Configuration
                </CardTitle>
                <CardDescription>
                  Configure form timing validation to detect bot submissions. Timing cookies track how long users spend
                  on forms before submitting.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex items-center space-x-2">
                  <Switch
                    id="timing_enabled"
                    checked={formData.timing?.enabled}
                    onCheckedChange={(checked) =>
                      setFormData({
                        ...formData,
                        timing: { ...formData.timing, enabled: checked },
                      })
                    }
                  />
                  <Label htmlFor="timing_enabled">Enable Timing Validation</Label>
                </div>

                {formData.timing?.enabled && (
                  <>
                    {/* Time Thresholds */}
                    <div className="space-y-4">
                      <h4 className="font-medium text-sm">Time Thresholds (seconds)</h4>
                      <div className="grid gap-4 md:grid-cols-3">
                        <div className="space-y-2">
                          <Label htmlFor="min_time_block">Block Time</Label>
                          <Input
                            id="min_time_block"
                            type="number"
                            min={0}
                            max={3600}
                            value={formData.timing?.min_time_block ?? 2}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                timing: { ...formData.timing, enabled: true, min_time_block: parseInt(e.target.value) || 0 },
                              })
                            }
                          />
                          <p className="text-xs text-muted-foreground">
                            Submissions faster than this are blocked (definite bot)
                          </p>
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="min_time_flag">Flag Time</Label>
                          <Input
                            id="min_time_flag"
                            type="number"
                            min={0}
                            max={3600}
                            value={formData.timing?.min_time_flag ?? 5}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                timing: { ...formData.timing, enabled: true, min_time_flag: parseInt(e.target.value) || 0 },
                              })
                            }
                          />
                          <p className="text-xs text-muted-foreground">
                            Submissions faster than this are flagged as suspicious
                          </p>
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="cookie_ttl">Cookie TTL</Label>
                          <Input
                            id="cookie_ttl"
                            type="number"
                            min={1}
                            max={86400}
                            value={formData.timing?.cookie_ttl ?? 3600}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                timing: { ...formData.timing, enabled: true, cookie_ttl: parseInt(e.target.value) || 3600 },
                              })
                            }
                          />
                          <p className="text-xs text-muted-foreground">
                            How long timing cookie is valid (seconds)
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Scoring */}
                    <div className="space-y-4">
                      <h4 className="font-medium text-sm">Scoring</h4>
                      <div className="grid gap-4 md:grid-cols-3">
                        <div className="space-y-2">
                          <Label htmlFor="score_no_cookie">No Cookie Score</Label>
                          <Input
                            id="score_no_cookie"
                            type="number"
                            min={0}
                            max={100}
                            value={formData.timing?.score_no_cookie ?? 30}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                timing: { ...formData.timing, enabled: true, score_no_cookie: parseInt(e.target.value) || 0 },
                              })
                            }
                          />
                          <p className="text-xs text-muted-foreground">
                            Score added when no timing cookie present
                          </p>
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="score_too_fast">Too Fast Score</Label>
                          <Input
                            id="score_too_fast"
                            type="number"
                            min={0}
                            max={100}
                            value={formData.timing?.score_too_fast ?? 40}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                timing: { ...formData.timing, enabled: true, score_too_fast: parseInt(e.target.value) || 0 },
                              })
                            }
                          />
                          <p className="text-xs text-muted-foreground">
                            Score added when submission is faster than block time
                          </p>
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="score_suspicious">Suspicious Score</Label>
                          <Input
                            id="score_suspicious"
                            type="number"
                            min={0}
                            max={100}
                            value={formData.timing?.score_suspicious ?? 20}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                timing: { ...formData.timing, enabled: true, score_suspicious: parseInt(e.target.value) || 0 },
                              })
                            }
                          />
                          <p className="text-xs text-muted-foreground">
                            Score added when submission is faster than flag time
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Path Configuration */}
                    <div className="space-y-4">
                      <h4 className="font-medium text-sm">Path Configuration</h4>
                      <div className="space-y-2">
                        <Label htmlFor="path_match_mode">Path Match Mode</Label>
                        <Select
                          value={formData.timing?.path_match_mode || 'exact'}
                          onValueChange={(value) =>
                            setFormData({
                              ...formData,
                              timing: { ...formData.timing, enabled: true, path_match_mode: value as 'exact' | 'prefix' | 'regex' },
                            })
                          }
                        >
                          <SelectTrigger className="w-48">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="exact">Exact Match</SelectItem>
                            <SelectItem value="prefix">Prefix Match</SelectItem>
                            <SelectItem value="regex">Regex Match</SelectItem>
                          </SelectContent>
                        </Select>
                        <p className="text-xs text-muted-foreground">
                          How start/end paths are matched against request URIs
                        </p>
                      </div>

                      <div className="grid gap-4 md:grid-cols-2">
                        {/* Start Paths */}
                        <div className="space-y-2">
                          <Label>Start Paths (GET requests set cookie)</Label>
                          <div className="flex gap-2">
                            <Input
                              value={newStartPath}
                              onChange={(e) => setNewStartPath(e.target.value)}
                              placeholder="/contact, /form/*"
                              onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addTimingPath('start_paths'))}
                            />
                            <Button type="button" onClick={() => addTimingPath('start_paths')}>
                              <Plus className="h-4 w-4" />
                            </Button>
                          </div>
                          <div className="flex flex-wrap gap-2 mt-2">
                            {(formData.timing?.start_paths || []).map((path) => (
                              <div
                                key={path}
                                className="flex items-center gap-1 rounded-md bg-green-100 px-2 py-1 text-sm text-green-800"
                              >
                                {path}
                                <button
                                  type="button"
                                  onClick={() => removeTimingPath('start_paths', path)}
                                  className="ml-1 hover:text-green-600"
                                >
                                  <X className="h-3 w-3" />
                                </button>
                              </div>
                            ))}
                          </div>
                          <p className="text-xs text-muted-foreground">
                            Empty = all GET requests set timing cookie
                          </p>
                        </div>

                        {/* End Paths */}
                        <div className="space-y-2">
                          <Label>End Paths (POST requests validated)</Label>
                          <div className="flex gap-2">
                            <Input
                              value={newEndPath}
                              onChange={(e) => setNewEndPath(e.target.value)}
                              placeholder="/contact/submit, /form/*/submit"
                              onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addTimingPath('end_paths'))}
                            />
                            <Button type="button" onClick={() => addTimingPath('end_paths')}>
                              <Plus className="h-4 w-4" />
                            </Button>
                          </div>
                          <div className="flex flex-wrap gap-2 mt-2">
                            {(formData.timing?.end_paths || []).map((path) => (
                              <div
                                key={path}
                                className="flex items-center gap-1 rounded-md bg-blue-100 px-2 py-1 text-sm text-blue-800"
                              >
                                {path}
                                <button
                                  type="button"
                                  onClick={() => removeTimingPath('end_paths', path)}
                                  className="ml-1 hover:text-blue-600"
                                >
                                  <X className="h-3 w-3" />
                                </button>
                              </div>
                            ))}
                          </div>
                          <p className="text-xs text-muted-foreground">
                            Empty = all POST requests are validated
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Info note */}
                    <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4">
                      <div className="flex items-start gap-3">
                        <Info className="h-5 w-5 text-yellow-600 mt-0.5" />
                        <div>
                          <p className="font-medium text-yellow-800">How Timing Validation Works</p>
                          <p className="text-sm text-yellow-700 mt-1">
                            When a user visits a start path (GET), a timing cookie is set. When they submit to an end path (POST),
                            the time elapsed is checked. Submissions faster than the thresholds add to the spam score.
                            The cookie is unique to this vhost: <code className="bg-yellow-100 px-1 rounded">_waf_timing_{formData.id || 'vhost_id'}</code>
                          </p>
                        </div>
                      </div>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {!isNew && (
            <TabsContent value="learned-fields">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        <BookOpen className="h-5 w-5" />
                        Learned Fields
                      </CardTitle>
                      <CardDescription>
                        Form fields aggregated across all endpoints in this virtual host.
                      </CardDescription>
                    </div>
                    {learnedFields.length > 0 && (
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          if (confirm('Clear all learning data for this virtual host? This cannot be undone.')) {
                            clearLearningMutation.mutate()
                          }
                        }}
                        disabled={clearLearningMutation.isPending}
                        className="text-red-600 hover:text-red-700 hover:bg-red-50"
                      >
                        <Trash2 className="h-4 w-4 mr-1" />
                        Clear Data
                      </Button>
                    )}
                  </div>
                </CardHeader>
                <CardContent>
                  {learnedFieldsLoading ? (
                    <div className="text-center py-8 text-muted-foreground">
                      Loading learned fields...
                    </div>
                  ) : learnedFields.length === 0 ? (
                    <div className="text-center py-8 space-y-2">
                      <BookOpen className="h-12 w-12 mx-auto text-muted-foreground/50" />
                      <p className="text-muted-foreground">No fields learned yet</p>
                      <p className="text-sm text-muted-foreground">
                        Field names will be automatically discovered as requests flow through endpoints
                        belonging to this virtual host. Learning uses 10% sampling.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {/* Learning stats */}
                      {learningStats && (
                        <div className="rounded-lg border border-blue-200 bg-blue-50 p-3">
                          <div className="flex items-center gap-4 text-sm text-blue-700">
                            <span>
                              <strong>{learnedFields.length}</strong> unique fields discovered
                            </span>
                            <span className="text-blue-300">|</span>
                            <span>
                              <strong>{learningStats.batch_count || 0}</strong> batches processed
                            </span>
                            {learningStats.cache_available && (
                              <>
                                <span className="text-blue-300">|</span>
                                <span className="text-green-600">Cache active</span>
                              </>
                            )}
                          </div>
                        </div>
                      )}

                      {/* Fields table */}
                      <div className="rounded-md border">
                        <table className="w-full">
                          <thead className="bg-muted/50">
                            <tr>
                              <th className="px-4 py-3 text-left text-sm font-medium">Field Name</th>
                              <th className="px-4 py-3 text-left text-sm font-medium">Type</th>
                              <th className="px-4 py-3 text-left text-sm font-medium">Count</th>
                              <th className="px-4 py-3 text-left text-sm font-medium">Last Seen</th>
                              <th className="px-4 py-3 text-left text-sm font-medium">Endpoints</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y">
                            {learnedFields.map((field) => (
                              <tr key={field.name} className="hover:bg-muted/30">
                                <td className="px-4 py-3">
                                  <code className="text-sm bg-muted px-1.5 py-0.5 rounded">{field.name}</code>
                                </td>
                                <td className="px-4 py-3 text-sm text-muted-foreground">
                                  {field.type || 'text'}
                                </td>
                                <td className="px-4 py-3 text-sm">
                                  {field.count.toLocaleString()}
                                </td>
                                <td className="px-4 py-3 text-sm text-muted-foreground">
                                  {field.last_seen
                                    ? new Date(field.last_seen * 1000).toLocaleDateString()
                                    : '—'}
                                </td>
                                <td className="px-4 py-3">
                                  {field.endpoints && field.endpoints.length > 0 ? (
                                    <div className="flex flex-wrap gap-1">
                                      {field.endpoints.slice(0, 3).map((ep) => (
                                        <span
                                          key={ep}
                                          className="text-xs bg-gray-100 text-gray-600 px-1.5 py-0.5 rounded"
                                        >
                                          {ep}
                                        </span>
                                      ))}
                                      {field.endpoints.length > 3 && (
                                        <span className="text-xs text-muted-foreground">
                                          +{field.endpoints.length - 3} more
                                        </span>
                                      )}
                                    </div>
                                  ) : (
                                    <span className="text-sm text-muted-foreground">—</span>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>

                      {/* Info note */}
                      <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4">
                        <div className="flex items-start gap-3">
                          <Info className="h-5 w-5 text-yellow-600 mt-0.5" />
                          <div>
                            <p className="font-medium text-yellow-800">About Vhost-Level Learning</p>
                            <p className="text-sm text-yellow-700 mt-1">
                              This view shows fields aggregated across all endpoints in this virtual host.
                              To configure field requirements for a specific endpoint, visit that endpoint's
                              configuration page. Learning data is retained for 30 days of inactivity.
                            </p>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          )}
        </Tabs>

        <div className="flex justify-end gap-4 mt-6">
          <Button type="button" variant="outline" onClick={() => navigate('/vhosts')}>
            Cancel
          </Button>
          <Button
            type="button"
            variant="secondary"
            onClick={handleApply}
            disabled={saveMutation.isPending}
          >
            <Check className="mr-2 h-4 w-4" />
            {saveMutation.isPending && !shouldNavigate ? 'Applying...' : 'Apply'}
          </Button>
          <Button type="submit" disabled={saveMutation.isPending}>
            <Save className="mr-2 h-4 w-4" />
            {saveMutation.isPending && shouldNavigate ? 'Saving...' : 'Save'}
          </Button>
        </div>
      </form>
    </div>
  )
}
