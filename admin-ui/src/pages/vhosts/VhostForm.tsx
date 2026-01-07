import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { vhostsApi, configApi, learningApi, timingApi, fingerprintProfilesApi, defenseProfilesApi, LearnedField } from '@/api/client'
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
import { ArrowLeft, Save, Plus, X, Server, BookOpen, Trash2, Info, Check, Timer, Activity, Fingerprint, Shield, GripVertical, ArrowUp, ArrowDown } from 'lucide-react'
import type { Vhost, BehavioralFlow, FingerprintProfile, DefenseProfile, DefenseProfileAttachmentItem, DefenseAggregation, DefenseScoreAggregation } from '@/api/types'
import { Slider } from '@/components/ui/slider'
import { Badge } from '@/components/ui/badge'

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
  behavioral: {
    enabled: false,
    flows: [],
    tracking: {
      fill_duration: true,
      submission_counts: true,
      unique_ips: true,
      avg_spam_score: true,
    },
    baselines: {
      learning_period_days: 7,
      min_samples: 168,
    },
    anomaly_detection: {
      enabled: true,
      std_dev_threshold: 2.5,
      action: 'flag',
      score_addition: 15,
    },
  },
  fingerprint_profiles: {
    enabled: true,
    profiles: undefined,
    no_match_action: 'use_default',
    no_match_score: 15,
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

  // Behavioral flow state
  const [newFlowName, setNewFlowName] = useState('')
  const [newFlowStartPath, setNewFlowStartPath] = useState('')
  const [newFlowEndPath, setNewFlowEndPath] = useState('')

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

  // Fetch global timing config to get the cookie_name setting
  const { data: globalTimingData } = useQuery({
    queryKey: ['timing', 'config'],
    queryFn: timingApi.getConfig,
  })
  const globalTimingCookieName = globalTimingData?.cookie_name || '_waf_timing'

  // Fetch learned fields for existing vhosts
  const { data: learnedFieldsData, isLoading: learnedFieldsLoading, refetch: refetchLearnedFields } = useQuery({
    queryKey: ['vhost-learned-fields', id],
    queryFn: () => learningApi.getVhostFields(id!),
    enabled: !!id,
  })

  // Fetch fingerprint profiles
  const { data: fingerprintProfilesData } = useQuery({
    queryKey: ['fingerprint-profiles'],
    queryFn: fingerprintProfilesApi.list,
  })
  const availableFingerprintProfiles = fingerprintProfilesData?.profiles || []

  // Fetch defense profiles
  const { data: defenseProfilesData } = useQuery({
    queryKey: ['defense-profiles'],
    queryFn: defenseProfilesApi.list,
  })
  const availableDefenseProfiles: DefenseProfile[] = defenseProfilesData?.profiles || []

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
        behavioral: vhost.behavioral ? {
          ...vhost.behavioral,
          flows: Array.isArray(vhost.behavioral.flows) ? vhost.behavioral.flows.map((f: BehavioralFlow) => ({
            ...f,
            start_paths: Array.isArray(f.start_paths) ? f.start_paths : [],
            end_paths: Array.isArray(f.end_paths) ? f.end_paths : [],
            start_methods: Array.isArray(f.start_methods) ? f.start_methods : [],
            end_methods: Array.isArray(f.end_methods) ? f.end_methods : [],
          })) : [],
        } : defaultVhost.behavioral,
        // Normalize defense_profiles.profiles (Lua cjson may encode empty arrays as objects)
        defense_profiles: vhost.defense_profiles ? {
          ...vhost.defense_profiles,
          profiles: Array.isArray(vhost.defense_profiles.profiles) ? vhost.defense_profiles.profiles : [],
        } : undefined,
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
            <TabsTrigger value="behavioral" className="flex items-center gap-1">
              <Activity className="h-3 w-3" />
              Behavioral
            </TabsTrigger>
            <TabsTrigger value="fingerprinting" className="flex items-center gap-1">
              <Fingerprint className="h-3 w-3" />
              Fingerprinting
            </TabsTrigger>
            <TabsTrigger value="defense-profiles" className="flex items-center gap-1">
              <Shield className="h-3 w-3" />
              Defense Profiles
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

                <div className="flex items-center justify-between rounded-lg border p-3">
                  <div className="space-y-0.5">
                    <Label htmlFor="debug_headers">Debug Headers</Label>
                    <p className="text-xs text-muted-foreground">
                      Expose WAF debug response headers for this vhost. Requires global debug to be enabled in Thresholds.
                    </p>
                  </div>
                  <Switch
                    id="debug_headers"
                    checked={formData.waf?.debug_headers ?? true}
                    onCheckedChange={(checked) =>
                      setFormData({
                        ...formData,
                        waf: {
                          ...formData.waf,
                          enabled: formData.waf?.enabled ?? true,
                          mode: formData.waf?.mode || 'monitoring',
                          debug_headers: checked,
                        },
                      })
                    }
                  />
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
                            The cookie is unique to this vhost: <code className="bg-yellow-100 px-1 rounded">{globalTimingCookieName}_{formData.id || 'vhost_id'}</code>
                          </p>
                        </div>
                      </div>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="behavioral">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5" />
                  Behavioral Tracking
                </CardTitle>
                <CardDescription>
                  Configure ML-based behavioral analysis to detect anomalies in submission patterns.
                  The system learns normal traffic patterns and flags deviations.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex items-center space-x-2">
                  <Switch
                    id="behavioral_enabled"
                    checked={formData.behavioral?.enabled}
                    onCheckedChange={(checked) =>
                      setFormData({
                        ...formData,
                        behavioral: { ...formData.behavioral, enabled: checked },
                      })
                    }
                  />
                  <Label htmlFor="behavioral_enabled">Enable Behavioral Tracking</Label>
                </div>

                {formData.behavioral?.enabled && (
                  <>
                    {/* Flows Configuration */}
                    <div className="space-y-4">
                      <h4 className="font-medium text-sm">Tracking Flows</h4>
                      <p className="text-sm text-muted-foreground">
                        Define user journeys to track. Each flow has start paths (page views) and end paths (form submissions).
                      </p>

                      {/* Existing flows */}
                      {(formData.behavioral?.flows || []).map((flow, index) => (
                        <div key={index} className="p-4 border rounded-lg space-y-3">
                          <div className="flex items-center justify-between">
                            <span className="font-medium">{flow.name}</span>
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                const flows = [...(formData.behavioral?.flows || [])]
                                flows.splice(index, 1)
                                setFormData({
                                  ...formData,
                                  behavioral: { ...formData.behavioral, enabled: true, flows },
                                })
                              }}
                              className="text-red-600 hover:text-red-700"
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                          <div className="grid gap-2 md:grid-cols-2 text-sm">
                            <div>
                              <span className="text-muted-foreground">Start paths: </span>
                              {flow.start_paths?.join(', ') || 'None'}
                            </div>
                            <div>
                              <span className="text-muted-foreground">End paths: </span>
                              {flow.end_paths?.join(', ') || 'None'}
                            </div>
                          </div>
                        </div>
                      ))}

                      {/* Add new flow */}
                      <div className="p-4 border border-dashed rounded-lg space-y-3">
                        <h5 className="text-sm font-medium">Add New Flow</h5>
                        <div className="grid gap-4 md:grid-cols-3">
                          <div className="space-y-2">
                            <Label htmlFor="new_flow_name">Flow Name</Label>
                            <Input
                              id="new_flow_name"
                              value={newFlowName}
                              onChange={(e) => setNewFlowName(e.target.value)}
                              placeholder="e.g., contact_form"
                            />
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="new_flow_start">Start Path</Label>
                            <Input
                              id="new_flow_start"
                              value={newFlowStartPath}
                              onChange={(e) => setNewFlowStartPath(e.target.value)}
                              placeholder="/contact"
                            />
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="new_flow_end">End Path</Label>
                            <Input
                              id="new_flow_end"
                              value={newFlowEndPath}
                              onChange={(e) => setNewFlowEndPath(e.target.value)}
                              placeholder="/contact/submit"
                            />
                          </div>
                        </div>
                        <Button
                          type="button"
                          variant="outline"
                          onClick={() => {
                            if (newFlowName && newFlowStartPath && newFlowEndPath) {
                              const newFlow: BehavioralFlow = {
                                name: newFlowName,
                                start_paths: [newFlowStartPath],
                                end_paths: [newFlowEndPath],
                                path_match_mode: 'prefix',
                              }
                              setFormData({
                                ...formData,
                                behavioral: {
                                  ...formData.behavioral,
                                  enabled: true,
                                  flows: [...(formData.behavioral?.flows || []), newFlow],
                                },
                              })
                              setNewFlowName('')
                              setNewFlowStartPath('')
                              setNewFlowEndPath('')
                            }
                          }}
                          disabled={!newFlowName || !newFlowStartPath || !newFlowEndPath}
                        >
                          <Plus className="h-4 w-4 mr-2" />
                          Add Flow
                        </Button>
                      </div>
                    </div>

                    {/* Tracking Options */}
                    <div className="space-y-4">
                      <h4 className="font-medium text-sm">Tracking Options</h4>
                      <div className="grid gap-4 md:grid-cols-2">
                        <div className="flex items-center justify-between rounded-lg border p-3">
                          <Label htmlFor="track_duration">Track Fill Duration</Label>
                          <Switch
                            id="track_duration"
                            checked={formData.behavioral?.tracking?.fill_duration ?? true}
                            onCheckedChange={(checked) =>
                              setFormData({
                                ...formData,
                                behavioral: {
                                  ...formData.behavioral,
                                  enabled: true,
                                  tracking: { ...formData.behavioral?.tracking, fill_duration: checked },
                                },
                              })
                            }
                          />
                        </div>
                        <div className="flex items-center justify-between rounded-lg border p-3">
                          <Label htmlFor="track_counts">Track Submission Counts</Label>
                          <Switch
                            id="track_counts"
                            checked={formData.behavioral?.tracking?.submission_counts ?? true}
                            onCheckedChange={(checked) =>
                              setFormData({
                                ...formData,
                                behavioral: {
                                  ...formData.behavioral,
                                  enabled: true,
                                  tracking: { ...formData.behavioral?.tracking, submission_counts: checked },
                                },
                              })
                            }
                          />
                        </div>
                        <div className="flex items-center justify-between rounded-lg border p-3">
                          <Label htmlFor="track_ips">Track Unique IPs</Label>
                          <Switch
                            id="track_ips"
                            checked={formData.behavioral?.tracking?.unique_ips ?? true}
                            onCheckedChange={(checked) =>
                              setFormData({
                                ...formData,
                                behavioral: {
                                  ...formData.behavioral,
                                  enabled: true,
                                  tracking: { ...formData.behavioral?.tracking, unique_ips: checked },
                                },
                              })
                            }
                          />
                        </div>
                        <div className="flex items-center justify-between rounded-lg border p-3">
                          <Label htmlFor="track_spam">Track Avg Spam Score</Label>
                          <Switch
                            id="track_spam"
                            checked={formData.behavioral?.tracking?.avg_spam_score ?? true}
                            onCheckedChange={(checked) =>
                              setFormData({
                                ...formData,
                                behavioral: {
                                  ...formData.behavioral,
                                  enabled: true,
                                  tracking: { ...formData.behavioral?.tracking, avg_spam_score: checked },
                                },
                              })
                            }
                          />
                        </div>
                      </div>
                    </div>

                    {/* Baseline Settings */}
                    <div className="space-y-4">
                      <h4 className="font-medium text-sm">Baseline Learning</h4>
                      <div className="grid gap-4 md:grid-cols-2">
                        <div className="space-y-2">
                          <Label htmlFor="learning_days">Learning Period (days)</Label>
                          <Input
                            id="learning_days"
                            type="number"
                            min={1}
                            max={90}
                            value={formData.behavioral?.baselines?.learning_period_days ?? 7}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                behavioral: {
                                  ...formData.behavioral,
                                  enabled: true,
                                  baselines: {
                                    ...formData.behavioral?.baselines,
                                    learning_period_days: parseInt(e.target.value) || 7,
                                  },
                                },
                              })
                            }
                          />
                          <p className="text-xs text-muted-foreground">
                            How many days of data to use for baseline calculation
                          </p>
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="min_samples">Minimum Samples</Label>
                          <Input
                            id="min_samples"
                            type="number"
                            min={24}
                            max={1000}
                            value={formData.behavioral?.baselines?.min_samples ?? 168}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                behavioral: {
                                  ...formData.behavioral,
                                  enabled: true,
                                  baselines: {
                                    ...formData.behavioral?.baselines,
                                    min_samples: parseInt(e.target.value) || 168,
                                  },
                                },
                              })
                            }
                          />
                          <p className="text-xs text-muted-foreground">
                            Minimum hourly buckets needed before baseline is ready
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Anomaly Detection */}
                    <div className="space-y-4">
                      <h4 className="font-medium text-sm">Anomaly Detection</h4>
                      <div className="flex items-center space-x-2 mb-4">
                        <Switch
                          id="anomaly_enabled"
                          checked={formData.behavioral?.anomaly_detection?.enabled ?? true}
                          onCheckedChange={(checked) =>
                            setFormData({
                              ...formData,
                              behavioral: {
                                ...formData.behavioral,
                                enabled: true,
                                anomaly_detection: { ...formData.behavioral?.anomaly_detection, enabled: checked },
                              },
                            })
                          }
                        />
                        <Label htmlFor="anomaly_enabled">Enable Anomaly Detection</Label>
                      </div>

                      {formData.behavioral?.anomaly_detection?.enabled && (
                        <div className="grid gap-4 md:grid-cols-3">
                          <div className="space-y-2">
                            <Label htmlFor="std_dev_threshold">Z-Score Threshold</Label>
                            <Input
                              id="std_dev_threshold"
                              type="number"
                              step="0.1"
                              min={1}
                              max={5}
                              value={formData.behavioral?.anomaly_detection?.std_dev_threshold ?? 2.5}
                              onChange={(e) =>
                                setFormData({
                                  ...formData,
                                  behavioral: {
                                    ...formData.behavioral,
                                    enabled: true,
                                    anomaly_detection: {
                                      ...formData.behavioral?.anomaly_detection,
                                      enabled: true,
                                      std_dev_threshold: parseFloat(e.target.value) || 2.5,
                                    },
                                  },
                                })
                              }
                            />
                            <p className="text-xs text-muted-foreground">
                              Standard deviations from baseline to trigger
                            </p>
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="anomaly_action">Action</Label>
                            <Select
                              value={formData.behavioral?.anomaly_detection?.action || 'flag'}
                              onValueChange={(value) =>
                                setFormData({
                                  ...formData,
                                  behavioral: {
                                    ...formData.behavioral,
                                    enabled: true,
                                    anomaly_detection: {
                                      ...formData.behavioral?.anomaly_detection,
                                      enabled: true,
                                      action: value as 'flag' | 'score',
                                    },
                                  },
                                })
                              }
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="flag">Flag (add to spam score)</SelectItem>
                                <SelectItem value="score">Score Only (log)</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="score_addition">Score Addition</Label>
                            <Input
                              id="score_addition"
                              type="number"
                              min={0}
                              max={100}
                              value={formData.behavioral?.anomaly_detection?.score_addition ?? 15}
                              onChange={(e) =>
                                setFormData({
                                  ...formData,
                                  behavioral: {
                                    ...formData.behavioral,
                                    enabled: true,
                                    anomaly_detection: {
                                      ...formData.behavioral?.anomaly_detection,
                                      enabled: true,
                                      score_addition: parseInt(e.target.value) || 15,
                                    },
                                  },
                                })
                              }
                            />
                            <p className="text-xs text-muted-foreground">
                              Points to add when anomaly detected
                            </p>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Info note */}
                    <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
                      <div className="flex items-start gap-3">
                        <Info className="h-5 w-5 text-blue-600 mt-0.5" />
                        <div>
                          <p className="font-medium text-blue-800">How Behavioral Tracking Works</p>
                          <p className="text-sm text-blue-700 mt-1">
                            The system collects hourly statistics for each flow (submissions, unique IPs, spam scores).
                            After the learning period, it calculates statistical baselines. When current activity
                            significantly deviates from the baseline (measured in standard deviations), it triggers
                            an anomaly alert which can add to the spam score.
                          </p>
                          {!isNew && (
                            <p className="text-sm text-blue-700 mt-2">
                              View detailed analytics in the{' '}
                              <a href="/analytics/behavioral" className="underline font-medium">
                                Behavioral Analytics
                              </a>{' '}
                              dashboard.
                            </p>
                          )}
                        </div>
                      </div>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="fingerprinting">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Fingerprint className="h-5 w-5" />
                  Fingerprint Profiles
                </CardTitle>
                <CardDescription>
                  Configure which fingerprint profiles to use for client detection and fingerprint generation.
                  Profiles are matched in priority order, and the first match determines the fingerprint headers.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex items-center space-x-2">
                  <Switch
                    id="fp_enabled"
                    checked={formData.fingerprint_profiles?.enabled !== false}
                    onCheckedChange={(checked) =>
                      setFormData({
                        ...formData,
                        fingerprint_profiles: { ...formData.fingerprint_profiles, enabled: checked },
                      })
                    }
                  />
                  <Label htmlFor="fp_enabled">Enable Fingerprint Profiles</Label>
                </div>

                {formData.fingerprint_profiles?.enabled !== false && (
                  <>
                    {/* Profile Selection */}
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <h4 className="font-medium text-sm">Profile Selection</h4>
                        <div className="text-sm text-muted-foreground">
                          {formData.fingerprint_profiles?.profiles?.length || 0} selected
                        </div>
                      </div>

                      <div className="space-y-2">
                        <div className="flex items-center space-x-2 mb-4">
                          <Switch
                            id="fp_use_all"
                            checked={!formData.fingerprint_profiles?.profiles || formData.fingerprint_profiles.profiles.length === 0}
                            onCheckedChange={(checked) =>
                              setFormData({
                                ...formData,
                                fingerprint_profiles: {
                                  ...formData.fingerprint_profiles,
                                  enabled: true,
                                  profiles: checked ? undefined : [],
                                },
                              })
                            }
                          />
                          <Label htmlFor="fp_use_all">Use all global profiles</Label>
                        </div>

                        {formData.fingerprint_profiles?.profiles && formData.fingerprint_profiles.profiles.length >= 0 && (
                          <div className="space-y-2">
                            <Label>Selected Profiles (in priority order)</Label>
                            <div className="flex flex-wrap gap-2 min-h-[40px] p-2 border rounded-md bg-muted/30">
                              {(formData.fingerprint_profiles?.profiles || []).map((profileId) => {
                                const profile = availableFingerprintProfiles.find((p) => p.id === profileId)
                                return (
                                  <Badge
                                    key={profileId}
                                    variant="secondary"
                                    className="flex items-center gap-1 cursor-pointer hover:bg-secondary/80"
                                  >
                                    {profile?.name || profileId}
                                    <button
                                      type="button"
                                      onClick={() => {
                                        setFormData({
                                          ...formData,
                                          fingerprint_profiles: {
                                            ...formData.fingerprint_profiles,
                                            enabled: true,
                                            profiles: (formData.fingerprint_profiles?.profiles || []).filter(
                                              (id) => id !== profileId
                                            ),
                                          },
                                        })
                                      }}
                                      className="ml-1 hover:text-destructive"
                                    >
                                      <X className="h-3 w-3" />
                                    </button>
                                  </Badge>
                                )
                              })}
                              {(formData.fingerprint_profiles?.profiles || []).length === 0 && (
                                <span className="text-sm text-muted-foreground">
                                  No profiles selected - click profiles below to add
                                </span>
                              )}
                            </div>

                            <Label className="mt-4">Available Profiles</Label>
                            <div className="grid gap-2 md:grid-cols-2">
                              {availableFingerprintProfiles
                                .filter((p) => !(formData.fingerprint_profiles?.profiles || []).includes(p.id))
                                .map((profile) => (
                                  <div
                                    key={profile.id}
                                    className="flex items-center justify-between p-3 border rounded-lg cursor-pointer hover:bg-muted/50"
                                    onClick={() => {
                                      setFormData({
                                        ...formData,
                                        fingerprint_profiles: {
                                          ...formData.fingerprint_profiles,
                                          enabled: true,
                                          profiles: [
                                            ...(formData.fingerprint_profiles?.profiles || []),
                                            profile.id,
                                          ],
                                        },
                                      })
                                    }}
                                  >
                                    <div>
                                      <div className="font-medium text-sm">
                                        {profile.name}
                                        {profile.builtin && (
                                          <Badge variant="outline" className="ml-2 text-xs">
                                            Built-in
                                          </Badge>
                                        )}
                                      </div>
                                      <div className="text-xs text-muted-foreground">
                                        Priority: {profile.priority} | Action: {profile.action}
                                        {profile.action === 'flag' && profile.score ? ` (+${profile.score})` : ''}
                                      </div>
                                    </div>
                                    <Plus className="h-4 w-4 text-muted-foreground" />
                                  </div>
                                ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* No Match Behavior */}
                    <div className="space-y-4">
                      <h4 className="font-medium text-sm">No Match Behavior</h4>
                      <p className="text-sm text-muted-foreground">
                        Configure what happens when no profile matches the request
                      </p>

                      <div className="grid gap-4 md:grid-cols-2">
                        <div className="space-y-2">
                          <Label htmlFor="no_match_action">Action</Label>
                          <Select
                            value={formData.fingerprint_profiles?.no_match_action || 'use_default'}
                            onValueChange={(value) =>
                              setFormData({
                                ...formData,
                                fingerprint_profiles: {
                                  ...formData.fingerprint_profiles,
                                  enabled: true,
                                  no_match_action: value as 'use_default' | 'flag' | 'allow',
                                },
                              })
                            }
                          >
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="use_default">Use Default (legacy fingerprint)</SelectItem>
                              <SelectItem value="flag">Flag as Suspicious</SelectItem>
                              <SelectItem value="allow">Allow (no action)</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>

                        {formData.fingerprint_profiles?.no_match_action === 'flag' && (
                          <div className="space-y-2">
                            <Label htmlFor="no_match_score">Score to Add</Label>
                            <Input
                              id="no_match_score"
                              type="number"
                              min={0}
                              max={100}
                              value={formData.fingerprint_profiles?.no_match_score ?? 15}
                              onChange={(e) =>
                                setFormData({
                                  ...formData,
                                  fingerprint_profiles: {
                                    ...formData.fingerprint_profiles,
                                    enabled: true,
                                    no_match_score: parseInt(e.target.value) || 15,
                                  },
                                })
                              }
                            />
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Info note */}
                    <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
                      <div className="flex items-start gap-3">
                        <Info className="h-5 w-5 text-blue-600 mt-0.5" />
                        <div>
                          <p className="font-medium text-blue-800">How Fingerprint Profiles Work</p>
                          <p className="text-sm text-blue-700 mt-1">
                            Fingerprint profiles detect client types (browsers, bots, scripts) based on HTTP headers.
                            The first matching profile determines which headers are used for fingerprint generation.
                            Actions from all matching profiles are aggregated (scores add up).
                          </p>
                          <p className="text-sm text-blue-700 mt-2">
                            Manage profiles in{' '}
                            <a href="/security/fingerprint-profiles" className="underline font-medium">
                              Security &gt; Fingerprint Profiles
                            </a>
                          </p>
                        </div>
                      </div>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="defense-profiles">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Defense Profiles
                </CardTitle>
                <CardDescription>
                  Configure which defense profiles to evaluate for this virtual host.
                  Multiple profiles can run in parallel and results are aggregated.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex items-center space-x-2">
                  <Switch
                    id="dp_enabled"
                    checked={formData.defense_profiles?.enabled !== false}
                    onCheckedChange={(checked) =>
                      setFormData({
                        ...formData,
                        defense_profiles: {
                          ...formData.defense_profiles,
                          enabled: checked,
                          profiles: formData.defense_profiles?.profiles || [],
                          aggregation: formData.defense_profiles?.aggregation || 'OR',
                          score_aggregation: formData.defense_profiles?.score_aggregation || 'SUM',
                        },
                      })
                    }
                  />
                  <Label htmlFor="dp_enabled">Enable Defense Profiles</Label>
                </div>

                {formData.defense_profiles?.enabled !== false && (
                  <>
                    {/* Aggregation Settings */}
                    <div className="space-y-4">
                      <h4 className="font-medium text-sm">Aggregation Settings</h4>
                      <div className="grid gap-4 md:grid-cols-3">
                        <div className="space-y-2">
                          <Label htmlFor="dp_aggregation">Decision Aggregation</Label>
                          <Select
                            value={formData.defense_profiles?.aggregation || 'OR'}
                            onValueChange={(value: DefenseAggregation) =>
                              setFormData({
                                ...formData,
                                defense_profiles: {
                                  ...formData.defense_profiles,
                                  enabled: true,
                                  profiles: formData.defense_profiles?.profiles || [],
                                  aggregation: value,
                                  score_aggregation: formData.defense_profiles?.score_aggregation || 'SUM',
                                },
                              })
                            }
                          >
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="OR">OR - Block if ANY profile blocks</SelectItem>
                              <SelectItem value="AND">AND - Block if ALL profiles block</SelectItem>
                              <SelectItem value="MAJORITY">MAJORITY - Block if &gt;50% block</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>

                        <div className="space-y-2">
                          <Label htmlFor="dp_score_aggregation">Score Aggregation</Label>
                          <Select
                            value={formData.defense_profiles?.score_aggregation || 'SUM'}
                            onValueChange={(value: DefenseScoreAggregation) =>
                              setFormData({
                                ...formData,
                                defense_profiles: {
                                  ...formData.defense_profiles,
                                  enabled: true,
                                  profiles: formData.defense_profiles?.profiles || [],
                                  aggregation: formData.defense_profiles?.aggregation || 'OR',
                                  score_aggregation: value,
                                },
                              })
                            }
                          >
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="SUM">SUM - Add all scores</SelectItem>
                              <SelectItem value="MAX">MAX - Use highest score</SelectItem>
                              <SelectItem value="WEIGHTED_AVG">WEIGHTED - Average by weight</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>

                        <div className="space-y-2">
                          <div className="flex items-center space-x-2 mt-6">
                            <Switch
                              id="dp_short_circuit"
                              checked={formData.defense_profiles?.short_circuit !== false}
                              onCheckedChange={(checked) =>
                                setFormData({
                                  ...formData,
                                  defense_profiles: {
                                    ...formData.defense_profiles,
                                    enabled: true,
                                    profiles: formData.defense_profiles?.profiles || [],
                                    aggregation: formData.defense_profiles?.aggregation || 'OR',
                                    score_aggregation: formData.defense_profiles?.score_aggregation || 'SUM',
                                    short_circuit: checked,
                                  },
                                })
                              }
                            />
                            <Label htmlFor="dp_short_circuit">Short-circuit on block</Label>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Attached Profiles */}
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <h4 className="font-medium text-sm">Attached Profiles</h4>
                        <div className="text-sm text-muted-foreground">
                          {formData.defense_profiles?.profiles?.length || 0} profile(s) attached
                        </div>
                      </div>

                      {(formData.defense_profiles?.profiles?.length || 0) === 0 ? (
                        <div className="rounded-lg border border-dashed border-amber-300 bg-amber-50 p-6 text-center">
                          <Shield className="h-8 w-8 mx-auto mb-2 text-amber-600" />
                          <p className="font-medium text-amber-800">Using Default Profile</p>
                          <p className="text-sm text-amber-700 mt-1">
                            When no profiles are attached, the <strong>Legacy</strong> profile is used automatically.
                          </p>
                          <p className="text-xs text-amber-600 mt-2">
                            This provides backward-compatible behavior with all defense mechanisms.
                            Add custom profiles below to override.
                          </p>
                        </div>
                      ) : (
                        <div className="space-y-2">
                          {(formData.defense_profiles?.profiles || []).map((attached, index) => {
                            const profile = availableDefenseProfiles.find((p) => p.id === attached.id)
                            return (
                              <div
                                key={attached.id}
                                className="flex items-center gap-3 p-3 border rounded-lg bg-muted/30"
                              >
                                <div className="flex flex-col gap-1">
                                  <button
                                    type="button"
                                    onClick={() => {
                                      if (index === 0) return
                                      const profiles = [...(formData.defense_profiles?.profiles || [])]
                                      const temp = profiles[index]
                                      profiles[index] = profiles[index - 1]
                                      profiles[index - 1] = temp
                                      profiles.forEach((p, i) => { p.priority = (i + 1) * 100 })
                                      setFormData({
                                        ...formData,
                                        defense_profiles: { ...formData.defense_profiles, profiles, enabled: true, aggregation: formData.defense_profiles?.aggregation || 'OR', score_aggregation: formData.defense_profiles?.score_aggregation || 'SUM' },
                                      })
                                    }}
                                    disabled={index === 0}
                                    className="p-0.5 hover:bg-muted rounded disabled:opacity-30"
                                  >
                                    <ArrowUp className="h-3 w-3" />
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => {
                                      const profiles = formData.defense_profiles?.profiles || []
                                      if (index >= profiles.length - 1) return
                                      const newProfiles = [...profiles]
                                      const temp = newProfiles[index]
                                      newProfiles[index] = newProfiles[index + 1]
                                      newProfiles[index + 1] = temp
                                      newProfiles.forEach((p, i) => { p.priority = (i + 1) * 100 })
                                      setFormData({
                                        ...formData,
                                        defense_profiles: { ...formData.defense_profiles, profiles: newProfiles, enabled: true, aggregation: formData.defense_profiles?.aggregation || 'OR', score_aggregation: formData.defense_profiles?.score_aggregation || 'SUM' },
                                      })
                                    }}
                                    disabled={index >= (formData.defense_profiles?.profiles?.length || 0) - 1}
                                    className="p-0.5 hover:bg-muted rounded disabled:opacity-30"
                                  >
                                    <ArrowDown className="h-3 w-3" />
                                  </button>
                                </div>

                                <GripVertical className="h-4 w-4 text-muted-foreground" />

                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2">
                                    <span className="font-medium text-sm truncate">
                                      {profile?.name || attached.id}
                                    </span>
                                    {profile?.builtin && (
                                      <Badge variant="outline" className="text-xs shrink-0">
                                        Built-in
                                      </Badge>
                                    )}
                                    <Badge variant="secondary" className="text-xs shrink-0">
                                      #{index + 1}
                                    </Badge>
                                  </div>
                                  {profile?.description && (
                                    <p className="text-xs text-muted-foreground truncate">
                                      {profile.description}
                                    </p>
                                  )}
                                </div>

                                <div className="flex items-center gap-4">
                                  <div className="w-32">
                                    <Label className="text-xs text-muted-foreground">
                                      Weight: {Math.round((attached.weight ?? 1) * 100)}%
                                    </Label>
                                    <Slider
                                      value={[(attached.weight ?? 1) * 100]}
                                      min={0}
                                      max={100}
                                      step={5}
                                      onValueChange={([value]) => {
                                        const profiles = [...(formData.defense_profiles?.profiles || [])]
                                        profiles[index] = { ...profiles[index], weight: value / 100 }
                                        setFormData({
                                          ...formData,
                                          defense_profiles: { ...formData.defense_profiles, profiles, enabled: true, aggregation: formData.defense_profiles?.aggregation || 'OR', score_aggregation: formData.defense_profiles?.score_aggregation || 'SUM' },
                                        })
                                      }}
                                    />
                                  </div>

                                  <button
                                    type="button"
                                    onClick={() => {
                                      setFormData({
                                        ...formData,
                                        defense_profiles: {
                                          ...formData.defense_profiles,
                                          profiles: (formData.defense_profiles?.profiles || []).filter((p) => p.id !== attached.id),
                                          enabled: true,
                                          aggregation: formData.defense_profiles?.aggregation || 'OR',
                                          score_aggregation: formData.defense_profiles?.score_aggregation || 'SUM',
                                        },
                                      })
                                    }}
                                    className="p-1 hover:bg-destructive/10 hover:text-destructive rounded"
                                  >
                                    <X className="h-4 w-4" />
                                  </button>
                                </div>
                              </div>
                            )
                          })}
                        </div>
                      )}
                    </div>

                    {/* Available Profiles */}
                    {availableDefenseProfiles.filter((p) => !(formData.defense_profiles?.profiles || []).some((ap) => ap.id === p.id)).length > 0 && (
                      <div className="space-y-4">
                        <h4 className="font-medium text-sm">Available Profiles</h4>
                        <div className="grid gap-2 md:grid-cols-2">
                          {availableDefenseProfiles
                            .filter((p) => !(formData.defense_profiles?.profiles || []).some((ap) => ap.id === p.id))
                            .map((profile) => (
                              <div
                                key={profile.id}
                                className="flex items-center justify-between p-3 border rounded-lg cursor-pointer hover:bg-muted/50 transition-colors"
                                onClick={() => {
                                  const currentProfiles = formData.defense_profiles?.profiles || []
                                  const newItem: DefenseProfileAttachmentItem = {
                                    id: profile.id,
                                    priority: (currentProfiles.length + 1) * 100,
                                    weight: 1,
                                  }
                                  setFormData({
                                    ...formData,
                                    defense_profiles: {
                                      ...formData.defense_profiles,
                                      profiles: [...currentProfiles, newItem],
                                      enabled: true,
                                      aggregation: formData.defense_profiles?.aggregation || 'OR',
                                      score_aggregation: formData.defense_profiles?.score_aggregation || 'SUM',
                                    },
                                  })
                                }}
                              >
                                <div className="min-w-0 flex-1">
                                  <div className="flex items-center gap-2">
                                    <span className="font-medium text-sm truncate">
                                      {profile.name}
                                    </span>
                                    {profile.builtin && (
                                      <Badge variant="outline" className="text-xs">
                                        Built-in
                                      </Badge>
                                    )}
                                  </div>
                                  {profile.description && (
                                    <p className="text-xs text-muted-foreground truncate">
                                      {profile.description}
                                    </p>
                                  )}
                                </div>
                                <Plus className="h-4 w-4 text-muted-foreground shrink-0 ml-2" />
                              </div>
                            ))}
                        </div>
                      </div>
                    )}

                    {/* Info note */}
                    <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
                      <div className="flex items-start gap-3">
                        <Info className="h-5 w-5 text-blue-600 mt-0.5 shrink-0" />
                        <div>
                          <p className="font-medium text-blue-800">How It Works</p>
                          <ul className="text-sm text-blue-700 mt-1 space-y-1 list-disc list-inside">
                            <li>Profiles are evaluated in parallel for performance</li>
                            <li>Each profile returns a score and block/allow decision</li>
                            <li>Results are aggregated using the configured strategies</li>
                            <li>Vhost settings are inherited by endpoints unless overridden</li>
                          </ul>
                          <p className="text-sm text-blue-700 mt-2">
                            Manage profiles in{' '}
                            <a href="/security/defense-profiles" className="underline font-medium">
                              Security &gt; Defense Profiles
                            </a>
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
