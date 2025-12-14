import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { endpointsApi, vhostsApi, configApi, learningApi, captchaApi, LearnedField } from '@/api/client'
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
import { ArrowLeft, Save, Plus, X, Globe, Server, Info, BookOpen, Trash2, CheckCircle, Hash, EyeOff, ShieldCheck } from 'lucide-react'
import type { Endpoint, Vhost, Thresholds, EndpointCaptchaConfig, CaptchaProvider } from '@/api/types'

const defaultEndpoint: Partial<Endpoint> = {
  enabled: true,
  mode: 'monitoring',
  priority: 100,
  vhost_id: null,  // null = global endpoint
  matching: {
    paths: [],
    methods: ['POST', 'PUT', 'PATCH'],
    content_types: ['application/json', 'application/x-www-form-urlencoded'],
  },
  thresholds: {},  // Empty = inherit all from global
  keywords: {
    inherit_global: true,
  },
  fields: {
    required: [],
    max_length: {},
    ignore_fields: [],
    expected: [],
    unexpected_action: 'flag',
  },
  rate_limiting: {
    enabled: true,
    requests_per_minute: 30,
  },
  patterns: {
    inherit_global: true,
  },
  actions: {
    on_flag: 'tag',
    on_block: 'reject',
    log_level: 'info',
  },
  hash_content: {
    enabled: false,  // Disabled by default - user must explicitly enable and specify fields
    fields: [],
  },
}

// Default global thresholds (fallback if API fails)
const DEFAULT_GLOBAL_THRESHOLDS: Thresholds = {
  spam_score_block: 80,
  spam_score_flag: 50,
  hash_count_block: 10,
  ip_rate_limit: 30,
  ip_daily_limit: 500,
  hash_unique_ips_block: 5,
}

// Common ignore fields for CSRF tokens etc.
const COMMON_IGNORE_FIELDS = [
  '_csrf',
  '_token',
  'csrf_token',
  'authenticity_token',
  'captcha',
  'g-recaptcha-response',
  'h-captcha-response',
]

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
const COMMON_CONTENT_TYPES = [
  'application/json',
  'application/x-www-form-urlencoded',
  'multipart/form-data',
  'text/plain',
  'text/html',
  'application/xml',
]

export function EndpointForm() {
  const { id } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const isNew = !id

  const [formData, setFormData] = useState<Partial<Endpoint>>(defaultEndpoint)
  const [newPath, setNewPath] = useState('')
  const [pathType, setPathType] = useState<'exact' | 'prefix' | 'regex'>('exact')
  const [newContentType, setNewContentType] = useState('')
  const [newRequiredField, setNewRequiredField] = useState('')
  const [newMaxLengthField, setNewMaxLengthField] = useState('')
  const [newMaxLengthValue, setNewMaxLengthValue] = useState('')
  const [newIgnoreField, setNewIgnoreField] = useState('')
  const [newHashField, setNewHashField] = useState('')
  const [newExpectedField, setNewExpectedField] = useState('')

  // Fetch vhosts for dropdown
  const { data: vhostsData } = useQuery({
    queryKey: ['vhosts'],
    queryFn: vhostsApi.list,
  })

  // Fetch global thresholds for inherited values display
  const { data: globalThresholdsData } = useQuery({
    queryKey: ['config', 'thresholds'],
    queryFn: configApi.getThresholds,
  })

  // Fetch CAPTCHA providers for dropdown
  const { data: captchaProvidersData } = useQuery({
    queryKey: ['captcha', 'providers'],
    queryFn: captchaApi.listProviders,
  })

  // Fetch global CAPTCHA config
  const { data: captchaConfigData } = useQuery({
    queryKey: ['captcha', 'config'],
    queryFn: captchaApi.getConfig,
  })

  const { data, isLoading } = useQuery({
    queryKey: ['endpoint', id],
    queryFn: () => endpointsApi.get(id!),
    enabled: !!id,
  })

  // Fetch learned fields for existing endpoints
  const { data: learnedFieldsData, isLoading: learnedFieldsLoading, refetch: refetchLearnedFields } = useQuery({
    queryKey: ['endpoint-learned-fields', id],
    queryFn: () => learningApi.getEndpointFields(id!),
    enabled: !!id,
  })

  useEffect(() => {
    // API returns endpoint directly (not wrapped in .data)
    const endpoint = (data as { endpoint?: Endpoint } | undefined)?.endpoint || data as Endpoint | undefined
    if (endpoint && typeof endpoint === 'object' && 'id' in endpoint) {
      // Ensure arrays are proper arrays (Lua cjson may encode empty arrays as objects)
      const normalized: Partial<Endpoint> = {
        ...endpoint,
        vhost_id: endpoint.vhost_id || null,
        matching: endpoint.matching ? {
          ...endpoint.matching,
          paths: Array.isArray(endpoint.matching.paths) ? endpoint.matching.paths : [],
          methods: Array.isArray(endpoint.matching.methods) ? endpoint.matching.methods : ['POST', 'PUT', 'PATCH'],
          content_types: Array.isArray(endpoint.matching.content_types) ? endpoint.matching.content_types : [],
        } : defaultEndpoint.matching,
        keywords: endpoint.keywords ? {
          ...endpoint.keywords,
          additional_blocked: Array.isArray(endpoint.keywords.additional_blocked) ? endpoint.keywords.additional_blocked : [],
          additional_flagged: Array.isArray(endpoint.keywords.additional_flagged) ? endpoint.keywords.additional_flagged : [],
        } : defaultEndpoint.keywords,
        fields: endpoint.fields ? {
          required: Array.isArray(endpoint.fields.required) ? endpoint.fields.required : [],
          max_length: typeof endpoint.fields.max_length === 'object' ? endpoint.fields.max_length : {},
        } : defaultEndpoint.fields,
      }
      setFormData(normalized)
    }
  }, [data])

  // Extract vhosts for dropdown
  const rawVhosts = (vhostsData as { vhosts: Vhost[] } | undefined)?.vhosts
  const vhosts = (Array.isArray(rawVhosts) ? rawVhosts : []) as Vhost[]

  // Extract global thresholds (with fallback)
  const globalThresholds: Thresholds = {
    ...DEFAULT_GLOBAL_THRESHOLDS,
    ...((globalThresholdsData as { thresholds?: Partial<Thresholds> } | undefined)?.thresholds || {}),
  }

  // Extract CAPTCHA providers
  const captchaProviders: CaptchaProvider[] = captchaProvidersData?.providers || []
  const enabledCaptchaProviders = captchaProviders.filter(p => p.enabled)
  const globalCaptchaConfig = captchaConfigData?.config

  const saveMutation = useMutation({
    mutationFn: (data: Partial<Endpoint>) =>
      isNew ? endpointsApi.create(data) : endpointsApi.update(id!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['endpoints'] })
      toast({ title: isNew ? 'Endpoint created' : 'Endpoint updated' })
      navigate('/endpoints')
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
    mutationFn: () => learningApi.clearEndpointFields(id!),
    onSuccess: () => {
      refetchLearnedFields()
      toast({ title: 'Learning data cleared' })
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to clear learning data',
        variant: 'destructive',
      })
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    saveMutation.mutate(formData)
  }

  // Helper functions for adding learned fields to configuration
  const addToRequiredFields = (fieldName: string) => {
    const required = Array.isArray(formData.fields?.required) ? formData.fields.required : []
    if (!required.includes(fieldName)) {
      setFormData({
        ...formData,
        fields: {
          ...formData.fields,
          required: [...required, fieldName],
        },
      })
      toast({ title: `Added "${fieldName}" to required fields` })
    }
  }

  const addToHashFields = (fieldName: string) => {
    const hashFields = Array.isArray(formData.hash_content?.fields) ? formData.hash_content.fields : []
    if (!hashFields.includes(fieldName)) {
      setFormData({
        ...formData,
        hash_content: {
          ...formData.hash_content,
          enabled: true,
          fields: [...hashFields, fieldName],
        },
      })
      toast({ title: `Added "${fieldName}" to hash fields` })
    }
  }

  const addToIgnoreFields = (fieldName: string) => {
    const ignoreFields = Array.isArray(formData.fields?.ignore_fields) ? formData.fields.ignore_fields : []
    if (!ignoreFields.includes(fieldName)) {
      setFormData({
        ...formData,
        fields: {
          ...formData.fields,
          ignore_fields: [...ignoreFields, fieldName],
        },
      })
      toast({ title: `Added "${fieldName}" to ignored fields` })
    }
  }

  const addToExpectedFields = (fieldName: string) => {
    const expectedFields = Array.isArray(formData.fields?.expected) ? formData.fields.expected : []
    if (!expectedFields.includes(fieldName)) {
      setFormData({
        ...formData,
        fields: {
          ...formData.fields,
          expected: [...expectedFields, fieldName],
        },
      })
      toast({ title: `Added "${fieldName}" to expected fields` })
    }
  }

  // Extract learned fields from response (ensure array - Lua cjson may encode empty arrays as objects)
  const learnedFields: LearnedField[] = Array.isArray(learnedFieldsData?.fields) ? learnedFieldsData.fields : []
  const learningStats = learnedFieldsData?.learning_stats

  const addPath = () => {
    if (!newPath) return

    if (pathType === 'exact') {
      setFormData({
        ...formData,
        matching: {
          ...formData.matching,
          paths: [...(formData.matching?.paths || []), newPath],
        },
      })
    } else if (pathType === 'prefix') {
      setFormData({
        ...formData,
        matching: {
          ...formData.matching,
          path_prefix: newPath,
        },
      })
    } else {
      setFormData({
        ...formData,
        matching: {
          ...formData.matching,
          path_regex: newPath,
        },
      })
    }
    setNewPath('')
  }

  const removePath = (path: string) => {
    setFormData({
      ...formData,
      matching: {
        ...formData.matching,
        paths: formData.matching?.paths?.filter((p) => p !== path),
      },
    })
  }

  const toggleMethod = (method: string) => {
    const methods = Array.isArray(formData.matching?.methods) ? formData.matching.methods : []
    if (methods.includes(method)) {
      setFormData({
        ...formData,
        matching: {
          ...formData.matching,
          methods: methods.filter((m) => m !== method),
        },
      })
    } else {
      setFormData({
        ...formData,
        matching: {
          ...formData.matching,
          methods: [...methods, method],
        },
      })
    }
  }

  if (!isNew && isLoading) {
    return <div>Loading...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={() => navigate('/endpoints')}>
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div>
          <h2 className="text-3xl font-bold tracking-tight">
            {isNew ? 'New Endpoint' : 'Edit Endpoint'}
          </h2>
          <p className="text-muted-foreground">
            {isNew ? 'Create a new endpoint configuration' : `Editing ${formData.name || formData.id}`}
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit}>
        <Tabs defaultValue="general" className="space-y-4">
          <TabsList>
            <TabsTrigger value="general">General</TabsTrigger>
            <TabsTrigger value="matching">Matching</TabsTrigger>
            <TabsTrigger value="fields">Fields</TabsTrigger>
            <TabsTrigger value="waf">WAF Settings</TabsTrigger>
            <TabsTrigger value="rate-limiting">Rate Limiting</TabsTrigger>
            <TabsTrigger value="captcha" className="flex items-center gap-1">
              <ShieldCheck className="h-3 w-3" />
              CAPTCHA
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
                <CardDescription>Basic endpoint configuration</CardDescription>
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
                      placeholder="my-endpoint"
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="name">Name</Label>
                    <Input
                      id="name"
                      value={formData.name || ''}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      placeholder="My Endpoint"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="description">Description</Label>
                  <Input
                    id="description"
                    value={formData.description || ''}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    placeholder="Description of this endpoint"
                  />
                </div>

                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="mode">Mode</Label>
                    <Select
                      value={formData.mode || 'monitoring'}
                      onValueChange={(value) =>
                        setFormData({ ...formData, mode: value as Endpoint['mode'] })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="monitoring">Monitoring</SelectItem>
                        <SelectItem value="blocking">Blocking</SelectItem>
                        <SelectItem value="passthrough">Passthrough</SelectItem>
                        <SelectItem value="strict">Strict</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="priority">Priority</Label>
                    <Input
                      id="priority"
                      type="number"
                      value={formData.priority || 100}
                      onChange={(e) =>
                        setFormData({ ...formData, priority: parseInt(e.target.value) })
                      }
                    />
                    <p className="text-xs text-muted-foreground">Lower = higher priority</p>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="vhost">Virtual Host Scope</Label>
                  <Select
                    value={formData.vhost_id || '_global'}
                    onValueChange={(value) =>
                      setFormData({ ...formData, vhost_id: value === '_global' ? null : value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="_global">
                        <div className="flex items-center gap-2">
                          <Globe className="h-4 w-4 text-green-500" />
                          Global (all vhosts)
                        </div>
                      </SelectItem>
                      {vhosts.map((vhost) => (
                        <SelectItem key={vhost.id} value={vhost.id}>
                          <div className="flex items-center gap-2">
                            <Server className="h-4 w-4 text-blue-500" />
                            {vhost.name || vhost.id}
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    Global endpoints apply to all vhosts. Vhost-specific endpoints take priority.
                  </p>
                </div>

                <div className="flex items-center space-x-2">
                  <Switch
                    id="enabled"
                    checked={formData.enabled}
                    onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
                  />
                  <Label htmlFor="enabled">Enabled</Label>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="matching">
            <Card>
              <CardHeader>
                <CardTitle>Request Matching</CardTitle>
                <CardDescription>Define which requests this endpoint handles</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <Label>Paths</Label>
                  <div className="flex gap-2">
                    <Select value={pathType} onValueChange={(v) => setPathType(v as typeof pathType)}>
                      <SelectTrigger className="w-32">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="exact">Exact</SelectItem>
                        <SelectItem value="prefix">Prefix</SelectItem>
                        <SelectItem value="regex">Regex</SelectItem>
                      </SelectContent>
                    </Select>
                    <Input
                      value={newPath}
                      onChange={(e) => setNewPath(e.target.value)}
                      placeholder={
                        pathType === 'exact'
                          ? '/api/contact'
                          : pathType === 'prefix'
                          ? '/api/v2/'
                          : '^/api/.*$'
                      }
                      onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addPath())}
                      className="flex-1"
                    />
                    <Button type="button" onClick={addPath}>
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>

                  {/* Exact paths */}
                  {(() => {
                    const paths = Array.isArray(formData.matching?.paths) ? formData.matching.paths : []
                    return paths.length > 0 ? (
                      <div className="space-y-2">
                        <p className="text-sm font-medium">Exact paths:</p>
                        <div className="flex flex-wrap gap-2">
                          {paths.map((path) => (
                            <div
                              key={path}
                              className="flex items-center gap-1 rounded-md bg-secondary px-2 py-1 text-sm"
                            >
                              <code>{path}</code>
                              <button
                                type="button"
                                onClick={() => removePath(path)}
                                className="ml-1 hover:text-destructive"
                              >
                                <X className="h-3 w-3" />
                              </button>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : null
                  })()}

                  {formData.matching?.path_prefix && (
                    <div className="space-y-2">
                      <p className="text-sm font-medium">Path prefix:</p>
                      <div className="flex items-center gap-2">
                        <code className="rounded-md bg-secondary px-2 py-1 text-sm">
                          {formData.matching.path_prefix}*
                        </code>
                        <button
                          type="button"
                          onClick={() =>
                            setFormData({
                              ...formData,
                              matching: { ...formData.matching, path_prefix: undefined },
                            })
                          }
                          className="hover:text-destructive"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </div>
                    </div>
                  )}

                  {formData.matching?.path_regex && (
                    <div className="space-y-2">
                      <p className="text-sm font-medium">Path regex:</p>
                      <div className="flex items-center gap-2">
                        <code className="rounded-md bg-secondary px-2 py-1 text-sm">
                          /{formData.matching.path_regex}/
                        </code>
                        <button
                          type="button"
                          onClick={() =>
                            setFormData({
                              ...formData,
                              matching: { ...formData.matching, path_regex: undefined },
                            })
                          }
                          className="hover:text-destructive"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <Label>HTTP Methods</Label>
                  <div className="flex flex-wrap gap-2">
                    {HTTP_METHODS.map((method) => {
                      const methods = Array.isArray(formData.matching?.methods) ? formData.matching.methods : []
                      return (
                        <Button
                          key={method}
                          type="button"
                          variant={methods.includes(method) ? 'default' : 'outline'}
                          size="sm"
                          onClick={() => toggleMethod(method)}
                        >
                          {method}
                        </Button>
                      )
                    })}
                  </div>
                </div>

                <div className="space-y-4">
                  <Label>Content Types</Label>
                  <div className="flex gap-2">
                    <Select
                      value={newContentType}
                      onValueChange={(value) => {
                        if (value && !formData.matching?.content_types?.includes(value)) {
                          setFormData({
                            ...formData,
                            matching: {
                              ...formData.matching,
                              content_types: [...(formData.matching?.content_types || []), value],
                            },
                          })
                        }
                        setNewContentType('')
                      }}
                    >
                      <SelectTrigger className="flex-1">
                        <SelectValue placeholder="Add content type..." />
                      </SelectTrigger>
                      <SelectContent>
                        {COMMON_CONTENT_TYPES.filter(
                          (ct) => !formData.matching?.content_types?.includes(ct)
                        ).map((ct) => (
                          <SelectItem key={ct} value={ct}>
                            {ct}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Input
                      value={newContentType}
                      onChange={(e) => setNewContentType(e.target.value)}
                      placeholder="Or enter custom..."
                      className="flex-1"
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && newContentType) {
                          e.preventDefault()
                          if (!formData.matching?.content_types?.includes(newContentType)) {
                            setFormData({
                              ...formData,
                              matching: {
                                ...formData.matching,
                                content_types: [...(formData.matching?.content_types || []), newContentType],
                              },
                            })
                          }
                          setNewContentType('')
                        }
                      }}
                    />
                  </div>

                  {(() => {
                    const contentTypes = Array.isArray(formData.matching?.content_types) ? formData.matching.content_types : []
                    return contentTypes.length > 0 ? (
                      <div className="flex flex-wrap gap-2">
                        {contentTypes.map((ct) => (
                          <div
                            key={ct}
                            className="flex items-center gap-1 rounded-md bg-secondary px-2 py-1 text-sm"
                          >
                            <code>{ct}</code>
                            <button
                              type="button"
                              onClick={() =>
                                setFormData({
                                  ...formData,
                                  matching: {
                                    ...formData.matching,
                                    content_types: contentTypes.filter((c) => c !== ct),
                                  },
                                })
                              }
                              className="ml-1 hover:text-destructive"
                            >
                              <X className="h-3 w-3" />
                            </button>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        No content type restrictions (matches all)
                      </p>
                    )
                  })()}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="fields">
            <Card>
              <CardHeader>
                <CardTitle>Field Validation</CardTitle>
                <CardDescription>Configure form field requirements and constraints</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <Label>Required Fields</Label>
                  <p className="text-sm text-muted-foreground">
                    Form submissions must include these fields
                  </p>
                  <div className="flex gap-2">
                    <Input
                      value={newRequiredField}
                      onChange={(e) => setNewRequiredField(e.target.value)}
                      placeholder="Field name (e.g., email)"
                      className="flex-1"
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && newRequiredField) {
                          e.preventDefault()
                          const fields = formData.fields?.required || []
                          if (!fields.includes(newRequiredField)) {
                            setFormData({
                              ...formData,
                              fields: {
                                ...formData.fields,
                                required: [...fields, newRequiredField],
                              },
                            })
                          }
                          setNewRequiredField('')
                        }
                      }}
                    />
                    <Button
                      type="button"
                      onClick={() => {
                        if (newRequiredField) {
                          const fields = formData.fields?.required || []
                          if (!fields.includes(newRequiredField)) {
                            setFormData({
                              ...formData,
                              fields: {
                                ...formData.fields,
                                required: [...fields, newRequiredField],
                              },
                            })
                          }
                          setNewRequiredField('')
                        }
                      }}
                    >
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>

                  {(() => {
                    const required = Array.isArray(formData.fields?.required) ? formData.fields.required : []
                    return required.length > 0 ? (
                      <div className="flex flex-wrap gap-2">
                        {required.map((field) => (
                          <div
                            key={field}
                            className="flex items-center gap-1 rounded-md bg-secondary px-2 py-1 text-sm"
                          >
                            <code>{field}</code>
                            <button
                              type="button"
                              onClick={() =>
                                setFormData({
                                  ...formData,
                                  fields: {
                                    ...formData.fields,
                                    required: required.filter((f) => f !== field),
                                  },
                                })
                              }
                              className="ml-1 hover:text-destructive"
                            >
                              <X className="h-3 w-3" />
                            </button>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground italic">
                        No required fields configured
                      </p>
                    )
                  })()}
                </div>

                <div className="space-y-4">
                  <Label>Max Field Lengths</Label>
                  <p className="text-sm text-muted-foreground">
                    Maximum character length for specific fields
                  </p>
                  <div className="flex gap-2">
                    <Input
                      value={newMaxLengthField}
                      onChange={(e) => setNewMaxLengthField(e.target.value)}
                      placeholder="Field name"
                      className="flex-1"
                    />
                    <Input
                      type="number"
                      value={newMaxLengthValue}
                      onChange={(e) => setNewMaxLengthValue(e.target.value)}
                      placeholder="Max length"
                      className="w-32"
                    />
                    <Button
                      type="button"
                      onClick={() => {
                        if (newMaxLengthField && newMaxLengthValue) {
                          setFormData({
                            ...formData,
                            fields: {
                              ...formData.fields,
                              max_length: {
                                ...formData.fields?.max_length,
                                [newMaxLengthField]: parseInt(newMaxLengthValue),
                              },
                            },
                          })
                          setNewMaxLengthField('')
                          setNewMaxLengthValue('')
                        }
                      }}
                    >
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>

                  {(() => {
                    const maxLength = typeof formData.fields?.max_length === 'object' ? formData.fields.max_length : {}
                    const entries = Object.entries(maxLength || {})
                    return entries.length > 0 ? (
                      <div className="space-y-2">
                        {entries.map(([field, length]) => (
                          <div
                            key={field}
                            className="flex items-center justify-between rounded-md bg-secondary px-3 py-2 text-sm"
                          >
                            <div>
                              <code>{field}</code>
                              <span className="text-muted-foreground mx-2">max</span>
                              <span className="font-medium">{length}</span>
                              <span className="text-muted-foreground ml-1">chars</span>
                            </div>
                            <button
                              type="button"
                              onClick={() => {
                                const { [field]: _, ...rest } = maxLength
                                setFormData({
                                  ...formData,
                                  fields: {
                                    ...formData.fields,
                                    max_length: rest,
                                  },
                                })
                              }}
                              className="hover:text-destructive"
                            >
                              <X className="h-3 w-3" />
                            </button>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground italic">
                        No max length constraints configured
                      </p>
                    )
                  })()}
                </div>

                <div className="space-y-4">
                  <Label>Ignored Fields</Label>
                  <p className="text-sm text-muted-foreground">
                    Fields to exclude from WAF inspection (CSRF tokens, captchas, etc.)
                  </p>
                  <div className="flex gap-2">
                    <Select
                      value={newIgnoreField}
                      onValueChange={(value) => {
                        const ignoreFields = Array.isArray(formData.fields?.ignore_fields) ? formData.fields.ignore_fields : []
                        if (value && !ignoreFields.includes(value)) {
                          setFormData({
                            ...formData,
                            fields: {
                              ...formData.fields,
                              ignore_fields: [...ignoreFields, value],
                            },
                          })
                        }
                        setNewIgnoreField('')
                      }}
                    >
                      <SelectTrigger className="flex-1">
                        <SelectValue placeholder="Add common field..." />
                      </SelectTrigger>
                      <SelectContent>
                        {COMMON_IGNORE_FIELDS.filter(
                          (f) => !(Array.isArray(formData.fields?.ignore_fields) ? formData.fields.ignore_fields : []).includes(f)
                        ).map((field) => (
                          <SelectItem key={field} value={field}>
                            {field}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Input
                      value={newIgnoreField}
                      onChange={(e) => setNewIgnoreField(e.target.value)}
                      placeholder="Or enter custom..."
                      className="flex-1"
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && newIgnoreField) {
                          e.preventDefault()
                          const ignoreFields = Array.isArray(formData.fields?.ignore_fields) ? formData.fields.ignore_fields : []
                          if (!ignoreFields.includes(newIgnoreField)) {
                            setFormData({
                              ...formData,
                              fields: {
                                ...formData.fields,
                                ignore_fields: [...ignoreFields, newIgnoreField],
                              },
                            })
                          }
                          setNewIgnoreField('')
                        }
                      }}
                    />
                    <Button
                      type="button"
                      onClick={() => {
                        if (newIgnoreField) {
                          const ignoreFields = Array.isArray(formData.fields?.ignore_fields) ? formData.fields.ignore_fields : []
                          if (!ignoreFields.includes(newIgnoreField)) {
                            setFormData({
                              ...formData,
                              fields: {
                                ...formData.fields,
                                ignore_fields: [...ignoreFields, newIgnoreField],
                              },
                            })
                          }
                          setNewIgnoreField('')
                        }
                      }}
                    >
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>

                  {(() => {
                    const ignoreFields = Array.isArray(formData.fields?.ignore_fields) ? formData.fields.ignore_fields : []
                    return ignoreFields.length > 0 ? (
                      <div className="flex flex-wrap gap-2">
                        {ignoreFields.map((field) => (
                          <div
                            key={field}
                            className="flex items-center gap-1 rounded-md bg-secondary px-2 py-1 text-sm"
                          >
                            <code>{field}</code>
                            <button
                              type="button"
                              onClick={() =>
                                setFormData({
                                  ...formData,
                                  fields: {
                                    ...formData.fields,
                                    ignore_fields: ignoreFields.filter((f) => f !== field),
                                  },
                                })
                              }
                              className="ml-1 hover:text-destructive"
                            >
                              <X className="h-3 w-3" />
                            </button>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground italic">
                        No fields excluded from inspection
                      </p>
                    )
                  })()}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5" />
                  Optional Expected Fields (Anti-Stuffing)
                </CardTitle>
                <CardDescription>
                  Define optional fields that are allowed in addition to required fields. Any other fields trigger the configured action.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="rounded-lg border border-amber-200 bg-amber-50 p-4">
                  <div className="flex items-start gap-3">
                    <Info className="h-5 w-5 text-amber-500 mt-0.5" />
                    <div>
                      <p className="font-medium text-amber-800">Prevent Form Stuffing Attacks</p>
                      <p className="text-sm text-amber-700 mt-1">
                        Bots often add extra fields to forms to confuse spam detection or inject malicious data.
                        <strong> Required fields are automatically expected.</strong> Use this section to add optional
                        fields that are allowed but not required. Any field not in required, expected, or ignored lists
                        will trigger the action below.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <Label>Optional Expected Fields</Label>
                  <p className="text-sm text-muted-foreground">
                    Optional fields allowed in addition to required fields (ignored fields are always allowed)
                  </p>
                  <div className="flex gap-2">
                    <Input
                      value={newExpectedField}
                      onChange={(e) => setNewExpectedField(e.target.value)}
                      placeholder="Field name (e.g., email, message)"
                      className="flex-1"
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && newExpectedField) {
                          e.preventDefault()
                          const expectedFields = Array.isArray(formData.fields?.expected) ? formData.fields.expected : []
                          if (!expectedFields.includes(newExpectedField)) {
                            setFormData({
                              ...formData,
                              fields: {
                                ...formData.fields,
                                expected: [...expectedFields, newExpectedField],
                              },
                            })
                          }
                          setNewExpectedField('')
                        }
                      }}
                    />
                    <Button
                      type="button"
                      onClick={() => {
                        if (newExpectedField) {
                          const expectedFields = Array.isArray(formData.fields?.expected) ? formData.fields.expected : []
                          if (!expectedFields.includes(newExpectedField)) {
                            setFormData({
                              ...formData,
                              fields: {
                                ...formData.fields,
                                expected: [...expectedFields, newExpectedField],
                              },
                            })
                          }
                          setNewExpectedField('')
                        }
                      }}
                    >
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>

                  {(() => {
                    const expectedFields = Array.isArray(formData.fields?.expected) ? formData.fields.expected : []
                    return expectedFields.length > 0 ? (
                      <div className="flex flex-wrap gap-2">
                        {expectedFields.map((field) => (
                          <div
                            key={field}
                            className="flex items-center gap-1 rounded-md bg-amber-100 px-2 py-1 text-sm text-amber-800"
                          >
                            <code>{field}</code>
                            <button
                              type="button"
                              onClick={() =>
                                setFormData({
                                  ...formData,
                                  fields: {
                                    ...formData.fields,
                                    expected: expectedFields.filter((f) => f !== field),
                                  },
                                })
                              }
                              className="ml-1 hover:text-red-600"
                            >
                              <X className="h-3 w-3" />
                            </button>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground italic">
                        No optional expected fields defined. If required fields are set, only those (plus ignored) will be allowed.
                      </p>
                    )
                  })()}
                </div>

                {(() => {
                  const expectedFields = Array.isArray(formData.fields?.expected) ? formData.fields.expected : []
                  const requiredFields = Array.isArray(formData.fields?.required) ? formData.fields.required : []
                  const hasFieldRestrictions = expectedFields.length > 0 || requiredFields.length > 0
                  return hasFieldRestrictions ? (
                    <div className="space-y-2">
                      <Label htmlFor="unexpected_action">Action for Unexpected Fields</Label>
                      <Select
                        value={formData.fields?.unexpected_action || 'flag'}
                        onValueChange={(value) =>
                          setFormData({
                            ...formData,
                            fields: {
                              ...formData.fields,
                              unexpected_action: value as 'flag' | 'block' | 'ignore' | 'filter',
                            },
                          })
                        }
                      >
                        <SelectTrigger className="w-64">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="flag">
                            Flag (+5 score per field)
                          </SelectItem>
                          <SelectItem value="block">
                            Block immediately
                          </SelectItem>
                          <SelectItem value="filter">
                            Filter (remove from request)
                          </SelectItem>
                          <SelectItem value="ignore">
                            Ignore (allow anyway)
                          </SelectItem>
                        </SelectContent>
                      </Select>
                      <p className="text-xs text-muted-foreground">
                        What to do when a form contains fields not in required, expected, or ignored lists
                      </p>
                      {formData.fields?.unexpected_action === 'filter' && (
                        <div className="rounded-lg border border-red-200 bg-red-50 p-3 mt-2">
                          <p className="text-sm text-red-700">
                            <strong>Warning:</strong> Filtering modifies the request body, which may break form
                            signing/CSRF protections that hash all fields. Use only if you understand the implications.
                          </p>
                        </div>
                      )}
                    </div>
                  ) : null
                })()}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Content Hashing</CardTitle>
                <CardDescription>
                  Hash specific form fields for duplicate detection via HAProxy stick-tables
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex items-center space-x-2">
                  <Switch
                    id="hash_content_enabled"
                    checked={formData.hash_content?.enabled === true}
                    onCheckedChange={(checked) =>
                      setFormData({
                        ...formData,
                        hash_content: { ...formData.hash_content, enabled: checked },
                      })
                    }
                  />
                  <Label htmlFor="hash_content_enabled">Enable Content Hashing</Label>
                </div>

                {formData.hash_content?.enabled && (
                  <div className="space-y-4">
                    <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
                      <div className="flex items-start gap-3">
                        <Info className="h-5 w-5 text-blue-500 mt-0.5" />
                        <div>
                          <p className="font-medium text-blue-800">How Content Hashing Works</p>
                          <p className="text-sm text-blue-700 mt-1">
                            Only the specified fields will be hashed (SHA256) and sent to HAProxy via the X-Form-Hash header.
                            HAProxy uses this to detect duplicate submissions and coordinate rate limiting across replicas.
                          </p>
                        </div>
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label>Fields to Hash</Label>
                      <p className="text-sm text-muted-foreground">
                        Specify which form fields should be included in the content hash
                      </p>
                      <div className="flex gap-2">
                        <Input
                          value={newHashField}
                          onChange={(e) => setNewHashField(e.target.value)}
                          placeholder="Field name (e.g., email, message)"
                          className="flex-1"
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' && newHashField) {
                              e.preventDefault()
                              const hashFields = Array.isArray(formData.hash_content?.fields) ? formData.hash_content.fields : []
                              if (!hashFields.includes(newHashField)) {
                                setFormData({
                                  ...formData,
                                  hash_content: {
                                    ...formData.hash_content,
                                    enabled: true,
                                    fields: [...hashFields, newHashField],
                                  },
                                })
                              }
                              setNewHashField('')
                            }
                          }}
                        />
                        <Button
                          type="button"
                          onClick={() => {
                            if (newHashField) {
                              const hashFields = Array.isArray(formData.hash_content?.fields) ? formData.hash_content.fields : []
                              if (!hashFields.includes(newHashField)) {
                                setFormData({
                                  ...formData,
                                  hash_content: {
                                    ...formData.hash_content,
                                    enabled: true,
                                    fields: [...hashFields, newHashField],
                                  },
                                })
                              }
                              setNewHashField('')
                            }
                          }}
                        >
                          <Plus className="h-4 w-4" />
                        </Button>
                      </div>

                      {(() => {
                        const hashFields = Array.isArray(formData.hash_content?.fields) ? formData.hash_content.fields : []
                        return hashFields.length > 0 ? (
                          <div className="flex flex-wrap gap-2 mt-2">
                            {hashFields.map((field) => (
                              <div
                                key={field}
                                className="flex items-center gap-1 rounded-md bg-green-100 px-2 py-1 text-sm text-green-800"
                              >
                                <code>{field}</code>
                                <button
                                  type="button"
                                  onClick={() =>
                                    setFormData({
                                      ...formData,
                                      hash_content: {
                                        ...formData.hash_content,
                                        enabled: true,
                                        fields: hashFields.filter((f) => f !== field),
                                      },
                                    })
                                  }
                                  className="ml-1 hover:text-red-600"
                                >
                                  <X className="h-3 w-3" />
                                </button>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-sm text-yellow-600 italic mt-2">
                            No fields specified - content hashing will be skipped
                          </p>
                        )
                      })()}
                    </div>
                  </div>
                )}

                {!formData.hash_content?.enabled && (
                  <p className="text-sm text-muted-foreground">
                    Content hashing is disabled. Enable it to detect duplicate form submissions.
                  </p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="waf">
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
                      <Label htmlFor="ip_rate_limit">IP Rate Limit (per minute)</Label>
                      <Input
                        id="ip_rate_limit"
                        type="number"
                        value={formData.thresholds?.ip_rate_limit ?? ''}
                        placeholder={String(globalThresholds.ip_rate_limit)}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            thresholds: {
                              ...formData.thresholds,
                              ip_rate_limit: e.target.value ? parseInt(e.target.value) : undefined,
                            },
                          })
                        }
                      />
                      <p className="text-xs text-muted-foreground">Max requests per IP per minute</p>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="ip_daily_limit">IP Daily Limit</Label>
                      <Input
                        id="ip_daily_limit"
                        type="number"
                        value={formData.thresholds?.ip_daily_limit ?? ''}
                        placeholder={String(globalThresholds.ip_daily_limit)}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            thresholds: {
                              ...formData.thresholds,
                              ip_daily_limit: e.target.value ? parseInt(e.target.value) : undefined,
                            },
                          })
                        }
                      />
                      <p className="text-xs text-muted-foreground">Max requests per IP per day</p>
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
          </TabsContent>

          <TabsContent value="rate-limiting">
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
                    <div className="space-y-2 max-w-sm">
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
                        Maximum number of requests allowed per IP address per minute
                      </p>
                    </div>

                    <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4">
                      <div className="flex items-start gap-3">
                        <Info className="h-5 w-5 text-yellow-600 mt-0.5" />
                        <div>
                          <p className="font-medium text-yellow-800">Rate Limiting Behavior</p>
                          <p className="text-sm text-yellow-700 mt-1">
                            When rate limit is exceeded, requests will be rejected with a 429 Too Many Requests response.
                            The limit is tracked per IP address and resets every minute.
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="captcha">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5" />
                  CAPTCHA Settings
                </CardTitle>
                <CardDescription>
                  Challenge suspicious requests with CAPTCHA instead of blocking them outright
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {!globalCaptchaConfig?.enabled && (
                  <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4">
                    <div className="flex items-start gap-3">
                      <Info className="h-5 w-5 text-yellow-600 mt-0.5" />
                      <div>
                        <p className="font-medium text-yellow-800">CAPTCHA is Disabled Globally</p>
                        <p className="text-sm text-yellow-700 mt-1">
                          CAPTCHA protection is currently disabled at the global level. Enable it in CAPTCHA Settings
                          to use per-endpoint CAPTCHA configuration.
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {enabledCaptchaProviders.length === 0 && (
                  <div className="rounded-lg border border-orange-200 bg-orange-50 p-4">
                    <div className="flex items-start gap-3">
                      <Info className="h-5 w-5 text-orange-500 mt-0.5" />
                      <div>
                        <p className="font-medium text-orange-800">No CAPTCHA Providers Configured</p>
                        <p className="text-sm text-orange-700 mt-1">
                          Add and enable a CAPTCHA provider in CAPTCHA Providers before configuring per-endpoint CAPTCHA.
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                <div className="flex items-center space-x-2">
                  <Switch
                    id="captcha_enabled"
                    checked={(formData as any).captcha?.enabled === true}
                    onCheckedChange={(checked) =>
                      setFormData({
                        ...formData,
                        captcha: { ...(formData as any).captcha, enabled: checked },
                      } as any)
                    }
                  />
                  <Label htmlFor="captcha_enabled">Enable CAPTCHA for this endpoint</Label>
                </div>

                {(formData as any).captcha?.enabled && (
                  <div className="space-y-6 pl-6 border-l-2 border-blue-200">
                    <div className="space-y-2">
                      <Label>Provider</Label>
                      <Select
                        value={(formData as any).captcha?.provider || '_default'}
                        onValueChange={(value) =>
                          setFormData({
                            ...formData,
                            captcha: {
                              ...(formData as any).captcha,
                              provider: value === '_default' ? undefined : value,
                            },
                          } as any)
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="_default">
                            Use global default
                            {globalCaptchaConfig?.default_provider &&
                              ` (${captchaProviders.find(p => p.id === globalCaptchaConfig.default_provider)?.name || 'auto'})`}
                          </SelectItem>
                          {captchaProviders.map((provider) => (
                            <SelectItem key={provider.id} value={provider.id} disabled={!provider.enabled}>
                              {provider.name} ({provider.type})
                              {!provider.enabled && ' [Disabled]'}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label>Trigger Mode</Label>
                      <Select
                        value={(formData as any).captcha?.trigger || 'on_block'}
                        onValueChange={(value) =>
                          setFormData({
                            ...formData,
                            captcha: {
                              ...(formData as any).captcha,
                              trigger: value as 'on_block' | 'on_flag' | 'always',
                            },
                          } as any)
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="on_block">On Block - Challenge when request would be blocked</SelectItem>
                          <SelectItem value="on_flag">On Flag - Challenge when spam score exceeds threshold</SelectItem>
                          <SelectItem value="always">Always - Challenge all requests to this endpoint</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    {(formData as any).captcha?.trigger === 'on_flag' && (
                      <div className="space-y-2">
                        <Label>Spam Score Threshold</Label>
                        <Input
                          type="number"
                          min="0"
                          max="100"
                          value={(formData as any).captcha?.spam_score_threshold || 50}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              captcha: {
                                ...(formData as any).captcha,
                                spam_score_threshold: parseInt(e.target.value) || 50,
                              },
                            } as any)
                          }
                          className="w-32"
                        />
                        <p className="text-sm text-muted-foreground">
                          Challenge requests with spam score at or above this value
                        </p>
                      </div>
                    )}

                    <div className="space-y-2">
                      <Label>Trust Duration Override (seconds)</Label>
                      <div className="flex items-center gap-2">
                        <Input
                          type="number"
                          min="0"
                          placeholder={String(globalCaptchaConfig?.trust_duration || 86400)}
                          value={(formData as any).captcha?.trust_duration || ''}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              captcha: {
                                ...(formData as any).captcha,
                                trust_duration: e.target.value ? parseInt(e.target.value) : undefined,
                              },
                            } as any)
                          }
                          className="w-40"
                        />
                        <span className="text-sm text-muted-foreground">
                          Leave empty to use global default ({((globalCaptchaConfig?.trust_duration || 86400) / 3600).toFixed(0)}h)
                        </span>
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label>Exempt IPs</Label>
                      <p className="text-sm text-muted-foreground">
                        IP addresses that bypass CAPTCHA for this endpoint (one per line)
                      </p>
                      <textarea
                        className="flex min-h-[80px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                        placeholder="10.0.0.0/8&#10;192.168.1.0/24"
                        value={((formData as any).captcha?.exempt_ips || []).join('\n')}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            captcha: {
                              ...(formData as any).captcha,
                              exempt_ips: e.target.value.split('\n').filter(ip => ip.trim()),
                            },
                          } as any)
                        }
                      />
                    </div>
                  </div>
                )}

                <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
                  <div className="flex items-start gap-3">
                    <Info className="h-5 w-5 text-blue-500 mt-0.5" />
                    <div>
                      <p className="font-medium text-blue-800">How CAPTCHA Works</p>
                      <p className="text-sm text-blue-700 mt-1">
                        When enabled, suspicious requests will be presented with a CAPTCHA challenge instead of
                        being blocked. Users who complete the challenge receive a trust token that allows them
                        to bypass CAPTCHA for subsequent requests during the trust duration period.
                      </p>
                    </div>
                  </div>
                </div>
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
                        Form fields automatically discovered from traffic. Use these to configure field requirements.
                      </CardDescription>
                    </div>
                    {learnedFields.length > 0 && (
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          if (confirm('Clear all learning data for this endpoint? This cannot be undone.')) {
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
                        Field names will be automatically discovered as requests flow through this endpoint.
                        Learning uses 10% sampling to minimize performance impact.
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
                              <th className="px-4 py-3 text-right text-sm font-medium">Actions</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y">
                            {learnedFields.map((field) => {
                              const required = Array.isArray(formData.fields?.required) ? formData.fields.required : []
                              const hashFields = Array.isArray(formData.hash_content?.fields) ? formData.hash_content.fields : []
                              const ignoreFields = Array.isArray(formData.fields?.ignore_fields) ? formData.fields.ignore_fields : []
                              const expectedFields = Array.isArray(formData.fields?.expected) ? formData.fields.expected : []

                              const isRequired = required.includes(field.name)
                              const isHashed = hashFields.includes(field.name)
                              const isIgnored = ignoreFields.includes(field.name)
                              const isExpected = expectedFields.includes(field.name)

                              return (
                                <tr key={field.name} className="hover:bg-muted/30">
                                  <td className="px-4 py-3">
                                    <code className="text-sm bg-muted px-1.5 py-0.5 rounded">{field.name}</code>
                                    <div className="flex gap-1 mt-1">
                                      {isRequired && (
                                        <span className="text-xs bg-green-100 text-green-700 px-1.5 py-0.5 rounded">Required</span>
                                      )}
                                      {isHashed && (
                                        <span className="text-xs bg-purple-100 text-purple-700 px-1.5 py-0.5 rounded">Hashed</span>
                                      )}
                                      {isExpected && (
                                        <span className="text-xs bg-amber-100 text-amber-700 px-1.5 py-0.5 rounded">Expected</span>
                                      )}
                                      {isIgnored && (
                                        <span className="text-xs bg-gray-100 text-gray-700 px-1.5 py-0.5 rounded">Ignored</span>
                                      )}
                                    </div>
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
                                  <td className="px-4 py-3 text-right">
                                    <div className="flex justify-end gap-1">
                                      <Button
                                        type="button"
                                        variant="ghost"
                                        size="sm"
                                        onClick={() => addToRequiredFields(field.name)}
                                        disabled={isRequired}
                                        title="Add to Required Fields"
                                        className={isRequired ? 'text-green-600' : ''}
                                      >
                                        <CheckCircle className="h-4 w-4" />
                                      </Button>
                                      <Button
                                        type="button"
                                        variant="ghost"
                                        size="sm"
                                        onClick={() => addToHashFields(field.name)}
                                        disabled={isHashed}
                                        title="Add to Hash Fields"
                                        className={isHashed ? 'text-purple-600' : ''}
                                      >
                                        <Hash className="h-4 w-4" />
                                      </Button>
                                      <Button
                                        type="button"
                                        variant="ghost"
                                        size="sm"
                                        onClick={() => addToExpectedFields(field.name)}
                                        disabled={isExpected}
                                        title="Add to Expected Fields"
                                        className={isExpected ? 'text-amber-600' : ''}
                                      >
                                        <ShieldCheck className="h-4 w-4" />
                                      </Button>
                                      <Button
                                        type="button"
                                        variant="ghost"
                                        size="sm"
                                        onClick={() => addToIgnoreFields(field.name)}
                                        disabled={isIgnored}
                                        title="Add to Ignored Fields"
                                        className={isIgnored ? 'text-gray-600' : ''}
                                      >
                                        <EyeOff className="h-4 w-4" />
                                      </Button>
                                    </div>
                                  </td>
                                </tr>
                              )
                            })}
                          </tbody>
                        </table>
                      </div>

                      {/* Bulk actions */}
                      <div className="flex flex-wrap gap-2">
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            learnedFields.forEach(f => addToRequiredFields(f.name))
                          }}
                        >
                          <CheckCircle className="h-4 w-4 mr-1" />
                          Add All to Required
                        </Button>
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            learnedFields.forEach(f => addToHashFields(f.name))
                          }}
                        >
                          <Hash className="h-4 w-4 mr-1" />
                          Add All to Hash
                        </Button>
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            learnedFields.forEach(f => addToExpectedFields(f.name))
                          }}
                        >
                          <ShieldCheck className="h-4 w-4 mr-1" />
                          Add All to Expected
                        </Button>
                      </div>

                      {/* Info note */}
                      <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4">
                        <div className="flex items-start gap-3">
                          <Info className="h-5 w-5 text-yellow-600 mt-0.5" />
                          <div>
                            <p className="font-medium text-yellow-800">About Field Learning</p>
                            <p className="text-sm text-yellow-700 mt-1">
                              Field names are automatically discovered using 10% probabilistic sampling to minimize
                              performance impact. Types are inferred from field names only (no values stored for compliance).
                              Data is retained for 30 days of inactivity. Click the icons to add fields to your configuration.
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
          <Button type="button" variant="outline" onClick={() => navigate('/endpoints')}>
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
