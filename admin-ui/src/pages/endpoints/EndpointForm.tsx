import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { endpointsApi, vhostsApi, configApi, learningApi, captchaApi, fingerprintProfilesApi, defenseProfilesApi, attackSignaturesApi, LearnedField } from '@/api/client'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useToast } from '@/components/ui/use-toast'
import { ArrowLeft, Save, ShieldCheck, ShieldAlert, BookOpen, Fingerprint, Check, Shield, Layers } from 'lucide-react'
import type { Endpoint, Vhost, Thresholds, CaptchaProvider, FingerprintProfile, DefenseProfile, AttackSignature } from '@/api/types'

// Helper to ensure arrays (Lua JSON may serialize empty tables as {} instead of [])
const ensureArray = <T,>(value: unknown): T[] => {
  if (Array.isArray(value)) return value
  return []
}
import {
  GeneralTab,
  MatchingTab,
  FieldsTab,
  WafSettingsTab,
  RateLimitingTab,
  CaptchaTab,
  SecurityTab,
  FingerprintingTab,
  DefenseProfilesTab,
  DefenseLinesTab,
  LearnedFieldsTab,
} from './tabs'

// Canonical field locations:
//   fields.ignore (not ignore_fields)
//   fields.honeypot (not security.honeypot_fields)
//   fields.hash (not hash_content at root)
//   security contains action/score settings only
const defaultEndpoint: Partial<Endpoint> = {
  enabled: true,
  mode: 'monitoring',
  priority: 100,
  vhost_id: null,
  matching: {
    paths: [],
    methods: ['POST', 'PUT', 'PATCH'],
    content_types: ['application/json', 'application/x-www-form-urlencoded'],
  },
  thresholds: {},
  keywords: {
    inherit_global: true,
  },
  fields: {
    required: [],
    max_length: {},
    ignore: [],
    expected: [],
    honeypot: [],
    hash: {
      enabled: false,
      fields: [],
    },
    unexpected_action: 'flag',
  },
  rate_limiting: {
    enabled: true,
    requests_per_minute: 30,
    requests_per_day: 500,
  },
  patterns: {
    inherit_global: true,
  },
  actions: {
    on_flag: 'tag',
    on_block: 'reject',
    log_level: 'info',
  },
  security: {
    honeypot_action: 'block',
    honeypot_score: 50,
    check_disposable_email: false,
    disposable_email_action: 'flag',
    disposable_email_score: 20,
    check_field_anomalies: true,
  },
  fingerprint_profiles: {
    enabled: true,
    profiles: undefined,
    no_match_action: 'use_default',
    no_match_score: 15,
  },
}

const DEFAULT_GLOBAL_THRESHOLDS: Thresholds = {
  spam_score_block: 80,
  spam_score_flag: 50,
  hash_count_block: 10,
  ip_rate_limit: 30,
  ip_daily_limit: 500,
  hash_unique_ips_block: 5,
}

export function EndpointForm() {
  const { id } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const isNew = !id

  const [formData, setFormData] = useState<Partial<Endpoint>>(defaultEndpoint)
  const [shouldNavigate, setShouldNavigate] = useState(true)

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

  // Fetch fingerprint profiles
  const { data: fingerprintProfilesData } = useQuery({
    queryKey: ['fingerprint-profiles'],
    queryFn: fingerprintProfilesApi.list,
  })
  const availableFingerprintProfiles: FingerprintProfile[] = ensureArray<FingerprintProfile>(fingerprintProfilesData?.profiles)

  // Fetch defense profiles
  const { data: defenseProfilesData } = useQuery({
    queryKey: ['defense-profiles'],
    queryFn: defenseProfilesApi.list,
  })
  const availableDefenseProfiles: DefenseProfile[] = ensureArray<DefenseProfile>(defenseProfilesData?.profiles)

  // Fetch attack signatures
  const { data: attackSignaturesData } = useQuery({
    queryKey: ['attack-signatures'],
    queryFn: () => attackSignaturesApi.list({ enabled: true }),
  })
  const availableAttackSignatures: AttackSignature[] = ensureArray<AttackSignature>(attackSignaturesData?.signatures)

  useEffect(() => {
    const endpoint = (data as { endpoint?: Endpoint } | undefined)?.endpoint || data as Endpoint | undefined
    if (endpoint && typeof endpoint === 'object' && 'id' in endpoint) {
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
          ...endpoint.fields,
          required: Array.isArray(endpoint.fields.required) ? endpoint.fields.required : [],
          max_length: typeof endpoint.fields.max_length === 'object' ? endpoint.fields.max_length : {},
          ignore: Array.isArray(endpoint.fields.ignore) ? endpoint.fields.ignore : [],
          expected: Array.isArray(endpoint.fields.expected) ? endpoint.fields.expected : [],
          honeypot: Array.isArray(endpoint.fields.honeypot) ? endpoint.fields.honeypot : [],
          hash: endpoint.fields.hash ? {
            enabled: endpoint.fields.hash.enabled === true,
            fields: Array.isArray(endpoint.fields.hash.fields) ? endpoint.fields.hash.fields : [],
          } : defaultEndpoint.fields?.hash,
        } : defaultEndpoint.fields,
        security: endpoint.security ? {
          ...endpoint.security,
        } : defaultEndpoint.security,
      }
      setFormData(normalized)
    }
  }, [data])

  // Extract data for components
  const rawVhosts = (vhostsData as { vhosts: Vhost[] } | undefined)?.vhosts
  const vhosts = (Array.isArray(rawVhosts) ? rawVhosts : []) as Vhost[]

  const globalThresholds: Thresholds = {
    ...DEFAULT_GLOBAL_THRESHOLDS,
    ...((globalThresholdsData as { thresholds?: Partial<Thresholds> } | undefined)?.thresholds || {}),
  }

  const captchaProviders: CaptchaProvider[] = captchaProvidersData?.providers || []
  const globalCaptchaConfig = captchaConfigData?.config

  const learnedFields: LearnedField[] = Array.isArray(learnedFieldsData?.fields) ? learnedFieldsData.fields : []
  const learningStats = learnedFieldsData?.learning_stats

  // Mutations
  const saveMutation = useMutation({
    mutationFn: (data: Partial<Endpoint>) =>
      isNew ? endpointsApi.create(data) : endpointsApi.update(id!, data),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['endpoints'] })
      queryClient.invalidateQueries({ queryKey: ['endpoint', id] })
      toast({ title: isNew ? 'Endpoint created' : 'Endpoint updated' })
      if (shouldNavigate) {
        navigate('/endpoints')
      } else {
        if (isNew && response?.endpoint?.id) {
          navigate(`/endpoints/${response.endpoint.id}`, { replace: true })
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

  // Helper functions for learned fields
  const addToRequiredFields = (fieldName: string) => {
    const required = Array.isArray(formData.fields?.required) ? formData.fields.required : []
    if (!required.includes(fieldName)) {
      setFormData({
        ...formData,
        fields: { ...formData.fields, required: [...required, fieldName] },
      })
      toast({ title: `Added "${fieldName}" to required fields` })
    }
  }

  const addToHashFields = (fieldName: string) => {
    const hashFields = Array.isArray(formData.fields?.hash?.fields) ? formData.fields.hash.fields : []
    if (!hashFields.includes(fieldName)) {
      setFormData({
        ...formData,
        fields: {
          ...formData.fields,
          hash: { ...formData.fields?.hash, enabled: true, fields: [...hashFields, fieldName] },
        },
      })
      toast({ title: `Added "${fieldName}" to hash fields` })
    }
  }

  const addToIgnoreFields = (fieldName: string) => {
    const ignoreFields = Array.isArray(formData.fields?.ignore) ? formData.fields.ignore : []
    if (!ignoreFields.includes(fieldName)) {
      setFormData({
        ...formData,
        fields: { ...formData.fields, ignore: [...ignoreFields, fieldName] },
      })
      toast({ title: `Added "${fieldName}" to ignored fields` })
    }
  }

  const addToExpectedFields = (fieldName: string) => {
    const expectedFields = Array.isArray(formData.fields?.expected) ? formData.fields.expected : []
    if (!expectedFields.includes(fieldName)) {
      setFormData({
        ...formData,
        fields: { ...formData.fields, expected: [...expectedFields, fieldName] },
      })
      toast({ title: `Added "${fieldName}" to expected fields` })
    }
  }

  const addToHoneypotFields = (fieldName: string) => {
    const honeypotFields = Array.isArray(formData.fields?.honeypot) ? formData.fields.honeypot : []
    if (!honeypotFields.includes(fieldName)) {
      setFormData({
        ...formData,
        fields: { ...formData.fields, honeypot: [...honeypotFields, fieldName] },
      })
      toast({ title: `Added "${fieldName}" to honeypot fields` })
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setShouldNavigate(true)
    saveMutation.mutate(formData)
  }

  const handleApply = () => {
    setShouldNavigate(false)
    saveMutation.mutate(formData)
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
            <TabsTrigger value="security" className="flex items-center gap-1">
              <ShieldAlert className="h-3 w-3" />
              Security
            </TabsTrigger>
            <TabsTrigger value="fingerprinting" className="flex items-center gap-1">
              <Fingerprint className="h-3 w-3" />
              Fingerprinting
            </TabsTrigger>
            <TabsTrigger value="defense-profiles" className="flex items-center gap-1">
              <Shield className="h-3 w-3" />
              Defense Profiles
            </TabsTrigger>
            <TabsTrigger value="defense-lines" className="flex items-center gap-1">
              <Layers className="h-3 w-3" />
              Defense Lines
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
            <GeneralTab
              formData={formData}
              setFormData={setFormData}
              isEdit={!isNew}
              vhosts={vhosts}
            />
          </TabsContent>

          <TabsContent value="matching">
            <MatchingTab
              formData={formData}
              setFormData={setFormData}
              isEdit={!isNew}
            />
          </TabsContent>

          <TabsContent value="fields">
            <div className="space-y-6">
              <FieldsTab
                formData={formData}
                setFormData={setFormData}
                isEdit={!isNew}
              />
            </div>
          </TabsContent>

          <TabsContent value="waf">
            <WafSettingsTab
              formData={formData}
              setFormData={setFormData}
              isEdit={!isNew}
              globalThresholds={globalThresholds}
            />
          </TabsContent>

          <TabsContent value="rate-limiting">
            <RateLimitingTab
              formData={formData}
              setFormData={setFormData}
              isEdit={!isNew}
            />
          </TabsContent>

          <TabsContent value="captcha">
            <CaptchaTab
              formData={formData}
              setFormData={setFormData}
              isEdit={!isNew}
              captchaProviders={captchaProviders}
              globalCaptchaConfig={globalCaptchaConfig}
            />
          </TabsContent>

          <TabsContent value="security">
            <SecurityTab
              formData={formData}
              setFormData={setFormData}
              isEdit={!isNew}
            />
          </TabsContent>

          <TabsContent value="fingerprinting">
            <FingerprintingTab
              formData={formData}
              setFormData={setFormData}
              isEdit={!isNew}
              availableProfiles={availableFingerprintProfiles}
            />
          </TabsContent>

          <TabsContent value="defense-profiles">
            <DefenseProfilesTab
              formData={formData}
              setFormData={setFormData}
              isEdit={!isNew}
              availableProfiles={availableDefenseProfiles}
            />
          </TabsContent>

          <TabsContent value="defense-lines">
            <DefenseLinesTab
              formData={formData}
              setFormData={setFormData}
              isEdit={!isNew}
              availableProfiles={availableDefenseProfiles}
              availableSignatures={availableAttackSignatures}
            />
          </TabsContent>

          {!isNew && (
            <TabsContent value="learned-fields">
              <LearnedFieldsTab
                formData={formData}
                setFormData={setFormData}
                isEdit={!isNew}
                learnedFields={learnedFields}
                learnedFieldsLoading={learnedFieldsLoading}
                learningStats={learningStats}
                onClearLearning={() => clearLearningMutation.mutate()}
                clearLearningPending={clearLearningMutation.isPending}
                addToRequiredFields={addToRequiredFields}
                addToHashFields={addToHashFields}
                addToIgnoreFields={addToIgnoreFields}
                addToExpectedFields={addToExpectedFields}
                addToHoneypotFields={addToHoneypotFields}
              />
            </TabsContent>
          )}
        </Tabs>

        <div className="flex justify-end gap-4 mt-6">
          <Button type="button" variant="outline" onClick={() => navigate('/endpoints')}>
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
