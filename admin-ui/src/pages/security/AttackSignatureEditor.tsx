import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { attackSignaturesApi } from '@/api/client'
import type {
  AttackSignature,
  AttackSignatures,
  DefenseType,
} from '@/api/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs'
import { useToast } from '@/components/ui/use-toast'
import { usePermissions } from '@/hooks/usePermissions'
import {
  ArrowLeft,
  Loader2,
  Save,
  Plus,
  Trash2,
  Info,
} from 'lucide-react'
import { SignatureStatsPanel } from '@/components/attack-signatures/SignatureStatsPanel'

// Defense type info for UI
const DEFENSE_INFO: Record<DefenseType, { label: string; description: string }> = {
  ip_allowlist: { label: 'IP Allowlist', description: 'Trusted IPs that bypass checks' },
  geoip: { label: 'GeoIP', description: 'Geographic blocking and scoring' },
  ip_reputation: { label: 'IP Reputation', description: 'Reputation-based IP blocking' },
  timing_token: { label: 'Timing Token', description: 'Timing validation settings' },
  behavioral: { label: 'Behavioral', description: 'Human behavior validation' },
  honeypot: { label: 'Honeypot', description: 'Hidden field traps' },
  keyword_filter: { label: 'Keyword Filter', description: 'Content keyword matching' },
  content_hash: { label: 'Content Hash', description: 'Known bad content hashes' },
  expected_fields: { label: 'Expected Fields', description: 'Form structure validation' },
  pattern_scan: { label: 'Pattern Scan', description: 'Regex content scanning' },
  disposable_email: { label: 'Disposable Email', description: 'Temp email detection' },
  field_anomalies: { label: 'Field Anomalies', description: 'Field value validation' },
  fingerprint: { label: 'Fingerprint', description: 'Browser/client fingerprinting' },
  header_consistency: { label: 'Header Consistency', description: 'HTTP header validation' },
  rate_limiter: { label: 'Rate Limiter', description: 'Request rate control' },
}

// Helper to create empty signature structure
function createEmptySignature(): AttackSignature {
  return {
    id: '',
    name: '',
    description: '',
    enabled: true,
    priority: 100,
    tags: [],
    signatures: {},
  }
}

// String array editor component
function StringArrayEditor({
  label,
  value,
  onChange,
  placeholder,
  disabled,
}: {
  label: string
  value: string[]
  onChange: (value: string[]) => void
  placeholder?: string
  disabled?: boolean
}) {
  const [newItem, setNewItem] = useState('')

  const handleAdd = () => {
    if (newItem.trim() && !value.includes(newItem.trim())) {
      onChange([...value, newItem.trim()])
      setNewItem('')
    }
  }

  const handleRemove = (index: number) => {
    onChange(value.filter((_, i) => i !== index))
  }

  return (
    <div className="space-y-2">
      <Label>{label}</Label>
      <div className="flex gap-2">
        <Input
          value={newItem}
          onChange={(e) => setNewItem(e.target.value)}
          placeholder={placeholder}
          disabled={disabled}
          onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), handleAdd())}
        />
        <Button
          type="button"
          variant="outline"
          size="icon"
          onClick={handleAdd}
          disabled={disabled || !newItem.trim()}
        >
          <Plus className="h-4 w-4" />
        </Button>
      </div>
      {value.length > 0 && (
        <div className="flex flex-wrap gap-2 mt-2">
          {value.map((item, i) => (
            <Badge key={i} variant="secondary" className="flex items-center gap-1">
              <span className="font-mono text-xs">{item}</span>
              {!disabled && (
                <button
                  type="button"
                  onClick={() => handleRemove(i)}
                  className="hover:text-destructive"
                >
                  <Trash2 className="h-3 w-3" />
                </button>
              )}
            </Badge>
          ))}
        </div>
      )}
    </div>
  )
}

// Scored item array editor (keyword + score)
function ScoredItemArrayEditor({
  label,
  value,
  onChange,
  itemLabel,
  placeholder,
  disabled,
}: {
  label: string
  value: { [key: string]: string | number }[]
  onChange: (value: { [key: string]: string | number }[]) => void
  itemLabel: string
  placeholder?: string
  disabled?: boolean
}) {
  const [newItem, setNewItem] = useState('')
  const [newScore, setNewScore] = useState(20)

  const handleAdd = () => {
    if (newItem.trim()) {
      onChange([...value, { [itemLabel]: newItem.trim(), score: newScore }])
      setNewItem('')
      setNewScore(20)
    }
  }

  const handleRemove = (index: number) => {
    onChange(value.filter((_, i) => i !== index))
  }

  return (
    <div className="space-y-2">
      <Label>{label}</Label>
      <div className="flex gap-2">
        <Input
          value={newItem}
          onChange={(e) => setNewItem(e.target.value)}
          placeholder={placeholder}
          disabled={disabled}
          className="flex-1"
        />
        <Input
          type="number"
          value={newScore}
          onChange={(e) => setNewScore(parseInt(e.target.value) || 0)}
          disabled={disabled}
          className="w-20"
          placeholder="Score"
        />
        <Button
          type="button"
          variant="outline"
          size="icon"
          onClick={handleAdd}
          disabled={disabled || !newItem.trim()}
        >
          <Plus className="h-4 w-4" />
        </Button>
      </div>
      {value.length > 0 && (
        <div className="flex flex-wrap gap-2 mt-2">
          {value.map((item, i) => (
            <Badge key={i} variant="secondary" className="flex items-center gap-1">
              <span className="font-mono text-xs">{item[itemLabel]}</span>
              <span className="text-muted-foreground">+{item.score}</span>
              {!disabled && (
                <button
                  type="button"
                  onClick={() => handleRemove(i)}
                  className="hover:text-destructive"
                >
                  <Trash2 className="h-3 w-3" />
                </button>
              )}
            </Badge>
          ))}
        </div>
      )}
    </div>
  )
}

export default function AttackSignatureEditor() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const { canEditAttackSignature } = usePermissions()

  const isNew = !id || id === 'new'
  const [signature, setSignature] = useState<AttackSignature>(createEmptySignature())
  const [tagsInput, setTagsInput] = useState('')
  const [hasChanges, setHasChanges] = useState(false)

  // Fetch existing signature
  const { data: signatureData, isLoading } = useQuery({
    queryKey: ['attack-signature', id],
    queryFn: () => attackSignaturesApi.get(id!),
    enabled: !isNew && !!id,
  })

  // Update state when data loads
  useEffect(() => {
    if (signatureData?.signature) {
      setSignature(signatureData.signature)
      setTagsInput(signatureData.signature.tags?.join(', ') || '')
    }
  }, [signatureData])

  // Save mutation
  const saveMutation = useMutation({
    mutationFn: async (data: AttackSignature) => {
      if (isNew) {
        return attackSignaturesApi.create(data)
      } else {
        return attackSignaturesApi.update(id!, data)
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attack-signatures'] })
      queryClient.invalidateQueries({ queryKey: ['attack-signature', id] })
      setHasChanges(false)
      toast({
        title: isNew ? 'Signature Created' : 'Signature Updated',
        description: 'Attack signature has been saved successfully.',
      })
      if (isNew) {
        navigate('/security/attack-signatures')
      }
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: error.message,
        variant: 'destructive',
      })
    },
  })

  const handleSave = () => {
    if (!signature.id || !signature.name) {
      toast({
        title: 'Validation Error',
        description: 'ID and Name are required.',
        variant: 'destructive',
      })
      return
    }

    const tagsArray = tagsInput
      .split(',')
      .map(t => t.trim())
      .filter(t => t.length > 0)

    saveMutation.mutate({
      ...signature,
      tags: tagsArray,
    })
  }

  const updateSignature = (updates: Partial<AttackSignature>) => {
    setSignature(prev => ({ ...prev, ...updates }))
    setHasChanges(true)
  }

  const updateSignatures = (defenseType: DefenseType, updates: Partial<AttackSignatures[typeof defenseType]>) => {
    setSignature(prev => ({
      ...prev,
      signatures: {
        ...prev.signatures,
        [defenseType]: {
          ...(prev.signatures[defenseType] || {}),
          ...updates,
        },
      },
    }))
    setHasChanges(true)
  }

  const isReadOnly = !canEditAttackSignature || signature.builtin

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate('/security/attack-signatures')}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h2 className="text-2xl font-bold tracking-tight">
              {isNew ? 'New Attack Signature' : signature.name}
            </h2>
            <p className="text-muted-foreground">
              {isNew ? 'Create a new attack signature' : `ID: ${signature.id}`}
            </p>
          </div>
          {signature.builtin && (
            <Badge variant="secondary">Built-in</Badge>
          )}
        </div>
        <Button
          onClick={handleSave}
          disabled={saveMutation.isPending || isReadOnly || !hasChanges}
        >
          {saveMutation.isPending ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <Save className="h-4 w-4 mr-2" />
          )}
          Save
        </Button>
      </div>

      {/* Basic Info */}
      <Card>
        <CardHeader>
          <CardTitle>Basic Information</CardTitle>
          <CardDescription>General signature settings and metadata</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="id">Signature ID</Label>
              <Input
                id="id"
                value={signature.id}
                onChange={(e) => updateSignature({ id: e.target.value })}
                disabled={!isNew || isReadOnly}
                placeholder="my-attack-signature"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                value={signature.name}
                onChange={(e) => updateSignature({ name: e.target.value })}
                disabled={isReadOnly}
                placeholder="My Attack Signature"
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="description">Description</Label>
            <Textarea
              id="description"
              value={signature.description || ''}
              onChange={(e) => updateSignature({ description: e.target.value })}
              disabled={isReadOnly}
              placeholder="Describe what this signature detects..."
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="tags">Tags</Label>
              <Input
                id="tags"
                value={tagsInput}
                onChange={(e) => { setTagsInput(e.target.value); setHasChanges(true) }}
                disabled={isReadOnly}
                placeholder="wordpress, login, brute-force"
              />
              <p className="text-sm text-muted-foreground">Comma-separated tags</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="priority">Priority</Label>
              <Input
                id="priority"
                type="number"
                value={signature.priority || 100}
                onChange={(e) => updateSignature({ priority: parseInt(e.target.value) || 100 })}
                disabled={isReadOnly}
              />
              <p className="text-sm text-muted-foreground">Lower = higher priority</p>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="flex items-center space-x-2">
              <Switch
                id="enabled"
                checked={signature.enabled}
                onCheckedChange={(enabled) => updateSignature({ enabled })}
                disabled={isReadOnly}
              />
              <Label htmlFor="enabled">Enabled</Label>
            </div>
            <div className="space-y-2">
              <Label htmlFor="expires_at">Expiration Date (optional)</Label>
              <Input
                id="expires_at"
                type="date"
                value={signature.expires_at ? signature.expires_at.split('T')[0] : ''}
                onChange={(e) => updateSignature({
                  expires_at: e.target.value ? new Date(e.target.value).toISOString() : undefined
                })}
                disabled={isReadOnly}
              />
              <p className="text-sm text-muted-foreground">Leave empty for no expiration</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Statistics Panel - only show for existing signatures */}
      {!isNew && id && (
        <SignatureStatsPanel
          signatureId={id}
          signatureName={signature.name}
        />
      )}

      {/* Signature Patterns */}
      <Card>
        <CardHeader>
          <CardTitle>Signature Patterns</CardTitle>
          <CardDescription>
            Configure patterns for each defense type. Only sections with patterns will be active.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="fingerprint">
            <TabsList className="flex-wrap h-auto gap-1">
              {(Object.keys(DEFENSE_INFO) as DefenseType[]).map((type) => (
                <TabsTrigger
                  key={type}
                  value={type}
                  className="text-xs"
                >
                  {DEFENSE_INFO[type].label}
                  {signature.signatures[type] && Object.keys(signature.signatures[type] || {}).length > 0 && (
                    <Badge variant="secondary" className="ml-1 h-4 w-4 p-0 text-[10px]">
                      *
                    </Badge>
                  )}
                </TabsTrigger>
              ))}
            </TabsList>

            {/* Fingerprint Tab */}
            <TabsContent value="fingerprint" className="space-y-4 mt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                <Info className="h-4 w-4" />
                <span>Configure user-agent patterns and fingerprint matching</span>
              </div>
              <StringArrayEditor
                label="Blocked User-Agents (immediate block)"
                value={signature.signatures.fingerprint?.blocked_user_agents || []}
                onChange={(val) => updateSignatures('fingerprint', { blocked_user_agents: val })}
                placeholder="WPScan, nikto, sqlmap..."
                disabled={isReadOnly}
              />
              <ScoredItemArrayEditor
                label="Flagged User-Agents (add score)"
                value={(signature.signatures.fingerprint?.flagged_user_agents || []) as { pattern: string; score: number }[]}
                onChange={(val) => updateSignatures('fingerprint', { flagged_user_agents: val as { pattern: string; score: number }[] })}
                itemLabel="pattern"
                placeholder="python-requests, curl/..."
                disabled={isReadOnly}
              />
            </TabsContent>

            {/* Keyword Filter Tab */}
            <TabsContent value="keyword_filter" className="space-y-4 mt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                <Info className="h-4 w-4" />
                <span>Configure blocked and flagged keywords/patterns</span>
              </div>
              <StringArrayEditor
                label="Blocked Keywords (immediate block)"
                value={signature.signatures.keyword_filter?.blocked_keywords || []}
                onChange={(val) => updateSignatures('keyword_filter', { blocked_keywords: val })}
                placeholder="<?php, eval(, system(..."
                disabled={isReadOnly}
              />
              <ScoredItemArrayEditor
                label="Flagged Keywords (add score)"
                value={(signature.signatures.keyword_filter?.flagged_keywords || []) as { keyword: string; score: number }[]}
                onChange={(val) => updateSignatures('keyword_filter', { flagged_keywords: val as { keyword: string; score: number }[] })}
                itemLabel="keyword"
                placeholder="wp-admin, ../..."
                disabled={isReadOnly}
              />
              <StringArrayEditor
                label="Blocked Patterns (regex)"
                value={signature.signatures.keyword_filter?.blocked_patterns || []}
                onChange={(val) => updateSignatures('keyword_filter', { blocked_patterns: val })}
                placeholder="[url=, <script>..."
                disabled={isReadOnly}
              />
            </TabsContent>

            {/* Rate Limiter Tab */}
            <TabsContent value="rate_limiter" className="space-y-4 mt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                <Info className="h-4 w-4" />
                <span>Configure rate limiting overrides</span>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Requests per Second</Label>
                  <Input
                    type="number"
                    value={signature.signatures.rate_limiter?.requests_per_second || ''}
                    onChange={(e) => updateSignatures('rate_limiter', {
                      requests_per_second: e.target.value ? parseInt(e.target.value) : undefined
                    })}
                    disabled={isReadOnly}
                    placeholder="Leave empty to use default"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Requests per Minute</Label>
                  <Input
                    type="number"
                    value={signature.signatures.rate_limiter?.requests_per_minute || ''}
                    onChange={(e) => updateSignatures('rate_limiter', {
                      requests_per_minute: e.target.value ? parseInt(e.target.value) : undefined
                    })}
                    disabled={isReadOnly}
                    placeholder="Leave empty to use default"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Requests per Hour</Label>
                  <Input
                    type="number"
                    value={signature.signatures.rate_limiter?.requests_per_hour || ''}
                    onChange={(e) => updateSignatures('rate_limiter', {
                      requests_per_hour: e.target.value ? parseInt(e.target.value) : undefined
                    })}
                    disabled={isReadOnly}
                    placeholder="Leave empty to use default"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Burst Limit</Label>
                  <Input
                    type="number"
                    value={signature.signatures.rate_limiter?.burst_limit || ''}
                    onChange={(e) => updateSignatures('rate_limiter', {
                      burst_limit: e.target.value ? parseInt(e.target.value) : undefined
                    })}
                    disabled={isReadOnly}
                    placeholder="Leave empty to use default"
                  />
                </div>
              </div>
            </TabsContent>

            {/* Behavioral Tab */}
            <TabsContent value="behavioral" className="space-y-4 mt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                <Info className="h-4 w-4" />
                <span>Configure behavioral detection requirements</span>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Min Time on Page (ms)</Label>
                  <Input
                    type="number"
                    value={signature.signatures.behavioral?.min_time_on_page_ms || ''}
                    onChange={(e) => updateSignatures('behavioral', {
                      min_time_on_page_ms: e.target.value ? parseInt(e.target.value) : undefined
                    })}
                    disabled={isReadOnly}
                    placeholder="e.g., 3000"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Min Interaction Score</Label>
                  <Input
                    type="number"
                    value={signature.signatures.behavioral?.min_interaction_score || ''}
                    onChange={(e) => updateSignatures('behavioral', {
                      min_interaction_score: e.target.value ? parseInt(e.target.value) : undefined
                    })}
                    disabled={isReadOnly}
                    placeholder="e.g., 50"
                  />
                </div>
              </div>
              <div className="flex flex-wrap gap-4">
                <div className="flex items-center space-x-2">
                  <Switch
                    id="require_mouse"
                    checked={signature.signatures.behavioral?.require_mouse_movement || false}
                    onCheckedChange={(val) => updateSignatures('behavioral', { require_mouse_movement: val })}
                    disabled={isReadOnly}
                  />
                  <Label htmlFor="require_mouse">Require Mouse Movement</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Switch
                    id="require_keyboard"
                    checked={signature.signatures.behavioral?.require_keyboard_input || false}
                    onCheckedChange={(val) => updateSignatures('behavioral', { require_keyboard_input: val })}
                    disabled={isReadOnly}
                  />
                  <Label htmlFor="require_keyboard">Require Keyboard Input</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Switch
                    id="require_scroll"
                    checked={signature.signatures.behavioral?.require_scroll || false}
                    onCheckedChange={(val) => updateSignatures('behavioral', { require_scroll: val })}
                    disabled={isReadOnly}
                  />
                  <Label htmlFor="require_scroll">Require Scroll</Label>
                </div>
              </div>
            </TabsContent>

            {/* Honeypot Tab */}
            <TabsContent value="honeypot" className="space-y-4 mt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                <Info className="h-4 w-4" />
                <span>Configure honeypot field names (hidden fields that bots fill)</span>
              </div>
              <StringArrayEditor
                label="Honeypot Field Names"
                value={signature.signatures.honeypot?.field_names || []}
                onChange={(val) => updateSignatures('honeypot', { field_names: val })}
                placeholder="fax, website_url, email2..."
                disabled={isReadOnly}
              />
              <div className="space-y-2">
                <Label>Score if Filled (instead of blocking)</Label>
                <Input
                  type="number"
                  value={signature.signatures.honeypot?.score_if_filled || ''}
                  onChange={(e) => updateSignatures('honeypot', {
                    score_if_filled: e.target.value ? parseInt(e.target.value) : undefined
                  })}
                  disabled={isReadOnly}
                  placeholder="Leave empty to block"
                />
              </div>
            </TabsContent>

            {/* Expected Fields Tab */}
            <TabsContent value="expected_fields" className="space-y-4 mt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                <Info className="h-4 w-4" />
                <span>Configure expected form field structure</span>
              </div>
              <StringArrayEditor
                label="Required Fields"
                value={signature.signatures.expected_fields?.required_fields || []}
                onChange={(val) => updateSignatures('expected_fields', { required_fields: val })}
                placeholder="log, pwd, email..."
                disabled={isReadOnly}
              />
              <StringArrayEditor
                label="Forbidden Fields"
                value={signature.signatures.expected_fields?.forbidden_fields || []}
                onChange={(val) => updateSignatures('expected_fields', { forbidden_fields: val })}
                placeholder="cmd, exec, shell..."
                disabled={isReadOnly}
              />
              <div className="space-y-2">
                <Label>Max Extra Fields</Label>
                <Input
                  type="number"
                  value={signature.signatures.expected_fields?.max_extra_fields || ''}
                  onChange={(e) => updateSignatures('expected_fields', {
                    max_extra_fields: e.target.value ? parseInt(e.target.value) : undefined
                  })}
                  disabled={isReadOnly}
                  placeholder="e.g., 5"
                />
              </div>
            </TabsContent>

            {/* Disposable Email Tab */}
            <TabsContent value="disposable_email" className="space-y-4 mt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                <Info className="h-4 w-4" />
                <span>Configure disposable email domain blocking</span>
              </div>
              <StringArrayEditor
                label="Blocked Domains"
                value={signature.signatures.disposable_email?.blocked_domains || []}
                onChange={(val) => updateSignatures('disposable_email', { blocked_domains: val })}
                placeholder="tempmail.com, guerrillamail.com..."
                disabled={isReadOnly}
              />
              <StringArrayEditor
                label="Allowed Domains (override)"
                value={signature.signatures.disposable_email?.allowed_domains || []}
                onChange={(val) => updateSignatures('disposable_email', { allowed_domains: val })}
                placeholder="gmail.com, outlook.com..."
                disabled={isReadOnly}
              />
              <StringArrayEditor
                label="Blocked Patterns (regex)"
                value={signature.signatures.disposable_email?.blocked_patterns || []}
                onChange={(val) => updateSignatures('disposable_email', { blocked_patterns: val })}
                placeholder="+.*@..."
                disabled={isReadOnly}
              />
            </TabsContent>

            {/* Header Consistency Tab */}
            <TabsContent value="header_consistency" className="space-y-4 mt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                <Info className="h-4 w-4" />
                <span>Configure HTTP header validation rules</span>
              </div>
              <StringArrayEditor
                label="Required Headers"
                value={signature.signatures.header_consistency?.required_headers || []}
                onChange={(val) => updateSignatures('header_consistency', { required_headers: val })}
                placeholder="User-Agent, Accept..."
                disabled={isReadOnly}
              />
              <StringArrayEditor
                label="Forbidden Headers"
                value={signature.signatures.header_consistency?.forbidden_headers || []}
                onChange={(val) => updateSignatures('header_consistency', { forbidden_headers: val })}
                placeholder="X-Scanner, X-Attack..."
                disabled={isReadOnly}
              />
            </TabsContent>

            {/* Pattern Scan Tab */}
            <TabsContent value="pattern_scan" className="space-y-4 mt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                <Info className="h-4 w-4" />
                <span>Configure regex pattern scanning</span>
              </div>
              <StringArrayEditor
                label="Blocked Patterns (regex)"
                value={signature.signatures.pattern_scan?.blocked_patterns || []}
                onChange={(val) => updateSignatures('pattern_scan', { blocked_patterns: val })}
                placeholder="<script>.*</script>..."
                disabled={isReadOnly}
              />
              <ScoredItemArrayEditor
                label="Flagged Patterns (add score)"
                value={(signature.signatures.pattern_scan?.flagged_patterns || []) as { pattern: string; score: number }[]}
                onChange={(val) => updateSignatures('pattern_scan', { flagged_patterns: val as { pattern: string; score: number }[] })}
                itemLabel="pattern"
                placeholder="https?://bit.ly/..."
                disabled={isReadOnly}
              />
              <StringArrayEditor
                label="Fields to Scan (empty = all)"
                value={signature.signatures.pattern_scan?.scan_fields || []}
                onChange={(val) => updateSignatures('pattern_scan', { scan_fields: val })}
                placeholder="message, comment..."
                disabled={isReadOnly}
              />
            </TabsContent>

            {/* IP Allowlist Tab */}
            <TabsContent value="ip_allowlist" className="space-y-4 mt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                <Info className="h-4 w-4" />
                <span>Configure trusted IPs that bypass checks</span>
              </div>
              <StringArrayEditor
                label="Allowed CIDRs"
                value={signature.signatures.ip_allowlist?.allowed_cidrs || []}
                onChange={(val) => updateSignatures('ip_allowlist', { allowed_cidrs: val })}
                placeholder="192.168.1.0/24, 10.0.0.0/8..."
                disabled={isReadOnly}
              />
              <StringArrayEditor
                label="Allowed IPs"
                value={signature.signatures.ip_allowlist?.allowed_ips || []}
                onChange={(val) => updateSignatures('ip_allowlist', { allowed_ips: val })}
                placeholder="192.168.1.100..."
                disabled={isReadOnly}
              />
            </TabsContent>

            {/* GeoIP Tab */}
            <TabsContent value="geoip" className="space-y-4 mt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                <Info className="h-4 w-4" />
                <span>Configure geographic blocking and scoring</span>
              </div>
              <StringArrayEditor
                label="Blocked Countries (ISO codes)"
                value={signature.signatures.geoip?.blocked_countries || []}
                onChange={(val) => updateSignatures('geoip', { blocked_countries: val })}
                placeholder="RU, CN, KP..."
                disabled={isReadOnly}
              />
              <ScoredItemArrayEditor
                label="Flagged Countries"
                value={(signature.signatures.geoip?.flagged_countries || []) as { country: string; score: number }[]}
                onChange={(val) => updateSignatures('geoip', { flagged_countries: val as { country: string; score: number }[] })}
                itemLabel="country"
                placeholder="UA, BY..."
                disabled={isReadOnly}
              />
            </TabsContent>

            {/* IP Reputation Tab */}
            <TabsContent value="ip_reputation" className="space-y-4 mt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                <Info className="h-4 w-4" />
                <span>Configure reputation-based IP blocking</span>
              </div>
              <StringArrayEditor
                label="Blocked CIDRs"
                value={signature.signatures.ip_reputation?.blocked_cidrs || []}
                onChange={(val) => updateSignatures('ip_reputation', { blocked_cidrs: val })}
                placeholder="1.2.3.0/24..."
                disabled={isReadOnly}
              />
              <StringArrayEditor
                label="Blocked ASNs"
                value={signature.signatures.ip_reputation?.blocked_asns || []}
                onChange={(val) => updateSignatures('ip_reputation', { blocked_asns: val })}
                placeholder="AS12345..."
                disabled={isReadOnly}
              />
              <div className="space-y-2">
                <Label>Min Reputation Score</Label>
                <Input
                  type="number"
                  value={signature.signatures.ip_reputation?.min_reputation_score || ''}
                  onChange={(e) => updateSignatures('ip_reputation', {
                    min_reputation_score: e.target.value ? parseInt(e.target.value) : undefined
                  })}
                  disabled={isReadOnly}
                  placeholder="e.g., 50"
                />
              </div>
            </TabsContent>

            {/* Content Hash Tab */}
            <TabsContent value="content_hash" className="space-y-4 mt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                <Info className="h-4 w-4" />
                <span>Configure known bad content hash detection</span>
              </div>
              <StringArrayEditor
                label="Blocked Hashes (SHA256)"
                value={signature.signatures.content_hash?.blocked_hashes || []}
                onChange={(val) => updateSignatures('content_hash', { blocked_hashes: val })}
                placeholder="abc123..."
                disabled={isReadOnly}
              />
              <StringArrayEditor
                label="Blocked Fuzzy Hashes"
                value={signature.signatures.content_hash?.blocked_fuzzy_hashes || []}
                onChange={(val) => updateSignatures('content_hash', { blocked_fuzzy_hashes: val })}
                placeholder="ssdeep hash..."
                disabled={isReadOnly}
              />
            </TabsContent>

            {/* Timing Token Tab */}
            <TabsContent value="timing_token" className="space-y-4 mt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                <Info className="h-4 w-4" />
                <span>Configure timing validation settings</span>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Min Time (ms)</Label>
                  <Input
                    type="number"
                    value={signature.signatures.timing_token?.min_time_ms || ''}
                    onChange={(e) => updateSignatures('timing_token', {
                      min_time_ms: e.target.value ? parseInt(e.target.value) : undefined
                    })}
                    disabled={isReadOnly}
                    placeholder="e.g., 2000"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Max Time (ms)</Label>
                  <Input
                    type="number"
                    value={signature.signatures.timing_token?.max_time_ms || ''}
                    onChange={(e) => updateSignatures('timing_token', {
                      max_time_ms: e.target.value ? parseInt(e.target.value) : undefined
                    })}
                    disabled={isReadOnly}
                    placeholder="e.g., 600000"
                  />
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <Switch
                  id="require_token"
                  checked={signature.signatures.timing_token?.require_token || false}
                  onCheckedChange={(val) => updateSignatures('timing_token', { require_token: val })}
                  disabled={isReadOnly}
                />
                <Label htmlFor="require_token">Require Timing Token</Label>
              </div>
            </TabsContent>

            {/* Field Anomalies Tab */}
            <TabsContent value="field_anomalies" className="space-y-4 mt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                <Info className="h-4 w-4" />
                <span>Configure field value validation rules</span>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Max Field Length</Label>
                  <Input
                    type="number"
                    value={signature.signatures.field_anomalies?.max_field_length || ''}
                    onChange={(e) => updateSignatures('field_anomalies', {
                      max_field_length: e.target.value ? parseInt(e.target.value) : undefined
                    })}
                    disabled={isReadOnly}
                    placeholder="e.g., 1000"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Max Total Size</Label>
                  <Input
                    type="number"
                    value={signature.signatures.field_anomalies?.max_total_size || ''}
                    onChange={(e) => updateSignatures('field_anomalies', {
                      max_total_size: e.target.value ? parseInt(e.target.value) : undefined
                    })}
                    disabled={isReadOnly}
                    placeholder="e.g., 10000"
                  />
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Stats Card (if viewing existing) */}
      {!isNew && signature.stats && (
        <Card>
          <CardHeader>
            <CardTitle>Statistics</CardTitle>
            <CardDescription>Match statistics for this signature</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4">
              <div>
                <div className="text-2xl font-bold">{signature.stats.total_matches?.toLocaleString() || 0}</div>
                <div className="text-sm text-muted-foreground">Total Matches</div>
              </div>
              <div>
                <div className="text-2xl font-bold">
                  {signature.stats.last_match_at
                    ? new Date(signature.stats.last_match_at).toLocaleDateString()
                    : 'Never'}
                </div>
                <div className="text-sm text-muted-foreground">Last Match</div>
              </div>
              <div>
                <div className="text-2xl font-bold">
                  {Object.keys(signature.stats.matches_by_type || {}).length}
                </div>
                <div className="text-sm text-muted-foreground">Active Defense Types</div>
              </div>
            </div>
            {signature.stats.matches_by_type && Object.keys(signature.stats.matches_by_type).length > 0 && (
              <div className="mt-4">
                <Label className="mb-2 block">Matches by Type</Label>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(signature.stats.matches_by_type).map(([type, count]) => (
                    <Badge key={type} variant="outline">
                      {type}: {count.toLocaleString()}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
