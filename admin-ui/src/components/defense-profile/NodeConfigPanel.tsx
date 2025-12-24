import { useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import { Button } from '@/components/ui/button'
import { Trash2, Plus } from 'lucide-react'
import type { Node } from '@xyflow/react'
import type { DefenseType, OperatorType, ActionType, ThresholdRange } from '@/api/types'
import { DEFENSE_METADATA, OPERATOR_METADATA, ACTION_METADATA } from './nodes'

interface NodeConfigPanelProps {
  selectedNode: Node | null
  onNodeUpdate: (nodeId: string, updates: Partial<Node['data']>) => void
  onNodeDelete: (nodeId: string) => void
  className?: string
}

export function NodeConfigPanel({
  selectedNode,
  onNodeUpdate,
  onNodeDelete,
  className,
}: NodeConfigPanelProps) {
  const handleUpdate = useCallback(
    (key: string, value: unknown) => {
      if (!selectedNode) return
      onNodeUpdate(selectedNode.id, { [key]: value })
    },
    [selectedNode, onNodeUpdate]
  )

  const handleConfigUpdate = useCallback(
    (key: string, value: unknown) => {
      if (!selectedNode) return
      const newConfig = { ...(selectedNode.data.config || {}), [key]: value }
      onNodeUpdate(selectedNode.id, { config: newConfig })
    },
    [selectedNode, onNodeUpdate]
  )

  if (!selectedNode) {
    return (
      <Card className={className}>
        <CardHeader className="py-3">
          <CardTitle className="text-sm">Node Configuration</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Select a node to configure its properties
          </p>
        </CardContent>
      </Card>
    )
  }

  const nodeType = selectedNode.type
  const data = selectedNode.data

  return (
    <Card className={className}>
      <CardHeader className="py-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm">Node Configuration</CardTitle>
          {nodeType !== 'start' && (
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-destructive"
              onClick={() => onNodeDelete(selectedNode.id)}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Node ID (read-only) */}
        <div className="space-y-2">
          <Label className="text-xs">Node ID</Label>
          <Input value={selectedNode.id} disabled className="text-xs font-mono" />
        </div>

        {/* Label */}
        {nodeType !== 'start' && (
          <div className="space-y-2">
            <Label className="text-xs">Label</Label>
            <Input
              value={(data.label as string) || ''}
              onChange={(e) => handleUpdate('label', e.target.value)}
              placeholder="Custom label..."
              className="text-sm"
            />
          </div>
        )}

        <Separator />

        {/* Type-specific configuration */}
        {nodeType === 'start' && (
          <div className="text-sm text-muted-foreground">
            <p>This is the entry point for all traffic.</p>
            <p className="mt-2">Connect to the first defense check or action.</p>
          </div>
        )}

        {nodeType === 'defense' && (
          <DefenseConfig
            defense={data.defense as DefenseType}
            config={(data.config as Record<string, unknown>) || {}}
            onDefenseChange={(defense) => handleUpdate('defense', defense)}
            onConfigChange={handleConfigUpdate}
          />
        )}

        {nodeType === 'operator' && (
          <OperatorConfig
            operator={data.operator as OperatorType}
            config={(data.config as Record<string, unknown>) || {}}
            onOperatorChange={(operator) => handleUpdate('operator', operator)}
            onConfigChange={handleConfigUpdate}
          />
        )}

        {nodeType === 'action' && (
          <ActionConfig
            action={data.action as ActionType}
            config={(data.config as Record<string, unknown>) || {}}
            onActionChange={(action) => handleUpdate('action', action)}
            onConfigChange={handleConfigUpdate}
          />
        )}
      </CardContent>
    </Card>
  )
}

// Defense configuration
interface DefenseConfigProps {
  defense: DefenseType
  config: Record<string, unknown>
  onDefenseChange: (defense: DefenseType) => void
  onConfigChange: (key: string, value: unknown) => void
}

function DefenseConfig({ defense, config, onDefenseChange, onConfigChange }: DefenseConfigProps) {
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label className="text-xs">Defense Type</Label>
        <Select value={defense} onValueChange={(v) => onDefenseChange(v as DefenseType)}>
          <SelectTrigger className="text-sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {Object.entries(DEFENSE_METADATA).map(([key, meta]) => (
              <SelectItem key={key} value={key}>
                {meta.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Output mode configuration */}
      <div className="space-y-2">
        <Label className="text-xs">Output Mode</Label>
        <Select
          value={(config.output_mode as string) || 'binary'}
          onValueChange={(v) => onConfigChange('output_mode', v)}
        >
          <SelectTrigger className="text-sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="binary">Binary (allow/block)</SelectItem>
            <SelectItem value="score">Score (0-100)</SelectItem>
            <SelectItem value="both">Both (score + block)</SelectItem>
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">
          How this defense should contribute to the flow
        </p>
      </div>

      {/* Score weight for score mode */}
      {((config.output_mode as string) === 'score' || (config.output_mode as string) === 'both') && (
        <div className="space-y-2">
          <Label className="text-xs">Score Weight</Label>
          <Input
            type="number"
            min="0"
            max="100"
            value={(config.score_weight as number) || 1}
            onChange={(e) => onConfigChange('score_weight', parseFloat(e.target.value) || 1)}
            className="text-sm"
          />
          <p className="text-xs text-muted-foreground">Multiplier for the defense score</p>
        </div>
      )}

      <Separator />

      {/* Defense-specific configurations */}
      <DefenseSpecificConfig defense={defense} config={config} onConfigChange={onConfigChange} />
    </div>
  )
}

// Defense-specific configuration components
interface DefenseSpecificConfigProps {
  defense: DefenseType
  config: Record<string, unknown>
  onConfigChange: (key: string, value: unknown) => void
}

function DefenseSpecificConfig({ defense, config, onConfigChange }: DefenseSpecificConfigProps) {
  switch (defense) {
    case 'timing_token':
      return (
        <div className="space-y-3">
          <Label className="text-xs font-medium">Timing Token Settings</Label>
          <div className="space-y-2">
            <Label className="text-xs">Minimum Time (ms)</Label>
            <Input
              type="number"
              min="0"
              value={(config.min_time_ms as number) || 1000}
              onChange={(e) => onConfigChange('min_time_ms', parseInt(e.target.value) || 1000)}
              className="text-sm"
            />
            <p className="text-xs text-muted-foreground">Submissions faster than this are suspicious</p>
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Maximum Time (ms)</Label>
            <Input
              type="number"
              min="0"
              value={(config.max_time_ms as number) || 3600000}
              onChange={(e) => onConfigChange('max_time_ms', parseInt(e.target.value) || 3600000)}
              className="text-sm"
            />
            <p className="text-xs text-muted-foreground">Submissions slower than this may be stale</p>
          </div>
        </div>
      )

    case 'rate_limiter':
      return (
        <div className="space-y-3">
          <Label className="text-xs font-medium">Rate Limiter Settings</Label>
          <div className="space-y-2">
            <Label className="text-xs">Requests per Window</Label>
            <Input
              type="number"
              min="1"
              value={(config.max_requests as number) || 10}
              onChange={(e) => onConfigChange('max_requests', parseInt(e.target.value) || 10)}
              className="text-sm"
            />
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Window (seconds)</Label>
            <Input
              type="number"
              min="1"
              value={(config.window_seconds as number) || 60}
              onChange={(e) => onConfigChange('window_seconds', parseInt(e.target.value) || 60)}
              className="text-sm"
            />
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Rate Limit Key</Label>
            <Select
              value={(config.key_type as string) || 'ip'}
              onValueChange={(v) => onConfigChange('key_type', v)}
            >
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ip">Client IP</SelectItem>
                <SelectItem value="ip_path">IP + Path</SelectItem>
                <SelectItem value="ip_endpoint">IP + Endpoint</SelectItem>
                <SelectItem value="session">Session</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      )

    case 'keyword_filter':
      return (
        <div className="space-y-3">
          <Label className="text-xs font-medium">Keyword Filter Settings</Label>
          <div className="space-y-2">
            <Label className="text-xs">Match Mode</Label>
            <Select
              value={(config.match_mode as string) || 'any'}
              onValueChange={(v) => onConfigChange('match_mode', v)}
            >
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="any">Block if ANY keyword matches</SelectItem>
                <SelectItem value="all">Block if ALL keywords match</SelectItem>
                <SelectItem value="count">Score based on match count</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Block Threshold (for count mode)</Label>
            <Input
              type="number"
              min="1"
              value={(config.block_threshold as number) || 3}
              onChange={(e) => onConfigChange('block_threshold', parseInt(e.target.value) || 3)}
              className="text-sm"
            />
          </div>
          <p className="text-xs text-muted-foreground">
            Keywords are managed in Settings → Keywords
          </p>
        </div>
      )

    case 'geoip':
      return (
        <div className="space-y-3">
          <Label className="text-xs font-medium">GeoIP Settings</Label>
          <div className="space-y-2">
            <Label className="text-xs">Mode</Label>
            <Select
              value={(config.mode as string) || 'blocklist'}
              onValueChange={(v) => onConfigChange('mode', v)}
            >
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="blocklist">Block listed countries</SelectItem>
                <SelectItem value="allowlist">Allow only listed countries</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <p className="text-xs text-muted-foreground">
            Country lists are managed in Settings → GeoIP
          </p>
        </div>
      )

    case 'ip_reputation':
      return (
        <div className="space-y-3">
          <Label className="text-xs font-medium">IP Reputation Settings</Label>
          <div className="space-y-2">
            <Label className="text-xs">Block Threshold</Label>
            <Input
              type="number"
              min="0"
              max="100"
              value={(config.block_threshold as number) || 80}
              onChange={(e) => onConfigChange('block_threshold', parseInt(e.target.value) || 80)}
              className="text-sm"
            />
            <p className="text-xs text-muted-foreground">IPs with reputation score above this are blocked (0-100)</p>
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Score Contribution</Label>
            <Input
              type="number"
              min="0"
              max="100"
              value={(config.score_contribution as number) || 50}
              onChange={(e) => onConfigChange('score_contribution', parseInt(e.target.value) || 50)}
              className="text-sm"
            />
            <p className="text-xs text-muted-foreground">Max score to add when IP has bad reputation</p>
          </div>
        </div>
      )

    case 'behavioral':
      return (
        <div className="space-y-3">
          <Label className="text-xs font-medium">Behavioral Analysis Settings</Label>
          <div className="space-y-2">
            <Label className="text-xs">Mouse Movement Required</Label>
            <Select
              value={String(config.require_mouse_movement ?? true)}
              onValueChange={(v) => onConfigChange('require_mouse_movement', v === 'true')}
            >
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="true">Yes</SelectItem>
                <SelectItem value="false">No</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Keystroke Analysis</Label>
            <Select
              value={String(config.analyze_keystrokes ?? true)}
              onValueChange={(v) => onConfigChange('analyze_keystrokes', v === 'true')}
            >
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="true">Enabled</SelectItem>
                <SelectItem value="false">Disabled</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Min Interaction Score</Label>
            <Input
              type="number"
              min="0"
              max="100"
              value={(config.min_interaction_score as number) || 30}
              onChange={(e) => onConfigChange('min_interaction_score', parseInt(e.target.value) || 30)}
              className="text-sm"
            />
            <p className="text-xs text-muted-foreground">Minimum behavioral score to pass</p>
          </div>
        </div>
      )

    case 'honeypot':
      return (
        <div className="space-y-3">
          <Label className="text-xs font-medium">Honeypot Settings</Label>
          <div className="space-y-2">
            <Label className="text-xs">Field Names (comma-separated)</Label>
            <Input
              value={(config.field_names as string) || 'hp_field,website_url,fax_number'}
              onChange={(e) => onConfigChange('field_names', e.target.value)}
              className="text-sm"
              placeholder="hp_field,website_url"
            />
            <p className="text-xs text-muted-foreground">Hidden fields that bots fill in</p>
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Action on Fill</Label>
            <Select
              value={(config.action_on_fill as string) || 'block'}
              onValueChange={(v) => onConfigChange('action_on_fill', v)}
            >
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="block">Block immediately</SelectItem>
                <SelectItem value="score">Add to score only</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      )

    case 'expected_fields':
      return (
        <div className="space-y-3">
          <Label className="text-xs font-medium">Expected Fields Settings</Label>
          <div className="space-y-2">
            <Label className="text-xs">Required Fields (comma-separated)</Label>
            <Input
              value={(config.required_fields as string) || ''}
              onChange={(e) => onConfigChange('required_fields', e.target.value)}
              className="text-sm"
              placeholder="name,email,message"
            />
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Forbidden Fields (comma-separated)</Label>
            <Input
              value={(config.forbidden_fields as string) || ''}
              onChange={(e) => onConfigChange('forbidden_fields', e.target.value)}
              className="text-sm"
              placeholder="admin,password"
            />
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Strict Mode</Label>
            <Select
              value={String(config.strict_mode ?? false)}
              onValueChange={(v) => onConfigChange('strict_mode', v === 'true')}
            >
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="false">Allow extra fields</SelectItem>
                <SelectItem value="true">Block extra fields</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      )

    case 'disposable_email':
      return (
        <div className="space-y-3">
          <Label className="text-xs font-medium">Disposable Email Settings</Label>
          <div className="space-y-2">
            <Label className="text-xs">Email Field Name</Label>
            <Input
              value={(config.email_field as string) || 'email'}
              onChange={(e) => onConfigChange('email_field', e.target.value)}
              className="text-sm"
            />
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Action</Label>
            <Select
              value={(config.action as string) || 'block'}
              onValueChange={(v) => onConfigChange('action', v)}
            >
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="block">Block</SelectItem>
                <SelectItem value="score">Add to score</SelectItem>
                <SelectItem value="flag">Flag only</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      )

    case 'fingerprint':
      return (
        <div className="space-y-3">
          <Label className="text-xs font-medium">Fingerprint Settings</Label>
          <div className="space-y-2">
            <Label className="text-xs">Profile to Match</Label>
            <Select
              value={(config.profile as string) || 'browser'}
              onValueChange={(v) => onConfigChange('profile', v)}
            >
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="browser">Browser</SelectItem>
                <SelectItem value="mobile">Mobile</SelectItem>
                <SelectItem value="api-client">API Client</SelectItem>
                <SelectItem value="curl">cURL</SelectItem>
                <SelectItem value="bot">Known Bot</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Mismatch Action</Label>
            <Select
              value={(config.mismatch_action as string) || 'score'}
              onValueChange={(v) => onConfigChange('mismatch_action', v)}
            >
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="block">Block</SelectItem>
                <SelectItem value="score">Add to score</SelectItem>
                <SelectItem value="flag">Flag only</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      )

    case 'header_consistency':
      return (
        <div className="space-y-3">
          <Label className="text-xs font-medium">Header Consistency Settings</Label>
          <div className="space-y-2">
            <Label className="text-xs">Check User-Agent Consistency</Label>
            <Select
              value={String(config.check_user_agent ?? true)}
              onValueChange={(v) => onConfigChange('check_user_agent', v === 'true')}
            >
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="true">Yes</SelectItem>
                <SelectItem value="false">No</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Check Accept Headers</Label>
            <Select
              value={String(config.check_accept ?? true)}
              onValueChange={(v) => onConfigChange('check_accept', v === 'true')}
            >
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="true">Yes</SelectItem>
                <SelectItem value="false">No</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      )

    case 'content_hash':
      return (
        <div className="space-y-3">
          <Label className="text-xs font-medium">Content Hash Settings</Label>
          <p className="text-xs text-muted-foreground">
            Compares form content against known spam/malicious hashes.
            Hash lists are managed in Settings → Content Hashes.
          </p>
          <div className="space-y-2">
            <Label className="text-xs">Fields to Hash</Label>
            <Input
              value={(config.hash_fields as string) || 'message,content,body'}
              onChange={(e) => onConfigChange('hash_fields', e.target.value)}
              className="text-sm"
              placeholder="message,content"
            />
          </div>
        </div>
      )

    case 'pattern_scan':
      return (
        <div className="space-y-3">
          <Label className="text-xs font-medium">Pattern Scan Settings</Label>
          <p className="text-xs text-muted-foreground">
            Scans form content for spam patterns (URLs, phone numbers, etc.)
          </p>
          <div className="space-y-2">
            <Label className="text-xs">URL Threshold</Label>
            <Input
              type="number"
              min="0"
              value={(config.url_threshold as number) || 3}
              onChange={(e) => onConfigChange('url_threshold', parseInt(e.target.value) || 3)}
              className="text-sm"
            />
            <p className="text-xs text-muted-foreground">Flag if more than this many URLs</p>
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Check for Phone Numbers</Label>
            <Select
              value={String(config.check_phones ?? true)}
              onValueChange={(v) => onConfigChange('check_phones', v === 'true')}
            >
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="true">Yes</SelectItem>
                <SelectItem value="false">No</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      )

    case 'field_anomalies':
      return (
        <div className="space-y-3">
          <Label className="text-xs font-medium">Field Anomaly Settings</Label>
          <div className="space-y-2">
            <Label className="text-xs">Max Field Length</Label>
            <Input
              type="number"
              min="0"
              value={(config.max_field_length as number) || 10000}
              onChange={(e) => onConfigChange('max_field_length', parseInt(e.target.value) || 10000)}
              className="text-sm"
            />
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Check for Binary Content</Label>
            <Select
              value={String(config.check_binary ?? true)}
              onValueChange={(v) => onConfigChange('check_binary', v === 'true')}
            >
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="true">Yes</SelectItem>
                <SelectItem value="false">No</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      )

    case 'ip_allowlist':
      return (
        <div className="space-y-3">
          <Label className="text-xs font-medium">IP Allowlist Settings</Label>
          <p className="text-xs text-muted-foreground">
            IPs/CIDRs on the allowlist bypass all other checks.
            Manage the list in Settings → IP Allowlist.
          </p>
          <div className="space-y-2">
            <Label className="text-xs">Action for Allowed IPs</Label>
            <Select
              value={(config.allow_action as string) || 'skip_all'}
              onValueChange={(v) => onConfigChange('allow_action', v)}
            >
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="skip_all">Skip all checks</SelectItem>
                <SelectItem value="skip_this">Skip this check only</SelectItem>
                <SelectItem value="reduce_score">Reduce score by 50%</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      )

    default:
      return (
        <p className="text-xs text-muted-foreground">
          No additional configuration for this defense type.
        </p>
      )
  }
}

// Operator configuration
interface OperatorConfigProps {
  operator: OperatorType
  config: Record<string, unknown>
  onOperatorChange: (operator: OperatorType) => void
  onConfigChange: (key: string, value: unknown) => void
}

function OperatorConfig({ operator, config, onOperatorChange, onConfigChange }: OperatorConfigProps) {
  const defaultRanges: ThresholdRange[] = [
    { min: 0, max: 30, output: 'low' },
    { min: 30, max: 60, output: 'medium' },
    { min: 60, max: 100, output: 'high' },
    { min: 100, max: null, output: 'critical' },
  ]
  const ranges = (config.ranges as ThresholdRange[]) || defaultRanges

  const updateRange = (index: number, field: keyof ThresholdRange, value: unknown) => {
    const newRanges = [...ranges]
    newRanges[index] = { ...newRanges[index], [field]: value }
    onConfigChange('ranges', newRanges)
  }

  const addRange = () => {
    if (ranges.length >= 10) return
    const lastRange = ranges[ranges.length - 1]
    const newMin = lastRange.max ?? (lastRange.min + 20)
    // Generate a unique output name
    const existingOutputs = new Set(ranges.map(r => r.output))
    const outputNames = ['very_low', 'low', 'medium', 'high', 'very_high', 'critical', 'extreme']
    let newOutput = `range_${ranges.length + 1}`
    for (const name of outputNames) {
      if (!existingOutputs.has(name)) {
        newOutput = name
        break
      }
    }
    const newRanges = [
      ...ranges.slice(0, -1),
      { ...lastRange, max: newMin },
      { min: newMin, max: null, output: newOutput },
    ]
    onConfigChange('ranges', newRanges)
  }

  const removeRange = (index: number) => {
    if (ranges.length <= 2) return
    const newRanges = ranges.filter((_, i) => i !== index)
    // If we removed the last range, set the new last range's max to null
    if (index === ranges.length - 1 && newRanges.length > 0) {
      newRanges[newRanges.length - 1] = { ...newRanges[newRanges.length - 1], max: null }
    }
    onConfigChange('ranges', newRanges)
  }

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label className="text-xs">Operator Type</Label>
        <Select value={operator} onValueChange={(v) => onOperatorChange(v as OperatorType)}>
          <SelectTrigger className="text-sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {Object.entries(OPERATOR_METADATA).map(([key, meta]) => (
              <SelectItem key={key} value={key}>
                {meta.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Threshold branch specific configuration */}
      {operator === 'threshold_branch' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Label className="text-xs">Score Ranges ({ranges.length})</Label>
            <Button
              variant="ghost"
              size="sm"
              onClick={addRange}
              disabled={ranges.length >= 10}
              className="h-6 text-xs"
            >
              <Plus className="h-3 w-3 mr-1" />
              Add
            </Button>
          </div>
          <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
            {ranges.map((range, index) => (
              <div key={index} className="flex items-center gap-1 text-xs bg-muted/30 rounded p-1.5">
                <Input
                  type="number"
                  value={range.min}
                  onChange={(e) => updateRange(index, 'min', parseInt(e.target.value) || 0)}
                  className="w-14 text-xs h-7"
                  placeholder="Min"
                />
                <span className="text-muted-foreground">-</span>
                <Input
                  type="number"
                  value={range.max ?? ''}
                  onChange={(e) =>
                    updateRange(index, 'max', e.target.value ? parseInt(e.target.value) : null)
                  }
                  className="w-14 text-xs h-7"
                  placeholder="∞"
                />
                <Input
                  value={range.output}
                  onChange={(e) => updateRange(index, 'output', e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, '_'))}
                  className="flex-1 min-w-[60px] text-xs h-7"
                  placeholder="output"
                />
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => removeRange(index)}
                  disabled={ranges.length <= 2}
                  className="h-7 w-7 text-muted-foreground hover:text-destructive"
                >
                  <Trash2 className="h-3 w-3" />
                </Button>
              </div>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">
            Each range routes to its output handle. Min 2, max 10 ranges.
          </p>
        </div>
      )}
    </div>
  )
}

// Action configuration
interface ActionConfigProps {
  action: ActionType
  config: Record<string, unknown>
  onActionChange: (action: ActionType) => void
  onConfigChange: (key: string, value: unknown) => void
}

function ActionConfig({ action, config, onActionChange, onConfigChange }: ActionConfigProps) {
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label className="text-xs">Action Type</Label>
        <Select value={action} onValueChange={(v) => onActionChange(v as ActionType)}>
          <SelectTrigger className="text-sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {Object.entries(ACTION_METADATA).map(([key, meta]) => (
              <SelectItem key={key} value={key}>
                {meta.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Tarpit-specific configuration */}
      {action === 'tarpit' && (
        <div className="space-y-2">
          <Label className="text-xs">Delay (seconds)</Label>
          <Input
            type="number"
            min="1"
            max="60"
            value={(config.delay_seconds as number) || 10}
            onChange={(e) => onConfigChange('delay_seconds', parseInt(e.target.value) || 10)}
            className="text-sm"
          />
          <p className="text-xs text-muted-foreground">How long to delay the response</p>

          <Label className="text-xs">Then</Label>
          <Select
            value={(config.then as string) || 'block'}
            onValueChange={(v) => onConfigChange('then', v)}
          >
            <SelectTrigger className="text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="block">Block (403)</SelectItem>
              <SelectItem value="reject">Reject (429)</SelectItem>
            </SelectContent>
          </Select>
        </div>
      )}

      {/* Flag-specific configuration */}
      {action === 'flag' && (
        <div className="space-y-2">
          <Label className="text-xs">Flag Label</Label>
          <Input
            value={(config.flag_label as string) || ''}
            onChange={(e) => onConfigChange('flag_label', e.target.value)}
            placeholder="suspicious_activity"
            className="text-sm"
          />
          <p className="text-xs text-muted-foreground">Label to add for logging/review</p>
        </div>
      )}

      {/* Block-specific configuration */}
      {action === 'block' && (
        <div className="space-y-2">
          <Label className="text-xs">HTTP Status</Label>
          <Select
            value={String((config.http_status as number) || 403)}
            onValueChange={(v) => onConfigChange('http_status', parseInt(v))}
          >
            <SelectTrigger className="text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="403">403 Forbidden</SelectItem>
              <SelectItem value="429">429 Too Many Requests</SelectItem>
              <SelectItem value="503">503 Service Unavailable</SelectItem>
            </SelectContent>
          </Select>
        </div>
      )}

      {/* Monitor action description */}
      {action === 'monitor' && (
        <p className="text-xs text-muted-foreground">
          Logs the request with all gathered data but allows it to proceed.
          Useful for testing new profiles without blocking traffic.
        </p>
      )}

      {/* Allow action description */}
      {action === 'allow' && (
        <p className="text-xs text-muted-foreground">
          Immediately passes the request to the backend without further checks.
        </p>
      )}
    </div>
  )
}
