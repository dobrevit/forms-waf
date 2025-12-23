import { memo } from 'react'
import { Handle, Position } from '@xyflow/react'
import { cn } from '@/lib/utils'
import {
  Play,
  Shield,
  Calculator,
  CheckCircle,
  Ban,
  Clock,
  ShieldCheck,
  Flag,
  Eye,
  GitBranch,
  Plus,
  Minus,
  Network,
  MapPin,
  ShieldAlert,
  Timer,
  Activity,
  Flower2,
  FileSearch,
  Hash,
  FileText,
  Search,
  Mail,
  AlertTriangle,
  Fingerprint,
  FileWarning,
  Gauge,
  BookOpen,
} from 'lucide-react'
import type { DefenseType, OperatorType, ActionType, ObservationType, ThresholdRange } from '@/api/types'

// Default threshold ranges (matches backend defaults)
const DEFAULT_THRESHOLD_RANGES: ThresholdRange[] = [
  { min: 0, max: 30, output: 'low' },
  { min: 30, max: 60, output: 'medium' },
  { min: 60, max: 100, output: 'high' },
  { min: 100, max: null, output: 'critical' },
]

// Color mapping for threshold outputs
const THRESHOLD_OUTPUT_COLORS: Record<string, string> = {
  very_low: '!bg-emerald-400',
  low: '!bg-green-500',
  medium: '!bg-yellow-500',
  high: '!bg-orange-500',
  critical: '!bg-red-500',
  very_high: '!bg-red-600',
}

function getThresholdHandleColor(output: string, index: number, total: number): string {
  // Check if we have a predefined color for this output name
  if (THRESHOLD_OUTPUT_COLORS[output]) {
    return THRESHOLD_OUTPUT_COLORS[output]
  }
  // Otherwise, use a gradient from green to red based on position
  const colors = ['!bg-green-500', '!bg-lime-500', '!bg-yellow-500', '!bg-amber-500', '!bg-orange-500', '!bg-red-500']
  const colorIndex = Math.floor((index / (total - 1)) * (colors.length - 1))
  return colors[Math.min(colorIndex, colors.length - 1)]
}

// Node data types
export interface StartNodeData {
  label?: string
}

export interface DefenseNodeData {
  label?: string
  defense: DefenseType
  config?: Record<string, unknown>
}

export interface OperatorNodeData {
  label?: string
  operator: OperatorType
  config?: Record<string, unknown>
  inputs?: string[]
}

export interface ActionNodeData {
  label?: string
  action: ActionType
  config?: Record<string, unknown>
}

export interface ObservationNodeData {
  label?: string
  observation: ObservationType
  config?: Record<string, unknown>
}

// Defense type icons and labels
const DEFENSE_INFO: Record<DefenseType, { icon: React.ElementType; label: string; color: string }> = {
  ip_allowlist: { icon: Network, label: 'IP Allowlist', color: 'bg-green-500' },
  geoip: { icon: MapPin, label: 'GeoIP', color: 'bg-blue-500' },
  ip_reputation: { icon: ShieldAlert, label: 'IP Reputation', color: 'bg-orange-500' },
  timing_token: { icon: Timer, label: 'Timing Token', color: 'bg-purple-500' },
  behavioral: { icon: Activity, label: 'Behavioral', color: 'bg-indigo-500' },
  honeypot: { icon: Flower2, label: 'Honeypot', color: 'bg-yellow-500' },
  keyword_filter: { icon: FileSearch, label: 'Keyword Filter', color: 'bg-red-500' },
  content_hash: { icon: Hash, label: 'Content Hash', color: 'bg-gray-500' },
  expected_fields: { icon: FileText, label: 'Expected Fields', color: 'bg-teal-500' },
  pattern_scan: { icon: Search, label: 'Pattern Scan', color: 'bg-pink-500' },
  disposable_email: { icon: Mail, label: 'Disposable Email', color: 'bg-amber-500' },
  field_anomalies: { icon: AlertTriangle, label: 'Field Anomalies', color: 'bg-lime-500' },
  fingerprint: { icon: Fingerprint, label: 'Fingerprint', color: 'bg-cyan-500' },
  header_consistency: { icon: FileWarning, label: 'Header Consistency', color: 'bg-violet-500' },
  rate_limiter: { icon: Gauge, label: 'Rate Limiter', color: 'bg-rose-500' },
}

// Operator type icons and labels
const OPERATOR_INFO: Record<OperatorType, { icon: React.ElementType; label: string; color: string }> = {
  sum: { icon: Plus, label: 'Sum', color: 'bg-blue-600' },
  threshold_branch: { icon: GitBranch, label: 'Threshold Branch', color: 'bg-purple-600' },
  and: { icon: Calculator, label: 'AND', color: 'bg-indigo-600' },
  or: { icon: Calculator, label: 'OR', color: 'bg-indigo-600' },
  max: { icon: Plus, label: 'Max', color: 'bg-teal-600' },
  min: { icon: Minus, label: 'Min', color: 'bg-teal-600' },
}

// Action type icons and labels
const ACTION_INFO: Record<ActionType, { icon: React.ElementType; label: string; color: string }> = {
  allow: { icon: CheckCircle, label: 'Allow', color: 'bg-green-600' },
  block: { icon: Ban, label: 'Block', color: 'bg-red-600' },
  tarpit: { icon: Clock, label: 'Tarpit', color: 'bg-orange-600' },
  captcha: { icon: ShieldCheck, label: 'CAPTCHA', color: 'bg-yellow-600' },
  flag: { icon: Flag, label: 'Flag', color: 'bg-amber-600' },
  monitor: { icon: Eye, label: 'Monitor', color: 'bg-gray-600' },
}

// Observation type icons and labels (non-blocking, side-effect only)
const OBSERVATION_INFO: Record<ObservationType, { icon: React.ElementType; label: string; color: string }> = {
  field_learner: { icon: BookOpen, label: 'Field Learner', color: 'bg-emerald-600' },
}

// Base node wrapper
function NodeWrapper({
  children,
  selected,
  className,
}: {
  children: React.ReactNode
  selected?: boolean
  className?: string
}) {
  return (
    <div
      className={cn(
        'px-4 py-2 rounded-lg border-2 shadow-md min-w-[140px]',
        selected ? 'border-primary ring-2 ring-primary/20' : 'border-border',
        className
      )}
    >
      {children}
    </div>
  )
}

// Node props type for React Flow (simplified to avoid complex generics)
interface CustomNodeProps {
  data: Record<string, unknown>
  selected?: boolean
}

// Start Node
export const StartNode = memo(({ selected }: CustomNodeProps) => {
  return (
    <NodeWrapper selected={selected} className="bg-slate-100 dark:bg-slate-800">
      <div className="flex items-center gap-2 justify-center">
        <div className="p-1 rounded bg-slate-500">
          <Play className="h-4 w-4 text-white" />
        </div>
        <span className="font-medium text-sm">Start</span>
      </div>
      <Handle
        type="source"
        position={Position.Bottom}
        className="w-3 h-3 !bg-slate-500"
        id="next"
      />
    </NodeWrapper>
  )
})
StartNode.displayName = 'StartNode'

// Defense Node
export const DefenseNode = memo(({ data, selected }: CustomNodeProps) => {
  const defense = data.defense as DefenseType
  const label = data.label as string | undefined
  const info = DEFENSE_INFO[defense] || { icon: Shield, label: defense, color: 'bg-gray-500' }
  const Icon = info.icon
  const isAllowlist = defense === 'ip_allowlist'

  return (
    <NodeWrapper selected={selected} className="bg-white dark:bg-slate-900">
      <Handle
        type="target"
        position={Position.Top}
        className="w-3 h-3 !bg-gray-400"
        id="input"
      />
      <div className="flex items-center gap-2">
        <div className={cn('p-1 rounded', info.color)}>
          <Icon className="h-4 w-4 text-white" />
        </div>
        <div className="flex flex-col">
          <span className="font-medium text-sm">{label || info.label}</span>
          <span className="text-xs text-muted-foreground">Defense</span>
        </div>
      </div>
      {isAllowlist ? (
        <>
          {/* IP Allowlist has special handles: allowed (in list) and continue (not in list) */}
          <Handle
            type="source"
            position={Position.Bottom}
            className="w-3 h-3 !bg-green-500"
            id="allowed"
            style={{ left: '30%' }}
            title="IP in allowlist"
          />
          <Handle
            type="source"
            position={Position.Bottom}
            className="w-3 h-3 !bg-yellow-500"
            id="continue"
            style={{ left: '70%' }}
            title="IP not in allowlist (continue)"
          />
        </>
      ) : (
        <>
          <Handle
            type="source"
            position={Position.Bottom}
            className="w-3 h-3 !bg-green-500"
            id="continue"
            style={{ left: '30%' }}
            title="Continue"
          />
          <Handle
            type="source"
            position={Position.Bottom}
            className="w-3 h-3 !bg-red-500"
            id="blocked"
            style={{ left: '70%' }}
            title="Blocked"
          />
        </>
      )}
    </NodeWrapper>
  )
})
DefenseNode.displayName = 'DefenseNode'

// Operator Node
export const OperatorNode = memo(({ data, selected }: CustomNodeProps) => {
  const operator = data.operator as OperatorType
  const label = data.label as string | undefined
  const config = data.config as Record<string, unknown> | undefined
  const info = OPERATOR_INFO[operator] || { icon: Calculator, label: operator, color: 'bg-gray-500' }
  const Icon = info.icon
  const isThresholdBranch = operator === 'threshold_branch'

  // Get threshold ranges from config or use defaults
  const ranges = isThresholdBranch
    ? ((config?.ranges as ThresholdRange[]) || DEFAULT_THRESHOLD_RANGES)
    : []

  return (
    <NodeWrapper
      selected={selected}
      className={cn(
        'bg-blue-50 dark:bg-blue-950',
        isThresholdBranch && 'min-w-[180px]'
      )}
    >
      <Handle
        type="target"
        position={Position.Top}
        className="w-3 h-3 !bg-gray-400"
        id="input"
      />
      <div className="flex items-center gap-2">
        <div className={cn('p-1 rounded', info.color)}>
          <Icon className="h-4 w-4 text-white" />
        </div>
        <div className="flex flex-col">
          <span className="font-medium text-sm">{label || info.label}</span>
          <span className="text-xs text-muted-foreground">Operator</span>
        </div>
      </div>
      {isThresholdBranch ? (
        <>
          {/* Dynamic threshold range handles - spread horizontally at bottom */}
          {ranges.map((range, index) => {
            const position = ((index + 1) / (ranges.length + 1)) * 100
            return (
              <Handle
                key={range.output}
                type="source"
                position={Position.Bottom}
                className={cn('w-3 h-3', getThresholdHandleColor(range.output, index, ranges.length))}
                id={range.output}
                style={{ left: `${position}%` }}
                title={`${range.output} (${range.min}-${range.max ?? '∞'})`}
              />
            )
          })}
          {/* Output labels below the node */}
          <div className="absolute -bottom-5 left-0 right-0 flex justify-around text-[9px] text-muted-foreground">
            {ranges.map((range) => (
              <span key={range.output} className="truncate max-w-[40px]" title={range.output}>
                {range.output}
              </span>
            ))}
          </div>
        </>
      ) : (
        <Handle
          type="source"
          position={Position.Bottom}
          className="w-3 h-3 !bg-blue-500"
          id="next"
        />
      )}
    </NodeWrapper>
  )
})
OperatorNode.displayName = 'OperatorNode'

// Action Node
export const ActionNode = memo(({ data, selected }: CustomNodeProps) => {
  const action = data.action as ActionType
  const label = data.label as string | undefined
  const info = ACTION_INFO[action] || { icon: CheckCircle, label: action, color: 'bg-gray-500' }
  const Icon = info.icon

  return (
    <NodeWrapper selected={selected} className={cn('text-white', info.color)}>
      <Handle
        type="target"
        position={Position.Top}
        className="w-3 h-3 !bg-white"
        id="input"
      />
      <div className="flex items-center gap-2 justify-center">
        <Icon className="h-5 w-5" />
        <div className="flex flex-col">
          <span className="font-medium text-sm">{label || info.label}</span>
          <span className="text-xs opacity-80">Action</span>
        </div>
      </div>
    </NodeWrapper>
  )
})
ActionNode.displayName = 'ActionNode'

// Observation Node (non-blocking, always continues)
export const ObservationNode = memo(({ data, selected }: CustomNodeProps) => {
  const observation = data.observation as ObservationType
  const label = data.label as string | undefined
  const info = OBSERVATION_INFO[observation] || { icon: BookOpen, label: observation, color: 'bg-gray-500' }
  const Icon = info.icon

  return (
    <NodeWrapper selected={selected} className="bg-emerald-50 dark:bg-emerald-950 border-emerald-300">
      <Handle
        type="target"
        position={Position.Top}
        className="w-3 h-3 !bg-gray-400"
        id="input"
      />
      <div className="flex items-center gap-2">
        <div className={cn('p-1 rounded', info.color)}>
          <Icon className="h-4 w-4 text-white" />
        </div>
        <div className="flex flex-col">
          <span className="font-medium text-sm">{label || info.label}</span>
          <span className="text-xs text-muted-foreground">Observation</span>
        </div>
      </div>
      {/* Observation nodes always continue - no blocking */}
      <Handle
        type="source"
        position={Position.Bottom}
        className="w-3 h-3 !bg-emerald-500"
        id="continue"
        title="Continue"
      />
    </NodeWrapper>
  )
})
ObservationNode.displayName = 'ObservationNode'

// Export node types mapping for React Flow
export const nodeTypes = {
  start: StartNode,
  defense: DefenseNode,
  operator: OperatorNode,
  action: ActionNode,
  observation: ObservationNode,
}

// Export metadata for toolbox
export const DEFENSE_METADATA = DEFENSE_INFO
export const OPERATOR_METADATA = OPERATOR_INFO
export const ACTION_METADATA = ACTION_INFO
export const OBSERVATION_METADATA = OBSERVATION_INFO
