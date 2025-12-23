import { cn } from '@/lib/utils'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import {
  DEFENSE_METADATA,
  OPERATOR_METADATA,
  ACTION_METADATA,
  OBSERVATION_METADATA,
} from './nodes'
import type { DefenseType, OperatorType, ActionType, ObservationType } from '@/api/types'

interface DraggableNodeProps {
  type: 'defense' | 'operator' | 'action' | 'observation'
  subtype: string
  icon: React.ElementType
  label: string
  color: string
}

function DraggableNode({ type, subtype, icon: Icon, label, color }: DraggableNodeProps) {
  const onDragStart = (event: React.DragEvent) => {
    event.dataTransfer.setData('application/reactflow/type', type)
    event.dataTransfer.setData('application/reactflow/subtype', subtype)
    event.dataTransfer.effectAllowed = 'move'
  }

  return (
    <div
      className="flex items-center gap-2 p-2 rounded-md border bg-background hover:bg-muted cursor-grab active:cursor-grabbing"
      draggable
      onDragStart={onDragStart}
    >
      <div className={cn('p-1 rounded', color)}>
        <Icon className="h-3 w-3 text-white" />
      </div>
      <span className="text-xs font-medium">{label}</span>
    </div>
  )
}

interface NodeToolboxProps {
  className?: string
}

export function NodeToolbox({ className }: NodeToolboxProps) {
  return (
    <Card className={cn('w-64 overflow-auto', className)}>
      <CardHeader className="py-3">
        <CardTitle className="text-sm">Node Toolbox</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 pb-4">
        {/* Defense Nodes */}
        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            Defense Checks
          </h4>
          <div className="grid gap-1">
            {(Object.entries(DEFENSE_METADATA) as [DefenseType, typeof DEFENSE_METADATA[DefenseType]][]).map(
              ([key, meta]) => (
                <DraggableNode
                  key={key}
                  type="defense"
                  subtype={key}
                  icon={meta.icon}
                  label={meta.label}
                  color={meta.color}
                />
              )
            )}
          </div>
        </div>

        <Separator />

        {/* Operator Nodes */}
        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            Operators
          </h4>
          <div className="grid gap-1">
            {(Object.entries(OPERATOR_METADATA) as [OperatorType, typeof OPERATOR_METADATA[OperatorType]][]).map(
              ([key, meta]) => (
                <DraggableNode
                  key={key}
                  type="operator"
                  subtype={key}
                  icon={meta.icon}
                  label={meta.label}
                  color={meta.color}
                />
              )
            )}
          </div>
        </div>

        <Separator />

        {/* Action Nodes */}
        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            Actions
          </h4>
          <div className="grid gap-1">
            {(Object.entries(ACTION_METADATA) as [ActionType, typeof ACTION_METADATA[ActionType]][]).map(
              ([key, meta]) => (
                <DraggableNode
                  key={key}
                  type="action"
                  subtype={key}
                  icon={meta.icon}
                  label={meta.label}
                  color={meta.color}
                />
              )
            )}
          </div>
        </div>

        <Separator />

        {/* Observation Nodes */}
        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            Observation
          </h4>
          <p className="text-xs text-muted-foreground mb-2">
            Non-blocking nodes for learning and analytics
          </p>
          <div className="grid gap-1">
            {(Object.entries(OBSERVATION_METADATA) as [ObservationType, typeof OBSERVATION_METADATA[ObservationType]][]).map(
              ([key, meta]) => (
                <DraggableNode
                  key={key}
                  type="observation"
                  subtype={key}
                  icon={meta.icon}
                  label={meta.label}
                  color={meta.color}
                />
              )
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
