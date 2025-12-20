import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'

export interface ConditionalSectionProps {
  label: string
  description?: string
  enabled: boolean
  onToggle: (enabled: boolean) => void
  children: React.ReactNode
  inheritedFrom?: 'vhost' | 'global'
  className?: string
}

export function ConditionalSection({
  label,
  description,
  enabled,
  onToggle,
  children,
  inheritedFrom,
  className = '',
}: ConditionalSectionProps) {
  return (
    <div className={`space-y-4 ${className}`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Switch
            id={`toggle-${label.toLowerCase().replace(/\s+/g, '-')}`}
            checked={enabled}
            onCheckedChange={onToggle}
          />
          <div className="space-y-0.5">
            <Label
              htmlFor={`toggle-${label.toLowerCase().replace(/\s+/g, '-')}`}
              className="cursor-pointer"
            >
              {label}
            </Label>
            {description && (
              <p className="text-sm text-muted-foreground">{description}</p>
            )}
          </div>
        </div>
        {inheritedFrom && (
          <Badge variant="outline" className="text-xs">
            Inherited from {inheritedFrom}
          </Badge>
        )}
      </div>

      {enabled && (
        <div className="ml-10 space-y-4 border-l-2 border-muted pl-4">
          {children}
        </div>
      )}
    </div>
  )
}
