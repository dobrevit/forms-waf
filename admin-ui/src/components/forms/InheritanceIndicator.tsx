import { Badge } from '@/components/ui/badge'
import { Globe, Server, Check } from 'lucide-react'

export interface InheritanceIndicatorProps {
  inheritedFrom?: 'vhost' | 'global'
  isOverridden?: boolean
  className?: string
}

export function InheritanceIndicator({
  inheritedFrom,
  isOverridden,
  className = '',
}: InheritanceIndicatorProps) {
  if (!inheritedFrom) return null

  if (isOverridden) {
    return (
      <Badge variant="default" className={`text-xs ${className}`}>
        <Check className="h-3 w-3 mr-1" />
        Overridden
      </Badge>
    )
  }

  const Icon = inheritedFrom === 'global' ? Globe : Server
  const label = inheritedFrom === 'global' ? 'Global' : 'Vhost'

  return (
    <Badge variant="outline" className={`text-xs ${className}`}>
      <Icon className="h-3 w-3 mr-1" />
      Inherited from {label}
    </Badge>
  )
}
