import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'

export interface ThresholdSliderProps {
  label: string
  value: number
  onChange: (value: number) => void
  min: number
  max: number
  step?: number
  description?: string
  inheritedValue?: number
  unit?: string
  className?: string
}

export function ThresholdSlider({
  label,
  value,
  onChange,
  min,
  max,
  step = 1,
  description,
  inheritedValue,
  unit,
  className = '',
}: ThresholdSliderProps) {
  const displayValue = value ?? inheritedValue ?? min

  return (
    <div className={`space-y-2 ${className}`}>
      <div className="flex items-center justify-between">
        <Label>{label}</Label>
        <div className="flex items-center gap-2">
          <Input
            type="number"
            value={displayValue}
            onChange={(e) => onChange(parseInt(e.target.value) || min)}
            min={min}
            max={max}
            step={step}
            className="w-20 text-right"
          />
          {unit && <span className="text-sm text-muted-foreground">{unit}</span>}
        </div>
      </div>

      <input
        type="range"
        value={displayValue}
        onChange={(e) => onChange(parseInt(e.target.value))}
        min={min}
        max={max}
        step={step}
        className="w-full h-2 bg-secondary rounded-lg appearance-none cursor-pointer accent-primary"
      />

      <div className="flex justify-between text-xs text-muted-foreground">
        <span>{min}{unit ? ` ${unit}` : ''}</span>
        {inheritedValue !== undefined && value !== inheritedValue && (
          <span className="text-amber-600">
            Inherited: {inheritedValue}{unit ? ` ${unit}` : ''}
          </span>
        )}
        <span>{max}{unit ? ` ${unit}` : ''}</span>
      </div>

      {description && (
        <p className="text-sm text-muted-foreground">{description}</p>
      )}
    </div>
  )
}
