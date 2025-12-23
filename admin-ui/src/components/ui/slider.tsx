import * as React from "react"
import { cn } from "@/lib/utils"

interface SliderProps {
  value?: number[]
  defaultValue?: number[]
  min?: number
  max?: number
  step?: number
  disabled?: boolean
  onValueChange?: (value: number[]) => void
  className?: string
}

const Slider = React.forwardRef<HTMLInputElement, SliderProps>(
  ({ value, defaultValue, min = 0, max = 100, step = 1, disabled, onValueChange, className }, ref) => {
    const currentValue = value?.[0] ?? defaultValue?.[0] ?? min

    return (
      <input
        ref={ref}
        type="range"
        min={min}
        max={max}
        step={step}
        value={currentValue}
        disabled={disabled}
        onChange={(e) => onValueChange?.([parseFloat(e.target.value)])}
        className={cn(
          "w-full h-2 bg-secondary rounded-lg appearance-none cursor-pointer",
          "accent-primary",
          "[&::-webkit-slider-thumb]:appearance-none",
          "[&::-webkit-slider-thumb]:w-4",
          "[&::-webkit-slider-thumb]:h-4",
          "[&::-webkit-slider-thumb]:rounded-full",
          "[&::-webkit-slider-thumb]:bg-primary",
          "[&::-webkit-slider-thumb]:cursor-pointer",
          "[&::-webkit-slider-thumb]:border-2",
          "[&::-webkit-slider-thumb]:border-background",
          "[&::-webkit-slider-thumb]:shadow",
          "[&::-moz-range-thumb]:w-4",
          "[&::-moz-range-thumb]:h-4",
          "[&::-moz-range-thumb]:rounded-full",
          "[&::-moz-range-thumb]:bg-primary",
          "[&::-moz-range-thumb]:cursor-pointer",
          "[&::-moz-range-thumb]:border-2",
          "[&::-moz-range-thumb]:border-background",
          "disabled:opacity-50 disabled:cursor-not-allowed",
          className
        )}
      />
    )
  }
)
Slider.displayName = "Slider"

export { Slider }
