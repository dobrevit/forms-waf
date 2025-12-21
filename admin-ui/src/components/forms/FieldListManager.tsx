import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Plus, X } from 'lucide-react'

export interface FieldListManagerProps {
  label: string
  description?: string
  items: string[]
  onAdd: (item: string) => void
  onRemove: (index: number) => void
  placeholder?: string
  maxItems?: number
  validation?: (item: string) => string | null
  renderItem?: (item: string, index: number) => React.ReactNode
  className?: string
  emptyMessage?: string
}

export function FieldListManager({
  label,
  description,
  items,
  onAdd,
  onRemove,
  placeholder = 'Enter value...',
  maxItems,
  validation,
  renderItem,
  className = '',
  emptyMessage = 'No items configured',
}: FieldListManagerProps) {
  const [inputValue, setInputValue] = useState('')
  const [error, setError] = useState<string | null>(null)

  const handleAdd = () => {
    if (!inputValue.trim()) return

    // Check for duplicates
    if (items.includes(inputValue.trim())) {
      setError('Item already exists')
      return
    }

    // Check max items
    if (maxItems && items.length >= maxItems) {
      setError(`Maximum of ${maxItems} items allowed`)
      return
    }

    // Run custom validation
    if (validation) {
      const validationError = validation(inputValue.trim())
      if (validationError) {
        setError(validationError)
        return
      }
    }

    onAdd(inputValue.trim())
    setInputValue('')
    setError(null)
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      handleAdd()
    }
  }

  return (
    <div className={`space-y-4 ${className}`}>
      <div className="space-y-1">
        <Label>{label}</Label>
        {description && (
          <p className="text-sm text-muted-foreground">{description}</p>
        )}
      </div>

      <div className="flex gap-2">
        <Input
          value={inputValue}
          onChange={(e) => {
            setInputValue(e.target.value)
            setError(null)
          }}
          placeholder={placeholder}
          className="flex-1"
          onKeyDown={handleKeyDown}
        />
        <Button
          type="button"
          onClick={handleAdd}
          disabled={!inputValue.trim() || (maxItems !== undefined && items.length >= maxItems)}
        >
          <Plus className="h-4 w-4" />
        </Button>
      </div>

      {error && (
        <p className="text-sm text-destructive">{error}</p>
      )}

      {items.length > 0 ? (
        <div className="flex flex-wrap gap-2">
          {items.map((item, index) => (
            <div
              key={`${item}-${index}`}
              className="flex items-center gap-1 rounded-md bg-secondary px-2 py-1 text-sm"
            >
              {renderItem ? renderItem(item, index) : <code>{item}</code>}
              <button
                type="button"
                onClick={() => onRemove(index)}
                className="ml-1 hover:text-destructive"
              >
                <X className="h-3 w-3" />
              </button>
            </div>
          ))}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground italic">{emptyMessage}</p>
      )}
    </div>
  )
}
