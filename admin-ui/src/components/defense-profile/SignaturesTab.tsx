import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { attackSignaturesApi } from '@/api/client'
import type { AttackSignatureAttachment, AttackSignatureAttachmentItem, SignatureMergeMode, DefenseType } from '@/api/types'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Info, Plus, X, Target, ArrowUp, ArrowDown, Loader2, Search } from 'lucide-react'

interface SignaturesTabProps {
  attachment: AttackSignatureAttachment | undefined
  onAttachmentChange: (attachment: AttackSignatureAttachment) => void
  profileDefenseTypes: DefenseType[]  // Defense types used by the profile
  isBuiltin?: boolean
}

// Default attachment when none exists
const DEFAULT_ATTACHMENT: AttackSignatureAttachment = {
  items: [],
  merge_mode: 'UNION',
}

// Helper to ensure items is always an array
const ensureItemsArray = (items: unknown): AttackSignatureAttachmentItem[] => {
  if (Array.isArray(items)) return items
  if (items && typeof items === 'object') {
    const values = Object.values(items)
    if (values.length > 0 && typeof values[0] === 'object') {
      return values as AttackSignatureAttachmentItem[]
    }
  }
  return []
}

export function SignaturesTab({
  attachment,
  onAttachmentChange,
  profileDefenseTypes,
  isBuiltin = false,
}: SignaturesTabProps) {
  const [searchQuery, setSearchQuery] = useState('')

  // Fetch available signatures
  const { data: signaturesData, isLoading } = useQuery({
    queryKey: ['attack-signatures'],
    queryFn: () => attackSignaturesApi.list(),
  })

  const availableSignatures = useMemo(() => {
    const signatures = signaturesData?.signatures || []
    // Filter by search query
    if (!searchQuery) return signatures
    const query = searchQuery.toLowerCase()
    return signatures.filter(
      (sig) =>
        sig.name.toLowerCase().includes(query) ||
        sig.description?.toLowerCase().includes(query) ||
        sig.tags?.some((t) => t.toLowerCase().includes(query))
    )
  }, [signaturesData?.signatures, searchQuery])

  // Current attachment data
  const currentAttachment = attachment || DEFAULT_ATTACHMENT
  const attachedItems = ensureItemsArray(currentAttachment.items)

  // Get attached signature IDs
  const attachedIds = new Set(attachedItems.map((item) => item.signature_id))

  // Filter available signatures that aren't already attached
  const signaturesNotAttached = availableSignatures.filter((sig) => !attachedIds.has(sig.id))

  // Helper to update attachment
  const updateAttachment = (updates: Partial<AttackSignatureAttachment>) => {
    onAttachmentChange({
      ...currentAttachment,
      items: attachedItems,
      ...updates,
    })
  }

  // Add a signature
  const addSignature = (signatureId: string) => {
    const newItem: AttackSignatureAttachmentItem = {
      signature_id: signatureId,
      priority: (attachedItems.length + 1) * 100,
      enabled: true,
    }
    updateAttachment({
      items: [...attachedItems, newItem],
    })
  }

  // Remove a signature
  const removeSignature = (signatureId: string) => {
    updateAttachment({
      items: attachedItems.filter((item) => item.signature_id !== signatureId),
    })
  }

  // Update a signature item
  const updateItem = (signatureId: string, updates: Partial<AttackSignatureAttachmentItem>) => {
    updateAttachment({
      items: attachedItems.map((item) =>
        item.signature_id === signatureId ? { ...item, ...updates } : item
      ),
    })
  }

  // Move signature up in priority
  const moveUp = (index: number) => {
    if (index === 0) return
    const newItems = [...attachedItems]
    const temp = newItems[index]
    newItems[index] = newItems[index - 1]
    newItems[index - 1] = temp
    // Recalculate priorities
    newItems.forEach((item, i) => {
      item.priority = (i + 1) * 100
    })
    updateAttachment({ items: newItems })
  }

  // Move signature down in priority
  const moveDown = (index: number) => {
    if (index >= attachedItems.length - 1) return
    const newItems = [...attachedItems]
    const temp = newItems[index]
    newItems[index] = newItems[index + 1]
    newItems[index + 1] = temp
    // Recalculate priorities
    newItems.forEach((item, i) => {
      item.priority = (i + 1) * 100
    })
    updateAttachment({ items: newItems })
  }

  // Get defense types this profile uses (for showing relevance)
  const defenseTypesSet = new Set(profileDefenseTypes)

  // Check if a signature has relevant patterns for this profile
  const getRelevantSections = (signatureId: string): DefenseType[] => {
    const signature = availableSignatures.find((s) => s.id === signatureId)
    if (!signature?.signatures) return []

    const relevant: DefenseType[] = []
    for (const key of Object.keys(signature.signatures)) {
      if (defenseTypesSet.has(key as DefenseType)) {
        relevant.push(key as DefenseType)
      }
    }
    return relevant
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6 overflow-auto h-full">
      {/* Info banner */}
      <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
        <div className="flex items-start gap-3">
          <Info className="h-5 w-5 text-blue-600 mt-0.5 shrink-0" />
          <div>
            <p className="font-medium text-blue-800">Attack Signatures</p>
            <p className="text-sm text-blue-700 mt-1">
              Attach attack signatures to enhance this defense profile with specific attack patterns.
              Signatures provide patterns for user agents, keywords, IPs, and other detection criteria.
            </p>
            {profileDefenseTypes.length > 0 && (
              <p className="text-sm text-blue-700 mt-2">
                <strong>Profile uses:</strong> {profileDefenseTypes.join(', ')}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Merge Mode */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Merge Mode</CardTitle>
          <CardDescription>
            How to combine patterns from multiple signatures
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Select
            value={currentAttachment.merge_mode}
            onValueChange={(value: SignatureMergeMode) => updateAttachment({ merge_mode: value })}
            disabled={isBuiltin}
          >
            <SelectTrigger className="w-64">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="UNION">
                <div className="flex flex-col">
                  <span>UNION</span>
                  <span className="text-xs text-muted-foreground">Combine all patterns</span>
                </div>
              </SelectItem>
              <SelectItem value="FIRST_MATCH">
                <div className="flex flex-col">
                  <span>FIRST_MATCH</span>
                  <span className="text-xs text-muted-foreground">Stop at first matching signature</span>
                </div>
              </SelectItem>
            </SelectContent>
          </Select>
        </CardContent>
      </Card>

      {/* Attached Signatures */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-medium">Attached Signatures</CardTitle>
              <CardDescription>
                {attachedItems.length} signature{attachedItems.length !== 1 ? 's' : ''} attached
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {attachedItems.length === 0 ? (
            <div className="rounded-lg border border-dashed p-6 text-center">
              <Target className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
              <p className="font-medium">No Signatures Attached</p>
              <p className="text-sm text-muted-foreground mt-1">
                Add attack signatures below to enhance this profile's detection capabilities.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {attachedItems.map((item, index) => {
                const signature = availableSignatures.find((s) => s.id === item.signature_id)
                const relevantSections = getRelevantSections(item.signature_id)
                return (
                  <div
                    key={item.signature_id}
                    className="flex items-center gap-3 p-3 border rounded-lg bg-muted/30"
                  >
                    {!isBuiltin && (
                      <div className="flex flex-col gap-1">
                        <button
                          type="button"
                          onClick={() => moveUp(index)}
                          disabled={index === 0}
                          className="p-0.5 hover:bg-muted rounded disabled:opacity-30"
                        >
                          <ArrowUp className="h-3 w-3" />
                        </button>
                        <button
                          type="button"
                          onClick={() => moveDown(index)}
                          disabled={index >= attachedItems.length - 1}
                          className="p-0.5 hover:bg-muted rounded disabled:opacity-30"
                        >
                          <ArrowDown className="h-3 w-3" />
                        </button>
                      </div>
                    )}

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge variant="secondary" className="text-xs shrink-0">
                          #{index + 1}
                        </Badge>
                        <span className="font-medium text-sm truncate">
                          {signature?.name || item.signature_id}
                        </span>
                        {signature?.builtin && (
                          <Badge variant="outline" className="text-xs shrink-0">
                            Built-in
                          </Badge>
                        )}
                        {relevantSections.length > 0 && (
                          <Badge variant="secondary" className="text-xs shrink-0">
                            {relevantSections.length} relevant section{relevantSections.length !== 1 ? 's' : ''}
                          </Badge>
                        )}
                      </div>
                      {signature?.description && (
                        <p className="text-xs text-muted-foreground truncate mt-1">
                          {signature.description}
                        </p>
                      )}
                      {signature?.tags && signature.tags.length > 0 && (
                        <div className="flex gap-1 mt-1 flex-wrap">
                          {signature.tags.slice(0, 3).map((tag) => (
                            <Badge key={tag} variant="outline" className="text-xs">
                              {tag}
                            </Badge>
                          ))}
                          {signature.tags.length > 3 && (
                            <span className="text-xs text-muted-foreground">
                              +{signature.tags.length - 3} more
                            </span>
                          )}
                        </div>
                      )}
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      <div className="flex items-center gap-2">
                        <Switch
                          checked={item.enabled !== false}
                          onCheckedChange={(enabled) => updateItem(item.signature_id, { enabled })}
                          disabled={isBuiltin}
                        />
                        <Label className="text-xs text-muted-foreground">
                          {item.enabled !== false ? 'Enabled' : 'Disabled'}
                        </Label>
                      </div>
                      {!isBuiltin && (
                        <button
                          type="button"
                          onClick={() => removeSignature(item.signature_id)}
                          className="p-1 hover:bg-destructive/10 hover:text-destructive rounded"
                        >
                          <X className="h-4 w-4" />
                        </button>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Available Signatures */}
      {!isBuiltin && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Available Signatures</CardTitle>
            <CardDescription>
              Click to attach a signature to this profile
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search signatures..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>

            {signaturesNotAttached.length === 0 ? (
              <div className="text-center py-4 text-sm text-muted-foreground">
                {searchQuery
                  ? 'No matching signatures found'
                  : 'All available signatures are attached'}
              </div>
            ) : (
              <div className="grid gap-2 max-h-64 overflow-auto">
                {signaturesNotAttached.map((signature) => {
                  const relevantSections = getRelevantSections(signature.id)
                  const hasRelevantSections = relevantSections.length > 0
                  return (
                    <div
                      key={signature.id}
                      className={`flex items-center justify-between p-3 border rounded-lg cursor-pointer transition-colors ${
                        hasRelevantSections
                          ? 'hover:bg-primary/5 hover:border-primary/30'
                          : 'hover:bg-muted/50 opacity-75'
                      }`}
                      onClick={() => addSignature(signature.id)}
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-medium text-sm truncate">
                            {signature.name}
                          </span>
                          {signature.builtin && (
                            <Badge variant="outline" className="text-xs">
                              Built-in
                            </Badge>
                          )}
                          {hasRelevantSections ? (
                            <Badge variant="secondary" className="text-xs bg-primary/10 text-primary">
                              {relevantSections.length} relevant
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="text-xs">
                              No matching nodes
                            </Badge>
                          )}
                        </div>
                        {signature.description && (
                          <p className="text-xs text-muted-foreground truncate mt-1">
                            {signature.description}
                          </p>
                        )}
                      </div>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="shrink-0"
                        onClick={(e) => {
                          e.stopPropagation()
                          addSignature(signature.id)
                        }}
                      >
                        <Plus className="h-4 w-4" />
                      </Button>
                    </div>
                  )
                })}
              </div>
            )}

            <p className="text-xs text-muted-foreground">
              Manage signatures in{' '}
              <a href="/security/attack-signatures" className="underline font-medium">
                Security &gt; Attack Signatures
              </a>
            </p>
          </CardContent>
        </Card>
      )}

      {isBuiltin && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 p-4">
          <div className="flex items-start gap-3">
            <Info className="h-5 w-5 text-amber-600 mt-0.5 shrink-0" />
            <div>
              <p className="font-medium text-amber-800">Built-in Profile</p>
              <p className="text-sm text-amber-700 mt-1">
                This is a built-in profile. To customize signature attachments, clone this profile
                and modify the clone.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
