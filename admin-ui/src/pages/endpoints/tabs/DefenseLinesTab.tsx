import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { Info, Plus, X, Target, ChevronDown, ArrowUp, ArrowDown, Shield, Layers } from 'lucide-react'
import type { DefenseLinesTabProps } from './types'
import type { DefenseLineAttachment } from '@/api/types'
import { useState } from 'react'

// Helper to ensure signature_ids is always an array
// (JSON from Lua may serialize empty tables as {} instead of [])
const ensureArray = (value: unknown): string[] => {
  if (Array.isArray(value)) return value
  if (value && typeof value === 'object') return Object.values(value) as string[]
  return []
}

// Normalize defense lines to ensure signature_ids is always an array
const normalizeDefenseLines = (lines: unknown): DefenseLineAttachment[] => {
  if (!Array.isArray(lines)) return []
  return lines.map((line) => ({
    ...line,
    signature_ids: ensureArray(line?.signature_ids),
  }))
}

export function DefenseLinesTab({
  formData,
  setFormData,
  availableProfiles,
  availableSignatures,
}: DefenseLinesTabProps) {
  const defenseLines = normalizeDefenseLines(formData.defense_lines)
  const [expandedLines, setExpandedLines] = useState<Set<number>>(new Set([0]))

  // Helper to update defense_lines
  const updateDefenseLines = (lines: DefenseLineAttachment[]) => {
    setFormData({
      ...formData,
      defense_lines: lines,
    })
  }

  // Add a new defense line
  const addDefenseLine = () => {
    const newLine: DefenseLineAttachment = {
      profile_id: availableProfiles[0]?.id || '',
      signature_ids: [],
      enabled: true,
    }
    updateDefenseLines([...defenseLines, newLine])
    setExpandedLines(new Set([...expandedLines, defenseLines.length]))
  }

  // Remove a defense line
  const removeDefenseLine = (index: number) => {
    updateDefenseLines(defenseLines.filter((_, i) => i !== index))
  }

  // Update a specific defense line
  const updateLine = (index: number, updates: Partial<DefenseLineAttachment>) => {
    updateDefenseLines(
      defenseLines.map((line, i) =>
        i === index ? { ...line, ...updates } : line
      )
    )
  }

  // Move line up
  const moveUp = (index: number) => {
    if (index === 0) return
    const newLines = [...defenseLines]
    const temp = newLines[index]
    newLines[index] = newLines[index - 1]
    newLines[index - 1] = temp
    updateDefenseLines(newLines)
  }

  // Move line down
  const moveDown = (index: number) => {
    if (index >= defenseLines.length - 1) return
    const newLines = [...defenseLines]
    const temp = newLines[index]
    newLines[index] = newLines[index + 1]
    newLines[index + 1] = temp
    updateDefenseLines(newLines)
  }

  // Add a signature to a line
  const addSignature = (lineIndex: number, signatureId: string) => {
    const line = defenseLines[lineIndex]
    if (!line || line.signature_ids?.includes(signatureId)) return
    updateLine(lineIndex, {
      signature_ids: [...(line.signature_ids || []), signatureId],
    })
  }

  // Remove a signature from a line
  const removeSignature = (lineIndex: number, signatureId: string) => {
    const line = defenseLines[lineIndex]
    if (!line) return
    updateLine(lineIndex, {
      signature_ids: (line.signature_ids || []).filter((id) => id !== signatureId),
    })
  }

  // Toggle expanded state
  const toggleExpanded = (index: number) => {
    const newExpanded = new Set(expandedLines)
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedLines(newExpanded)
  }

  // Get available signatures not yet added to a line
  const getAvailableSignatures = (lineIndex: number) => {
    const line = defenseLines[lineIndex]
    const attachedIds = line?.signature_ids || []
    return availableSignatures.filter((s) => !attachedIds.includes(s.id))
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Layers className="h-5 w-5" />
          Defense Lines
        </CardTitle>
        <CardDescription>
          Add additional defense layers that run after the base defense profile.
          Each defense line combines a profile with attack signatures for targeted protection.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Explanation banner */}
        <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
          <div className="flex items-start gap-3">
            <Info className="h-5 w-5 text-blue-600 mt-0.5 shrink-0" />
            <div>
              <p className="font-medium text-blue-800">How Defense Lines Work</p>
              <ul className="text-sm text-blue-700 mt-1 space-y-1 list-disc list-inside">
                <li><strong>Base profile</strong> (from Defense Profiles tab) runs first</li>
                <li>Defense lines run <strong>after</strong> base profile passes</li>
                <li>If <strong>any</strong> defense line blocks, the request is blocked</li>
                <li>Each line combines a profile with attack signatures for targeted protection</li>
                <li>Use this for attack-specific defenses (e.g., WordPress bot scanner)</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Defense Lines List */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="font-medium text-sm">Defense Lines</h4>
            <button
              type="button"
              onClick={addDefenseLine}
              className="flex items-center gap-1 text-sm text-primary hover:underline"
            >
              <Plus className="h-4 w-4" />
              Add Defense Line
            </button>
          </div>

          {defenseLines.length === 0 ? (
            <div className="rounded-lg border border-dashed p-6 text-center">
              <Layers className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
              <p className="font-medium">No Defense Lines</p>
              <p className="text-sm text-muted-foreground mt-1">
                Only the base defense profile will be used.
                Add defense lines for additional targeted protection.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {defenseLines.map((line, index) => {
                const profile = availableProfiles.find((p) => p.id === line.profile_id)
                const lineSignatures = (line.signature_ids || [])
                  .map((id) => availableSignatures.find((s) => s.id === id))
                  .filter(Boolean)
                const availableToAdd = getAvailableSignatures(index)
                const isExpanded = expandedLines.has(index)

                return (
                  <Collapsible
                    key={index}
                    open={isExpanded}
                    onOpenChange={() => toggleExpanded(index)}
                  >
                    <div className="border rounded-lg overflow-hidden">
                      {/* Line Header */}
                      <div className="flex items-center gap-3 p-3 bg-muted/30">
                        <div className="flex flex-col gap-1">
                          <button
                            type="button"
                            onClick={(e) => { e.stopPropagation(); moveUp(index) }}
                            disabled={index === 0}
                            className="p-0.5 hover:bg-muted rounded disabled:opacity-30"
                          >
                            <ArrowUp className="h-3 w-3" />
                          </button>
                          <button
                            type="button"
                            onClick={(e) => { e.stopPropagation(); moveDown(index) }}
                            disabled={index >= defenseLines.length - 1}
                            className="p-0.5 hover:bg-muted rounded disabled:opacity-30"
                          >
                            <ArrowDown className="h-3 w-3" />
                          </button>
                        </div>

                        <CollapsibleTrigger asChild>
                          <button
                            type="button"
                            className="flex-1 flex items-center gap-3 text-left"
                          >
                            <ChevronDown
                              className={`h-4 w-4 transition-transform ${isExpanded ? 'rotate-0' : '-rotate-90'}`}
                            />
                            <Badge variant="secondary" className="shrink-0">
                              #{index + 1}
                            </Badge>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <Shield className="h-4 w-4 text-muted-foreground" />
                                <span className="font-medium text-sm truncate">
                                  {profile?.name || line.profile_id || 'Select Profile'}
                                </span>
                                {lineSignatures.length > 0 && (
                                  <Badge variant="outline" className="text-xs">
                                    <Target className="h-3 w-3 mr-1" />
                                    {lineSignatures.length} signature{lineSignatures.length !== 1 ? 's' : ''}
                                  </Badge>
                                )}
                              </div>
                            </div>
                          </button>
                        </CollapsibleTrigger>

                        <div className="flex items-center gap-2">
                          <Switch
                            checked={line.enabled !== false}
                            onCheckedChange={(enabled) => updateLine(index, { enabled })}
                            onClick={(e) => e.stopPropagation()}
                          />
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation()
                              removeDefenseLine(index)
                            }}
                            className="p-1 hover:bg-destructive/10 hover:text-destructive rounded"
                          >
                            <X className="h-4 w-4" />
                          </button>
                        </div>
                      </div>

                      {/* Line Content */}
                      <CollapsibleContent>
                        <div className="p-4 space-y-4 border-t">
                          {/* Profile Selection */}
                          <div className="space-y-2">
                            <Label>Defense Profile</Label>
                            <Select
                              value={line.profile_id}
                              onValueChange={(value) => updateLine(index, { profile_id: value })}
                            >
                              <SelectTrigger>
                                <SelectValue placeholder="Select a profile" />
                              </SelectTrigger>
                              <SelectContent>
                                {availableProfiles.map((p) => (
                                  <SelectItem key={p.id} value={p.id}>
                                    <div className="flex items-center gap-2">
                                      <span>{p.name}</span>
                                      {p.builtin && (
                                        <Badge variant="outline" className="text-xs">Built-in</Badge>
                                      )}
                                    </div>
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                            {profile?.description && (
                              <p className="text-xs text-muted-foreground">{profile.description}</p>
                            )}
                          </div>

                          {/* Attack Signatures */}
                          <div className="space-y-2">
                            <Label className="flex items-center gap-2">
                              <Target className="h-4 w-4" />
                              Attack Signatures
                            </Label>
                            <p className="text-xs text-muted-foreground mb-2">
                              Signatures provide attack-specific patterns that merge with the profile&apos;s defense nodes.
                            </p>

                            {/* Attached Signatures */}
                            {lineSignatures.length > 0 && (
                              <div className="space-y-2 mb-3">
                                {lineSignatures.map((sig) => (
                                  <div
                                    key={sig!.id}
                                    className="flex items-center justify-between p-2 border rounded bg-muted/20"
                                  >
                                    <div className="flex items-center gap-2 min-w-0">
                                      <Target className="h-4 w-4 text-muted-foreground shrink-0" />
                                      <span className="text-sm font-medium truncate">{sig!.name}</span>
                                      {sig!.builtin && (
                                        <Badge variant="outline" className="text-xs shrink-0">Built-in</Badge>
                                      )}
                                      {sig!.tags && sig!.tags.length > 0 && (
                                        <div className="flex gap-1 shrink-0">
                                          {sig!.tags.slice(0, 2).map((tag) => (
                                            <Badge key={tag} variant="secondary" className="text-xs">
                                              {tag}
                                            </Badge>
                                          ))}
                                        </div>
                                      )}
                                    </div>
                                    <button
                                      type="button"
                                      onClick={() => removeSignature(index, sig!.id)}
                                      className="p-1 hover:bg-destructive/10 hover:text-destructive rounded shrink-0"
                                    >
                                      <X className="h-3 w-3" />
                                    </button>
                                  </div>
                                ))}
                              </div>
                            )}

                            {/* Add Signature */}
                            {availableToAdd.length > 0 && (
                              <Select
                                value=""
                                onValueChange={(value) => addSignature(index, value)}
                              >
                                <SelectTrigger>
                                  <SelectValue placeholder="Add attack signature..." />
                                </SelectTrigger>
                                <SelectContent>
                                  {availableToAdd.map((sig) => (
                                    <SelectItem key={sig.id} value={sig.id}>
                                      <div className="flex items-center gap-2">
                                        <span>{sig.name}</span>
                                        {sig.builtin && (
                                          <Badge variant="outline" className="text-xs">Built-in</Badge>
                                        )}
                                        {sig.tags && sig.tags.length > 0 && (
                                          <span className="text-xs text-muted-foreground">
                                            ({sig.tags.slice(0, 2).join(', ')})
                                          </span>
                                        )}
                                      </div>
                                    </SelectItem>
                                  ))}
                                </SelectContent>
                              </Select>
                            )}

                            {availableToAdd.length === 0 && lineSignatures.length > 0 && (
                              <p className="text-xs text-muted-foreground">
                                All available signatures are attached.
                              </p>
                            )}
                          </div>
                        </div>
                      </CollapsibleContent>
                    </div>
                  </Collapsible>
                )
              })}
            </div>
          )}
        </div>

        {/* Links to related pages */}
        <div className="flex gap-4 text-sm">
          <a
            href="/security/defense-profiles"
            className="text-primary hover:underline flex items-center gap-1"
          >
            <Shield className="h-4 w-4" />
            Manage Defense Profiles
          </a>
          <a
            href="/security/attack-signatures"
            className="text-primary hover:underline flex items-center gap-1"
          >
            <Target className="h-4 w-4" />
            Manage Attack Signatures
          </a>
        </div>
      </CardContent>
    </Card>
  )
}
