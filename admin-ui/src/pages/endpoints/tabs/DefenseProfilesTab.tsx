import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Slider } from '@/components/ui/slider'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Info, Plus, X, Shield, GripVertical, ArrowUp, ArrowDown } from 'lucide-react'
import type { DefenseProfilesTabProps } from './types'
import type { DefenseProfileAttachmentItem, DefenseAggregation, DefenseScoreAggregation } from '@/api/types'

const DEFAULT_AGGREGATION: DefenseAggregation = 'OR'
const DEFAULT_SCORE_AGGREGATION: DefenseScoreAggregation = 'SUM'

// Helper to ensure profiles is always an array
// (JSON from Lua may serialize empty tables as {} instead of [])
const ensureProfilesArray = (profiles: unknown): DefenseProfileAttachmentItem[] => {
  if (Array.isArray(profiles)) return profiles
  if (profiles && typeof profiles === 'object') {
    // Try to extract values if it's an object
    const values = Object.values(profiles)
    if (values.length > 0 && typeof values[0] === 'object') {
      return values as DefenseProfileAttachmentItem[]
    }
  }
  return []
}

export function DefenseProfilesTab({ formData, setFormData, availableProfiles }: DefenseProfilesTabProps) {
  const defenseProfiles = formData.defense_profiles

  // Get current attached profiles (ensure it's always an array)
  const attachedProfiles = ensureProfilesArray(defenseProfiles?.profiles)

  // Helper to update defense_profiles
  const updateDefenseProfiles = (updates: Partial<typeof defenseProfiles>) => {
    setFormData({
      ...formData,
      defense_profiles: {
        enabled: defenseProfiles?.enabled ?? true,
        profiles: ensureProfilesArray(defenseProfiles?.profiles),
        aggregation: defenseProfiles?.aggregation || DEFAULT_AGGREGATION,
        score_aggregation: defenseProfiles?.score_aggregation || DEFAULT_SCORE_AGGREGATION,
        ...updates,
      },
    })
  }

  // Add a profile
  const addProfile = (profileId: string) => {
    const profile = availableProfiles.find((p) => p.id === profileId)
    if (!profile) return

    const newItem: DefenseProfileAttachmentItem = {
      id: profileId,
      priority: (attachedProfiles.length + 1) * 100,
      weight: 1,
    }

    updateDefenseProfiles({
      profiles: [...attachedProfiles, newItem],
    })
  }

  // Remove a profile
  const removeProfile = (profileId: string) => {
    updateDefenseProfiles({
      profiles: attachedProfiles.filter((p) => p.id !== profileId),
    })
  }

  // Update a profile's settings
  const updateProfile = (profileId: string, updates: Partial<DefenseProfileAttachmentItem>) => {
    updateDefenseProfiles({
      profiles: attachedProfiles.map((p) =>
        p.id === profileId ? { ...p, ...updates } : p
      ),
    })
  }

  // Move profile up in priority
  const moveUp = (index: number) => {
    if (index === 0) return
    const newProfiles = [...attachedProfiles]
    const temp = newProfiles[index]
    newProfiles[index] = newProfiles[index - 1]
    newProfiles[index - 1] = temp
    // Recalculate priorities
    newProfiles.forEach((p, i) => {
      p.priority = (i + 1) * 100
    })
    updateDefenseProfiles({ profiles: newProfiles })
  }

  // Move profile down in priority
  const moveDown = (index: number) => {
    if (index >= attachedProfiles.length - 1) return
    const newProfiles = [...attachedProfiles]
    const temp = newProfiles[index]
    newProfiles[index] = newProfiles[index + 1]
    newProfiles[index + 1] = temp
    // Recalculate priorities
    newProfiles.forEach((p, i) => {
      p.priority = (i + 1) * 100
    })
    updateDefenseProfiles({ profiles: newProfiles })
  }

  // Get available (not yet attached) profiles
  const availableToAdd = availableProfiles.filter(
    (p) => !attachedProfiles.some((ap) => ap.id === p.id)
  )

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5" />
          Defense Profiles
        </CardTitle>
        <CardDescription>
          Configure which defense profiles to evaluate for this endpoint.
          Multiple profiles can run in parallel and results are aggregated.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex items-center space-x-2">
          <Switch
            id="dp_enabled"
            checked={defenseProfiles?.enabled !== false}
            onCheckedChange={(checked) => updateDefenseProfiles({ enabled: checked })}
          />
          <Label htmlFor="dp_enabled">Enable Defense Profiles</Label>
        </div>

        {defenseProfiles?.enabled !== false && (
          <>
            {/* Aggregation Settings */}
            <div className="space-y-4">
              <h4 className="font-medium text-sm">Aggregation Settings</h4>
              <div className="grid gap-4 md:grid-cols-3">
                <div className="space-y-2">
                  <Label htmlFor="aggregation">Decision Aggregation</Label>
                  <Select
                    value={defenseProfiles?.aggregation || DEFAULT_AGGREGATION}
                    onValueChange={(value: DefenseAggregation) =>
                      updateDefenseProfiles({ aggregation: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="OR">OR - Block if ANY profile blocks</SelectItem>
                      <SelectItem value="AND">AND - Block if ALL profiles block</SelectItem>
                      <SelectItem value="MAJORITY">MAJORITY - Block if &gt;50% block</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    How to combine blocking decisions
                  </p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="score_aggregation">Score Aggregation</Label>
                  <Select
                    value={defenseProfiles?.score_aggregation || DEFAULT_SCORE_AGGREGATION}
                    onValueChange={(value: DefenseScoreAggregation) =>
                      updateDefenseProfiles({ score_aggregation: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="SUM">SUM - Add all scores</SelectItem>
                      <SelectItem value="MAX">MAX - Use highest score</SelectItem>
                      <SelectItem value="WEIGHTED_AVG">WEIGHTED - Average by weight</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    How to calculate total score
                  </p>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center space-x-2 mt-6">
                    <Switch
                      id="short_circuit"
                      checked={defenseProfiles?.short_circuit !== false}
                      onCheckedChange={(checked) =>
                        updateDefenseProfiles({ short_circuit: checked })
                      }
                    />
                    <Label htmlFor="short_circuit">Short-circuit on block</Label>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Stop evaluating after first blocking profile
                  </p>
                </div>
              </div>
            </div>

            {/* Attached Profiles */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h4 className="font-medium text-sm">Attached Profiles</h4>
                <div className="text-sm text-muted-foreground">
                  {attachedProfiles.length} profile{attachedProfiles.length !== 1 ? 's' : ''} attached
                </div>
              </div>

              {attachedProfiles.length === 0 ? (
                <div className="rounded-lg border border-dashed border-amber-300 bg-amber-50 p-6 text-center">
                  <Shield className="h-8 w-8 mx-auto mb-2 text-amber-600" />
                  <p className="font-medium text-amber-800">Using Default Profile</p>
                  <p className="text-sm text-amber-700 mt-1">
                    When no profiles are attached, the <strong>Legacy</strong> profile is used automatically.
                  </p>
                  <p className="text-xs text-amber-600 mt-2">
                    This provides backward-compatible behavior with all defense mechanisms.
                    Add custom profiles below to override.
                  </p>
                </div>
              ) : (
                <div className="space-y-2">
                  {attachedProfiles.map((attached, index) => {
                    const profile = availableProfiles.find((p) => p.id === attached.id)
                    return (
                      <div
                        key={attached.id}
                        className="flex items-center gap-3 p-3 border rounded-lg bg-muted/30"
                      >
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
                            disabled={index >= attachedProfiles.length - 1}
                            className="p-0.5 hover:bg-muted rounded disabled:opacity-30"
                          >
                            <ArrowDown className="h-3 w-3" />
                          </button>
                        </div>

                        <GripVertical className="h-4 w-4 text-muted-foreground" />

                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-sm truncate">
                              {profile?.name || attached.id}
                            </span>
                            {profile?.builtin && (
                              <Badge variant="outline" className="text-xs shrink-0">
                                Built-in
                              </Badge>
                            )}
                            <Badge variant="secondary" className="text-xs shrink-0">
                              #{index + 1}
                            </Badge>
                          </div>
                          {profile?.description && (
                            <p className="text-xs text-muted-foreground truncate">
                              {profile.description}
                            </p>
                          )}
                        </div>

                        <div className="flex items-center gap-4">
                          <div className="w-32">
                            <Label className="text-xs text-muted-foreground">
                              Weight: {Math.round((attached.weight ?? 1) * 100)}%
                            </Label>
                            <Slider
                              value={[(attached.weight ?? 1) * 100]}
                              min={0}
                              max={100}
                              step={5}
                              onValueChange={([value]) =>
                                updateProfile(attached.id, { weight: value / 100 })
                              }
                            />
                          </div>

                          <button
                            type="button"
                            onClick={() => removeProfile(attached.id)}
                            className="p-1 hover:bg-destructive/10 hover:text-destructive rounded"
                          >
                            <X className="h-4 w-4" />
                          </button>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>

            {/* Available Profiles */}
            {availableToAdd.length > 0 && (
              <div className="space-y-4">
                <h4 className="font-medium text-sm">Available Profiles</h4>
                <div className="grid gap-2 md:grid-cols-2">
                  {availableToAdd.map((profile) => (
                    <div
                      key={profile.id}
                      className="flex items-center justify-between p-3 border rounded-lg cursor-pointer hover:bg-muted/50 transition-colors"
                      onClick={() => addProfile(profile.id)}
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-sm truncate">
                            {profile.name}
                          </span>
                          {profile.builtin && (
                            <Badge variant="outline" className="text-xs">
                              Built-in
                            </Badge>
                          )}
                        </div>
                        {profile.description && (
                          <p className="text-xs text-muted-foreground truncate">
                            {profile.description}
                          </p>
                        )}
                      </div>
                      <Plus className="h-4 w-4 text-muted-foreground shrink-0 ml-2" />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Info note */}
            <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
              <div className="flex items-start gap-3">
                <Info className="h-5 w-5 text-blue-600 mt-0.5 shrink-0" />
                <div>
                  <p className="font-medium text-blue-800">How It Works</p>
                  <ul className="text-sm text-blue-700 mt-1 space-y-1 list-disc list-inside">
                    <li><strong>Default:</strong> If no profiles are attached, the &quot;Legacy&quot; profile runs automatically</li>
                    <li>Profiles are evaluated in parallel for performance</li>
                    <li>Each profile returns a score and block/allow decision</li>
                    <li>Results are aggregated using the configured strategies</li>
                    <li>Endpoint settings override vhost-level configuration</li>
                  </ul>
                  <p className="text-sm text-blue-700 mt-2">
                    Manage profiles in{' '}
                    <a href="/security/defense-profiles" className="underline font-medium">
                      Security &gt; Defense Profiles
                    </a>
                  </p>
                </div>
              </div>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}
