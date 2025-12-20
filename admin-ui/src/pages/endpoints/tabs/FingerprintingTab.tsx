import { Input } from '@/components/ui/input'
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
import { Info, Plus, X, Fingerprint } from 'lucide-react'
import type { FingerprintingTabProps } from './types'

export function FingerprintingTab({ formData, setFormData, availableProfiles }: FingerprintingTabProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Fingerprint className="h-5 w-5" />
          Fingerprint Profiles
        </CardTitle>
        <CardDescription>
          Configure which fingerprint profiles to use for this endpoint.
          Endpoint settings override vhost-level configuration.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex items-center space-x-2">
          <Switch
            id="fp_enabled"
            checked={formData.fingerprint_profiles?.enabled !== false}
            onCheckedChange={(checked) =>
              setFormData({
                ...formData,
                fingerprint_profiles: { ...formData.fingerprint_profiles, enabled: checked },
              })
            }
          />
          <Label htmlFor="fp_enabled">Enable Fingerprint Profiles</Label>
        </div>

        {formData.fingerprint_profiles?.enabled !== false && (
          <>
            {/* Profile Selection */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h4 className="font-medium text-sm">Profile Selection</h4>
                <div className="text-sm text-muted-foreground">
                  {formData.fingerprint_profiles?.profiles?.length || 0} selected
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center space-x-2 mb-4">
                  <Switch
                    id="fp_use_all"
                    checked={!formData.fingerprint_profiles?.profiles || formData.fingerprint_profiles.profiles.length === 0}
                    onCheckedChange={(checked) =>
                      setFormData({
                        ...formData,
                        fingerprint_profiles: {
                          ...formData.fingerprint_profiles,
                          enabled: true,
                          profiles: checked ? undefined : [],
                        },
                      })
                    }
                  />
                  <Label htmlFor="fp_use_all">Use all global profiles (or inherit from vhost)</Label>
                </div>

                {formData.fingerprint_profiles?.profiles && formData.fingerprint_profiles.profiles.length >= 0 && (
                  <div className="space-y-2">
                    <Label>Selected Profiles (in priority order)</Label>
                    <div className="flex flex-wrap gap-2 min-h-[40px] p-2 border rounded-md bg-muted/30">
                      {(formData.fingerprint_profiles?.profiles || []).map((profileId) => {
                        const profile = availableProfiles.find((p) => p.id === profileId)
                        return (
                          <Badge
                            key={profileId}
                            variant="secondary"
                            className="flex items-center gap-1 cursor-pointer hover:bg-secondary/80"
                          >
                            {profile?.name || profileId}
                            <button
                              type="button"
                              onClick={() => {
                                setFormData({
                                  ...formData,
                                  fingerprint_profiles: {
                                    ...formData.fingerprint_profiles,
                                    enabled: true,
                                    profiles: (formData.fingerprint_profiles?.profiles || []).filter(
                                      (id) => id !== profileId
                                    ),
                                  },
                                })
                              }}
                              className="ml-1 hover:text-destructive"
                            >
                              <X className="h-3 w-3" />
                            </button>
                          </Badge>
                        )
                      })}
                      {(formData.fingerprint_profiles?.profiles || []).length === 0 && (
                        <span className="text-sm text-muted-foreground">
                          No profiles selected - click profiles below to add
                        </span>
                      )}
                    </div>

                    <Label className="mt-4">Available Profiles</Label>
                    <div className="grid gap-2 md:grid-cols-2">
                      {availableProfiles
                        .filter((p) => !(formData.fingerprint_profiles?.profiles || []).includes(p.id))
                        .map((profile) => (
                          <div
                            key={profile.id}
                            className="flex items-center justify-between p-3 border rounded-lg cursor-pointer hover:bg-muted/50"
                            onClick={() => {
                              setFormData({
                                ...formData,
                                fingerprint_profiles: {
                                  ...formData.fingerprint_profiles,
                                  enabled: true,
                                  profiles: [
                                    ...(formData.fingerprint_profiles?.profiles || []),
                                    profile.id,
                                  ],
                                },
                              })
                            }}
                          >
                            <div>
                              <div className="font-medium text-sm">
                                {profile.name}
                                {profile.builtin && (
                                  <Badge variant="outline" className="ml-2 text-xs">
                                    Built-in
                                  </Badge>
                                )}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                Priority: {profile.priority} | Action: {profile.action}
                                {profile.action === 'flag' && profile.score ? ` (+${profile.score})` : ''}
                              </div>
                            </div>
                            <Plus className="h-4 w-4 text-muted-foreground" />
                          </div>
                        ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* No Match Behavior */}
            <div className="space-y-4">
              <h4 className="font-medium text-sm">No Match Behavior</h4>
              <p className="text-sm text-muted-foreground">
                Configure what happens when no profile matches the request
              </p>

              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="no_match_action">Action</Label>
                  <Select
                    value={formData.fingerprint_profiles?.no_match_action || 'use_default'}
                    onValueChange={(value) =>
                      setFormData({
                        ...formData,
                        fingerprint_profiles: {
                          ...formData.fingerprint_profiles,
                          enabled: true,
                          no_match_action: value as 'use_default' | 'flag' | 'allow',
                        },
                      })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="use_default">Use Default (legacy fingerprint)</SelectItem>
                      <SelectItem value="flag">Flag as Suspicious</SelectItem>
                      <SelectItem value="allow">Allow (no action)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {formData.fingerprint_profiles?.no_match_action === 'flag' && (
                  <div className="space-y-2">
                    <Label htmlFor="no_match_score">Score to Add</Label>
                    <Input
                      id="no_match_score"
                      type="number"
                      min={0}
                      max={100}
                      value={formData.fingerprint_profiles?.no_match_score ?? 15}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          fingerprint_profiles: {
                            ...formData.fingerprint_profiles,
                            enabled: true,
                            no_match_score: parseInt(e.target.value) || 15,
                          },
                        })
                      }
                    />
                  </div>
                )}
              </div>
            </div>

            {/* Info note */}
            <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
              <div className="flex items-start gap-3">
                <Info className="h-5 w-5 text-blue-600 mt-0.5" />
                <div>
                  <p className="font-medium text-blue-800">Inheritance</p>
                  <p className="text-sm text-blue-700 mt-1">
                    Endpoint fingerprint profile settings override vhost-level configuration.
                    If not configured here, the vhost settings (or global defaults) will be used.
                  </p>
                  <p className="text-sm text-blue-700 mt-2">
                    Manage profiles in{' '}
                    <a href="/security/fingerprint-profiles" className="underline font-medium">
                      Security &gt; Fingerprint Profiles
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
