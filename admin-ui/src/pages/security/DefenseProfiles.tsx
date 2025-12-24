import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { defenseProfilesApi } from '@/api/client'
import type { DefenseProfile } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/components/ui/use-toast'
import {
  Plus,
  Trash2,
  Shield,
  RotateCcw,
  Loader2,
  Copy,
  Play,
  GitBranch,
  Workflow,
} from 'lucide-react'
import { SimulateDialog } from '@/components/defense-profile/SimulateDialog'

const PROFILE_DESCRIPTIONS: Record<string, string> = {
  'legacy': 'Mirrors the original linear execution order for backward compatibility',
  'balanced-web': 'Good for typical web forms with CAPTCHA for medium scores',
  'strict-api': 'High-security for API endpoints with tarpit for suspicious requests',
  'permissive': 'Minimal protection for high-traffic, low-risk pages',
  'high-value': 'Maximum protection for payment and signup forms',
  'monitor-only': 'Runs all checks but never blocks - for testing and observation',
}

export default function DefenseProfiles() {
  const navigate = useNavigate()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const [cloneDialogOpen, setCloneDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [simulateDialogOpen, setSimulateDialogOpen] = useState(false)
  const [selectedProfile, setSelectedProfile] = useState<DefenseProfile | null>(null)
  const [simulateProfile, setSimulateProfile] = useState<DefenseProfile | null>(null)

  const [newProfile, setNewProfile] = useState({
    id: '',
    name: '',
    description: '',
    priority: 500,
  })

  const [cloneData, setCloneData] = useState({
    id: '',
    name: '',
  })

  // Fetch profiles
  const { data: profilesData, isLoading } = useQuery({
    queryKey: ['defense-profiles'],
    queryFn: () => defenseProfilesApi.list(),
  })

  const profiles = profilesData?.profiles || []

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (data: Omit<DefenseProfile, 'builtin'>) => defenseProfilesApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['defense-profiles'] })
      setCreateDialogOpen(false)
      setNewProfile({ id: '', name: '', description: '', priority: 500 })
      toast({
        title: 'Profile Created',
        description: 'Defense profile has been created successfully.',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: error.message,
        variant: 'destructive',
      })
    },
  })

  // Clone mutation
  const cloneMutation = useMutation({
    mutationFn: ({ sourceId, newId, newName }: { sourceId: string; newId: string; newName: string }) =>
      defenseProfilesApi.clone(sourceId, newId, newName),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['defense-profiles'] })
      setCloneDialogOpen(false)
      setSelectedProfile(null)
      setCloneData({ id: '', name: '' })
      toast({
        title: 'Profile Cloned',
        description: 'Defense profile has been cloned successfully.',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: error.message,
        variant: 'destructive',
      })
    },
  })

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => defenseProfilesApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['defense-profiles'] })
      setDeleteDialogOpen(false)
      setSelectedProfile(null)
      toast({
        title: 'Profile Deleted',
        description: 'Defense profile has been deleted.',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: error.message,
        variant: 'destructive',
      })
    },
  })

  // Toggle enabled mutation
  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      if (enabled) {
        return defenseProfilesApi.enable(id)
      } else {
        return defenseProfilesApi.disable(id)
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['defense-profiles'] })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: error.message,
        variant: 'destructive',
      })
    },
  })

  // Reset builtins mutation
  const resetMutation = useMutation({
    mutationFn: () => defenseProfilesApi.resetBuiltins(),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['defense-profiles'] })
      toast({
        title: 'Profiles Reset',
        description: `${data.count} built-in profiles have been reset to defaults.`,
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: error.message,
        variant: 'destructive',
      })
    },
  })

  const handleCreate = () => {
    if (!newProfile.id || !newProfile.name) {
      toast({
        title: 'Validation Error',
        description: 'ID and Name are required.',
        variant: 'destructive',
      })
      return
    }

    // Create with minimal graph structure
    createMutation.mutate({
      id: newProfile.id,
      name: newProfile.name,
      description: newProfile.description,
      enabled: true,
      priority: newProfile.priority,
      graph: {
        nodes: [
          {
            id: 'start',
            type: 'start',
            position: { x: 100, y: 200 },
            outputs: { next: 'action_allow' },
          },
          {
            id: 'action_allow',
            type: 'action',
            action: 'allow',
            position: { x: 300, y: 200 },
          },
        ],
      },
      settings: {
        default_action: 'allow',
        max_execution_time_ms: 100,
      },
    })
  }

  const handleClone = () => {
    if (!selectedProfile || !cloneData.id || !cloneData.name) {
      toast({
        title: 'Validation Error',
        description: 'ID and Name are required.',
        variant: 'destructive',
      })
      return
    }

    cloneMutation.mutate({
      sourceId: selectedProfile.id,
      newId: cloneData.id,
      newName: cloneData.name,
    })
  }

  const openCloneDialog = (profile: DefenseProfile) => {
    setSelectedProfile(profile)
    setCloneData({
      id: `${profile.id}-copy`,
      name: `${profile.name} (Copy)`,
    })
    setCloneDialogOpen(true)
  }

  const openDeleteDialog = (profile: DefenseProfile) => {
    setSelectedProfile(profile)
    setDeleteDialogOpen(true)
  }

  const openSimulateDialog = useCallback((profile: DefenseProfile) => {
    setSimulateProfile(profile)
    setSimulateDialogOpen(true)
  }, [])

  const getNodeCount = (profile: DefenseProfile): number => {
    return profile.graph?.nodes?.length || 0
  }

  const getDefenseCount = (profile: DefenseProfile): number => {
    return profile.graph?.nodes?.filter(n => n.type === 'defense').length || 0
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Defense Profiles</h2>
          <p className="text-muted-foreground">
            Configure defense mechanisms as visual flow-based pipelines
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => resetMutation.mutate()}
            disabled={resetMutation.isPending}
          >
            {resetMutation.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <RotateCcw className="h-4 w-4 mr-2" />
            )}
            Reset Built-ins
          </Button>
          <Button onClick={() => setCreateDialogOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            New Profile
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Defense Profiles
          </CardTitle>
          <CardDescription>
            Define how traffic flows through defense mechanisms with customizable DAG-based processing
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Profile</TableHead>
                <TableHead>Priority</TableHead>
                <TableHead>Nodes</TableHead>
                <TableHead>Defenses</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {profiles.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground">
                    No defense profiles found
                  </TableCell>
                </TableRow>
              ) : (
                profiles.map((profile) => (
                  <TableRow key={profile.id}>
                    <TableCell>
                      <div className="flex flex-col gap-1">
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{profile.name}</span>
                          {profile.builtin && (
                            <Badge variant="secondary" className="text-xs">Built-in</Badge>
                          )}
                          {profile.extends && (
                            <Badge variant="outline" className="text-xs">
                              <GitBranch className="h-3 w-3 mr-1" />
                              {profile.extends}
                            </Badge>
                          )}
                        </div>
                        <span className="text-sm text-muted-foreground">
                          {profile.description || PROFILE_DESCRIPTIONS[profile.id] || `ID: ${profile.id}`}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{profile.priority}</Badge>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-sm">{getNodeCount(profile)}</span>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-sm">{getDefenseCount(profile)}</span>
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={profile.enabled}
                        onCheckedChange={(enabled) =>
                          toggleMutation.mutate({ id: profile.id, enabled })
                        }
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => navigate(`/security/defense-profiles/${profile.id}`)}
                          title="Edit in Visual Editor"
                        >
                          <Workflow className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => openSimulateDialog(profile)}
                          title="Simulate"
                        >
                          <Play className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => openCloneDialog(profile)}
                          title="Clone"
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                        {!profile.builtin && (
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => openDeleteDialog(profile)}
                            title="Delete"
                          >
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Create Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Defense Profile</DialogTitle>
            <DialogDescription>
              Create a new defense profile. You can configure the defense flow in the visual editor.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="profile-id">Profile ID</Label>
              <Input
                id="profile-id"
                placeholder="my-custom-profile"
                value={newProfile.id}
                onChange={(e) => setNewProfile({ ...newProfile, id: e.target.value })}
              />
              <p className="text-sm text-muted-foreground">
                Unique identifier (alphanumeric, hyphens, underscores only)
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="profile-name">Name</Label>
              <Input
                id="profile-name"
                placeholder="My Custom Profile"
                value={newProfile.name}
                onChange={(e) => setNewProfile({ ...newProfile, name: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="profile-description">Description</Label>
              <Textarea
                id="profile-description"
                placeholder="Describe what this profile does..."
                value={newProfile.description}
                onChange={(e) => setNewProfile({ ...newProfile, description: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="profile-priority">Priority</Label>
              <Input
                id="profile-priority"
                type="number"
                value={newProfile.priority}
                onChange={(e) => setNewProfile({ ...newProfile, priority: parseInt(e.target.value) || 500 })}
              />
              <p className="text-sm text-muted-foreground">
                Lower numbers = higher priority. Built-in profiles range from 25-1000.
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreate} disabled={createMutation.isPending}>
              {createMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Create Profile
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Clone Dialog */}
      <Dialog open={cloneDialogOpen} onOpenChange={setCloneDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Clone Profile</DialogTitle>
            <DialogDescription>
              Create a copy of "{selectedProfile?.name}" with a new ID.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="clone-id">New Profile ID</Label>
              <Input
                id="clone-id"
                value={cloneData.id}
                onChange={(e) => setCloneData({ ...cloneData, id: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="clone-name">New Name</Label>
              <Input
                id="clone-name"
                value={cloneData.name}
                onChange={(e) => setCloneData({ ...cloneData, name: e.target.value })}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCloneDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleClone} disabled={cloneMutation.isPending}>
              {cloneMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Clone Profile
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Profile</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{selectedProfile?.name}"? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => selectedProfile && deleteMutation.mutate(selectedProfile.id)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Simulate Dialog */}
      {simulateProfile && (
        <SimulateDialog
          open={simulateDialogOpen}
          onOpenChange={setSimulateDialogOpen}
          profileId={simulateProfile.id}
          profileName={simulateProfile.name}
        />
      )}
    </div>
  )
}
