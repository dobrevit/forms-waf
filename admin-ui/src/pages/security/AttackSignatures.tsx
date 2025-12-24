import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { attackSignaturesApi } from '@/api/client'
import type { AttackSignature } from '@/api/types'
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/components/ui/use-toast'
import { usePermissions } from '@/hooks/usePermissions'
import {
  Plus,
  Trash2,
  Target,
  RotateCcw,
  Loader2,
  Copy,
  Edit,
  Filter,
  Download,
  Upload,
  BarChart3,
  AlertTriangle,
  Clock,
} from 'lucide-react'
import { SignatureStatsSummary } from '@/components/attack-signatures/SignatureStatsSummary'

// Check if a signature is expiring within the given days
function isExpiringSoon(expiresAt: string | undefined, withinDays: number = 7): boolean {
  if (!expiresAt) return false
  const expiryDate = new Date(expiresAt)
  const now = new Date()
  const diffMs = expiryDate.getTime() - now.getTime()
  const diffDays = diffMs / (1000 * 60 * 60 * 24)
  return diffDays > 0 && diffDays <= withinDays
}

// Check if a signature has expired
function isExpired(expiresAt: string | undefined): boolean {
  if (!expiresAt) return false
  const expiryDate = new Date(expiresAt)
  return expiryDate.getTime() < Date.now()
}

// Format days until expiry
function formatDaysUntilExpiry(expiresAt: string | undefined): string {
  if (!expiresAt) return ''
  const expiryDate = new Date(expiresAt)
  const now = new Date()
  const diffMs = expiryDate.getTime() - now.getTime()
  const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24))
  if (diffDays <= 0) return 'Expired'
  if (diffDays === 1) return '1 day'
  return `${diffDays} days`
}

export default function AttackSignatures() {
  const navigate = useNavigate()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const {
    canCreateAttackSignature,
    canEditAttackSignature,
    canDeleteAttackSignature,
    canResetAttackSignatures,
  } = usePermissions()

  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const [cloneDialogOpen, setCloneDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [exportDialogOpen, setExportDialogOpen] = useState(false)
  const [importDialogOpen, setImportDialogOpen] = useState(false)
  const [selectedSignature, setSelectedSignature] = useState<AttackSignature | null>(null)
  const [filterTag, setFilterTag] = useState<string>('_all')
  const [filterEnabled, setFilterEnabled] = useState<string>('all')

  const [newSignature, setNewSignature] = useState({
    id: '',
    name: '',
    description: '',
    priority: 100,
    tags: '',
  })

  const [cloneData, setCloneData] = useState({
    id: '',
    name: '',
  })

  const [importData, setImportData] = useState('')

  // Fetch signatures with stats
  const { data: signaturesData, isLoading } = useQuery({
    queryKey: ['attack-signatures', filterTag, filterEnabled],
    queryFn: () => attackSignaturesApi.list({
      tag: filterTag === '_all' ? undefined : filterTag,
      enabled: filterEnabled === 'all' ? undefined : filterEnabled === 'enabled',
      include_stats: true,
    }),
  })

  // Fetch tags for filter
  const { data: tagsData } = useQuery({
    queryKey: ['attack-signature-tags'],
    queryFn: () => attackSignaturesApi.getTags(),
  })

  const signatures = signaturesData?.signatures || []
  const tags = tagsData?.tags || []

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (data: Parameters<typeof attackSignaturesApi.create>[0]) =>
      attackSignaturesApi.create(data),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['attack-signatures'] })
      queryClient.invalidateQueries({ queryKey: ['attack-signature-tags'] })
      setCreateDialogOpen(false)
      setNewSignature({ id: '', name: '', description: '', priority: 100, tags: '' })
      toast({
        title: 'Signature Created',
        description: 'Attack signature has been created successfully.',
      })
      // Navigate to editor
      navigate(`/security/attack-signatures/${data.signature.id}`)
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
      attackSignaturesApi.clone(sourceId, newId, newName),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attack-signatures'] })
      setCloneDialogOpen(false)
      setSelectedSignature(null)
      setCloneData({ id: '', name: '' })
      toast({
        title: 'Signature Cloned',
        description: 'Attack signature has been cloned successfully.',
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
    mutationFn: (id: string) => attackSignaturesApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attack-signatures'] })
      queryClient.invalidateQueries({ queryKey: ['attack-signature-tags'] })
      setDeleteDialogOpen(false)
      setSelectedSignature(null)
      toast({
        title: 'Signature Deleted',
        description: 'Attack signature has been deleted.',
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
        return attackSignaturesApi.enable(id)
      } else {
        return attackSignaturesApi.disable(id)
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attack-signatures'] })
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
    mutationFn: () => attackSignaturesApi.resetBuiltins(),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['attack-signatures'] })
      queryClient.invalidateQueries({ queryKey: ['attack-signature-tags'] })
      toast({
        title: 'Signatures Reset',
        description: `${data.count} built-in signatures have been reset to defaults.`,
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

  // Export mutation
  const exportMutation = useMutation({
    mutationFn: () => attackSignaturesApi.export(),
    onSuccess: (data) => {
      // Create download
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `attack-signatures-${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      setExportDialogOpen(false)
      toast({
        title: 'Export Complete',
        description: `Exported ${data.count} signatures.`,
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

  // Import mutation
  const importMutation = useMutation({
    mutationFn: (signatures: AttackSignature[]) =>
      attackSignaturesApi.import(signatures, { skip_existing: true }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['attack-signatures'] })
      queryClient.invalidateQueries({ queryKey: ['attack-signature-tags'] })
      setImportDialogOpen(false)
      setImportData('')
      toast({
        title: 'Import Complete',
        description: `Imported ${data.imported} of ${data.total} signatures.${data.errors.length ? ` ${data.errors.length} errors.` : ''}`,
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
    if (!newSignature.id || !newSignature.name) {
      toast({
        title: 'Validation Error',
        description: 'ID and Name are required.',
        variant: 'destructive',
      })
      return
    }

    const tagsArray = newSignature.tags
      .split(',')
      .map(t => t.trim())
      .filter(t => t.length > 0)

    createMutation.mutate({
      id: newSignature.id,
      name: newSignature.name,
      description: newSignature.description,
      enabled: true,
      priority: newSignature.priority,
      tags: tagsArray,
      signatures: {},
    })
  }

  const handleClone = () => {
    if (!selectedSignature || !cloneData.id || !cloneData.name) {
      toast({
        title: 'Validation Error',
        description: 'ID and Name are required.',
        variant: 'destructive',
      })
      return
    }

    cloneMutation.mutate({
      sourceId: selectedSignature.id,
      newId: cloneData.id,
      newName: cloneData.name,
    })
  }

  const handleImport = () => {
    try {
      const parsed = JSON.parse(importData)
      const signatures = parsed.signatures || parsed
      if (!Array.isArray(signatures)) {
        throw new Error('Expected signatures array')
      }
      importMutation.mutate(signatures)
    } catch (e) {
      toast({
        title: 'Invalid JSON',
        description: 'Please provide valid JSON with a signatures array.',
        variant: 'destructive',
      })
    }
  }

  const openCloneDialog = (signature: AttackSignature) => {
    setSelectedSignature(signature)
    setCloneData({
      id: `${signature.id}-copy`,
      name: `${signature.name} (Copy)`,
    })
    setCloneDialogOpen(true)
  }

  const openDeleteDialog = (signature: AttackSignature) => {
    setSelectedSignature(signature)
    setDeleteDialogOpen(true)
  }

  const getSignatureDefenseCount = (signature: AttackSignature): number => {
    return Object.keys(signature.signatures || {}).length
  }

  const formatNumber = (num: number): string => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
    return num.toString()
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
          <h2 className="text-2xl font-bold tracking-tight">Attack Signatures</h2>
          <p className="text-muted-foreground">
            Define attack-specific patterns to match against requests
          </p>
        </div>
        <div className="flex gap-2">
          {canResetAttackSignatures && (
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
          )}
          <Button
            variant="outline"
            onClick={() => setExportDialogOpen(true)}
          >
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
          {canCreateAttackSignature && (
            <>
              <Button
                variant="outline"
                onClick={() => setImportDialogOpen(true)}
              >
                <Upload className="h-4 w-4 mr-2" />
                Import
              </Button>
              <Button onClick={() => setCreateDialogOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />
                New Signature
              </Button>
            </>
          )}
        </div>
      </div>

      {/* Stats Summary */}
      <SignatureStatsSummary />

      {/* Expiration Warning Banner */}
      {(() => {
        const expiringSoon = signatures.filter(s => isExpiringSoon(s.expires_at, 7))
        const expired = signatures.filter(s => isExpired(s.expires_at))
        if (expiringSoon.length === 0 && expired.length === 0) return null
        return (
          <Card className="border-amber-200 bg-amber-50">
            <CardContent className="py-3">
              <div className="flex items-center gap-3">
                <AlertTriangle className="h-5 w-5 text-amber-600 shrink-0" />
                <div className="flex-1">
                  {expired.length > 0 && (
                    <p className="text-sm font-medium text-amber-800">
                      {expired.length} signature{expired.length !== 1 ? 's have' : ' has'} expired
                    </p>
                  )}
                  {expiringSoon.length > 0 && (
                    <p className="text-sm text-amber-700">
                      {expiringSoon.length} signature{expiringSoon.length !== 1 ? 's' : ''} expiring within 7 days
                    </p>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        )
      })()}

      {/* Filters */}
      <div className="flex gap-4">
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <Select value={filterTag} onValueChange={setFilterTag}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="All Tags" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="_all">All Tags</SelectItem>
              {tags.map((tagObj) => (
                <SelectItem key={tagObj.tag} value={tagObj.tag}>
                  {tagObj.tag} ({tagObj.count})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <Select value={filterEnabled} onValueChange={setFilterEnabled}>
          <SelectTrigger className="w-[140px]">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="enabled">Enabled</SelectItem>
            <SelectItem value="disabled">Disabled</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Target className="h-5 w-5" />
            Attack Signatures
          </CardTitle>
          <CardDescription>
            Attack-specific patterns that can be attached to defense profiles for targeted protection
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Signature</TableHead>
                <TableHead>Tags</TableHead>
                <TableHead>Priority</TableHead>
                <TableHead>Defenses</TableHead>
                <TableHead>Matches</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {signatures.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">
                    No attack signatures found
                  </TableCell>
                </TableRow>
              ) : (
                signatures.map((signature) => (
                  <TableRow key={signature.id}>
                    <TableCell>
                      <div className="flex flex-col gap-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-medium">{signature.name}</span>
                          {signature.builtin && (
                            <Badge variant="secondary" className="text-xs">Built-in</Badge>
                          )}
                          {isExpired(signature.expires_at) && (
                            <Badge variant="destructive" className="text-xs flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              Expired
                            </Badge>
                          )}
                          {!isExpired(signature.expires_at) && isExpiringSoon(signature.expires_at, 7) && (
                            <Badge variant="outline" className="text-xs text-amber-600 border-amber-300 flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {formatDaysUntilExpiry(signature.expires_at)}
                            </Badge>
                          )}
                        </div>
                        <span className="text-sm text-muted-foreground">
                          {signature.description || `ID: ${signature.id}`}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {signature.tags?.slice(0, 3).map((tag) => (
                          <Badge key={tag} variant="outline" className="text-xs">
                            {tag}
                          </Badge>
                        ))}
                        {(signature.tags?.length || 0) > 3 && (
                          <Badge variant="outline" className="text-xs">
                            +{(signature.tags?.length || 0) - 3}
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{signature.priority || 100}</Badge>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-sm">
                        {getSignatureDefenseCount(signature)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <BarChart3 className="h-3 w-3 text-muted-foreground" />
                        <span className="font-mono text-sm">
                          {formatNumber(signature.stats?.total_matches || 0)}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={signature.enabled}
                        onCheckedChange={(enabled) =>
                          toggleMutation.mutate({ id: signature.id, enabled })
                        }
                        disabled={!canEditAttackSignature}
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => navigate(`/security/attack-signatures/${signature.id}`)}
                          title="Edit Signature"
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        {canCreateAttackSignature && (
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => openCloneDialog(signature)}
                            title="Clone"
                          >
                            <Copy className="h-4 w-4" />
                          </Button>
                        )}
                        {!signature.builtin && canDeleteAttackSignature && (
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => openDeleteDialog(signature)}
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
            <DialogTitle>Create Attack Signature</DialogTitle>
            <DialogDescription>
              Create a new attack signature. You can configure the patterns in the editor.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="signature-id">Signature ID</Label>
              <Input
                id="signature-id"
                placeholder="my-attack-signature"
                value={newSignature.id}
                onChange={(e) => setNewSignature({ ...newSignature, id: e.target.value })}
              />
              <p className="text-sm text-muted-foreground">
                Unique identifier (alphanumeric, hyphens, underscores only)
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="signature-name">Name</Label>
              <Input
                id="signature-name"
                placeholder="My Attack Signature"
                value={newSignature.name}
                onChange={(e) => setNewSignature({ ...newSignature, name: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="signature-description">Description</Label>
              <Textarea
                id="signature-description"
                placeholder="Describe what this signature detects..."
                value={newSignature.description}
                onChange={(e) => setNewSignature({ ...newSignature, description: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="signature-tags">Tags</Label>
              <Input
                id="signature-tags"
                placeholder="wordpress, login, brute-force"
                value={newSignature.tags}
                onChange={(e) => setNewSignature({ ...newSignature, tags: e.target.value })}
              />
              <p className="text-sm text-muted-foreground">
                Comma-separated tags for categorization
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="signature-priority">Priority</Label>
              <Input
                id="signature-priority"
                type="number"
                value={newSignature.priority}
                onChange={(e) => setNewSignature({ ...newSignature, priority: parseInt(e.target.value) || 100 })}
              />
              <p className="text-sm text-muted-foreground">
                Lower numbers = higher priority (applied first)
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreate} disabled={createMutation.isPending}>
              {createMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Create & Edit
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Clone Dialog */}
      <Dialog open={cloneDialogOpen} onOpenChange={setCloneDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Clone Signature</DialogTitle>
            <DialogDescription>
              Create a copy of "{selectedSignature?.name}" with a new ID.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="clone-id">New Signature ID</Label>
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
              Clone Signature
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Signature</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{selectedSignature?.name}"? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => selectedSignature && deleteMutation.mutate(selectedSignature.id)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Export Dialog */}
      <AlertDialog open={exportDialogOpen} onOpenChange={setExportDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Export Signatures</AlertDialogTitle>
            <AlertDialogDescription>
              Export all attack signatures as JSON for backup or sharing.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => exportMutation.mutate()}
              disabled={exportMutation.isPending}
            >
              {exportMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Export
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Import Dialog */}
      <Dialog open={importDialogOpen} onOpenChange={setImportDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Import Signatures</DialogTitle>
            <DialogDescription>
              Paste JSON to import attack signatures. Existing signatures with the same ID will be skipped.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <Textarea
              placeholder='{"signatures": [...]}'
              className="min-h-[300px] font-mono text-sm"
              value={importData}
              onChange={(e) => setImportData(e.target.value)}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleImport} disabled={importMutation.isPending || !importData}>
              {importMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Import
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
