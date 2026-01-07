import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { backupApi } from '@/api/client'
import type { BackupEntityInfo, BackupExportOptions } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Loader2, Download, CheckCircle } from 'lucide-react'

interface ExportDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  entities: BackupEntityInfo[]
}

export function ExportDialog({ open, onOpenChange, entities }: ExportDialogProps) {
  const [includeUsers, setIncludeUsers] = useState(false)
  const [includeBuiltins, setIncludeBuiltins] = useState(true)
  const [selectedEntities, setSelectedEntities] = useState<Set<string>>(new Set())
  const [exportComplete, setExportComplete] = useState(false)

  const exportMutation = useMutation({
    mutationFn: (options: BackupExportOptions) => backupApi.downloadExport(options),
    onSuccess: () => {
      setExportComplete(true)
      setTimeout(() => {
        setExportComplete(false)
        onOpenChange(false)
      }, 2000)
    },
  })

  const handleExport = () => {
    const options: BackupExportOptions = {
      include_users: includeUsers,
      include_builtins: includeBuiltins,
    }

    // Only include entities filter if some are selected (not all)
    if (selectedEntities.size > 0 && selectedEntities.size < entities.length) {
      options.entities = Array.from(selectedEntities)
    }

    exportMutation.mutate(options)
  }

  const toggleEntity = (entityId: string) => {
    const newSet = new Set(selectedEntities)
    if (newSet.has(entityId)) {
      newSet.delete(entityId)
    } else {
      newSet.add(entityId)
    }
    setSelectedEntities(newSet)
  }

  const selectAll = () => {
    if (selectedEntities.size === entities.length) {
      setSelectedEntities(new Set())
    } else {
      setSelectedEntities(new Set(entities.map((e) => e.id)))
    }
  }

  const isAllSelected = selectedEntities.size === entities.length || selectedEntities.size === 0

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            Export Configuration
          </DialogTitle>
          <DialogDescription>
            Configure what to include in your backup file
          </DialogDescription>
        </DialogHeader>

        {exportComplete ? (
          <div className="flex flex-col items-center justify-center py-8">
            <CheckCircle className="h-12 w-12 text-green-500 mb-4" />
            <p className="text-lg font-medium">Export Complete!</p>
            <p className="text-sm text-muted-foreground">Your backup file has been downloaded.</p>
          </div>
        ) : (
          <>
            <div className="space-y-6">
              {/* Options */}
              <div className="space-y-4">
                <h4 className="font-medium">Options</h4>
                <div className="space-y-3">
                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="include-builtins"
                      checked={includeBuiltins}
                      onCheckedChange={(checked) => setIncludeBuiltins(checked === true)}
                    />
                    <Label htmlFor="include-builtins" className="text-sm">
                      Include built-in profiles and signatures
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="include-users"
                      checked={includeUsers}
                      onCheckedChange={(checked) => setIncludeUsers(checked === true)}
                    />
                    <Label htmlFor="include-users" className="text-sm">
                      Include users (passwords will be excluded)
                    </Label>
                  </div>
                </div>
              </div>

              {/* Entity Selection */}
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h4 className="font-medium">Entity Types</h4>
                  <Button variant="ghost" size="sm" onClick={selectAll}>
                    {isAllSelected ? 'Select None' : 'Select All'}
                  </Button>
                </div>
                <p className="text-sm text-muted-foreground">
                  Leave all unselected to export everything, or select specific types
                </p>
                <div className="grid grid-cols-2 gap-2 max-h-[200px] overflow-y-auto">
                  {entities.map((entity) => (
                    <div key={entity.id} className="flex items-center space-x-2">
                      <Checkbox
                        id={`entity-${entity.id}`}
                        checked={selectedEntities.has(entity.id)}
                        onCheckedChange={() => toggleEntity(entity.id)}
                      />
                      <Label htmlFor={`entity-${entity.id}`} className="text-sm">
                        {entity.name}
                      </Label>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button onClick={handleExport} disabled={exportMutation.isPending}>
                {exportMutation.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Exporting...
                  </>
                ) : (
                  <>
                    <Download className="h-4 w-4 mr-2" />
                    Download Backup
                  </>
                )}
              </Button>
            </DialogFooter>
          </>
        )}

        {exportMutation.isError && (
          <div className="border border-red-200 bg-red-50 rounded-lg p-3 text-sm text-red-800">
            Export failed: {(exportMutation.error as Error).message}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
