import { useState, useRef, useCallback } from 'react'
import { useMutation } from '@tanstack/react-query'
import { backupApi } from '@/api/client'
import type { Backup, BackupImportMode, BackupValidationResult, BackupImportResponse } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Loader2, Upload, CheckCircle, AlertTriangle, XCircle, FileJson } from 'lucide-react'

interface ImportDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

type ImportStep = 'upload' | 'validate' | 'configure' | 'importing' | 'complete'

export function ImportDialog({ open, onOpenChange }: ImportDialogProps) {
  const [step, setStep] = useState<ImportStep>('upload')
  const [backup, setBackup] = useState<Backup | null>(null)
  const [validation, setValidation] = useState<BackupValidationResult | null>(null)
  const [importMode, setImportMode] = useState<BackupImportMode>('merge')
  const [includeUsers, setIncludeUsers] = useState(true)
  const [importResult, setImportResult] = useState<BackupImportResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const validateMutation = useMutation({
    mutationFn: (backup: Backup) => backupApi.validate(backup),
    onSuccess: (result) => {
      setValidation(result)
      setStep('configure')
    },
    onError: (err: Error) => {
      setError(err.message)
    },
  })

  const importMutation = useMutation({
    mutationFn: ({ backup, mode, includeUsers }: { backup: Backup; mode: BackupImportMode; includeUsers: boolean }) =>
      backupApi.import(backup, mode, includeUsers),
    onSuccess: (result) => {
      setImportResult(result)
      setStep('complete')
    },
    onError: (err: Error) => {
      setError(err.message)
      setStep('configure')
    },
  })

  const handleFileSelect = useCallback(async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    setError(null)

    try {
      const text = await file.text()
      const parsed = JSON.parse(text) as Backup

      if (!parsed.metadata || !parsed.data) {
        throw new Error('Invalid backup file format')
      }

      setBackup(parsed)
      setStep('validate')
      validateMutation.mutate(parsed)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to parse backup file')
    }
  }, [validateMutation])

  const handleImport = () => {
    if (!backup) return
    setStep('importing')
    importMutation.mutate({ backup, mode: importMode, includeUsers })
  }

  const handleClose = () => {
    setStep('upload')
    setBackup(null)
    setValidation(null)
    setImportResult(null)
    setError(null)
    setImportMode('merge')
    setIncludeUsers(true)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
    onOpenChange(false)
  }

  const handleDrop = useCallback((event: React.DragEvent) => {
    event.preventDefault()
    const file = event.dataTransfer.files[0]
    // Check MIME type, with fallback to file extension (some systems report empty MIME type)
    const isJsonFile = file && (
      file.type === 'application/json' ||
      (!file.type && file.name.toLowerCase().endsWith('.json'))
    )
    if (isJsonFile) {
      const input = fileInputRef.current
      if (input) {
        const dataTransfer = new DataTransfer()
        dataTransfer.items.add(file)
        input.files = dataTransfer.files
        const changeEvent = new Event('change', { bubbles: true })
        input.dispatchEvent(changeEvent)
      }
    }
  }, [])

  const handleDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault()
  }, [])

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            Import Configuration
          </DialogTitle>
          <DialogDescription>
            Restore configuration from a backup file
          </DialogDescription>
        </DialogHeader>

        {/* Step: Upload */}
        {step === 'upload' && (
          <div className="space-y-4">
            <div
              className="border-2 border-dashed rounded-lg p-8 text-center hover:border-primary transition-colors cursor-pointer"
              onClick={() => fileInputRef.current?.click()}
              onDrop={handleDrop}
              onDragOver={handleDragOver}
            >
              <FileJson className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <p className="text-lg font-medium mb-2">Drop backup file here</p>
              <p className="text-sm text-muted-foreground">or click to browse</p>
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,application/json"
                className="hidden"
                onChange={handleFileSelect}
              />
            </div>

            {error && (
              <div className="border border-red-200 bg-red-50 rounded-lg p-3 text-sm text-red-800 flex items-center gap-2">
                <XCircle className="h-4 w-4 flex-shrink-0" />
                {error}
              </div>
            )}
          </div>
        )}

        {/* Step: Validating */}
        {step === 'validate' && (
          <div className="flex flex-col items-center justify-center py-8">
            <Loader2 className="h-12 w-12 text-primary animate-spin mb-4" />
            <p className="text-lg font-medium">Validating backup file...</p>
          </div>
        )}

        {/* Step: Configure */}
        {step === 'configure' && validation && backup && (
          <div className="space-y-6">
            {/* Validation Status */}
            <div className={`border rounded-lg p-4 ${
              validation.valid
                ? 'border-green-200 bg-green-50'
                : 'border-red-200 bg-red-50'
            }`}>
              <div className="flex items-center gap-2 mb-2">
                {validation.valid ? (
                  <CheckCircle className="h-5 w-5 text-green-600" />
                ) : (
                  <XCircle className="h-5 w-5 text-red-600" />
                )}
                <span className={`font-medium ${validation.valid ? 'text-green-800' : 'text-red-800'}`}>
                  {validation.valid ? 'Backup file is valid' : 'Backup file has issues'}
                </span>
              </div>
              {validation.errors.length > 0 && (
                <ul className="text-sm text-red-800 list-disc list-inside">
                  {validation.errors.map((err, i) => (
                    <li key={i}>{err}</li>
                  ))}
                </ul>
              )}
              {validation.warnings.length > 0 && (
                <ul className="text-sm text-amber-800 list-disc list-inside mt-2">
                  {validation.warnings.map((warn, i) => (
                    <li key={i}>{warn}</li>
                  ))}
                </ul>
              )}
            </div>

            {/* Backup Info */}
            <div className="space-y-3">
              <h4 className="font-medium">Backup Contents</h4>
              <div className="grid grid-cols-3 gap-2">
                {Object.entries(validation.summary).map(([entity, count]) => (
                  <div key={entity} className="flex items-center justify-between p-2 rounded border bg-muted/50">
                    <span className="text-sm capitalize">{entity.replace(/_/g, ' ')}</span>
                    <Badge variant="secondary">{count}</Badge>
                  </div>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                Created: {backup.metadata.created_at}
              </p>
            </div>

            {/* Conflicts */}
            {validation.conflicts && Object.keys(validation.conflicts).length > 0 && (
              <div className="space-y-2">
                <h4 className="font-medium flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-amber-500" />
                  Existing Items Found
                </h4>
                <div className="text-sm text-muted-foreground">
                  {Object.entries(validation.conflicts).map(([type, ids]) => (
                    <div key={type}>
                      <span className="capitalize">{type.replace(/_/g, ' ')}:</span>{' '}
                      {ids.length} existing item{ids.length !== 1 ? 's' : ''}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Import Options */}
            <div className="space-y-4">
              <h4 className="font-medium">Import Options</h4>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="import-mode">Import Mode</Label>
                  <Select value={importMode} onValueChange={(v) => setImportMode(v as BackupImportMode)}>
                    <SelectTrigger id="import-mode">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="merge">
                        <div>
                          <div className="font-medium">Merge</div>
                          <div className="text-xs text-muted-foreground">Add new items, skip existing</div>
                        </div>
                      </SelectItem>
                      <SelectItem value="update">
                        <div>
                          <div className="font-medium">Update</div>
                          <div className="text-xs text-muted-foreground">Add new items, update existing</div>
                        </div>
                      </SelectItem>
                      <SelectItem value="replace">
                        <div>
                          <div className="font-medium text-red-600">Replace</div>
                          <div className="text-xs text-muted-foreground">Full replacement (destructive)</div>
                        </div>
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="include-users"
                    checked={includeUsers}
                    onCheckedChange={(checked) => setIncludeUsers(checked === true)}
                  />
                  <Label htmlFor="include-users" className="text-sm">
                    Import users (they will need to set new passwords)
                  </Label>
                </div>
              </div>
            </div>

            {error && (
              <div className="border border-red-200 bg-red-50 rounded-lg p-3 text-sm text-red-800 flex items-center gap-2">
                <XCircle className="h-4 w-4 flex-shrink-0" />
                {error}
              </div>
            )}

            <DialogFooter>
              <Button variant="outline" onClick={handleClose}>
                Cancel
              </Button>
              <Button
                onClick={handleImport}
                disabled={!validation.valid}
                variant={importMode === 'replace' ? 'destructive' : 'default'}
              >
                <Upload className="h-4 w-4 mr-2" />
                {importMode === 'replace' ? 'Replace Configuration' : 'Import Configuration'}
              </Button>
            </DialogFooter>
          </div>
        )}

        {/* Step: Importing */}
        {step === 'importing' && (
          <div className="flex flex-col items-center justify-center py-8">
            <Loader2 className="h-12 w-12 text-primary animate-spin mb-4" />
            <p className="text-lg font-medium">Importing configuration...</p>
            <p className="text-sm text-muted-foreground">This may take a moment</p>
          </div>
        )}

        {/* Step: Complete */}
        {step === 'complete' && importResult && (
          <div className="space-y-6">
            <div className="flex flex-col items-center justify-center py-4">
              <CheckCircle className="h-12 w-12 text-green-500 mb-4" />
              <p className="text-lg font-medium">Import Complete!</p>
              <p className="text-sm text-muted-foreground">
                Configuration has been imported using {importResult.mode} mode
              </p>
            </div>

            {/* Results Summary */}
            <div className="space-y-4">
              <h4 className="font-medium">Import Results</h4>
              <div className="grid gap-2">
                {Object.entries(importResult.results.imported).map(([entity, count]) => {
                  if (count === 0 &&
                      (importResult.results.skipped[entity] || 0) === 0 &&
                      (importResult.results.updated[entity] || 0) === 0) {
                    return null
                  }
                  return (
                    <div key={entity} className="flex items-center justify-between p-2 rounded border bg-muted/50">
                      <span className="text-sm capitalize">{entity.replace(/_/g, ' ')}</span>
                      <div className="flex gap-2">
                        {count > 0 && (
                          <Badge variant="default" className="bg-green-500">+{count} imported</Badge>
                        )}
                        {(importResult.results.updated[entity] || 0) > 0 && (
                          <Badge variant="outline" className="text-blue-600 border-blue-300">
                            {importResult.results.updated[entity]} updated
                          </Badge>
                        )}
                        {(importResult.results.skipped[entity] || 0) > 0 && (
                          <Badge variant="secondary">
                            {importResult.results.skipped[entity]} skipped
                          </Badge>
                        )}
                      </div>
                    </div>
                  )
                }).filter(Boolean)}
              </div>
            </div>

            <DialogFooter>
              <Button onClick={handleClose}>
                Done
              </Button>
            </DialogFooter>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
