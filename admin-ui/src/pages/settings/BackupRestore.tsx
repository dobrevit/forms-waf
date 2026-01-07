import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { backupApi } from '@/api/client'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Download, Upload, Archive, Shield, AlertTriangle, HardDrive } from 'lucide-react'
import { ExportDialog } from '@/components/backup/ExportDialog'
import { ImportDialog } from '@/components/backup/ImportDialog'

export function BackupRestore() {
  const [showExportDialog, setShowExportDialog] = useState(false)
  const [showImportDialog, setShowImportDialog] = useState(false)

  const { data: entitiesData } = useQuery({
    queryKey: ['backup', 'entities'],
    queryFn: () => backupApi.getEntities(),
  })

  const entities = entitiesData?.entities || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Backup & Restore</h1>
          <p className="text-muted-foreground">
            Export and import WAF configuration for disaster recovery or appliance migration
          </p>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Export Card */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Download className="h-5 w-5" />
              Export Configuration
            </CardTitle>
            <CardDescription>
              Create a backup of your WAF configuration that can be used to restore or seed other appliances
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="text-sm text-muted-foreground space-y-2">
              <p>The export will include:</p>
              <ul className="list-disc list-inside space-y-1 ml-2">
                <li>Virtual hosts and endpoints</li>
                <li>Defense profiles and attack signatures</li>
                <li>Fingerprint profiles</li>
                <li>Keywords, hashes, and IP lists</li>
                <li>Global configuration settings</li>
              </ul>
            </div>
            <Button onClick={() => setShowExportDialog(true)} className="w-full">
              <Download className="h-4 w-4 mr-2" />
              Export Configuration
            </Button>
          </CardContent>
        </Card>

        {/* Import Card */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Upload className="h-5 w-5" />
              Import Configuration
            </CardTitle>
            <CardDescription>
              Restore configuration from a backup file or seed this appliance with existing configuration
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="text-sm text-muted-foreground space-y-2">
              <p>Import modes available:</p>
              <ul className="list-disc list-inside space-y-1 ml-2">
                <li><strong>Merge:</strong> Add new items, skip existing</li>
                <li><strong>Update:</strong> Add new items, update existing</li>
                <li><strong>Replace:</strong> Full replacement (use with caution)</li>
              </ul>
            </div>
            <Button onClick={() => setShowImportDialog(true)} variant="outline" className="w-full">
              <Upload className="h-4 w-4 mr-2" />
              Import Configuration
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Entity Types Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Archive className="h-5 w-5" />
            Configuration Entities
          </CardTitle>
          <CardDescription>
            The following entity types can be included in backup/restore operations
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {entities.map((entity) => (
              <div
                key={entity.id}
                className="flex items-center justify-between p-3 rounded-lg border bg-card"
              >
                <div className="flex items-center gap-2">
                  {entity.id === 'vhosts' && <HardDrive className="h-4 w-4 text-muted-foreground" />}
                  {entity.id === 'defense_profiles' && <Shield className="h-4 w-4 text-muted-foreground" />}
                  {entity.id === 'users' && <AlertTriangle className="h-4 w-4 text-amber-500" />}
                  {!['vhosts', 'defense_profiles', 'users'].includes(entity.id) && (
                    <Archive className="h-4 w-4 text-muted-foreground" />
                  )}
                  <span className="font-medium">{entity.name}</span>
                </div>
                <div className="flex gap-1">
                  {entity.has_builtins && (
                    <Badge variant="secondary" className="text-xs">
                      Has Builtins
                    </Badge>
                  )}
                  {entity.sensitive && (
                    <Badge variant="outline" className="text-xs text-amber-600 border-amber-300">
                      Sensitive
                    </Badge>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Warning Card */}
      <Card className="border-amber-200 bg-amber-50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-amber-800">
            <AlertTriangle className="h-5 w-5" />
            Important Notes
          </CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-amber-800 space-y-2">
          <ul className="list-disc list-inside space-y-1">
            <li>User passwords are excluded from backups for security reasons</li>
            <li>Imported users will need to set new passwords</li>
            <li>Built-in profiles can be optionally excluded to preserve customizations</li>
            <li>Replace mode will overwrite all existing configuration - use with caution</li>
            <li>Always test imports on a staging environment first</li>
          </ul>
        </CardContent>
      </Card>

      {/* Dialogs */}
      <ExportDialog
        open={showExportDialog}
        onOpenChange={setShowExportDialog}
        entities={entities}
      />
      <ImportDialog
        open={showImportDialog}
        onOpenChange={setShowImportDialog}
      />
    </div>
  )
}
