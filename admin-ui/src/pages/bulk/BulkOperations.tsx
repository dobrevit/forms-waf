import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { bulkApi } from '@/api/client'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useToast } from '@/components/ui/use-toast'
import {
  Download,
  Upload,
  Trash2,
  FileJson,
  Ban,
  Network,
  Hash,
  AlertTriangle,
  CheckCircle,
  Info,
} from 'lucide-react'

export function BulkOperations() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const [importText, setImportText] = useState('')
  const [importType, setImportType] = useState<'keywords' | 'ips' | 'hashes'>('keywords')
  const [mergeMode, setMergeMode] = useState(true)
  const [importResult, setImportResult] = useState<{
    imported: number
    skipped: number
    invalid?: number
    total: number
  } | null>(null)

  // Export queries
  const { data: keywordsData, refetch: refetchKeywords } = useQuery({
    queryKey: ['bulk', 'keywords'],
    queryFn: bulkApi.exportKeywords,
    enabled: false,
  })

  const { data: ipsData, refetch: refetchIps } = useQuery({
    queryKey: ['bulk', 'ips'],
    queryFn: bulkApi.exportIps,
    enabled: false,
  })

  const { data: hashesData, refetch: refetchHashes } = useQuery({
    queryKey: ['bulk', 'hashes'],
    queryFn: bulkApi.exportHashes,
    enabled: false,
  })

  // Import mutations
  const importKeywordsMutation = useMutation({
    mutationFn: ({ keywords, merge }: { keywords: string[]; merge: boolean }) =>
      bulkApi.importKeywords(keywords, merge),
    onSuccess: (result) => {
      setImportResult(result)
      queryClient.invalidateQueries({ queryKey: ['keywords'] })
      toast({
        title: 'Keywords imported',
        description: `Imported ${result.imported}, skipped ${result.skipped}`,
      })
    },
    onError: (error) => {
      toast({
        title: 'Import failed',
        description: error instanceof Error ? error.message : 'Failed to import',
        variant: 'destructive',
      })
    },
  })

  const importIpsMutation = useMutation({
    mutationFn: ({ ips, merge }: { ips: string[]; merge: boolean }) => bulkApi.importIps(ips, merge),
    onSuccess: (result) => {
      setImportResult(result)
      queryClient.invalidateQueries({ queryKey: ['config'] })
      toast({
        title: 'IPs imported',
        description: `Imported ${result.imported}, skipped ${result.skipped}, invalid ${result.invalid || 0}`,
      })
    },
    onError: (error) => {
      toast({
        title: 'Import failed',
        description: error instanceof Error ? error.message : 'Failed to import',
        variant: 'destructive',
      })
    },
  })

  const importHashesMutation = useMutation({
    mutationFn: ({ hashes, merge }: { hashes: string[]; merge: boolean }) =>
      bulkApi.importHashes(hashes, merge),
    onSuccess: (result) => {
      setImportResult(result)
      toast({
        title: 'Hashes imported',
        description: `Imported ${result.imported}, skipped ${result.skipped}, invalid ${result.invalid || 0}`,
      })
    },
    onError: (error) => {
      toast({
        title: 'Import failed',
        description: error instanceof Error ? error.message : 'Failed to import',
        variant: 'destructive',
      })
    },
  })

  const clearKeywordsMutation = useMutation({
    mutationFn: () => bulkApi.clearKeywords(true),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['keywords'] })
      toast({
        title: 'Keywords cleared',
        description: `Removed ${result.count} keywords`,
      })
    },
    onError: (error) => {
      toast({
        title: 'Clear failed',
        description: error instanceof Error ? error.message : 'Failed to clear',
        variant: 'destructive',
      })
    },
  })

  const handleExport = async (type: 'keywords' | 'ips' | 'hashes' | 'all') => {
    let data: unknown
    let filename: string

    if (type === 'keywords') {
      const result = await refetchKeywords()
      data = { keywords: result.data?.keywords || [], exported_at: new Date().toISOString() }
      filename = 'waf-keywords.json'
    } else if (type === 'ips') {
      const result = await refetchIps()
      data = { ips: result.data?.ips || [], exported_at: new Date().toISOString() }
      filename = 'waf-ips.json'
    } else if (type === 'hashes') {
      const result = await refetchHashes()
      data = { hashes: result.data?.hashes || [], exported_at: new Date().toISOString() }
      filename = 'waf-hashes.json'
    } else {
      const [kw, ip, hash] = await Promise.all([refetchKeywords(), refetchIps(), refetchHashes()])
      data = {
        keywords: kw.data?.keywords || [],
        ips: ip.data?.ips || [],
        hashes: hash.data?.hashes || [],
        exported_at: new Date().toISOString(),
      }
      filename = 'waf-export-all.json'
    }

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)

    toast({ title: 'Export complete', description: `Downloaded ${filename}` })
  }

  const handleImport = () => {
    setImportResult(null)
    const lines = importText
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#') && !line.startsWith('//'))

    if (lines.length === 0) {
      toast({
        title: 'No data to import',
        description: 'Please enter data to import',
        variant: 'destructive',
      })
      return
    }

    if (importType === 'keywords') {
      importKeywordsMutation.mutate({ keywords: lines, merge: mergeMode })
    } else if (importType === 'ips') {
      importIpsMutation.mutate({ ips: lines, merge: mergeMode })
    } else {
      importHashesMutation.mutate({ hashes: lines, merge: mergeMode })
    }
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (event) => {
      const content = event.target?.result as string
      try {
        // Try parsing as JSON first
        const json = JSON.parse(content)
        if (json.keywords && importType === 'keywords') {
          setImportText(json.keywords.join('\n'))
        } else if (json.ips && importType === 'ips') {
          setImportText(json.ips.join('\n'))
        } else if (json.hashes && importType === 'hashes') {
          setImportText(json.hashes.join('\n'))
        } else {
          // Assume it's a plain list
          setImportText(content)
        }
      } catch {
        // Not JSON, treat as plain text
        setImportText(content)
      }
    }
    reader.readAsText(file)
  }

  const isImporting =
    importKeywordsMutation.isPending ||
    importIpsMutation.isPending ||
    importHashesMutation.isPending

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <FileJson className="h-8 w-8 text-primary" />
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Bulk Operations</h2>
          <p className="text-muted-foreground">
            Import and export keywords, IP addresses, and blocked hashes
          </p>
        </div>
      </div>

      <Tabs defaultValue="export" className="space-y-4">
        <TabsList>
          <TabsTrigger value="export" className="flex items-center gap-2">
            <Download className="h-4 w-4" />
            Export
          </TabsTrigger>
          <TabsTrigger value="import" className="flex items-center gap-2">
            <Upload className="h-4 w-4" />
            Import
          </TabsTrigger>
          <TabsTrigger value="manage" className="flex items-center gap-2">
            <Trash2 className="h-4 w-4" />
            Manage
          </TabsTrigger>
        </TabsList>

        <TabsContent value="export">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card className="cursor-pointer hover:border-primary transition-colors" onClick={() => handleExport('keywords')}>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Ban className="h-5 w-5 text-red-500" />
                  Keywords
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Export blocked keywords list
                </p>
                <Button variant="outline" className="w-full">
                  <Download className="mr-2 h-4 w-4" />
                  Export JSON
                </Button>
              </CardContent>
            </Card>

            <Card className="cursor-pointer hover:border-primary transition-colors" onClick={() => handleExport('ips')}>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Network className="h-5 w-5 text-blue-500" />
                  IP Addresses
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Export allowed IP addresses
                </p>
                <Button variant="outline" className="w-full">
                  <Download className="mr-2 h-4 w-4" />
                  Export JSON
                </Button>
              </CardContent>
            </Card>

            <Card className="cursor-pointer hover:border-primary transition-colors" onClick={() => handleExport('hashes')}>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Hash className="h-5 w-5 text-purple-500" />
                  Blocked Hashes
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Export blocked content hashes
                </p>
                <Button variant="outline" className="w-full">
                  <Download className="mr-2 h-4 w-4" />
                  Export JSON
                </Button>
              </CardContent>
            </Card>

            <Card className="cursor-pointer hover:border-primary transition-colors" onClick={() => handleExport('all')}>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-lg">
                  <FileJson className="h-5 w-5 text-green-500" />
                  Export All
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Export everything in one file
                </p>
                <Button variant="outline" className="w-full">
                  <Download className="mr-2 h-4 w-4" />
                  Export JSON
                </Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="import">
          <Card>
            <CardHeader>
              <CardTitle>Import Data</CardTitle>
              <CardDescription>
                Import keywords, IP addresses, or blocked hashes from a file or text
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex gap-4">
                <div className="space-y-2">
                  <Label>Import Type</Label>
                  <div className="flex gap-2">
                    <Button
                      type="button"
                      variant={importType === 'keywords' ? 'default' : 'outline'}
                      onClick={() => setImportType('keywords')}
                    >
                      <Ban className="mr-2 h-4 w-4" />
                      Keywords
                    </Button>
                    <Button
                      type="button"
                      variant={importType === 'ips' ? 'default' : 'outline'}
                      onClick={() => setImportType('ips')}
                    >
                      <Network className="mr-2 h-4 w-4" />
                      IPs
                    </Button>
                    <Button
                      type="button"
                      variant={importType === 'hashes' ? 'default' : 'outline'}
                      onClick={() => setImportType('hashes')}
                    >
                      <Hash className="mr-2 h-4 w-4" />
                      Hashes
                    </Button>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Mode</Label>
                  <div className="flex items-center space-x-2 pt-2">
                    <Switch
                      id="merge"
                      checked={mergeMode}
                      onCheckedChange={setMergeMode}
                    />
                    <Label htmlFor="merge" className="text-sm">
                      {mergeMode ? 'Merge with existing' : 'Replace all'}
                    </Label>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label>Data (one per line)</Label>
                  <label className="cursor-pointer">
                    <input
                      type="file"
                      accept=".json,.txt,.csv"
                      className="hidden"
                      onChange={handleFileUpload}
                    />
                    <Button variant="outline" size="sm" asChild>
                      <span>
                        <Upload className="mr-2 h-4 w-4" />
                        Upload File
                      </span>
                    </Button>
                  </label>
                </div>
                <textarea
                  className="flex min-h-[200px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 font-mono"
                  placeholder={
                    importType === 'keywords'
                      ? 'spam\nbuy now\nfree money\n# Comments start with #'
                      : importType === 'ips'
                      ? '10.0.0.0/8\n192.168.1.100\n# Private networks'
                      : '64a8b9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9\n# SHA256 hashes'
                  }
                  value={importText}
                  onChange={(e) => setImportText(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  {importText.split('\n').filter((l) => l.trim() && !l.startsWith('#')).length} items
                  to import
                </p>
              </div>

              {!mergeMode && (
                <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4">
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="h-5 w-5 text-yellow-600 mt-0.5" />
                    <div>
                      <p className="font-medium text-yellow-800">Replace Mode Active</p>
                      <p className="text-sm text-yellow-700 mt-1">
                        This will remove all existing {importType} and replace them with the imported data.
                        This action cannot be undone.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {importResult && (
                <div className="rounded-lg border border-green-200 bg-green-50 p-4">
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-green-600 mt-0.5" />
                    <div>
                      <p className="font-medium text-green-800">Import Complete</p>
                      <div className="text-sm text-green-700 mt-1 space-x-4">
                        <span>Imported: {importResult.imported}</span>
                        <span>Skipped: {importResult.skipped}</span>
                        {importResult.invalid !== undefined && (
                          <span>Invalid: {importResult.invalid}</span>
                        )}
                        <span>Total: {importResult.total}</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              <Button onClick={handleImport} disabled={isImporting || !importText.trim()}>
                <Upload className="mr-2 h-4 w-4" />
                {isImporting ? 'Importing...' : `Import ${importType}`}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="manage">
          <Card>
            <CardHeader>
              <CardTitle>Bulk Management</CardTitle>
              <CardDescription>
                Dangerous operations - clear all data at once
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="rounded-lg border border-red-200 bg-red-50 p-4">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 text-red-600 mt-0.5" />
                  <div>
                    <p className="font-medium text-red-800">Danger Zone</p>
                    <p className="text-sm text-red-700 mt-1">
                      These actions are irreversible. Make sure to export your data before clearing.
                    </p>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 border rounded-lg">
                  <div>
                    <p className="font-medium">Clear All Blocked Keywords</p>
                    <p className="text-sm text-muted-foreground">
                      Remove all blocked keywords from the WAF
                    </p>
                  </div>
                  <Button
                    variant="destructive"
                    onClick={() => {
                      if (
                        confirm(
                          'Are you sure you want to clear ALL blocked keywords? This cannot be undone.'
                        )
                      ) {
                        clearKeywordsMutation.mutate()
                      }
                    }}
                    disabled={clearKeywordsMutation.isPending}
                  >
                    <Trash2 className="mr-2 h-4 w-4" />
                    {clearKeywordsMutation.isPending ? 'Clearing...' : 'Clear Keywords'}
                  </Button>
                </div>
              </div>

              <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
                <div className="flex items-start gap-3">
                  <Info className="h-5 w-5 text-blue-500 mt-0.5" />
                  <div>
                    <p className="font-medium text-blue-800">Data Safety</p>
                    <p className="text-sm text-blue-700 mt-1">
                      We recommend exporting your data before performing any bulk clear operations.
                      Exports can be used to restore your configuration if needed.
                    </p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
