import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { endpointsApi, vhostsApi } from '@/api/client'
import { usePermissions } from '@/hooks/usePermissions'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Input } from '@/components/ui/input'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
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
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useToast } from '@/components/ui/use-toast'
import { Plus, Search, Pencil, Trash2, Route, TestTube, Globe, Server, Copy } from 'lucide-react'
import type { Endpoint, Vhost } from '@/api/types'

export function EndpointList() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const {
    canCreateEndpoint,
    canEditEndpoint,
    canDeleteEndpoint,
    canEnableEndpoint,
    canDisableEndpoint,
    hasVhostAccess,
    isReadOnly
  } = usePermissions()
  const [search, setSearch] = useState('')
  const [vhostFilter, setVhostFilter] = useState<string>('all')
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [copySourceId, setCopySourceId] = useState<string | null>(null)
  const [copyNewId, setCopyNewId] = useState('')
  const [copyNewName, setCopyNewName] = useState('')
  const [testPath, setTestPath] = useState('')
  const [testMethod, setTestMethod] = useState('POST')
  const [testResult, setTestResult] = useState<unknown>(null)

  // Fetch vhosts for filter dropdown
  const { data: vhostsData } = useQuery({
    queryKey: ['vhosts'],
    queryFn: vhostsApi.list,
  })

  const { data, isLoading } = useQuery({
    queryKey: ['endpoints', vhostFilter],
    queryFn: () => endpointsApi.list(vhostFilter === 'all' ? undefined : vhostFilter),
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      enabled ? endpointsApi.enable(id) : endpointsApi.disable(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['endpoints'] })
      toast({ title: 'Status updated' })
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to update status',
        variant: 'destructive',
      })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: endpointsApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['endpoints'] })
      toast({ title: 'Endpoint deleted' })
      setDeleteId(null)
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to delete',
        variant: 'destructive',
      })
    },
  })

  const testMutation = useMutation({
    mutationFn: ({ path, method }: { path: string; method: string }) =>
      endpointsApi.match(path, method),
    onSuccess: (result) => {
      setTestResult(result)
    },
    onError: (error) => {
      toast({
        title: 'Test failed',
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive',
      })
    },
  })

  const copyMutation = useMutation({
    mutationFn: async ({ sourceId, newId, newName }: { sourceId: string; newId: string; newName: string }) => {
      const response = await endpointsApi.get(sourceId)
      const original = (response as { endpoint?: Endpoint })?.endpoint || response as Endpoint
      const copy = {
        ...original,
        id: newId,
        name: newName,
        enabled: false,  // Disabled by default
      }
      return endpointsApi.create(copy)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['endpoints'] })
      toast({ title: 'Endpoint copied', description: 'The copy is disabled by default' })
      setCopySourceId(null)
      setCopyNewId('')
      setCopyNewName('')
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to copy',
        variant: 'destructive',
      })
    },
  })

  // Ensure arrays (Lua cjson may encode empty arrays as objects)
  const rawEndpoints = (data as { endpoints: Endpoint[] } | undefined)?.endpoints
  const endpoints = (Array.isArray(rawEndpoints) ? rawEndpoints : []) as Endpoint[]
  // Filter endpoints by search and user's vhost scope
  const filteredEndpoints = useMemo(() => {
    return endpoints.filter((e) => {
      // Check vhost scope - global endpoints (no vhost_id) are always visible
      // Vhost-specific endpoints need scope check
      if (e.vhost_id && !hasVhostAccess(e.vhost_id)) return false

      // Apply search filter
      return (
        e.id.toLowerCase().includes(search.toLowerCase()) ||
        e.name?.toLowerCase().includes(search.toLowerCase())
      )
    })
  }, [endpoints, search, hasVhostAccess])

  // Extract vhosts for filter dropdown
  const rawVhosts = (vhostsData as { vhosts: Vhost[] } | undefined)?.vhosts
  const vhosts = (Array.isArray(rawVhosts) ? rawVhosts : []) as Vhost[]

  // Get vhost name by ID
  const getVhostName = (vhostId: string | null | undefined): string => {
    if (!vhostId) return 'Global'
    const vhost = vhosts.find((v) => v.id === vhostId)
    return vhost?.name || vhostId
  }

  const getModeColor = (mode: string) => {
    switch (mode) {
      case 'blocking':
        return 'destructive'
      case 'monitoring':
        return 'warning'
      case 'passthrough':
        return 'secondary'
      case 'strict':
        return 'default'
      default:
        return 'outline'
    }
  }

  const getPathDisplay = (endpoint: Endpoint) => {
    const paths = Array.isArray(endpoint.matching.paths) ? endpoint.matching.paths : []
    if (paths.length) {
      return paths.slice(0, 2).join(', ') + (paths.length > 2 ? '...' : '')
    }
    if (endpoint.matching.path_prefix) {
      return `${endpoint.matching.path_prefix}*`
    }
    if (endpoint.matching.path_regex) {
      return `/${endpoint.matching.path_regex}/`
    }
    return 'N/A'
  }

  // Check if ID already exists
  const isIdTaken = (id: string) => endpoints.some((e) => e.id === id)

  // Open copy dialog with pre-filled values
  const openCopyDialog = (endpoint: Endpoint) => {
    setCopySourceId(endpoint.id)
    setCopyNewId(`${endpoint.id}-copy`)
    setCopyNewName(`${endpoint.name || endpoint.id} (Copy)`)
  }

  // Validate copy form
  const copyIdError = copyNewId && isIdTaken(copyNewId) ? 'This ID already exists' : ''
  const canCopy = copyNewId && !copyIdError && !copyMutation.isPending

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Endpoints</h2>
          <p className="text-muted-foreground">
            Configure path-based WAF rules and routing
          </p>
        </div>
        {canCreateEndpoint && (
          <Button asChild>
            <Link to="/endpoints/new">
              <Plus className="mr-2 h-4 w-4" />
              Add Endpoint
            </Link>
          </Button>
        )}
      </div>

      {/* Test Endpoint Matching */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <TestTube className="h-5 w-5" />
            Test Endpoint Matching
          </CardTitle>
          <CardDescription>
            Test which endpoint configuration matches a given path
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <Input
              placeholder="Enter path (e.g., /api/contact)"
              value={testPath}
              onChange={(e) => setTestPath(e.target.value)}
              className="max-w-md"
            />
            <Select value={testMethod} onValueChange={setTestMethod}>
              <SelectTrigger className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="GET">GET</SelectItem>
                <SelectItem value="POST">POST</SelectItem>
                <SelectItem value="PUT">PUT</SelectItem>
                <SelectItem value="PATCH">PATCH</SelectItem>
                <SelectItem value="DELETE">DELETE</SelectItem>
              </SelectContent>
            </Select>
            <Button
              onClick={() => testMutation.mutate({ path: testPath, method: testMethod })}
              disabled={!testPath || testMutation.isPending}
            >
              Test
            </Button>
          </div>
          {testResult && (
            <div className="mt-4 rounded-md bg-muted p-4">
              <pre className="text-sm">{JSON.stringify(testResult, null, 2)}</pre>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Search and Filter */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search endpoints..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10"
          />
        </div>
        <Select value={vhostFilter} onValueChange={setVhostFilter}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Filter by vhost" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Endpoints</SelectItem>
            <SelectItem value="_global">Global Only</SelectItem>
            {vhosts.map((vhost) => (
              <SelectItem key={vhost.id} value={vhost.id}>
                {vhost.name || vhost.id}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-sm text-muted-foreground">
          {filteredEndpoints.length} endpoint{filteredEndpoints.length !== 1 ? 's' : ''}
        </p>
      </div>

      {/* Table */}
      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Scope</TableHead>
              <TableHead>Paths</TableHead>
              <TableHead>Methods</TableHead>
              <TableHead>Mode</TableHead>
              <TableHead>Priority</TableHead>
              <TableHead>Enabled</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8} className="text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : filteredEndpoints.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="text-center">
                  No endpoints found
                </TableCell>
              </TableRow>
            ) : (
              filteredEndpoints.map((endpoint) => (
                <TableRow key={endpoint.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Route className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <p className="font-medium">{endpoint.name || endpoint.id}</p>
                        <p className="text-xs text-muted-foreground">{endpoint.id}</p>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      {endpoint.vhost_id ? (
                        <>
                          <Server className="h-3 w-3 text-blue-500" />
                          <span className="text-sm">{getVhostName(endpoint.vhost_id)}</span>
                        </>
                      ) : (
                        <>
                          <Globe className="h-3 w-3 text-green-500" />
                          <span className="text-sm text-muted-foreground">Global</span>
                        </>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <code className="text-xs bg-muted px-1 py-0.5 rounded">
                      {getPathDisplay(endpoint)}
                    </code>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {(() => {
                        const methods = Array.isArray(endpoint.matching.methods)
                          ? endpoint.matching.methods
                          : ['POST', 'PUT', 'PATCH']
                        return methods.map((method) => (
                          <Badge key={method} variant="outline" className="text-xs">
                            {method}
                          </Badge>
                        ))
                      })()}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={getModeColor(endpoint.mode)}>
                      {endpoint.mode}
                    </Badge>
                  </TableCell>
                  <TableCell>{endpoint.priority || 100}</TableCell>
                  <TableCell>
                    <Switch
                      checked={endpoint.enabled}
                      onCheckedChange={(checked) =>
                        toggleMutation.mutate({ id: endpoint.id, enabled: checked })
                      }
                      disabled={
                        endpoint.enabled
                          ? !canDisableEndpoint(endpoint.vhost_id)
                          : !canEnableEndpoint(endpoint.vhost_id)
                      }
                    />
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      {canEditEndpoint(endpoint.vhost_id) && (
                        <Button variant="ghost" size="icon" asChild>
                          <Link to={`/endpoints/${endpoint.id}`}>
                            <Pencil className="h-4 w-4" />
                          </Link>
                        </Button>
                      )}
                      {canCreateEndpoint && (
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => openCopyDialog(endpoint)}
                          title="Copy endpoint"
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                      )}
                      {canDeleteEndpoint(endpoint.vhost_id) && (
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => setDeleteId(endpoint.id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteId} onOpenChange={() => setDeleteId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Endpoint</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this endpoint? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteId && deleteMutation.mutate(deleteId)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Copy Confirmation */}
      <AlertDialog open={!!copySourceId} onOpenChange={() => setCopySourceId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Copy Endpoint</AlertDialogTitle>
            <AlertDialogDescription>
              Create a copy of this endpoint. The copy will be disabled by default.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="copy-endpoint-id">ID</Label>
              <Input
                id="copy-endpoint-id"
                value={copyNewId}
                onChange={(e) => setCopyNewId(e.target.value)}
                placeholder="Enter unique ID"
              />
              {copyIdError && (
                <p className="text-sm text-destructive">{copyIdError}</p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="copy-endpoint-name">Name</Label>
              <Input
                id="copy-endpoint-name"
                value={copyNewName}
                onChange={(e) => setCopyNewName(e.target.value)}
                placeholder="Enter display name"
              />
            </div>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => copySourceId && copyMutation.mutate({ sourceId: copySourceId, newId: copyNewId, newName: copyNewName })}
              disabled={!canCopy}
            >
              {copyMutation.isPending ? 'Copying...' : 'Copy'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
