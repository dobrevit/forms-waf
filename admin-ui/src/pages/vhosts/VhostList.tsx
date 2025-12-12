import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { vhostsApi } from '@/api/client'
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
import { useToast } from '@/components/ui/use-toast'
import { Plus, Search, Pencil, Trash2, Globe, TestTube, Route } from 'lucide-react'
import type { Vhost } from '@/api/types'

export function VhostList() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [testHost, setTestHost] = useState('')
  const [testResult, setTestResult] = useState<unknown>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['vhosts'],
    queryFn: vhostsApi.list,
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      enabled ? vhostsApi.enable(id) : vhostsApi.disable(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vhosts'] })
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
    mutationFn: vhostsApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vhosts'] })
      toast({ title: 'Virtual host deleted' })
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
    mutationFn: (host: string) => vhostsApi.match(host),
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

  // Ensure arrays (Lua cjson may encode empty arrays as objects)
  const rawVhosts = (data as { vhosts: Vhost[] } | undefined)?.vhosts
  const vhosts = (Array.isArray(rawVhosts) ? rawVhosts : []) as Vhost[]
  const filteredVhosts = vhosts.filter((v) => {
    const hostnames = Array.isArray(v.hostnames) ? v.hostnames : []
    return (
      v.id.toLowerCase().includes(search.toLowerCase()) ||
      v.name?.toLowerCase().includes(search.toLowerCase()) ||
      hostnames.some((h) => h.toLowerCase().includes(search.toLowerCase()))
    )
  })

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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Virtual Hosts</h2>
          <p className="text-muted-foreground">
            Manage host-based routing and WAF configuration
          </p>
        </div>
        <Button asChild>
          <Link to="/vhosts/new">
            <Plus className="mr-2 h-4 w-4" />
            Add Virtual Host
          </Link>
        </Button>
      </div>

      {/* Test Host Matching */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <TestTube className="h-5 w-5" />
            Test Host Matching
          </CardTitle>
          <CardDescription>
            Test which virtual host configuration matches a given hostname
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <Input
              placeholder="Enter hostname (e.g., api.example.com)"
              value={testHost}
              onChange={(e) => setTestHost(e.target.value)}
              className="max-w-md"
            />
            <Button
              onClick={() => testMutation.mutate(testHost)}
              disabled={!testHost || testMutation.isPending}
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

      {/* Search */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search virtual hosts..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10"
          />
        </div>
      </div>

      {/* Table */}
      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Hostnames</TableHead>
              <TableHead>Endpoints</TableHead>
              <TableHead>Mode</TableHead>
              <TableHead>Routing</TableHead>
              <TableHead>Enabled</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : filteredVhosts.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center">
                  No virtual hosts found
                </TableCell>
              </TableRow>
            ) : (
              filteredVhosts.map((vhost) => (
                <TableRow key={vhost.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Globe className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <p className="font-medium">{vhost.name || vhost.id}</p>
                        <p className="text-xs text-muted-foreground">{vhost.id}</p>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {(() => {
                        const hostnames = Array.isArray(vhost.hostnames) ? vhost.hostnames : []
                        return (
                          <>
                            {hostnames.slice(0, 3).map((hostname) => (
                              <Badge key={hostname} variant="outline" className="text-xs">
                                {hostname}
                              </Badge>
                            ))}
                            {hostnames.length > 3 && (
                              <Badge variant="outline" className="text-xs">
                                +{hostnames.length - 3}
                              </Badge>
                            )}
                          </>
                        )
                      })()}
                    </div>
                  </TableCell>
                  <TableCell>
                    {vhost.endpoint_count !== undefined && vhost.endpoint_count > 0 ? (
                      <div className="flex items-center gap-1">
                        <Route className="h-3 w-3 text-blue-500" />
                        <span className="text-sm font-medium">{vhost.endpoint_count}</span>
                        <span className="text-xs text-muted-foreground">specific</span>
                      </div>
                    ) : (
                      <span className="text-sm text-muted-foreground">-</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge variant={getModeColor(vhost.waf?.mode || 'monitoring')}>
                      {vhost.waf?.mode || 'monitoring'}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary">
                      {vhost.routing?.use_haproxy ? 'HAProxy' : 'Direct'}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={vhost.enabled}
                      onCheckedChange={(checked) =>
                        toggleMutation.mutate({ id: vhost.id, enabled: checked })
                      }
                      disabled={vhost.id === '_default'}
                    />
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button variant="ghost" size="icon" asChild>
                        <Link to={`/vhosts/${vhost.id}`}>
                          <Pencil className="h-4 w-4" />
                        </Link>
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => setDeleteId(vhost.id)}
                        disabled={vhost.id === '_default'}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
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
            <AlertDialogTitle>Delete Virtual Host</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this virtual host? This action cannot be undone.
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
    </div>
  )
}
