import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { configApi } from '@/api/client'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
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
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { useToast } from '@/components/ui/use-toast'
import { Plus, Search, Trash2, Network, Shield } from 'lucide-react'

export function IpAllowList() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [newIp, setNewIp] = useState('')
  const [deleteIp, setDeleteIp] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['config', 'allowlist', 'ips'],
    queryFn: configApi.getAllowedIps,
  })

  const addMutation = useMutation({
    mutationFn: configApi.addAllowedIp,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config', 'allowlist', 'ips'] })
      toast({ title: 'IP added to allow list' })
      setNewIp('')
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to add IP',
        variant: 'destructive',
      })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: configApi.removeAllowedIp,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config', 'allowlist', 'ips'] })
      toast({ title: 'IP removed from allow list' })
      setDeleteIp(null)
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to remove IP',
        variant: 'destructive',
      })
    },
  })

  // Ensure arrays (Lua cjson may encode empty arrays as objects)
  const rawIps = (data as { ips: string[] } | undefined)?.ips
  const ips = Array.isArray(rawIps) ? rawIps : []
  const filteredIps = ips.filter((ip) =>
    ip.toLowerCase().includes(search.toLowerCase())
  )

  const handleAdd = () => {
    if (newIp.trim()) {
      addMutation.mutate(newIp.trim())
    }
  }

  const getIpType = (ip: string) => {
    if (ip.includes('/')) {
      return 'CIDR Range'
    }
    if (ip.includes(':')) {
      return 'IPv6'
    }
    return 'IPv4'
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">IP Allow List</h2>
        <p className="text-muted-foreground">
          IP addresses and ranges that bypass WAF filtering
        </p>
      </div>

      <Card className="border-green-200 bg-green-50">
        <CardContent className="flex items-center gap-4 py-4">
          <Shield className="h-5 w-5 text-green-500" />
          <div>
            <p className="font-medium text-green-800">Bypass WAF Processing</p>
            <p className="text-sm text-green-600">
              Traffic from allowed IPs skips all WAF checks. Use carefully.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Add New IP */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Network className="h-5 w-5" />
            Add IP Address
          </CardTitle>
          <CardDescription>
            Add an IP address or CIDR range to the allow list
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <Input
              placeholder="Enter IP (e.g., 192.168.1.1 or 10.0.0.0/8)"
              value={newIp}
              onChange={(e) => setNewIp(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAdd()}
              className="max-w-md"
            />
            <Button onClick={handleAdd} disabled={!newIp.trim() || addMutation.isPending}>
              <Plus className="mr-2 h-4 w-4" />
              Add
            </Button>
          </div>
          <p className="text-sm text-muted-foreground mt-2">
            Supports IPv4, IPv6, and CIDR notation (e.g., 10.0.0.0/8)
          </p>
        </CardContent>
      </Card>

      {/* Search */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search IPs..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10"
          />
        </div>
        <p className="text-sm text-muted-foreground">
          {filteredIps.length} of {ips.length} entries
        </p>
      </div>

      {/* Table */}
      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>IP / Range</TableHead>
              <TableHead>Type</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={3} className="text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : filteredIps.length === 0 ? (
              <TableRow>
                <TableCell colSpan={3} className="text-center">
                  No IPs in allow list
                </TableCell>
              </TableRow>
            ) : (
              filteredIps.map((ip) => (
                <TableRow key={ip}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Network className="h-4 w-4 text-green-500" />
                      <code className="bg-green-100 px-2 py-0.5 rounded text-green-800">
                        {ip}
                      </code>
                    </div>
                  </TableCell>
                  <TableCell>
                    <span className="text-muted-foreground text-sm">
                      {getIpType(ip)}
                    </span>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => setDeleteIp(ip)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteIp} onOpenChange={() => setDeleteIp(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove from Allow List</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to remove "{deleteIp}" from the allow list?
              Traffic from this IP will be subject to WAF processing.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteIp && deleteMutation.mutate(deleteIp)}
            >
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
